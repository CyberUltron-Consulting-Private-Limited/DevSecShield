"""CB-19 PR-1e + CB-24 PR-1e: the quantum risk grade and the crypto-agility fix class in the run CycloneDX export.

CB-19 PLAN §2.8 / CB-24 PLAN §11. Every asset component carries ``zs:q_grade`` ("Q0".."Q4" or ``none``),
``zs:q_label``, ``zs:q_reason``, ``zs:fix_class`` (incl. ``none`` / ``unknown``), ``zs:fix_class_floor``,
``zs:fix_class_confidence`` (``none`` when null) and ``zs:fix_class_basis``; the metadata names the grade model, its
version, the sha256 of its text, the grade inputs and the run's distributions, equal to the run posture API; the
serial changes when the grade model version, the grade inputs digest or the agility version changes (cx3 ST-A).

Oracle: the run's own API (``/runs/{id}/assets`` per asset id, ``/runs/{id}/posture``, ``/grade-model``) is the one
source of truth the export must equal; schema validity is checked by test code (support/cyclonedx_schema.py).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb19_24_export.py -q
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import re
import sys
from collections import Counter
from pathlib import Path

import pytest
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_cb19_run_grades as GR  # noqa: E402  (seed(): a run straight into the tables, Mosca settings)
from support.cyclonedx_schema import json_errors, xml_errors  # noqa: E402

from backend.new_models import CbomCollectionRun  # noqa: E402
from backend.utilities.cbom_sources.settings import get_or_create_settings  # noqa: E402

api, world = GR.api, GR.world  # the harness's fixtures, used by name below

GRADE_PROPS = ("zs:q_grade", "zs:q_label", "zs:q_reason")
AGILITY_PROPS = ("zs:fix_class", "zs:fix_class_floor", "zs:fix_class_confidence", "zs:fix_class_basis")
ASSET_REF = re.compile(r"^zs-asset-(\d+)$")
GRADES = {"Q0", "Q1", "Q2", "Q3", "Q4", "none"}
LABELS = {"Unknown", "Critical", "High", "Medium", "Low", "none"}
FIX_CLASSES = {"configurable", "code-fixed", "vendor-fixed", "hardware-fixed", "unknown", "none"}

WIN_CERT = GR._asset("certificate", "Cert:\\LocalMachine\\My\\AB12", algorithm="RSA", key_size=2048, name="web",
                     facts={"subject": "CN=web.bank.local", "issuer": "CN=Bank CA", "not_after": "2030-01-01T00:00:00Z",
                            "key_alg": "RSA", "key_size": 2048, "source": "windows-store", "has_private_key": True})
ASSETS = [
    # quantum-vulnerable, internet (Q1) / internal (Q2); a CA (anchor); a hybrid endpoint with a classical fallback
    GR._asset("tls_endpoint", "203.0.113.10:443", target="203.0.113.10", facts=GR.QV_TLS),
    GR._asset("tls_endpoint", "10.20.0.1:443", facts=GR.QV_TLS),
    GR._asset("certificate", "/etc/pki/ca.pem", facts=GR.CA, algorithm="RSA", key_size=2048, name="ca"),
    GR._asset("tls_endpoint", "10.20.0.1:8443", facts={"protocols": ["TLSv1.2", "TLSv1.3"], "pq_hybrid": True}),
    GR._asset("tls_endpoint", "10.20.0.1:9443", facts=GR.HYBRID_ONLY),  # Q4, no finding code: fix class none
    # Grover-weakened volume (Q3); no public-key cryptography (grade none)
    GR._asset("disk_encryption", "C:", algorithm="XtsAes128",
              facts={"source": "bitlocker", "status": "FullyEncrypted", "method": "XtsAes128", "protection": "On",
                     "mount": "C:"}),
    GR._asset("database_config", "10.20.0.1:5432", facts={"password_encryption": "scram-sha-256"}),
    # a Windows certificate whose key provider was not read: fix class unknown, floor vendor-fixed
    WIN_CERT,
    # SSH with a classical key exchange on an old OpenSSH (R-STACK vendor-fixed)
    GR._asset("ssh_endpoint", "10.20.0.1:22", facts={"banner": "SSH-2.0-OpenSSH_8.2p1", "kex": ["curve25519-sha256"]}),
]
VENDOR_ASSETS = [GR._asset("tls_endpoint", "10.30.0.1:443", target="10.30.0.1",
                           facts={"protocols": ["TLSv1.0", "TLSv1.2"], "group": "x25519"})]


def _seed(engine, *, mosca=GR.MOSCA) -> dict:
    return GR.seed(engine, mosca=mosca, sources=[
        {"name": "S-mixed", "assets": ASSETS},
        {"name": "S-vendor", "metadata": {"operated_by": "vendor"}, "assets": VENDOR_ASSETS},
        {"name": "S-net", "kind": "network_range", "assets": [GR._cov("10.40.0.9", "no answer", "timeout")],
         "result": {"targets": [{"target": "10.40.0.9", "status": "timeout"}]}},
    ])


def _props(component: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for prop in component.get("properties") or []:
        out.setdefault(prop["name"], []).append(prop.get("value"))
    return out


def _one(component: dict, name: str) -> str:
    values = _props(component).get(name)
    assert values is not None, f"{component.get('bom-ref')}: {name} absent"
    assert len(values) == 1, f"{component.get('bom-ref')}: {name} repeated {values}"
    return values[0]


def _assets(doc: dict) -> dict[int, dict]:
    return {int(m.group(1)): c for c in doc["components"] if (m := ASSET_REF.match(c.get("bom-ref", "")))}


def _export(api, run_id: int, fmt: str = "json"):
    r = api("GET", f"/1/cbom/sources/runs/{run_id}/cbom" + ("?format=xml" if fmt == "xml" else ""))
    assert r.status_code == 200, r.text
    return r


def _xml_props(xml: bytes) -> tuple[dict[str, list[str]], dict[str, dict[str, list[str]]]]:
    """(metadata properties, {bom-ref: component properties}) read from the XML download."""
    from lxml import etree

    ns = {"c": "http://cyclonedx.org/schema/bom/1.6"}
    root = etree.fromstring(xml)

    def props(node) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for p in node.findall("c:properties/c:property", ns):
            out.setdefault(p.get("name"), []).append(p.text or "")
        return out

    meta = props(root.find("c:metadata", ns))
    comps = {c.get("bom-ref"): props(c) for c in root.findall("c:components/c:component", ns)}
    return meta, comps


def _n(value):
    """The export's spelling of an API null."""
    return "none" if value is None else value


@pytest.fixture()
def seeded(api, world):
    w = _seed(world[0])
    run_id = w["run"]
    doc = _export(api, run_id).json()
    listed = api("GET", f"/1/cbom/sources/runs/{run_id}/assets?page_size=200")
    assert listed.status_code == 200, listed.text
    posture = api("GET", f"/1/cbom/sources/runs/{run_id}/posture").json()["posture"]
    return {"w": w, "run": run_id, "doc": doc, "list": listed.json(), "posture": posture, "engine": world[0]}


# ============================================================================== every component, every value
def test_every_asset_component_carries_the_grade_and_agility_properties(seeded):
    comps = _assets(seeded["doc"])
    assert len(comps) == len(ASSETS) + len(VENDOR_ASSETS)  # the coverage row is a gap, not a component
    seen: Counter = Counter()
    for comp in comps.values():
        grade, label, reason = (_one(comp, n) for n in GRADE_PROPS)
        fix, floor, confidence, basis = (_one(comp, n) for n in AGILITY_PROPS)
        assert grade in GRADES and label in LABELS and reason
        assert (grade == "none") == (label == "none")
        assert fix in FIX_CLASSES and floor in FIX_CLASSES - {"unknown"} and confidence in ("observed", "inferred", "none")
        assert (floor != "none") <= (fix == "unknown") and (confidence == "none") == (fix in ("unknown", "none"))
        parsed = json.loads(basis)
        assert isinstance(parsed, list) and len(basis) <= 512
        assert (parsed == []) == (fix == "none")
        assert all(set(p) == {"code", "class", "rule"} for p in parsed if isinstance(p, dict))
        seen.update({f"grade:{grade}", f"fix:{fix}", f"floor:{floor}", f"conf:{confidence}"})
    # the cases this run was built to hold, so the null spellings are really exercised
    for case in ("grade:Q1", "grade:Q2", "grade:Q3", "grade:Q4", "grade:none", "fix:none", "fix:unknown",
                 "fix:vendor-fixed", "floor:vendor-fixed", "floor:none", "conf:none"):
        assert seen[case], (case, seen)


def test_certificate_parts_are_not_graded(seeded):
    parts = [c for c in seeded["doc"]["components"] if not ASSET_REF.match(c["bom-ref"])]
    assert parts  # the certificates reference shared parts
    for part in parts:
        assert not set(_props(part)) & {*GRADE_PROPS, *AGILITY_PROPS}, part["bom-ref"]


def test_the_export_equals_the_run_asset_api_per_asset_id(seeded):
    """One source of truth: the values the run's asset list shows are the values the export writes, asset by asset."""
    comps = _assets(seeded["doc"])
    items = {i["id"]: i for i in seeded["list"]["items"] if i["type"] != "coverage"}
    assert set(items) == set(comps)
    for aid, item in items.items():
        comp = comps[aid]
        assert _one(comp, "zs:q_grade") == _n(item["q_grade"]), aid
        assert _one(comp, "zs:q_label") == _n(item["q_label"]), aid
        assert _one(comp, "zs:q_reason") == item["q_reason"], aid
        assert _one(comp, "zs:fix_class") == item["fix_class"], aid
        assert _one(comp, "zs:fix_class_floor") == _n(item["fix_class_floor"]), aid
        assert _one(comp, "zs:fix_class_confidence") == _n(item["fix_class_confidence"]), aid


def test_the_basis_lists_each_code_with_the_class_and_rule_of_the_asset_detail(seeded, api):
    comps = _assets(seeded["doc"])
    for aid in list(comps)[:6]:
        agility = api("GET", f"/1/cbom/sources/assets/{aid}").json()["asset"]["agility"]
        want = [{"code": p["code"], "class": p["class"], "rule": p["rule"]} for p in agility["by_code"]]
        assert json.loads(_one(comps[aid], "zs:fix_class_basis")) == want, aid


def test_metadata_equals_the_run_posture_api(seeded, api):
    meta = {k: v[0] for k, v in _props(seeded["doc"]["metadata"]).items() if k.startswith(("zs:grade", "zs:q_",
                                                                                              "zs:agility", "zs:fix"))}
    posture = seeded["posture"]
    model = api("GET", "/1/cbom/sources/grade-model").json()
    model = model.get("model", model) if isinstance(model.get("model"), dict) else model
    assert meta["zs:grade_model"] == posture["grade_model"] == "qg-1"
    assert meta["zs:grade_model_version"] == posture["grade_model_version"] == seeded["list"]["grade_model_version"]
    assert meta["zs:grade_model_sha256"] == model["text_sha256"] == hashlib.sha256(model["text"].encode()).hexdigest()
    inputs = json.loads(meta["zs:grade_inputs"])
    with Session(seeded["engine"]) as s:  # source "current": when the team's settings (its Mosca) were last written
        written = get_or_create_settings(s, 1).last_updated
    assert inputs.pop("captured_at") == written.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert inputs == posture["grade_inputs"] == seeded["list"]["grade_inputs"]
    assert json.loads(meta["zs:q_distribution"]) == posture["q_grades"]
    assert meta["zs:agility_model"] == "fx-1" and meta["zs:agility_version"] == posture["agility_version"]
    assert json.loads(meta["zs:fix_class_distribution"]) == posture["fix_classes"]
    assert json.loads(meta["zs:fix_class_distribution_excl_pq"]) == posture["fix_classes_excl_pq"]
    assert posture["fix_class_self_fixable_pct"] is not None
    assert float(meta["zs:fix_class_self_fixable_pct"]) == posture["fix_class_self_fixable_pct"]
    # the distributions count exactly the components
    comps = _assets(seeded["doc"]).values()
    assert Counter(_one(c, "zs:q_grade") for c in comps) == Counter(
        {k: v for k, v in json.loads(meta["zs:q_distribution"]).items() if v})
    assert Counter(_one(c, "zs:fix_class") for c in comps) == Counter(
        {k: v for k, v in json.loads(meta["zs:fix_class_distribution"]).items() if v})
    for name, value in meta.items():  # compact JSON, as zs:coverage_gap writes it
        if value.startswith(("{", "[")):
            assert value == json.dumps(json.loads(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_mosca_unset_grades_quantum_vulnerable_assets_q0_and_says_so(api, world):
    w = _seed(world[0], mosca=None)
    doc = _export(api, w["run"]).json()
    comp = _assets(doc)[w["S-mixed"]["assets"]["10.20.0.1:443"]]
    assert (_one(comp, "zs:q_grade"), _one(comp, "zs:q_label"), _one(comp, "zs:q_reason")) == (
        "Q0", "Unknown", "mosca_missing")
    inputs = json.loads(_one(doc["metadata"], "zs:grade_inputs"))
    assert inputs["mosca"] == {"x": None, "y": None, "z": None} and inputs["source"] == "current"


# ============================================================================== XML and the schemas
def test_json_and_xml_are_valid_and_carry_the_same_values(seeded, api):
    assert json_errors(seeded["doc"]) == []
    xml = _export(api, seeded["run"], "xml").content
    assert xml_errors(xml) == []
    meta, comps = _xml_props(xml)
    doc_meta = _props(seeded["doc"]["metadata"])
    for name in ("zs:grade_model", "zs:grade_model_version", "zs:grade_model_sha256", "zs:q_distribution",
                 "zs:agility_model", "zs:agility_version", "zs:fix_class_distribution",
                 "zs:fix_class_distribution_excl_pq", "zs:fix_class_self_fixable_pct"):
        assert meta[name] == doc_meta[name], name
    assert json.loads(meta["zs:grade_inputs"][0])["digest"] == json.loads(doc_meta["zs:grade_inputs"][0])["digest"]
    for aid, comp in _assets(seeded["doc"]).items():
        got = comps[f"zs-asset-{aid}"]
        for name in (*GRADE_PROPS, *AGILITY_PROPS):
            assert got[name] == _props(comp)[name], (aid, name)


# ============================================================================== serial (cx3 ST-A)
def test_the_serial_and_grade_metadata_are_stable_for_the_same_grade_content(seeded, api):
    """No request time in the grade content: repeat downloads keep the serial and the grade metadata (CB-38 PR-8
    signs the bytes of a finished run's download and needs them to repeat)."""
    import time

    time.sleep(1.1)  # a later second
    again = _export(api, seeded["run"]).json()
    assert again["serialNumber"] == seeded["doc"]["serialNumber"]
    names = ("zs:grade_inputs", "zs:q_distribution", "zs:fix_class_distribution")
    assert [_props(again["metadata"])[n] for n in names] == [_props(seeded["doc"]["metadata"])[n] for n in names]


def test_the_serial_differs_when_the_grade_inputs_digest_differs(seeded, api):
    before = seeded["doc"]
    with Session(seeded["engine"]) as s:
        settings = get_or_create_settings(s, 1)
        settings.risk_model = {**GR.MOSCA, "threat_years": 30}
        s.add(settings)
        s.commit()
    after = _export(api, seeded["run"]).json()
    digest = lambda d: json.loads(_one(d["metadata"], "zs:grade_inputs"))["digest"]  # noqa: E731
    assert digest(after) != digest(before)
    assert after["serialNumber"] != before["serialNumber"]


@pytest.mark.parametrize("target, attr", [("qgrade", "GRADE_MODEL_VERSION"), ("agility", "version")])
def test_the_serial_differs_when_a_model_version_differs(seeded, api, monkeypatch, target, attr):
    import importlib

    module = importlib.import_module(f"backend.utilities.cbom_sources.{target}")
    monkeypatch.setattr(module, attr, "qg-1+000000000000" if attr == "GRADE_MODEL_VERSION" else (lambda: "fx-1+0"))
    after = _export(api, seeded["run"]).json()
    assert after["serialNumber"] != seeded["doc"]["serialNumber"]


def test_export_serial_keys_every_input():
    from backend.utilities.cbom_sources.inventory import export_serial

    base = dict(grade_model_version="qg-1+aaaaaaaaaaaa", grade_inputs_digest="0" * 16, agility_version="fx-1+bb")
    one = export_serial(7, "2026.11.14.1", **base)
    assert one == export_serial(7, "2026.11.14.1", **base)
    for key, other in (("grade_model_version", "qg-1+cccccccccccc"), ("grade_inputs_digest", "1" * 16),
                       ("agility_version", "fx-1+dd")):
        assert export_serial(7, "2026.11.14.1", **{**base, key: other}) != one, key
    assert export_serial(7, "2026.11.14.1", "2026-11-14", **base) != one
    assert re.fullmatch(r"urn:uuid:[0-9a-f-]{36}", one)


# ============================================================================== helpers and streaming
def test_a_long_basis_is_capped_with_a_marker_and_stays_json():
    from backend.utilities.cbom_sources import inventory as INV

    per = tuple({"code": f"CODE_NUMBER_{i:03d}", "class": "configurable", "rule": "R-TABLE"} for i in range(40))
    value = INV.fix_class_basis(per)
    parsed = json.loads(value)
    assert len(value) <= 512 and parsed[-1] == f"…+{40 - (len(parsed) - 1)}"
    assert parsed[0] == {"code": "CODE_NUMBER_000", "class": "configurable", "rule": "R-TABLE"}
    assert INV.fix_class_basis(()) == "[]"


def test_the_streamed_download_is_still_the_in_memory_document(seeded):
    from starlette.responses import JSONResponse

    from backend.utilities.cbom_sources import inventory

    now = dt.datetime(2026, 11, 14, 9, 30, 0)
    with Session(seeded["engine"]) as s:
        run = s.get(CbomCollectionRun, seeded["run"])
        doc = inventory.cyclonedx(s, run, now)
        buf = io.BytesIO()
        inventory.write_cyclonedx(s, run, now, "json", buf)
    assert buf.getvalue() == JSONResponse(doc).body
    assert _one(doc["metadata"], "zs:grade_model") == "qg-1"
