"""Staging QA round 4 on the one results template (lane B8).

B  every asset type the collectors can emit has an explicit table name and plural (no "Ca template" / "Ca authority"
   from the capitalising fallback), the frontend's ASSET_TYPE_LABEL says the same, and the readiness card's groups
   carry the plural the page prints ("Fix 3 CA templates", not "3 Ca templates").
C  a withheld PQC readiness (``not_enough_identified``) is passed through as null with its reason, never turned
   into 0 on the run results' card or gauge.

Same SQLite + real-router harness as test_cbom_sources_api.py.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_sources_api as SOURCES_API  # shared SQLite + real-router harness
from test_cbom_sources_api import _collect_job

api = SOURCES_API.api  # fixtures
world = SOURCES_API.world

from sqlmodel import Session

from backend.utilities.cbom_sources import classify
from backend.utilities.cbom_sources import posture as POSTURE
from backend.utilities.cbom_sources import run_assets as RA
from backend.utilities.cbom_sources import run_results as RR

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _fresh_cache():
    RR.clear_cache()
    yield
    RR.clear_cache()


def _scan_node_types() -> set[str]:
    """Asset types the scan node can emit, read from its sources (``register_asset_types(...)`` and
    ``ctx.emit("<type>", ...)``), so a new collector type without a label fails here."""
    found: set[str] = set()
    for path in (REPO / "scan_node" / "zs_scan_node").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for call in re.findall(r"register_asset_types\(([^)]*)\)", text):
            found.update(re.findall(r"\"([a-z0-9_]+)\"", call))
        found.update(re.findall(r"\.emit\(\s*\"([a-z0-9_]+)\"", text))
    found.discard("not_a_type")  # a unit test's deliberately unknown type
    return found


# ----------------------------------------------------------------------------- B labels
def test_every_known_asset_type_has_an_explicit_label_and_plural():
    known = set(classify.ASSET_TYPES) | _scan_node_types()
    assert {"ca_template", "ca_authority", "managed_key", "key_store", "ike_endpoint"} <= known
    missing = sorted(t for t in known if t not in RA.TYPE_LABEL)
    assert missing == [], f"asset types without a table name (the fallback would capitalise them): {missing}"
    missing_plural = sorted(t for t in known if t not in RA.TYPE_LABEL_PLURAL)
    assert missing_plural == [], f"asset types without a plural: {missing_plural}"
    assert set(RA.TYPE_LABEL_PLURAL) == set(RA.TYPE_LABEL)


def test_ca_and_key_types_read_as_proper_names():
    assert RA.type_label("ca_template") == "CA template"
    assert RA.type_label("ca_authority") == "CA"
    assert RA.type_label_plural("ca_template") == "CA templates"
    assert RA.type_label_plural("ca_authority") == "CAs"
    assert RA.type_label("kms_key") == "KMS key"
    assert RA.type_label("ssh_host_key") == "SSH host key"
    # nothing known falls back to the capitalised raw name
    for t in RA.TYPE_LABEL:
        assert RA.type_label(t) == RA.TYPE_LABEL[t]
    # the fallback still covers an unknown future type, singular and plural
    assert RA.type_label("brand_new_thing") == "Brand new thing"
    assert RA.type_label_plural("brand_new_thing") == "Brand new things"
    assert RA.type_label(None) == "Other"


def test_plurals_are_not_naive():
    """Mass nouns and acronyms take a word, not a bare "s" ("Database TLS" -> not "Database TLSes")."""
    assert RA.type_label_plural("database_tls") == "Database TLS settings"
    assert RA.type_label_plural("disk_encryption") == "Disk encryption settings"
    assert RA.type_label_plural("os_crypto_policy") == "OS crypto policies"
    assert RA.type_label_plural("host_secret") == "Secrets in a service or script"
    for t, plural in RA.TYPE_LABEL_PLURAL.items():
        # "Not collected" and "Database settings" read the same counted
        assert plural != RA.TYPE_LABEL[t] or t in ("coverage", "database_config"), f"{t}: plural equals singular"
        assert not plural.endswith("ss") and "(" not in plural, f"{t}: {plural}"


def test_frontend_asset_type_label_matches_the_backend():
    """RunResults.tsx ASSET_TYPE_LABEL is the frontend's copy (dialog, Changes panel): the same names, every type."""
    src = (REPO / "frontend" / "components" / "cbom" / "sources" / "RunResults.tsx").read_text(encoding="utf-8")
    block = re.search(r"export const ASSET_TYPE_LABEL: Record<string, string> = \{(.*?)\n\};", src, re.DOTALL)
    assert block, "ASSET_TYPE_LABEL not found"
    frontend = dict(re.findall(r"^\s*([a-z0-9_]+):\s*\"([^\"]*)\",?\s*$", block.group(1), re.MULTILINE))
    assert frontend == RA.TYPE_LABEL


def test_readiness_actions_carry_the_plural_label():
    actions, _all = POSTURE.readiness_actions({("ca_template", None): 3, ("ca_authority", None): 1},
                                              {"quantum-vulnerable": 4, "quantum-safe": 1})
    by_type = {a["asset_type"]: a for a in actions}
    assert by_type["ca_template"]["type_label"] == "CA template"
    assert by_type["ca_template"]["type_label_plural"] == "CA templates"
    assert by_type["ca_authority"]["type_label"] == "CA"
    assert by_type["ca_authority"]["type_label_plural"] == "CAs"


# ----------------------------------------------------------------------------- C withheld readiness
# one judged (quantum-vulnerable RSA host key) and two passphrase-protected private keys whose algorithm was not read
# (class unknown): more unknown than judged, so posture withholds the percentage (not_enough_identified)
WITHHELD = [
    {"type": "ssh_host_key", "target": "10.30.0.1", "location": "/etc/ssh/ssh_host_rsa_key.pub", "algorithm": "RSA",
     "key_size": 2048, "facts": {"key_type": "ssh-rsa", "bits": 2048}},
    {"type": "private_key", "target": "10.30.0.1", "location": "/etc/app/a.key", "facts": {"encrypted": True}},
    {"type": "private_key", "target": "10.30.0.1", "location": "/etc/app/b.key", "facts": {"encrypted": True}},
]


def _run_with(api, engine, assets):
    _src, run, claim, hdr = _collect_job(api, engine)
    job = claim["job"]
    r = api("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": job["lease_id"], "batch_id": "b1", "assets": assets})
    assert r.status_code == 200, r.text
    r = api("POST", f"/cbom/node/jobs/{job['id']}/result", None, headers=hdr,
            json={"lease_id": job["lease_id"], "status": "success",
                  "result": {"counts": {"total": 3, "ok": 3, "failed": 0, "skipped": 0}}})
    assert r.status_code == 200, r.text
    return run


def test_withheld_readiness_is_null_with_its_reason_not_zero(api, world):
    engine, _ = world
    run = _run_with(api, engine, WITHHELD)
    with Session(engine) as s:
        posture = POSTURE.run_posture(s, team_id=1, run_id=run["id"], risk_model=None)
    assert posture["pqc_readiness_pct"] is None
    assert posture["readiness_basis"]["status"] == "not_enough_identified", posture["readiness_basis"]
    r = api("GET", f"/1/cbom/sources/runs/{run['id']}/results", "alice")
    assert r.status_code == 200, r.text
    out = r.json()
    card = out["dashboard"]["card_data"]
    assert card["quantum_readiness_score"] is None, "a withheld readiness is not 0 %"
    assert card["quantum_readiness_judged"] is False
    assert card["quantum_readiness_status"] == "not_enough_identified"
    pqc = out["distributions"]["pqc"]
    assert pqc["readiness_pct"] is None
    assert pqc["readiness_basis"] == posture["readiness_basis"], "the gauge gets posture's basis verbatim (Rule P)"


def test_judged_readiness_still_a_number_with_status_ok(api, world):
    engine, _ = world
    run = _run_with(api, engine, WITHHELD[:1])
    out = api("GET", f"/1/cbom/sources/runs/{run['id']}/results", "alice").json()
    card = out["dashboard"]["card_data"]
    assert card["quantum_readiness_score"] == 0 and card["quantum_readiness_judged"] is True
    assert card["quantum_readiness_status"] == "ok"
    assert out["distributions"]["pqc"]["readiness_basis"]["status"] == "ok"
