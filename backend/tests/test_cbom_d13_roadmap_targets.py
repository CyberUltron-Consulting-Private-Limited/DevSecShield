"""SOW D13 PQC Migration Roadmap (audit A-02, A-08, A-16): a NIST post-quantum target per asset, from its FUNCTION.

* The target table lives in the crypto KB (``pqc_context.migration_targets``) as algid selectors; ``pqc_targets``
  resolves them, so every printed name is algid's (``test_algid_single_source`` stays green).
* Every roadmap row (code scans AND collected infrastructure) carries the target of its function: a TLS endpoint gets
  the hybrid TLS group then the pure set, a certificate a signature set, a CA the category 5 / hash-based option, a
  symmetric key AES-256; never one constant.
* Each wave has a proposed date tied to NIST IR 8547 / CNSA 2.0 (KB ``wave_milestones``); the owner comes from the
  source's metadata (C5) or reads "unassigned — confirm with owner".
* The summary card "Quantum-safe N" and the "Already quantum-safe" section count the same population (Rule P).

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_d13_roadmap_targets.py -q
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TESTS = Path(__file__).resolve().parent
for p in (REPO, TESTS):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from backend.utilities.cbom_sources import algid as A  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources import pqc_targets as T  # noqa: E402
from backend.utilities.cbom_sources import waves as W  # noqa: E402
from backend.utilities.dashboard.cbom_team_rollup import AssetAgg  # noqa: E402
from backend.utilities.pdf import cbom_pqc_roadmap_pdf as roadmap  # noqa: E402
from test_cbom_deliverable_pqc_roadmap import (  # noqa: E402
    algo,
    body_of,
    make_view,
    pdf_full_text,
    squash,
)


def _ps(standard: str, category: int) -> str:
    """The FIPS parameter set algid names for (standard, category), read from algid (the oracle)."""
    names = {row[4] for row in A._ALGS.values()
             if row[2] == standard and row[3] == "standard" and row[5] == category and row[6] == "pure" and row[4]}
    assert len(names) == 1, names
    return names.pop()


KEM3, KEM5 = _ps("FIPS 203", 3), _ps("FIPS 203", 5)
DSA3, DSA5 = _ps("FIPS 204", 3), _ps("FIPS 204", 5)


# ----------------------------------------------------------------------------- the KB table
def test_the_kb_table_has_a_row_per_function_with_its_fips_reference():
    rows = T.table()
    assert set(rows) >= {"tls_kex", "ssh_kex", "vpn_kex", "key_establishment", "signature", "certificate",
                         "ca_signature", "code_signing", "asymmetric", "symmetric", "hash"}
    assert rows["key_establishment"]["target"] == KEM3 and rows["key_establishment"]["cnsa_target"] == KEM5
    assert rows["key_establishment"]["reference"] == "FIPS 203"
    assert rows["signature"]["target"] == DSA3 and rows["signature"]["cnsa_target"] == DSA5
    assert rows["signature"]["reference"] == "FIPS 204"
    assert rows["certificate"]["target"] == DSA3
    assert "FIPS 205" in rows["ca_signature"]["reference"] and rows["ca_signature"]["target"].startswith(DSA5)
    tls = rows["tls_kex"]
    hybrid = next(name for cp, name in A._TLS_GROUPS.items()
                  if A._ALGS[name][3] == "standard" and A._ALGS[name][6] == "hybrid" and "X25519" in A._ALGS[name][9]
                  and A._ALGS[name][5] == 3)
    assert tls["target"] == f"{hybrid} (hybrid)" and tls["then"] == KEM3 and tls["cnsa_target"] == KEM5
    assert "SP 800-208" in rows["code_signing"]["reference"] and DSA5 in rows["code_signing"]["target"]
    assert rows["symmetric"]["target"].startswith("AES-256") and rows["hash"]["target"].startswith("SHA-384")
    # targets differ by function: never one constant (end-entity certificates sign like any signing key)
    distinct = {r["target_text"] for u, r in rows.items() if u != "certificate"}
    assert len(distinct) == len(rows) - 1


def test_the_kb_never_spells_a_post_quantum_name_it_holds_algid_selectors():
    targets = crypto_kb.pqc_context()["migration_targets"]
    raw = json.dumps(targets)
    for name in (KEM3, KEM5, DSA3, DSA5):
        assert name not in raw
    assert all("select" in p or "text" in p for row in targets for p in row["target"])


def test_wave_milestones_are_dated_and_tied_to_ir_8547_and_cnsa_2():
    ms = T.milestones()
    assert [m["wave"] for m in ms] == [1, 2, 3, 4]
    dates = [m["date"] for m in ms]
    assert dates == sorted(dates) and all(len(d) == 10 for d in dates)
    assert dates[1] == "2030-12-31" and dates[3] == "2033-12-31"
    assert "CNSA 2.0" in ms[0]["basis"] and "IR 8547" in ms[1]["basis"] and "2035" in ms[3]["basis"]
    assert T.wave_milestone(9) is None and T.wave_milestone(None) is None


@pytest.mark.parametrize("asset_type,algorithm,facts,primitive,usage", [
    ("tls_endpoint", "TLS_AES_256_GCM_SHA384", {}, None, "tls_kex"),
    ("load_balancer_tls", None, {}, None, "tls_kex"),
    ("ssh_endpoint", None, {}, None, "ssh_kex"),
    ("ssh_host_key", "ssh-rsa", {}, None, "signature"),
    ("ike_endpoint", None, {}, None, "vpn_kex"),
    ("certificate", "RSA", {}, None, "certificate"),
    ("certificate", "RSA", {"is_ca": True}, None, "ca_signature"),
    ("certificate", "ECDSA", {"eku": ["codeSigning"]}, None, "code_signing"),
    ("cloud_ca", "RSA", {}, None, "ca_signature"),
    ("kms_key", "RSA_2048", {"key_usage": "SIGN_VERIFY"}, None, "signature"),
    ("kms_key", "RSA_2048", {"key_usage": "ENCRYPT_DECRYPT"}, None, "key_establishment"),
    ("kms_key", "RSA_2048", {}, None, "asymmetric"),
    ("kms_key", None, {"key_spec": "SYMMETRIC_DEFAULT"}, None, "symmetric"),
    ("managed_key", "DES-EDE3", {}, None, "symmetric"),
    ("storage_encryption", "AES-256", {}, None, "symmetric"),
    ("algorithm", "ECDSA P-256", None, "signature", "signature"),
    ("algorithm", "RSA-2048", None, "pke", "key_establishment"),
    ("algorithm", "SHA-1", None, "hash", "hash"),
    ("coverage", None, {}, None, None),
])
def test_the_function_is_derived_from_what_was_collected(asset_type, algorithm, facts, primitive, usage):
    assert T.usage_of(asset_type, algorithm, facts, primitive) == usage


def test_wave_items_carry_the_target_and_the_proposed_date():
    item = {"asset_key": "k", "suggested_wave": 2, **W.target_fields("tls_endpoint", None, {})}
    out = W._with_assignment([item], {})[0]
    assert out["wave"] == 2 and out["proposed_date"] == "2030-12-31"
    assert out["pq_usage"] == "tls_kex" and out["pq_target"] == T.table()["tls_kex"]["target_text"]
    assert out["pq_reference"] == "FIPS 203" and out["pq_target_cnsa"] == KEM5
    none = W._with_assignment([{"asset_key": "n", "suggested_wave": None}], {})[0]
    assert none["proposed_date"] is None


# ----------------------------------------------------------------------------- the PDF
def _node(label, asset_type, algorithm=None, **extra):
    t = W.target_fields(asset_type, algorithm, extra.pop("facts", {}))
    wave = extra.pop("wave", 4)
    return {"asset_id": hash(label) & 0xFFFF, "label": label, "type": asset_type, "algorithm": algorithm,
            "key_size": extra.pop("key_size", None), "impact": extra.pop("impact", "Low"), "source_name": "lab-net",
            "target": "10.0.0.5:443", "location": "", "collected_at": "2026-11-20T10:00:00Z",
            "suggested_wave": wave, "wave": wave, "assignment": extra.pop("assignment", None),
            "proposed_date": T.wave_milestone(wave)["date"], "owner_hint": extra.pop("owner_hint", None),
            "kex_group": extra.pop("kex_group", None), **t, **extra}


def _plan_view(assets=(), node_rows=(), **over):
    code_plans = {}
    from backend.utilities.dashboard.cbom_team_rollup import plan_key
    for a in assets:
        code_plans[plan_key(a)] = {"assigned": {}, "suggested": 4}
    return make_view(list(assets), remediation={"code_plans": code_plans, "node_rows": list(node_rows),
                                                "node_rows_omitted": 0}, **over)


def _flat(body):
    for f in body:
        inner = getattr(f, "_content", None)
        if isinstance(inner, list):  # KeepTogether
            yield from _flat(inner)
        else:
            yield f


def _tables(body):
    out = []
    for f in _flat(body):
        if f.__class__.__name__ == "Table":
            out.append([[getattr(c, "text", c if isinstance(c, str) else "") for c in row] for row in f._cellvalues])
    return out


def _table_with(body, header, *, also=None):
    """Every table whose header has ``header`` (and ``also``), merged: one header, all their rows."""
    found = [t for t in _tables(body) if header in t[0] and (also is None or also in t[0])]
    assert found, f"no table with header {header!r}: {[t[0] for t in _tables(body)]}"
    return [found[0][0]] + [r for t in found for r in t[1:]]


def test_every_infrastructure_row_has_a_nist_pq_target_from_its_function():
    rows = [_node("tls 10.0.0.5:443", "tls_endpoint", "ECDHE-RSA-AES128-SHA256", kex_group="x25519", wave=1),
            _node("CN=web", "certificate", "RSA", key_size=2048),
            _node("Root CA", "cloud_ca", "RSA", key_size=4096),
            _node("LabTdes", "managed_key", "DES-EDE3")]
    body = body_of(_plan_view(node_rows=rows))
    table = _table_with(body, "NIST PQ target", also="Type")
    head = table[0]
    col = next(i for i, h in enumerate(head) if "NIST PQ target" in str(h))
    cells = {r[1]: r[col] for r in table[1:]}
    assert T.table()["tls_kex"]["target"] in cells["tls 10.0.0.5:443"]
    assert DSA3 in cells["CN=web"] and "FIPS 204" in cells["CN=web"]
    assert DSA5 in cells["Root CA"] and "FIPS 205" in cells["Root CA"]
    assert cells["LabTdes"].startswith("AES-256")
    assert len(set(cells.values())) == 4  # not one constant
    # the TLS endpoint shows its key exchange group, not only the symmetric suite
    algo_col = next(i for i, h in enumerate(head) if "Algorithm" in str(h))
    assert "x25519" in next(r for r in table[1:] if r[1] == "tls 10.0.0.5:443")[algo_col]


def test_code_scan_rows_get_the_target_of_their_primitive_not_one_dual_constant():
    assets = [algo("ECDSA P-256", primitive="signature", key_size="256", curve="P-256", ident="s1"),
              algo("RSA-2048", primitive="pke", ident="k1")]
    body = body_of(_plan_view(assets))
    table = _table_with(body, "NIST PQ target", also="Seen")
    col = next(i for i, h in enumerate(table[0]) if "NIST PQ target" in str(h))
    by_title = {r[1]: r[col] for r in table[1:]}
    assert by_title["ECDSA P-256"].startswith(DSA3) and KEM3 not in by_title["ECDSA P-256"]
    assert by_title["RSA-2048"].startswith(KEM3) and DSA3 not in by_title["RSA-2048"]


def test_wave_rows_get_a_proposed_date_and_a_c5_owner_or_unassigned():
    rows = [_node("tls a", "tls_endpoint", wave=1, owner_hint="Network team"),
            _node("tls b", "tls_endpoint", wave=2),
            _node("cert c", "certificate", "RSA", wave=4,
                  assignment={"wave": 3, "owner": "PKI team", "target_date": "2028-03-31", "status": "open"})]
    table = _table_with(body_of(_plan_view(node_rows=rows)), "NIST PQ target", also="Type")
    head = [str(h) for h in table[0]]
    date_col = next(i for i, h in enumerate(head) if h.startswith("Target date"))
    owner_col = next(i for i, h in enumerate(head) if h.startswith("Owner"))
    by = {r[1]: r for r in table[1:]}
    # no classical weakness: the post-quantum milestone of the wave (a classical one is dated from the assessment:
    # test_cbom_d12_d13_review_fixes)
    assert by["tls a"][date_col] == "PQ by 2027-12-31 (proposed)" and by["tls a"][owner_col].startswith("Network team")
    assert by["tls b"][date_col] == "PQ by 2030-12-31 (proposed)" and by["tls b"][owner_col] == T.UNASSIGNED_OWNER
    assert by["cert c"][date_col] == "2028-03-31" and by["cert c"][owner_col] == "PKI team / open"


def test_the_wave_summary_lists_each_wave_with_its_date_basis_and_owners():
    rows = [_node("tls a", "tls_endpoint", wave=1, owner_hint="Network team"), _node("tls b", "tls_endpoint", wave=4)]
    body = body_of(_plan_view([algo("RSA-2048", ident="k1")], node_rows=rows))
    table = _table_with(body, "Post-quantum by")
    waves = {r[0]: r for r in table[1:]}
    assert set(waves) >= {"1", "4"}
    assert waves["1"][2] == "1" and "2027-12-31" in waves["1"][4] and "Network team" in waves["1"][6]
    assert waves["1"][3].startswith("within 90 days")  # the classical window, from the assessment
    assert waves["4"][2] == "2" and "2033-12-31" in waves["4"][4]  # one code row + one node row
    assert waves["4"][3].startswith("n/a")
    assert "CNSA 2.0" in waves["1"][5] and "SP 800-131A" in waves["1"][5]
    text = pdf_full_text(roadmap.build_pdf(_plan_view(node_rows=rows)))
    assert "confirm" in text and "before issue" in squash(text) or "beforeissue" in squash(text)


def test_the_quantum_safe_card_and_section_count_the_same_population():
    safe_cert = AssetAgg(source_key="sources:1", source_label="lab", asset_type="certificate", ident="c1",
                         title="CN=pq", location="", impact="Info", quantum_vulnerable=False, current=True)
    view = make_view([algo("RSA-2048", ident="k1"), safe_cert], pqc_safe=1)
    body = body_of(view)
    text = " ".join(str(c) for t in _tables(body) for r in t for c in r)
    flat = " ".join(getattr(f, "text", "") for f in _flat(body))
    assert "No quantum-safe algorithm occurrences" not in flat  # the card says 1: the section must not say none
    assert "Total quantum-safe" in text and "1" in text
    table = _table_with(body, "Of which hybrid")
    total = next(r for r in table if r[0] == "Total quantum-safe")
    assert total[1] == str(view.pqc_safe)
