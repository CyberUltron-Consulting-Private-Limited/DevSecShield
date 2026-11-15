"""#289 review: compliance clause rules read algorithm names only, follow the classifier's own lists, and never drop
an algorithm clause in silence.

E1 (blocker)  an asset's name never decides a clause: a gateway called ``des3-gw`` that offers only aes128-cbc is not
              cited under NIST TDEA or SEBI H-5; ``export-api`` / ``null-router`` with a weak-listed AES suite are not
              cited under SEBI H-5. Checked through the run posture (results page), the asset detail (KB panel), the
              OSCAL export links and the team deliverables' clause table.
E2 (major a)  IPSEC_WEAK_TRANSFORM / IKE_WEAK_ENCR cite every algorithm the classifier flags, read from the
              classifier's own lists (node_net.WEAK_ENCR, WEAK_INTEG, WEAK_GROUPS): IDEA and CAST included; NULL is
              no encryption algorithm (no SEBI H-5); HMAC-SHA-1 alone (Low, still allowed) cites nothing.
E3 (major b)  no algorithm recorded: the algorithm clauses are cited with ``evidence: "not_recorded"`` and a note,
              never dropped; the code scanner's "RSA: 1024-bit" wording gets the SP 800-131A 112-bit clause (and a
              P-384 key does not).
E4 (major c)  REUSED_NONCE / STATIC_IV cite RBI para 16 / para 140 like ECB.
E5 (minor)    SSH_DH_SHA1 / SSH_DH_GROUP1's SHA-1 signature citation carries the transcript-hash note.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.utilities.cbom_sources import clause_evidence as CE  # noqa: E402
from backend.utilities.cbom_sources import crypto_kb  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from backend.utilities.cbom_sources.classify_ext import node_net  # noqa: E402
from backend.utilities.cbom_sources.kb_remediation import explain  # noqa: E402
from test_cbom_compliance_precise_clauses import (CERTIN_8422, NIST_112, NIST_SHA1_SIG, NIST_TDEA,  # noqa: E402
                                                  RBI_16, RBI_140, SEBI_H5)
from test_cbom_posture import _store  # noqa: E402
from test_cbom_sources_api import api, world  # noqa: E402,F401  (shared fixtures)


@pytest.fixture(autouse=True)
def _fresh_kb(monkeypatch):
    for name in ("CBOM_KB_BUNDLE", "CBOM_KB_BUNDLE_SIG", "CBOM_KB_PUBKEYS"):
        monkeypatch.delenv(name, raising=False)
    crypto_kb.load.cache_clear()
    yield
    crypto_kb.load.cache_clear()


def _pairs(refs) -> set[tuple[str, str]]:
    return {(r["framework"], r["id"]) for r in refs}


def _row(asset_type: str, facts: dict, algorithm=None, key_size=None, name=None):
    return SimpleNamespace(asset_type=asset_type, algorithm=algorithm, key_size=key_size, protocol=None, facts=facts,
                           created_at=None, name=name, location=name, target=name)


def _clauses(row) -> dict[str, list[dict]]:
    """code -> clauses, as every Sources view computes them (clause_evidence.asset_clauses on today's codes)."""
    codes = classify(row.asset_type, row.algorithm, row.key_size, row.protocol, row.facts)["finding_codes"]
    out: dict[str, list[dict]] = {c: [] for c in codes}
    for code, ref in CE.asset_clauses(row, codes):
        out[code].append(ref)
    return out


# ----------------------------------------------------------------------------------------- E1: names never decide
NAMED = [
    {"type": "ssh_endpoint", "target": "des3-gw", "location": "des3-gw:22", "name": "des3-gw",
     "facts": {"kex": ["curve25519-sha256"], "hostkey_algorithms": ["ssh-ed25519"], "ciphers": ["aes128-cbc"],
               "macs": ["hmac-sha2-256"]}},
    {"type": "tls_endpoint", "target": "export-api.example.com", "location": "export-api.example.com:443",
     "name": "export-api.example.com",
     "facts": {"protocols": ["TLSv1.2"], "group": "x25519", "weak_ciphers": ["ECDHE-RSA-AES128-SHA"]}},
    {"type": "tls_endpoint", "target": "null-router", "location": "null-router:443", "name": "null-router",
     "facts": {"protocols": ["TLSv1.2"], "group": "x25519", "weak_ciphers": ["AES128-SHA"]}},
    {"type": "ssh_endpoint", "target": "10.40.0.9", "location": "10.40.0.9:22", "name": "aes-only-box",
     "facts": {"kex": ["curve25519-sha256"], "hostkey_algorithms": ["ssh-ed25519"], "ciphers": ["3des-cbc"],
               "macs": ["hmac-sha2-256"]}},
]


def test_e1_names_never_decide_a_clause_in_the_classifier_evidence():
    ssh = _clauses(_row("ssh_endpoint", NAMED[0]["facts"], name="des3-gw"))
    assert _pairs(ssh["SSH_CBC_CIPHER"]) == {CERTIN_8422, RBI_16, RBI_140}
    for spec in NAMED[1:3]:
        weak = _clauses(_row("tls_endpoint", spec["facts"], name=spec["name"]))["WEAK_CIPHER"]
        assert _pairs(weak) == {CERTIN_8422, RBI_16, RBI_140}, spec["name"]
        assert not any(r.get("evidence") for r in weak)
    # the real thing is still cited: 3des-cbc on a host whose name says nothing
    assert {NIST_TDEA, SEBI_H5} <= _pairs(_clauses(_row("ssh_endpoint", NAMED[3]["facts"]))["SSH_CBC_CIPHER"])


def test_e1_names_never_decide_through_posture_detail_oscal_and_deliverables(api, world):  # noqa: F811
    from backend.utilities.integrations import oscal

    engine, _ = world
    _src, run = _store(api, engine, NAMED)
    posture = api("GET", f"/1/cbom/sources/runs/{run['id']}/posture").json()["posture"]
    shown = {(fw["framework"], c["id"]): c["assets"] for fw in posture["compliance"] for c in fw["clauses"]}
    assert shown[NIST_TDEA] == 1 and shown[SEBI_H5] == 1  # only the 3des-cbc server
    assert shown[CERTIN_8422] == 4
    assets = api("GET", f"/1/cbom/sources/runs/{run['id']}/assets", params={"page_size": 200}).json()["items"]
    by_name = {a["name"]: a for a in assets}
    for name in ("des3-gw", "export-api.example.com", "null-router"):
        detail = api("GET", f"/1/cbom/sources/assets/{by_name[name]['id']}").json()["asset"]
        cited = {p for d in detail["details"] for p in _pairs(d["compliance"])}
        assert NIST_TDEA not in cited and SEBI_H5 not in cited, name
    import json

    from sqlmodel import Session

    from backend.new_models import CbomCollectionRun

    with Session(engine) as session:
        doc = json.dumps(oscal.run_document(session, session.get(CbomCollectionRun, run["id"])))
    # the OSCAL findings link TDEA once: from the 3des-cbc server (SSH_CBC_CIPHER / SSH_WEAK_CIPHER), never from a name
    assert "NIST: SP 800-131A Rev. 2, Sec. 2 Table 1 (TDEA)" in doc
    links = oscal._references("node", "WEAK_CIPHER", [["ECDHE-RSA-AES128-SHA"], ["AES128-SHA"]])
    assert not any("Annexure-H" in link["text"] for link in links)


def test_e1_deliverables_read_the_recorded_algorithms_not_the_title():
    from backend.utilities.pdf.cbom_collected_compliance import collected_clauses

    def agg(title, codes, evidence):
        return SimpleNamespace(current=True, source_key="sources:s1", asset_type="protocol", ident=title, title=title,
                               description=f"{title} offers CBC-mode SSH ciphers (aes128-cbc)",
                               finding_codes=tuple(codes), collector_codes=(), clause_evidence=evidence)

    view = SimpleNamespace(assets=[agg("des3-gw", ["SSH_CBC_CIPHER"], {"SSH_CBC_CIPHER": ["aes128-cbc"]}),
                                   agg("old-box", ["SSH_CBC_CIPHER"], None)])
    rows = {(r.framework, r.clause): r for r in collected_clauses(view)}
    assert rows[CERTIN_8422].assets == 2 and rows[CERTIN_8422].unrecorded == 0
    # old-box recorded no algorithm: cited for review, and said so; des3-gw is not behind TDEA
    assert rows[NIST_TDEA].assets == 1 and rows[NIST_TDEA].unrecorded == 1


# ------------------------------------------------------------------------------ E2: the classifier's own lists
def _members(pattern: re.Pattern) -> list[str]:
    """The names an anchored ``^(A|B|C)...$`` classifier list accepts, read from the pattern itself."""
    out = []
    for group in re.findall(r"\^\(([^()]*)\)", pattern.pattern):
        out += group.split("|")
    return out


ENCR = _members(node_net.WEAK_ENCR)
# every spelling the integrity list accepts, checked against the classifier's pattern (not a second list)
INTEG = [n for n in ("MD5", "HMAC-MD5", "HMAC-MD5-96", "SHA1", "HMAC-SHA1", "HMAC-SHA1-96", "DES-MAC", "KPDK-MD5",
                     "HMAC-SHA2-256", "AES-XCBC") if node_net.WEAK_INTEG.match(n)]


def test_e2_member_lists_are_read_from_the_classifier():
    assert {"IDEA", "CAST", "NULL", "DES", "3DES", "BLOWFISH"} <= set(ENCR)
    assert set(INTEG) == {"MD5", "HMAC-MD5", "HMAC-MD5-96", "SHA1", "HMAC-SHA1", "HMAC-SHA1-96", "DES-MAC",
                          "KPDK-MD5"}
    kb = crypto_kb.entry("node", "IPSEC_WEAK_TRANSFORM")["clause_rules"]
    assert node_net.WEAK_ENCR.pattern in [r["match"] for r in kb]  # match_from: the same pattern, not a second regex


@pytest.mark.parametrize("name", ENCR)
@pytest.mark.parametrize("kind,code", [("ipsec_policy", "IPSEC_WEAK_TRANSFORM"), ("ike_policy", "IKE_WEAK_ENCR")])
def test_e2_every_weak_encryption_member_is_cited(kind, code, name):
    facts = {"kind": kind, "vendor": "cisco", "section": "crypto map vpn1", "encryption": [name, "AES-256"]}
    refs = _clauses(_row("appliance_config", facts, name="vpn1"))[code]
    cited = _pairs(refs)
    assert {CERTIN_8422, RBI_16, RBI_140} <= cited, (code, name)
    assert (SEBI_H5 in cited) == (name != "NULL"), (code, name)  # NULL is no encryption algorithm
    assert (NIST_TDEA in cited) == (name == "3DES"), (code, name)
    assert not any(r.get("evidence") for r in refs)


@pytest.mark.parametrize("name", INTEG)
def test_e2_every_weak_integrity_member(name):
    facts = {"kind": "ipsec_policy", "vendor": "cisco", "section": "crypto map vpn1", "integrity": [name]}
    verdict = classify("appliance_config", None, None, None, facts)
    assert "IPSEC_WEAK_TRANSFORM" in verdict["finding_codes"], name
    cited = _pairs(_clauses(_row("appliance_config", facts))["IPSEC_WEAK_TRANSFORM"])
    deprecated = node_net._md5_class([name])  # the classifier's own Medium / Low split
    assert verdict["impacts"]["IPSEC_WEAK_TRANSFORM"] == ("Medium" if deprecated else "Low")
    assert cited == ({CERTIN_8422, RBI_16, RBI_140} if deprecated else set()), name
    ike = {"kind": "ike_policy", "vendor": "cisco", "section": "isakmp 10", "integrity": [name]}
    ike_cited = _pairs(_clauses(_row("appliance_config", ike))["IKE_WEAK_INTEG"])
    assert ike_cited == ({CERTIN_8422, RBI_16, RBI_140} if deprecated else set()), name


def test_e2_weak_pfs_groups_from_the_classifier_list():
    for group in sorted(node_net.WEAK_GROUPS):
        facts = {"kind": "ipsec_policy", "vendor": "cisco", "section": "crypto map vpn1", "pfs_groups": [group]}
        cited = _pairs(_clauses(_row("appliance_config", facts))["IPSEC_WEAK_TRANSFORM"])
        assert {CERTIN_8422, RBI_16, RBI_140} <= cited, group
        assert (NIST_112 in cited) == (group in {"MODP-768", "MODP-1024", "MODP-1024-S160", "MODP-1536", "ECP-192"})


def test_e2_review_probe_idea_cast():
    assert _pairs(crypto_kb.clauses_for("node", "IPSEC_WEAK_TRANSFORM", ["IDEA", "CAST"])) == \
        {CERTIN_8422, RBI_16, RBI_140, SEBI_H5}


# ------------------------------------------------------------------------------------- E3: nothing recorded
def test_e3_no_rule_clause_is_dropped_when_no_algorithm_was_recorded():
    findings = crypto_kb.load()["findings"]
    for ns in ("node", "code"):
        for code, e in findings[ns].items():
            base = set(e.get("clauses") or [])
            rule_keys = {k for r in e.get("clause_rules") or [] for k in r["clauses"]} - base
            for evidence in (None, "", []):
                refs = crypto_kb.clauses_for(ns, code, evidence)
                assert {r["key"] for r in refs} == base | rule_keys, (ns, code)
                for r in refs:
                    marked = r.get("evidence") == "not_recorded"
                    assert marked == (r["key"] in rule_keys), (ns, code, r["key"])
                    if marked:
                        assert crypto_kb.NOT_RECORDED in r["note"]


def test_e3_medium_or_worse_node_codes_cite_something_without_evidence_unless_reviewed_as_none():
    table = __import__("json").loads((ROOT / "scripts/crypto_kb/sources/compliance_clauses.json").read_text())
    for code, e in crypto_kb.load()["findings"]["node"].items():
        if e["default_impact"] not in ("Critical", "High", "Medium"):
            continue
        row = table["node"][code]
        if not row["clauses"] and not row["rules"]:
            continue  # reviewed: no clause of the knowledge base covers it (its basis says why)
        assert crypto_kb.clauses_for("node", code, None), code
    assert crypto_kb.clauses_for("node", "IKE_WEAK_INTEG", "")
    assert crypto_kb.clauses_for("node", "IPSEC_WEAK_TRANSFORM", None)


def test_e3_posture_marks_a_clause_cited_without_a_recorded_algorithm():
    # a stored code today's classifier no longer raises for the asset's facts: no algorithm recorded
    row = _row("tls_endpoint", {"protocols": ["TLSv1.2"]}, name="legacy")
    cited = CE.asset_clauses(row, ["WEAK_CIPHER"])
    tdea = [r for _c, r in cited if (r["framework"], r["id"]) == NIST_TDEA]
    assert tdea and tdea[0]["evidence"] == "not_recorded"
    assert {(r["framework"], r["id"]) for _c, r in cited if not r.get("evidence")} == {CERTIN_8422, RBI_16, RBI_140}


def _code_cited(code: str, **finding) -> set[tuple[str, str]]:
    out = explain({"finding_codes": [code], **finding})
    return {p for d in out for p in _pairs(d["compliance"])}


def test_e3_code_scanner_key_size_wording_gets_the_112_bit_clause():
    text = ("Undersized asymmetric key on RSA: 1024-bit is below the 2048-bit floor (NIST SP 800-57); use RSA-3072+ "
            "or an elliptic-curve / PQC equivalent.")
    assert crypto_kb.clauses_for("code", "WEAK_KEY_SIZE", text) and \
        NIST_112 in _pairs(crypto_kb.clauses_for("code", "WEAK_KEY_SIZE", text))
    assert NIST_112 in _code_cited("WEAK_KEY_SIZE", title="RSA", algorithm_name="RSA", description=text)
    assert NIST_112 in _code_cited("WEAK_KEY_SIZE", algorithm_name="DSA", key_size="1024", description="")
    # a P-384 key is 192-bit secure: never "below 112-bit"
    assert NIST_112 not in _code_cited("WEAK_KEY_SIZE", algorithm_name="ECDSA", key_size="384",
                                       description="Undersized asymmetric key on ECDSA: 384-bit")
    # a certificate row's title (its file name) is not read when the algorithm is known
    assert NIST_TDEA not in _code_cited("WEAK_ALGORITHM", title="des3-legacy.pem", algorithm_name="AES-128",
                                        description="Weak algorithm AES-128")


# ---------------------------------------------------------------------------------------- E4, E5
def test_e4_nonce_and_iv_reuse_cite_rbi_like_ecb():
    ecb = _pairs(crypto_kb.clauses_for("code", "WEAK_CIPHER_MODE", "AES-128-ECB"))
    for code in ("REUSED_NONCE", "STATIC_IV"):
        assert _pairs(crypto_kb.clauses_for("code", code, "AES-GCM")) == {RBI_16, RBI_140} == ecb, code


def test_e5_ssh_sha1_exchange_hash_citation_explains_itself():
    for code in ("SSH_DH_SHA1", "SSH_DH_GROUP1"):
        ref = next(r for r in crypto_kb.clauses_for("node", code, ["diffie-hellman-group14-sha1"])
                   if (r["framework"], r["id"]) == NIST_SHA1_SIG)
        assert "exchange hash" in ref["note"], code
