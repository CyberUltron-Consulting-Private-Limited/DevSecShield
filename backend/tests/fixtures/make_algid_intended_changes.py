#!/usr/bin/env python3
"""Write algid_intended_changes.json: every T-B3 corpus row whose verdict CB-04 PR-3a changes, with its oracle.

test_cbom_algid_classify.test_verdict_corpus_diff re-judges the corpus (algid_verdict_corpus.json, recorded at the base
with the classifier before algid) and accepts a difference only when this file lists the row with the same before and
after. This script does not accept a difference by default: each one must fall in one of the CATEGORIES below, each a
strict predicate on the row and its algid identity, tied to the DA spec row that orders the change
(round6/cbom/cb-04/DEVILS-ADVOCATE.md §4, §6, §7). A difference that fits none of them stops the script, so an
unintended verdict change cannot be written into the allowlist by re-running it. Run it after the change:

    PYTHONPATH=. backend/.venv/bin/python backend/tests/fixtures/make_algid_intended_changes.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent
REPO = FIXTURES.parents[2]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(FIXTURES))

import make_algid_verdict_corpus as corpus  # noqa: E402

from backend.utilities.cbom_sources import algid  # noqa: E402
from backend.utilities.cbom_sources.classify import cert_identity_input  # noqa: E402

OUT = FIXTURES / "algid_intended_changes.json"
OID = re.compile(r"^[0-2](\.(0|[1-9][0-9]*))+$")
CATEGORIES = {
    "classical-now-named": "A public-key identifier the old name rules did not know (a classical OID, brainpool, sect*, "
                           "MODP, curve25519, GOST, bign) now resolves to its quantum-vulnerable identity: qv None -> "
                           "True, QUANTUM_VULNERABLE (NO_PQ_KEX on a TLS group; DSA on a DSA OID). DA §7 T-B3 must-flip "
                           "'brainpool/sect/MODP/curve25519 (None->True, + NO_PQ_KEX on brainpool groups)'; §3.3 oid",
    "pq-now-named": "A post-quantum identifier (CSOR/PKIX OID, HSS/LMS/XMSS, composite, Dilithium/Kyber, McEliece, "
                    "FN-DSA, 'ML DSA 65', rsa3072_dilithium2) now resolves as quantum safe or hybrid: qv -> False, DSA "
                    "and QUANTUM_VULNERABLE dropped. DA §7 must-flip 'PQ and XMSS/HSS OIDs (None->False)', "
                    "'FN-DSA/\"ML DSA 65\"/rsa3072_dilithium2 (drop DSA/QV)'; §3.5 token-bounded DSA; OA-CB04-4",
    "tls-pq-group-evidence": "A TLS endpoint whose negotiated group algid knows as post-quantum: "
                             "classify.pq_kex_evidence is True, so no NO_PQ_KEX, qv False and posture class hybrid "
                             "(the :4432 old-node shape, KF-3a). DA §4 classify.py:208/249 and posture.py:42",
    "gost-r-34.10-signature": "GOST R 34.10-2012 keys are elliptic-curve keys (signature, RFC 9215; the same curves "
                              "key VKO agreement, the TLS gostr34102012_* and IKE GOST3410-2012-* groups), not a "
                              "symmetric cipher: the managed key leaves the symmetric path, qv False -> True. DA §4 "
                              "node_keys H-3",
    "placeholder-group": "s_client's '<NULL>' / '(NONE)' / 'Unknown OID' group is no group: the protocol evidence "
                         "decides (qv True) instead of an unknown group (qv None). DA §3.5 sentinels, FP-6",
    "ike-mlkem-group": "An IKE policy whose groups include ML-KEM (IKEv2 Transform Type 4 id 35-37, RFC 9370 "
                       "additional key exchange) by name or 'group N': no IKE_NO_PQ, qv False. DA §4 node_net H-8",
    "pca-raw-identifier": "An AWS Private CA row stored before CB-04 (algorithm ECDSA, key_alg ML_DSA_*) is judged by "
                          "its raw post-quantum identifier: QUANTUM_VULNERABLE dropped. DA §4 classify.py:418, §6 ST-2",
}


def _source(value: str) -> str:
    """Where algid's identity for ``value`` comes from: the registry or document the T-B2 tests check it against."""
    found = algid.resolve(value)
    if found is None:
        return "unresolved"
    if OID.match(value):
        where = ("NIST CSOR (sources/nist-csor-oids.json)" if value.startswith("2.16.840.1.101.3.4.")
                 else "IANA SMI Security for PKIX Algorithms (sources/iana-pkix-alg.csv)"
                 if value.startswith("1.3.6.1.5.5.7.6.") else "sources/curated.json classical_oids (RFC cited)")
        return f"OID {value} = {found.name or 'composite prototype arc'}: {where}"
    name = found.name
    tables = (("IANA TLS Supported Groups (sources/iana-tls-groups.csv)", algid._TLS_GROUPS.values()),
              ("IANA TLS SignatureScheme (sources/iana-tls-sigschemes.csv)", algid._TLS_SIGSCHEMES.values()),
              ("IANA SSH KEX + OpenSSH 10.0p2 ssh -Q kex (sources/iana-ssh-kex.csv)", algid._SSH_KEX.values()),
              ("IANA IKEv2 Transform Type 4 (sources/iana-ikev2-t4.csv)", algid._IKE_KE.values()))
    for where, names in tables:
        if name in names:
            break
    else:
        where = ("PQ marker scan (DA §3.5)" if found.matched_by == "marker"
                 else "sources/curated.json (FIPS / SP 800-208 / RFC row)")
    via = f" (alias of {name})" if found.matched_by == "alias" else ""
    return f"{value}{via}: {where}; quantum {found.quantum}"


def _subject(row: dict) -> str | None:
    """The identifier the changed verdict is judged by."""
    facts = row["facts"]
    if row["type"] in ("certificate", "cloud_ca"):
        return cert_identity_input(row["algorithm"], facts)
    if row["type"] == "managed_key":
        return row["algorithm"]
    if row["type"] == "tls_endpoint":
        return facts.get("negotiated_group")
    if row["type"] == "ssh_endpoint":
        return (facts.get("kex") or [None])[0]
    return None


def _category(row: dict, before: list, after: list) -> str | None:
    kind = row["key"].split("|", 1)[0]
    subject = _subject(row)
    found = algid.resolve(subject) if isinstance(subject, str) else None
    quantum = found.quantum if found else None
    if kind == "ike":
        groups = row["facts"]["groups"]
        pq = any(g == "group 36" or algid.quantum_vulnerable(g) is False for g in groups)
        return "ike-mlkem-group" if pq and before[0] is True and after == [False, [], None, "quantum-safe"] else None
    if kind == "pca-old":
        ok = quantum in ("safe", "hybrid") and before[0] is True and after[0] is False
        return "pca-raw-identifier" if ok else None
    if row["type"] == "tls_endpoint" and algid.is_sentinel(subject):
        return "placeholder-group" if before[0] is None and after[0] is True else None
    if row["type"] == "tls_endpoint" and quantum in ("safe", "hybrid"):
        return "tls-pq-group-evidence" if after == [False, [], None, "hybrid"] else None
    if row["type"] == "managed_key" and found is not None and (found.name or "").upper().startswith("GOST") \
            and before[0] is False and after[0] is True:
        return "gost-r-34.10-signature" if found.family_label == "EC" else None
    if quantum == "vulnerable" and before[0] is None and after[0] is True \
            and set(before[1]) <= set(after[1]):
        return "classical-now-named"
    if quantum in ("safe", "hybrid") and before[0] in (None, True) and after[0] is False \
            and "QUANTUM_VULNERABLE" not in after[1] and "DSA" not in after[1]:
        return "pq-now-named"
    return None


def main() -> int:
    recorded = json.loads((FIXTURES / "algid_verdict_corpus.json").read_text())["verdicts"]
    rows = {row["key"]: row for row in corpus.inputs()}
    entries: dict[str, list] = {}
    oracles: dict[str, str] = {}
    unexplained: list[str] = []
    for key in sorted(recorded):
        before, after = recorded[key], corpus.judge(rows[key])
        if before == after:
            continue
        category = _category(rows[key], before, after)
        if category is None:
            unexplained.append(f"{key}: {before} -> {after}")
            continue
        subject = _subject(rows[key])
        if isinstance(subject, str) and not algid.is_sentinel(subject):
            oracles[subject] = _source(subject)
            entries[key] = [before, after, category, subject]
        else:
            entries[key] = [before, after, category, None]  # the category's DA row is the oracle
    if unexplained:
        print("differences that fit no intended category (fix the code, or add a category with its DA row):")
        print("\n".join(unexplained))
        return 1
    lines = [f"  {json.dumps(k)}: {json.dumps(entries[k])}" for k in sorted(entries)]
    cited = [f"  {json.dumps(k)}: {json.dumps(oracles[k])}" for k in sorted(oracles)]
    OUT.write_text('{"base": "algid_verdict_corpus.json",\n"format": "changes: key -> [before, after, category, '
                   'judged identifier]; oracles: identifier -> the source algid\'s identity comes from",\n'
                   '"categories": %s,\n"changes": {\n%s\n},\n"oracles": {\n%s\n}}\n'
                   % (json.dumps(CATEGORIES, indent=1, ensure_ascii=False), ",\n".join(lines), ",\n".join(cited)))
    counts: dict[str, int] = {}
    for entry in entries.values():
        counts[entry[2]] = counts.get(entry[2], 0) + 1
    print(f"{len(entries)} intended changes -> {OUT.name}: {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
