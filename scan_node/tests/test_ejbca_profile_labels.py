"""EJBCA certificate profiles are labelled from every key algorithm they allow (owner bug C10d, 14 Nov 2026: a profile
that allows post-quantum algorithms was labelled RSA).  Post-quantum names come from algid only."""
from __future__ import annotations

import time

from zs_scan_node import algid
from zs_scan_node.collectors import ca
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber


def _ctx():
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="ca_connector",
                      scrubber=Scrubber([]), never_scan=NeverScan(), deadline=time.monotonic() + 60)


def _pq_signatures(n: int) -> list[str]:
    names = []
    for name, row in algid._ALGS.items():
        ident = algid.resolve(name)
        if row[0] == "PQ" and ident and ident.primitive == "signature" and ident.construction == "pure" \
                and not ident.stateful and ident.parameter_set:
            names.append(name)
    assert len(names) >= n
    return names[:n]


def _profile(body: dict) -> dict:
    ctx = _ctx()
    target = Target(label="ejbca.test", ip="127.0.0.1")
    assert ca._ejbca_profile(ctx, target, "https://ejbca.test/ejbca/ejbca-rest-api", "ENDUSER", body) == 1
    ctx.flush()
    (row,) = [a for a in ctx.collected if a["type"] == "ca_template"]
    return row


def test_a_profile_that_allows_a_pq_algorithm_is_not_labelled_rsa():
    pq1, pq2 = _pq_signatures(2)
    row = _profile({"available_key_algs": ["RSA", "ECDSA", pq1.upper(), pq2.upper()],
                    "available_bit_lengths": [1024, 2048, 4096]})
    assert row["algorithm"] != "RSA" and algid.family_label(row["algorithm"]) == "PQ"
    assert row["facts"]["key_type"] == row["algorithm"]
    assert row["key_size"] is None  # a PQ label carries no RSA modulus
    assert row["facts"]["key_bits"] == 1024  # the smallest RSA size it still allows (judged by the server)
    assert row["facts"]["pq_key_algs"] == [algid.resolve(pq1.upper()).name or pq1.upper(),
                                           algid.resolve(pq2.upper()).name or pq2.upper()]
    assert row["facts"]["classical_key_algs"] == ["RSA", "ECDSA"]
    assert row["facts"]["available_key_algs"] == ["RSA", "ECDSA", pq1.upper(), pq2.upper()]


def test_a_pq_only_profile_has_no_rsa_size():
    (pq,) = _pq_signatures(1)
    row = _profile({"available_key_algs": [pq], "available_bit_lengths": [2048]})
    assert algid.family_label(row["algorithm"]) == "PQ" and row["key_size"] is None and row["facts"]["key_bits"] is None
    assert row["facts"]["classical_key_algs"] == []


def test_classical_profiles_keep_their_labels():
    row = _profile({"available_key_algs": ["RSA", "ECDSA"], "available_bit_lengths": [1024, 2048]})
    assert row["algorithm"] == "RSA" and row["key_size"] == 1024 and row["facts"]["pq_key_algs"] == []
    row = _profile({"available_key_algs": ["ECDSA"], "available_bit_lengths": []})
    assert row["algorithm"] == "ECDSA" and row["key_size"] is None
    row = _profile({})
    assert row["algorithm"] is None and row["key_size"] is None
