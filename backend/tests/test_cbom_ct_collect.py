"""CT discovery collector on recorded answers: assets and facts against an independent openssl read (oracle.json),
precertificate handling, provider fallback, failures, limits and the findings it feeds (reused and new codes).

Expected values come from fixtures/ct/*/oracle.json (bench/ct/oracle.py, openssl x509; no product code) or from the
recorded provider JSON itself; "now" is fixed to the recording day.

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_ct_collect.py -q
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

import httpx
import pytest

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(Path(__file__).parent))

from backend.utilities.cbom_sources import ct_collect as C  # noqa: E402
from backend.utilities.cbom_sources import ct_providers as P  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from backend.utilities.cbom_sources.kinds import CtLogsConfig  # noqa: E402
from test_cbom_ct_provider import FakeClock, Replay, fast, oracle, recorded  # noqa: E402

NOW = dt.datetime(2026, 11, 12, 18, 0, 0)  # the recording day (17:46-17:59Z)


def run(domains, *, replay=None, chain_names=("certspotter",), expected=(), include_subdomains=True, clock=None,
        should_stop=lambda: None, deadline=None, now=NOW):
    replay = replay or Replay()
    clock = clock or FakeClock()
    import random

    client = P.CtHttp(transport=replay.transport(), clock=clock, rng=random.Random(3))
    chain = []
    for name in chain_names:
        chain.append(P.CertSpotter(client, rate=fast()) if name == "certspotter" else P.CrtSh(client, rate=fast()))
    cfg = CtLogsConfig.model_validate({"domains": list(domains), "include_subdomains": include_subdomains,
                                       "expected_issuers": list(expected)}).model_dump(mode="json")
    out: list[dict] = []
    result = C.collect_ct(cfg, "Certificate Transparency", out.append, should_stop, deadline=deadline, chain=chain,
                          http=client, clock=clock, now=now, cache=P.AnswerCache(0))
    certs = [a for a in out if a["type"] == "certificate"]
    gaps = [a for a in out if a["type"] == "coverage"]
    return result, certs, gaps, replay


# ----------------------------------------------------------------------------- facts against the oracle
def test_every_issuance_is_one_asset_with_the_facts_openssl_reads():
    result, certs, gaps, _ = run(["zeroshield.ai"])
    want = {r["serial"]: r for r in oracle("certspotter_zeroshield")}
    assert len(certs) == len(want) == 25 and gaps == []
    assert result["counts"] == {"total": 1, "ok": 1, "failed": 0, "skipped": 0, "partial": 0}
    for asset in certs:
        f = asset["facts"]
        o = want[f["serial"]]
        assert (f["not_before"], f["not_after"]) == (o["not_before"], o["not_after"])
        assert f["sig_alg"] == o["sig_alg"] and asset["key_size"] == o["key_bits"]
        assert sorted(f["san"]) == o["dns_names"]
        assert C.cn_of(f["subject"]) == o["subject_cn"] and C.cn_of(f["issuer"]) == o["issuer_cn"]
        assert asset["algorithm"] == ("ECDSA" if o["pubkey_alg"] == "id-ecPublicKey" else "RSA")
        if o["precert_poison"]:  # Cert Spotter does not know the final certificate: no fingerprint to correlate
            assert f["precertificate_only"] is True and f["precert_sha256"] == o["sha256"] and "fingerprint_sha256" not in f
        else:
            assert f["precertificate_only"] is False and f["fingerprint_sha256"] == o["sha256"] == o["cert_sha256"]
        assert f["tbs_sha256"] == o["tbs_sha256"] and f["issuer_name"] == o["issuer_friendly_name"]
        assert f["source"] == "ct" and f["ct_provider"] == "certspotter" and f["ct_detail"] == "full"
        assert asset["target"] == "zeroshield.ai" and asset["location"] == f"ct:{o['serial']}@{o['issuer_cn']}"
    assert sum(1 for a in certs if a["facts"]["precertificate_only"]) == 8


def test_a_certificate_found_by_two_names_is_one_asset():
    _r, certs, _g, replay = run(["zeroshield.ai", "ct-proof-host.zeroshield.ai", "example.com"], include_subdomains=False,
                                replay=Replay({("certspotter", "zeroshield.ai", "false", None): "certspotter_zeroshield",
                                               ("certspotter", "example.com", "false", None): "certspotter_example"}))
    wild = {r["serial"] for r in oracle("certspotter_wildcard_host")}
    by_serial = {a["facts"]["serial"]: a for a in certs}
    assert len(certs) == 25 + 17  # the host's 3 wildcard certificates are among zeroshield.ai's 25
    for serial in wild:
        assert by_serial[serial]["facts"]["matched_domains"] == ["ct-proof-host.zeroshield.ai", "zeroshield.ai"]
        assert by_serial[serial]["target"] == "ct-proof-host.zeroshield.ai"  # the first listed name, sorted
    assert len(replay.calls) == 3


def test_subdomains_of_a_listed_domain_are_not_searched_twice():
    _r, _c, _g, replay = run(["zeroshield.ai", "ct-proof-host.zeroshield.ai", "*.zeroshield.ai"])
    assert len(replay.calls) == 1


def test_an_idn_is_searched_as_punycode():
    result, certs, _g, replay = run(["bücher.de"])
    assert "domain=xn--bcher-kva.de" in replay.calls[0]
    assert len(certs) == len(oracle("certspotter_idn_buecher")) and {a["target"] for a in certs} == {"xn--bcher-kva.de"}
    assert result["targets"][0]["target"] == "xn--bcher-kva.de"


def test_an_empty_answer_is_a_read_target_with_no_assets():
    result, certs, gaps, _ = run(["zs-ct-empty-proof.example.com"], include_subdomains=False)
    assert certs == [] and gaps == [] and result["counts"]["ok"] == 1 and result["targets"][0]["assets"] == 0


# ----------------------------------------------------------------------------- findings (reused and new codes)
def _verdict(asset, now=NOW):
    return classify("certificate", asset["algorithm"], asset["key_size"], None, asset["facts"], now)


def test_expiry_codes_are_the_existing_ones():
    _r, certs, _g, _ = run(["zeroshield.ai"])
    soonest = min(certs, key=lambda a: a["facts"]["not_after"])
    assert soonest["facts"]["not_after"] == "2026-11-22T09:54:09Z"
    assert "CERT_EXPIRES_30D" in _verdict(soonest)["finding_codes"]
    assert "CERT_EXPIRED" in _verdict(soonest, dt.datetime(2026, 11, 23))["finding_codes"]
    assert soonest["facts"]["expired"] is False


def test_unexpected_issuer_is_flagged_only_when_the_team_lists_its_cas():
    _r, certs, _g, _ = run(["zeroshield.ai"])
    assert all("issuer_expected" not in a["facts"] for a in certs)
    _r, certs, _g, _ = run(["zeroshield.ai"], expected=["Let's Encrypt", "google trust"])
    by_issuer = {}
    for asset in certs:
        by_issuer.setdefault(asset["facts"]["issuer_name"], set()).add(asset["facts"]["issuer_expected"])
    assert by_issuer == {"Let's Encrypt": {True}, "Google Trust Services": {True}, "Amazon Trust Services": {False}}
    amazon = next(a for a in certs if a["facts"]["issuer_name"] == "Amazon Trust Services")
    verdict = _verdict(amazon)
    assert "CERT_UNEXPECTED_CA" in verdict["finding_codes"] and "Amazon Trust Services" in verdict["finding"]


def test_the_recorded_revoked_certificate_is_flagged():
    _r, certs, _g, _ = run(["example.com"])
    raw = {r["id"]: r for r in json.loads(recorded("certspotter_example")[2])}
    revoked = [a for a in certs if raw[a["facts"]["ct_provider_id"]]["revoked"]]
    assert len(revoked) == 1 and revoked[0]["facts"]["revoked"] is True
    assert "CERT_REVOKED" in _verdict(revoked[0])["finding_codes"]
    assert all("CERT_REVOKED" not in _verdict(a)["finding_codes"] for a in certs if a not in revoked)


def test_wildcard_sprawl_counts_live_wildcards_per_name():
    _r, certs, _g, _ = run(["example.com"])  # six *.example.com certificates in the recording, none revoked
    wild = [a for a in certs if "*.example.com" in a["facts"]["san"]]
    want = [r for r in oracle("certspotter_example") if "*.example.com" in r["dns_names"] and not r["revoked"]
            and r["not_after"] > "2026-11-12T18:00:00Z"]
    live = [a for a in wild if not a["facts"].get("revoked")]
    assert len(wild) == 6 and len(live) == len(want) == 6
    for asset in live:
        assert asset["facts"]["wildcard_sprawl"] == {"name": "*.example.com", "certificates": 6, "threshold": 3}
        assert "CERT_WILDCARD_SPRAWL" in _verdict(asset)["finding_codes"]
    _r, certs, _g, _ = run(["zeroshield.ai"])  # three *.zeroshield.ai: at the threshold, not over it
    assert not any("wildcard_sprawl" in a["facts"] for a in certs)


def test_weak_key_and_sha1_use_the_existing_codes():
    _r, certs, _g, _ = run(["zeroshield.ai"])
    asset = next(a for a in certs if a["algorithm"] == "RSA")
    weak = {**asset, "key_size": 1024, "facts": {**asset["facts"], "key_size": 1024, "sig_alg": "sha1WithRSAEncryption"}}
    codes = _verdict(weak)["finding_codes"]
    assert "RSA_LT_2048" in codes and "SIG_SHA1" in codes


# ----------------------------------------------------------------------------- failures, fallback, limits
def _always(case_or_fn):
    if callable(case_or_fn):
        return case_or_fn

    def answer(_request):
        status, headers, body = recorded(case_or_fn)
        return httpx.Response(status, headers=headers, content=body)

    return answer


def test_quota_spent_hands_the_names_to_crtsh_and_says_what_was_not_checked():
    clock = FakeClock()
    replay = Replay({("certspotter", "zeroshield.ai"): _always("certspotter_fullquota_10"),
                     ("certspotter", "example.com"): _always("certspotter_fullquota_10")})
    result, certs, gaps, replay = run(["zeroshield.ai", "example.com"], replay=replay, chain_names=("certspotter", "crtsh"),
                                      clock=clock, deadline=clock.t + 300)  # 348 s would pass it
    certspotter_calls = [u for u in replay.calls if "certspotter" in u]
    assert len(certspotter_calls) == 1  # throttled after the first 429: the second name goes straight to crt.sh
    assert {t["provider"] for t in result["targets"]} == {"crtsh"} and result["counts"]["ok"] == 2
    zs = [a for a in certs if a["target"] == "zeroshield.ai"]
    assert sorted(a["facts"]["serial"] for a in zs) == sorted(r["serial"] for r in oracle("crtsh_zeroshield_unexpired"))
    assert all(a["facts"]["ct_detail"] == "summary" and a["key_size"] is None and "fingerprint_sha256" not in a["facts"]
               for a in certs)
    note = [g for g in gaps if g["facts"]["check"] == "CT certificate details"]
    assert len(note) == 1 and "weak-key and SHA-1 checks were not run" in note[0]["facts"]["detail"]
    assert result["provider_calls"] == {"certspotter": 1, "crtsh": 2} and result["rate_limited"] == 1


def test_a_name_no_provider_can_read_is_a_coverage_gap_not_a_removal():
    replay = Replay({("certspotter", "zeroshield.ai"): _always("crtsh_reliability_00"),  # 502 three times
                     ("crtsh", "zeroshield.ai"): _always("crtsh_reliability_00")})
    result, certs, gaps, replay = run(["zeroshield.ai", "example.com"], replay=replay, chain_names=("certspotter", "crtsh"))
    zs = next(t for t in result["targets"] if t["target"] == "zeroshield.ai")
    assert zs["status"] == "error" and "HTTP 502" in zs["error"]
    gap = next(g for g in gaps if g["target"] == "zeroshield.ai")
    assert gap["facts"]["check"] == C.CHECK and gap["facts"]["status"] == "error" and gap["location"] == "ct:zeroshield.ai"
    assert result["counts"] == {"total": 2, "ok": 1, "failed": 1, "skipped": 0, "partial": 0}
    assert {a["target"] for a in certs} == {"example.com"}


def test_a_refused_query_is_not_sent_to_the_fallback():
    replay = Replay({("certspotter", "example.com"): _always("certspotter_error_bad_value")})
    result, _c, gaps, replay = run(["example.com"], replay=replay, chain_names=("certspotter", "crtsh"))
    assert result["targets"][0]["status"] == "error" and not any("crt.sh" in u for u in replay.calls)
    assert "include_subdomains" in gaps[0]["facts"]["detail"]


def test_stop_and_deadline_leave_the_rest_not_searched():
    stops = iter([None, "Stopped at the maximum run time"])
    result, certs, gaps, _ = run(["zeroshield.ai", "example.com"], should_stop=lambda: next(stops, "x"))
    assert [t["status"] for t in result["targets"]] == ["skipped", "ok"] or [t["status"] for t in result["targets"]] == ["ok", "skipped"]
    skipped = next(t for t in result["targets"] if t["status"] == "skipped")
    assert skipped["error"].startswith("Not searched:") and any(g["facts"]["status"] == "skipped" for g in gaps)
    clock = FakeClock()
    result, _c, _g, _ = run(["zeroshield.ai"], clock=clock, deadline=clock.t + C.DEADLINE_MARGIN_S - 1)
    assert result["targets"][0]["status"] == "skipped" and "maximum time" in result["targets"][0]["error"]


def test_a_truncated_answer_is_partial(monkeypatch):
    monkeypatch.setattr(P, "MAX_RESULTS", 120)
    result, certs, gaps, _ = run(["google.com"])
    assert result["targets"][0]["status"] == "partial" and result["counts"]["partial"] == 1
    assert len(certs) == 120 and gaps[0]["facts"]["status"] == "partial"


def test_bad_credentials_open_the_circuit_for_the_whole_job():
    replay = Replay({("certspotter", "zeroshield.ai"): _always("certspotter_error_bad_credentials"),
                     ("certspotter", "example.com"): _always("certspotter_error_bad_credentials")})
    result, _c, _g, replay = run(["zeroshield.ai", "example.com"], replay=replay, chain_names=("certspotter", "crtsh"))
    assert sum(1 for u in replay.calls if "certspotter" in u) == 1
    assert all(t["provider"] == "crtsh" for t in result["targets"])
