"""WinRM collector against a least-privilege account (AWS lab, Windows Server 2022, 2026-11-01).

The outputs below are what win01 returned to `svc-zscbom` (Remote Management Users, not an administrator):
Get-CimInstance was denied, Get-TlsCipherSuite came back as one List object, the certificate script exited 1
with valid JSON on stdout, and BitLocker was not installed.  Each used to lose data or mislabel the server.
"""
from __future__ import annotations

import json
import time
from types import SimpleNamespace

import pytest

from zs_scan_node.collectors import windows_winrm as W
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber

CERTS = json.dumps([
    {"Store": "My", "Subject": "CN=legacy.zslab.internal", "Issuer": "CN=legacy.zslab.internal",
     "Thumbprint": "E64138659BEC712EAE656A59A5C2FB29989D0348", "NotAfter": "2028-11-01T06:37:27.0000000Z",
     "SignatureAlgorithm": "sha1RSA", "KeyAlgorithm": "RSA", "KeySize": 1024, "HasPrivateKey": True},
    {"Store": "My", "Subject": "CN=win01.zslab.internal", "Issuer": "CN=ZeroShield CBOM Lab CA (zscbom)",
     "Thumbprint": "D0AAB0F87955E6B9D67141DED8D7DB34179B737E", "NotAfter": "2027-04-30T05:36:26.0000000Z",
     "SignatureAlgorithm": "sha256RSA", "KeyAlgorithm": "RSA", "KeySize": 2048, "HasPrivateKey": True}])
SUITES = json.dumps({"Source": "local", "Suites": ["TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                                                   "TLS_RSA_WITH_3DES_EDE_CBC_SHA"]})
WIN01 = {  # script -> (exit code, stdout, stderr)
    "os": (0, '{"Caption":"Windows Server 2022 Datacenter","Version":"10.0.20348.5773","BuildNumber":"20348",'
              '"DisplayVersion":"21H2","EditionID":"ServerDatacenter"}', ""),
    "schannel": (0, '[{"Protocol":"TLS 1.0","Side":"Server","Enabled":1,"DisabledByDefault":0},'
                    '{"Protocol":"TLS 1.0","Side":"Client","Enabled":1,"DisabledByDefault":0}]', ""),
    "schannel_algorithms": (0, '{"Kind":"Ciphers","Name":"Triple DES 168","Enabled":4294967295,'
                               '"ServerMinKeyBitLength":null}', ""),
    "cipher_suites": (0, SUITES, ""),
    "dotnet": (0, '[{"Key":"HKLM:\\\\SOFTWARE\\\\Microsoft\\\\.NETFramework\\\\v4.0.30319","SchUseStrongCrypto":0,'
                  '"SystemDefaultTlsVersions":null},{"Key":"HKLM:\\\\SOFTWARE\\\\WOW6432Node\\\\Microsoft\\\\'
                  '.NETFramework\\\\v4.0.30319","SchUseStrongCrypto":0,"SystemDefaultTlsVersions":null}]', ""),
    "rdp": (0, '{"SecurityLayer":0,"MinEncryptionLevel":2,"UserAuthentication":0}', ""),
    "bitlocker": (1, "", "Get-BitLockerVolume : The term 'Get-BitLockerVolume' is not recognized as the name of a "
                         "cmdlet ... CommandNotFoundException"),
    "certificates": (1, CERTS, "#< CLIXML <Objs Version=\"1.1.0.1\"><Obj S=\"progress\" RefId=\"0\"></Obj></Objs>"),
}


def _ctx() -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="windows_servers",
                      scrubber=Scrubber([]), never_scan=NeverScan([]), deadline=time.monotonic() + 60)


@pytest.fixture
def win01(monkeypatch):
    calls = []

    def fake_run(_sess, name):
        calls.append(name)
        return WIN01[name]
    monkeypatch.setattr(W, "_run", fake_run)
    monkeypatch.setattr(W, "_session", lambda *a, **k: object())
    monkeypatch.setattr(W, "check_name", lambda *a, **k: None)
    return calls


def test_collect_keeps_everything_a_non_admin_can_read(win01):
    ctx = _ctx()
    n = W.collect_target(ctx, Target("win01.zslab.internal", "10.60.20.86"), {}, "pw")
    ctx.flush()
    by_type = {}
    for a in ctx.collected:
        by_type.setdefault(a["type"], []).append(a)
    # certificates survive the non-zero exit code (stdout was valid JSON)
    assert {c["key_size"] for c in by_type["certificate"]} == {1024, 2048} and n == 3
    pol = by_type["os_crypto_policy"][0]["facts"]
    assert pol["os"]["Caption"] == "Windows Server 2022 Datacenter"
    assert pol["schannel_protocols"]["TLS 1.0"]["server"]["enabled"] is True
    assert pol["schannel_algorithms"]["Ciphers/Triple DES 168"]["enabled"] is True
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in pol["cipher_suites"] and pol["cipher_suite_source"] == "local"
    assert [d["sch_use_strong_crypto"] for d in pol["dotnet"]] == [0, 0]
    cov = {c["facts"]["check"]: c["facts"] for c in by_type["coverage"]}
    assert cov["BitLocker"]["status"] == "not_supported" and "not installed" in cov["BitLocker"]["detail"]
    assert "Certificate stores" not in cov


def test_parsers_accept_scalar_and_legacy_shapes():
    assert W.parse_cipher_suites('["TLS_A","TLS_B"]') == (["TLS_A", "TLS_B"], "local")
    assert W.parse_cipher_suites('{"Source":"policy","Suites":"TLS_ONLY"}') == (["TLS_ONLY"], "policy")
    assert W.parse_cipher_suites("not json") == ([], None)
    algos = W.parse_schannel_algorithms('[{"Kind":"Ciphers","Name":"RC4 128/128","Enabled":0},'
                                        '{"Kind":"Hashes","Name":"MD5","Enabled":-1},{"Kind":"Bogus","Name":"x"}]')
    assert algos["Ciphers/RC4 128/128"]["enabled"] is False and algos["Hashes/MD5"]["enabled"] is True
    assert len(algos) == 2


def test_shell_refused_is_not_unreachable():
    from winrm.exceptions import WSManFaultError
    denied = WSManFaultError(500, "Bad HTTP response returned from server. Code 500", "", "Access is denied.",
                             wsman_fault_code=5)
    sess = SimpleNamespace(run_ps=lambda _s: (_ for _ in ()).throw(denied))
    with pytest.raises(W._Fail) as exc:
        W._run(sess, "os")
    assert exc.value.status == "winrm_denied" and "RootSDDL" in exc.value.error
    other = WSManFaultError(500, "x", "", "The WS-Management service cannot process the request.", wsman_fault_code=2150858843)
    sess = SimpleNamespace(run_ps=lambda _s: (_ for _ in ()).throw(other))
    with pytest.raises(W._Fail) as exc:
        W._run(sess, "os")
    assert exc.value.status == "error" and "2150858843" in exc.value.error


def test_test_sample_reports_login_when_a_read_fails(monkeypatch):
    monkeypatch.setattr(W, "_session", lambda *a, **k: object())
    monkeypatch.setattr(W, "check_name", lambda *a, **k: None)
    monkeypatch.setattr(W, "_run", lambda _s, _n: (1, "", "Get-CimInstance : Access denied"))
    ctx = _ctx()
    W._test_one(ctx, Target("win01", "10.60.20.86"), {}, "pw", None)
    s = ctx.samples[0]
    assert s["login"] is True and s["reachable"] is True and "Access denied" in s["note"]
