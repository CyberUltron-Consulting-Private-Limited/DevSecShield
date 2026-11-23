"""FIX-B3: the read-only Active Directory collector (LDAPS / StartTLS) against an in-process LDAP server.

Fail-closed: a certificate that does not verify, a name that does not match, a never-scan target, a timeout and a
refused bind each end the target with its own status, and the password is never sent before TLS verified the DC.
Read-only: the client only binds, searches, starts TLS and unbinds; it never asks for a secret attribute or ``*``,
and drops one a server sends anyway.  No secret in the assets or the log.
"""
from __future__ import annotations

import time

import pytest
from ldap_stub import BIND_NAME, PASSWORD, LdapStub, make_pki
from zs_scan_node import ldapmini as L
from zs_scan_node.collectors import active_directory as AD
from zs_scan_node.collectors import run_job
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

READ_ONLY_OPS = {0x60, 0x63, 0x42, 0x77}  # bind, search, unbind, extended (StartTLS only)


@pytest.fixture()
def stub():
    servers: list[LdapStub] = []

    def make(**kw) -> LdapStub:
        s = LdapStub(**kw)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.close()


def _ctx(never=(), seconds=60, kind="collect") -> JobContext:
    return JobContext(job_id=1, attempt=1, run_id=None, kind=kind, source_kind="active_directory",
                      scrubber=Scrubber([]), never_scan=NeverScan(list(never)), deadline=time.monotonic() + seconds)


def _config(server: LdapStub, **kw) -> dict:
    return {"targets": ["localhost"], "port": server.port, "login_user": BIND_NAME, "credential_type": "password",
            "ca_pem": server.pki["ca"], "timeout_s": 20, "tls_mode": server.mode, **kw}


def _run(server: LdapStub, ctx: JobContext | None = None, **kw):
    ctx = ctx or _ctx()
    config = _config(server, **kw)
    status, error, _summary = run_job(ctx, {"kind": ctx.kind}, {"targets": config["targets"]},
                                     {"kind": "active_directory", "config": config, "secrets": {"password": PASSWORD}})
    return ctx, status, error


def _by_type(ctx: JobContext) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for a in ctx._buffer:
        out.setdefault(a["type"], []).append(a)
    return out


# ----------------------------------------------------------------------------- pure parts
def test_filters_round_trip_and_refuse_what_is_not_needed():
    for text in ("(objectClass=*)", "(sAMAccountName=krbtgt)", "(|(primaryGroupID=516)(primaryGroupID=521))",
                 "(&(objectCategory=computer)(!(primaryGroupID=516)))",
                 "(userAccountControl:1.2.840.113556.1.4.803:=8192)"):
        assert L.decode_filter(L.encode_filter(text)) == text
    for bad in ("(cn=a*b)", "(cn>=a)", "cn=a", "(&)", "(cn=a))"):
        with pytest.raises(L.LdapError):
            L.encode_filter(bad)


@pytest.mark.parametrize("attr", ["*", "+", "unicodePwd", "msDS-ManagedPassword", "ms-Mcs-AdmPwd", "msLAPS-Password",
                                  "supplementalCredentials", "msFVE-RecoveryPassword", ""])
def test_secret_attributes_and_wildcards_are_never_requested(attr):
    with pytest.raises(L.LdapError):
        L.search_request(1, "DC=x", 2, "(objectClass=*)", ["cn", attr])


def test_a_secret_attribute_a_server_sends_is_dropped_while_decoding():
    entry = L.seq(L.octets("CN=a"), L.seq(
        L.seq(L.octets("cn"), L.seq(L.octets("a"), tag=0x31)),
        L.seq(L.octets("unicodePwd"), L.seq(L.octets(b"\x00pw"), tag=0x31)),
        L.seq(L.octets("msLAPS-Password;range=0-*"), L.seq(L.octets("x"), tag=0x31))), tag=0x64)
    _t, op, _ = L.read_tlv(entry)
    dn, attrs = L.parse_entry(op)
    assert dn == "CN=a" and set(attrs) == {"cn"}


def test_malformed_and_oversized_answers_are_refused():
    with pytest.raises(L.LdapError):
        L.read_tlv(b"\x30\x85\x00\x00\x00\x00\x01")  # 5-byte length
    with pytest.raises(L.LdapError):
        L.read_tlv(b"\x30\x05\x02\x01")  # truncated
    with pytest.raises(L.LdapError):
        L.parse_message(L.seq(L.octets("x")))


def test_the_client_has_no_write_operation():
    assert not [n for n in dir(L.LdapClient) if any(w in n.lower() for w in ("add", "modify", "delete", "write",
                                                                                 "compare", "rename", "passwd"))]


@pytest.mark.parametrize("value,uac,kind,expect", [
    (None, 512, "service_account", {"rc4_only": True, "enc_types_source": "default", "weak": True}),
    (0x18, 512, "service_account", {"aes_enabled": True, "rc4_enabled": False, "weak": False}),
    (0x1C, 512, "domain_controller", {"aes_enabled": True, "rc4_enabled": True, "rc4_only": False}),
    (0x3, 0x200000 | 512, "service_account", {"des_enabled": True, "use_des_key_only": True}),
    (0x4, None, "gmsa", {"rc4_only": True, "enc_types": ["RC4-HMAC"]}),
])
def test_enctype_facts(value, uac, kind, expect):
    facts = AD.enctype_facts(value, uac, kind)
    assert {k: facts[k] for k in expect} == expect


def test_small_helpers():
    assert AD.filetime_to_iso("133485408000000000") == "2024-01-01T00:00:00Z"
    assert AD.filetime_to_iso("0") is None and AD.filetime_to_iso("x") is None
    assert AD.dn_to_dns("DC=Corp,DC=Example,DC=com") == "corp.example.com"
    assert AD.level_name(7) == "Windows Server 2016" and AD.level_name(None) is None


# ----------------------------------------------------------------------------- collection
@pytest.mark.parametrize("mode", ["ldaps", "starttls"])
def test_collects_tls_posture_kerberos_types_and_ad_cs_read_only(stub, mode, capsys):
    server = stub(mode=mode)
    ctx, status, error = _run(server)
    assert (status, error) == ("success", None)
    assert [(o.target, o.status) for o in ctx.outcomes] == [("localhost", "ok")]
    assets = _by_type(ctx)
    tls = assets["tls_endpoint"][0]
    assert tls["location"] == f"localhost:{server.port}" and tls["facts"]["ldap_tls_mode"] == mode
    assert tls["facts"]["versions"].get("TLSv1.0") is False and tls["facts"]["protocols"]
    assert tls["facts"]["leaf"]["subject"] and assets["certificate"][0]["facts"]["role"] == "domain_controller"
    domain = assets["ad_domain"][0]["facts"]
    assert domain["domain"] == "lab.test" and domain["domain_functional_level"] == 6
    assert domain["domain_functional_level_name"] == "Windows Server 2012 R2"
    assert domain["krbtgt_password_last_set"] == "2024-01-01T00:00:00Z"
    assert domain["accounts"]["computer_total"] == 7 and domain["accounts"]["computer_rc4_enabled"] == 4  # paged
    assert domain["enrollment_services"][0]["template_count"] == 3
    accounts = {a["name"]: a["facts"] for a in assets["kerberos_account"]}
    assert accounts["svc-sql"]["rc4_only"] and accounts["svc-sql"]["enc_types_source"] == "default"
    assert accounts["svc-legacy"]["des_enabled"] and accounts["svc-legacy"]["use_des_key_only"]
    assert "svc-web" not in accounts  # AES only: counted, not listed
    assert accounts["DC1$"]["account_type"] == "domain_controller" and accounts["krbtgt"]["account_type"] == "krbtgt"
    ca = [c for c in assets["certificate"] if c["facts"].get("role") == "ca"]
    assert ca and ca[0]["facts"]["enrollment_service"] == "Lab-CA"
    cov = {a["facts"]["check"]: a["facts"]["status"] for a in assets["coverage"]}
    assert cov["LDAP signing and channel binding"] == "not_supported"
    # read-only, never a secret attribute, never '*', every bind over TLS
    rec = server.record
    assert set(rec.ops) <= READ_ONLY_OPS
    assert not {a.lower() for a in rec.attributes} & L.SECRET_ATTRIBUTES and "*" not in rec.attributes
    assert rec.binds and all(tls_on for _name, tls_on in rec.binds)
    # the secret the server sent is not in any asset; the password is nowhere in the assets or the log
    blob = repr(ctx._buffer)
    assert "secret-hash" not in blob and "unicodePwd" not in blob and PASSWORD not in blob
    out = capsys.readouterr()
    assert PASSWORD not in out.out + out.err


def test_an_untrusted_certificate_fails_closed_and_the_password_is_not_sent(stub):
    server = stub(mode="ldaps")
    other = make_pki()
    ctx, status, error = _run(server, ca_pem=other["ca"])
    assert status == "failure" and "identity_unverified" in error and "password was not sent" in error
    assert server.record.binds == [] and server.record.passwords_seen == 0
    # the TLS posture read without credentials is kept
    assert _by_type(ctx)["tls_endpoint"]


def test_a_certificate_for_another_name_fails_closed(stub):
    server = stub(mode="ldaps", pki=make_pki(names=("dc9.other.test",), ips=()))
    _job_ctx, status, error = _run(server)
    assert status == "failure" and "identity_unverified" in error
    assert server.record.passwords_seen == 0


def test_starttls_refused_fails_closed(stub):
    server = stub(mode="ldaps")  # an LDAPS port: a StartTLS request gets no StartTLS
    server.mode = "plain-no-starttls"
    _job_ctx, status, _error = _run(server, tls_mode="starttls")
    assert status == "failure" and server.record.passwords_seen == 0


def test_a_never_scan_target_is_never_contacted(stub):
    server = stub(mode="ldaps")
    ctx, _status, _error = _run(server, ctx=_ctx(never=["127.0.0.0/8"]))
    assert [(o.status) for o in ctx.outcomes] == ["skipped_never_scan"]
    assert server.record.connections == 0 and server.record.passwords_seen == 0


def test_a_silent_directory_times_out_without_hanging_the_job(stub):
    server = stub(mode="ldaps", stall_after_bind=True)
    started = time.monotonic()
    ctx, _status, _error = _run(server, timeout_s=3)
    assert time.monotonic() - started < 25
    assert [o.status for o in ctx.outcomes] == ["timeout"]


def test_a_refused_bind_is_auth_failed_and_never_logs_the_password(stub, capsys):
    server = stub(mode="ldaps")
    ctx = _ctx()
    config = _config(server)
    status, error, _ = run_job(ctx, {"kind": "collect"}, {"targets": config["targets"]},
                               {"kind": "active_directory", "config": config, "secrets": {"password": "wrong-Pass-1!"}})
    assert status == "failure" and "auth_failed" in error
    out = capsys.readouterr()
    assert "wrong-Pass-1!" not in out.out + out.err + repr(ctx._buffer)


def test_a_missing_password_or_bad_ca_fails_before_any_connection(stub):
    server = stub(mode="ldaps")
    ctx = _ctx()
    status, error, _ = run_job(ctx, {"kind": "collect"}, {"targets": ["localhost"]},
                               {"kind": "active_directory", "config": _config(server), "secrets": {}})
    assert status == "failure" and "no password" in error
    status, error, _ = run_job(_ctx(), {"kind": "collect"}, {"targets": ["localhost"]},
                               {"kind": "active_directory", "config": _config(server, ca_pem="not a pem"),
                                "secrets": {"password": PASSWORD}})
    assert status == "failure" and "CA certificate" in error
    assert server.record.connections == 0


def test_connection_test_reports_the_domain_and_level(stub):
    server = stub(mode="ldaps")
    ctx = _ctx(kind="test_connection")
    status, _error, summary = run_job(ctx, {"kind": "test_connection"}, {"targets": ["localhost"]},
                                     {"kind": "active_directory", "config": _config(server),
                                      "secrets": {"password": PASSWORD}})
    assert status == "success" and summary == "1 of 1 samples ready"
    sample = ctx.samples[0]
    assert sample["login"] is True and "lab.test" in sample["note"] and "2012 R2" in sample["note"]
