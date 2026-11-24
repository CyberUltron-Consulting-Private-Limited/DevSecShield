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
                                  "supplementalCredentials", "msFVE-RecoveryPassword", "",
                                  # #488 review m1: options and numeric OIDs slipped past; three attributes were missing
                                  "userPassword;binary", "UNICODEPWD;range=0-*", " userPassword ;x", "2.5.4.35",
                                  "1.2.840.113556.1.4.90", "userPKCS12", "msSFU30Password",
                                  "msPKI-CredentialRoamingTokens", "userPKCS12;binary",
                                  # #488 review 6031264030 n-1: the OID. prefix, NUL / zero-width names, pwdHistory
                                  "OID.2.5.4.35", "oid.2.5.4.35", "OID.userPassword", "userPassword\x00",
                                  "user\u200bPassword", "unicodePwd\x00;binary", "pwdHistory", "PWDHISTORY;binary",
                                  "cn\u00e9"])
def test_secret_attributes_and_wildcards_are_never_requested(attr):
    with pytest.raises(L.LdapError):
        L.search_request(1, "DC=x", 2, "(objectClass=*)", ["cn", attr])


def test_a_secret_attribute_a_server_sends_is_dropped_while_decoding():
    entry = L.seq(L.octets("CN=a"), L.seq(
        L.seq(L.octets("cn"), L.seq(L.octets("a"), tag=0x31)),
        L.seq(L.octets("unicodePwd"), L.seq(L.octets(b"\x00pw"), tag=0x31)),
        L.seq(L.octets("msLAPS-Password;range=0-*"), L.seq(L.octets("x"), tag=0x31)),
        L.seq(L.octets("2.5.4.35"), L.seq(L.octets("x"), tag=0x31)),
        L.seq(L.octets("userPKCS12;binary"), L.seq(L.octets("x"), tag=0x31)),
        # #488 review 6031264030 n-1
        L.seq(L.octets("OID.2.5.4.35"), L.seq(L.octets("x"), tag=0x31)),
        L.seq(L.octets("userPassword\x00"), L.seq(L.octets("x"), tag=0x31)),
        L.seq(L.octets("pwdHistory"), L.seq(L.octets("x"), tag=0x31)),
        L.seq(L.octets("member;range=0-*"), L.seq(L.octets("CN=b"), tag=0x31))), tag=0x64)
    _t, op, _ = L.read_tlv(entry)
    dn, attrs = L.parse_entry(op)
    assert dn == "CN=a" and set(attrs) == {"cn", "member;range=0-*"}


def test_the_collector_attribute_lists_pass_the_check():
    from zs_scan_node.collectors import active_directory as ad

    for attrs in (ad.ROOT_DSE_ATTRS, ad.ACCOUNT_ATTRS, ["cn", "dNSHostName", "cACertificate", "certificateTemplates"]):
        assert L.check_attributes(attrs) == attrs


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
    # #488 review M1: unset is the DC's default (AES only on a DC patched from April 2026, KB5073381): unknown, not RC4
    (None, 512, "service_account", {"rc4_only": None, "rc4_enabled": None, "aes_enabled": None,
                                    "enc_types_source": "default", "dc_default": True, "weak": False}),
    (0, 512, "computer", {"rc4_enabled": None, "dc_default": True, "weak": False}),
    (None, 0x200000 | 512, "service_account", {"des_enabled": True, "rc4_enabled": None, "weak": True}),
    (0x18, 512, "service_account", {"aes_enabled": True, "rc4_enabled": False, "weak": False}),
    (0x1C, 512, "domain_controller", {"aes_enabled": True, "rc4_enabled": True, "rc4_only": False}),
    (0x3, 0x200000 | 512, "service_account", {"des_enabled": True, "use_des_key_only": True}),
    (0x4, None, "gmsa", {"rc4_only": True, "enc_types": ["RC4-HMAC"], "dc_default": False}),
])
def test_enctype_facts(value, uac, kind, expect):
    facts = AD.enctype_facts(value, uac, kind)
    assert {k: facts[k] for k in expect} == expect


def test_the_account_algorithm_is_its_strongest_key_type():
    """#488 review M4: the lowest bit is the weakest type; DC1$ (0x1C) was exported as RC4-HMAC."""
    assert AD.strongest(AD.enctypes(0x1C)) == "AES256-CTS-HMAC-SHA1-96"
    assert AD.strongest(AD.enctypes(0x7)) == "RC4-HMAC"
    assert AD.strongest(AD.enctypes(0x3)) == "DES-CBC-MD5"
    assert AD.strongest(AD.enctypes(0x20)) is None and AD.strongest([]) is None


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
    assert tls["target"] == "localhost" and tls["facts"]["service"] == "ldap"
    # the network prober's facts (#488 review M5): every suite per version, groups, the enumeration's completeness
    assert tls["facts"]["versions"].get("TLSv1.0") is False and tls["facts"]["cipher_suites"]
    assert "cipher_suites_complete" in tls["facts"] and "groups" in tls["facts"]
    # the directory is read first now (#488 review 6031264030 mi-1), so the AD CS CA certificate may come first
    assert tls["facts"]["leaf"]["subject"]
    assert "domain_controller" in {c["facts"].get("role") for c in assets["certificate"]}
    domain = assets["ad_domain"][0]["facts"]
    assert domain["domain"] == "lab.test" and domain["domain_functional_level"] == 6
    assert domain["domain_functional_level_name"] == "Windows Server 2012 R2"
    assert domain["krbtgt_password_last_set"] == "2024-01-01T00:00:00Z"
    # paged; the 4 computers without the attribute use the DC default (unknown), the 3 with 0x18 are AES only
    assert domain["accounts"]["computer_total"] == 7 and domain["accounts"]["computer_dc_default"] == 4
    assert "computer_rc4_enabled" not in domain["accounts"]
    # krbtgt is read once, as krbtgt, never as a service account (#488 review M3)
    assert domain["accounts"]["service_account_total"] == 3 and domain["accounts"]["krbtgt_total"] == 1
    assert any("(!(sAMAccountName=krbtgt))" in f for f in server.record.filters)
    assert domain["enrollment_services"][0]["template_count"] == 3
    rows = assets["kerberos_account"]
    assert sorted(a["name"] for a in rows) == ["DC1$", "gmsa-app$", "krbtgt", "svc-legacy", "svc-sql"]  # krbtgt once
    accounts = {a["name"]: a["facts"] for a in rows}
    algorithms = {a["name"]: a.get("algorithm") for a in rows}
    assert algorithms["DC1$"] == "AES256-CTS-HMAC-SHA1-96" and algorithms["svc-sql"] is None
    assert accounts["svc-sql"]["rc4_enabled"] is None and accounts["svc-sql"]["enc_types_source"] == "default"
    assert accounts["svc-sql"]["dc_default"] is True and accounts["krbtgt"]["judged_by"].startswith("domain_functional")
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


def test_a_weak_suite_the_dc_accepts_but_does_not_prefer_is_found(stub):
    """#488 review M5: one ClientHello per legacy version saw only the suite the server preferred.  This DC (an ECDSA
    certificate) prefers ECDHE-ECDSA-AES256-GCM-SHA384 and still accepts the CBC suite ECDHE-ECDSA-AES128-SHA; the
    prober's enumeration lists both and names the weak one (OpenSSL 3 here serves no RC4 or 3DES at all, so the
    accepted-not-preferred suite is a CBC one; the same enumeration finds RC4 or 3DES on a DC that accepts them)."""
    server = stub(mode="ldaps", ciphers="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA")
    ctx, status, _error = _run(server)
    assert status == "success"
    facts = _by_type(ctx)["tls_endpoint"][0]["facts"]
    assert facts["negotiated_cipher"] == "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    names = {s["name"] for s in facts["cipher_suites"]["TLSv1.2"]}
    assert {"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"} <= names
    assert "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA" in facts["weak_ciphers_accepted"]["cbc"]


def test_timeout_s_bounds_the_whole_tls_posture_read():
    """#488 review m2: a DC that accepts TCP and never answers, with timeout_s=5, took 20.2 s (s_client 15 s plus three
    8 s probes, none bounded by the target's deadline)."""
    import socket
    import threading

    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(64)
    held: list[socket.socket] = []
    stop = threading.Event()

    def accept() -> None:
        silent.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(silent.accept()[0])
            except OSError:
                continue

    threading.Thread(target=accept, daemon=True).start()
    try:
        ctx = _ctx()
        config = {"targets": ["127.0.0.1"], "port": silent.getsockname()[1], "login_user": BIND_NAME,
                  "credential_type": "password", "ca_pem": make_pki()["ca"], "timeout_s": 5, "tls_mode": "ldaps"}
        started = time.monotonic()
        run_job(ctx, {"kind": "collect"}, {"targets": config["targets"]},
                {"kind": "active_directory", "config": config, "secrets": {"password": PASSWORD}})
        took = time.monotonic() - started
    finally:
        stop.set()
        silent.close()
        for c in held:
            c.close()
    assert took < 7.5, took
    assert [o.status for o in ctx.outcomes] == ["timeout"]


# ----------------------------------------------------------------------------- #488 review 6031264030
class _SlowProxy:
    """A TCP proxy that holds the server's first reply on every connection for ``delay`` seconds: a healthy DC across
    a slow WAN link (the review's ``slow_proxy.py``, in-process)."""

    def __init__(self, upstream_port: int, delay: float) -> None:
        import socket
        import threading

        self.upstream, self.delay = upstream_port, delay
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self._open: list[socket.socket] = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        import socket
        import threading

        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            try:
                server = socket.create_connection(("127.0.0.1", self.upstream), timeout=5)
            except OSError:
                client.close()
                continue
            server.settimeout(None)
            self._open += [client, server]
            threading.Thread(target=self._pipe, args=(client, server, 0.0), daemon=True).start()
            threading.Thread(target=self._pipe, args=(server, client, self.delay), daemon=True).start()

    @staticmethod
    def _pipe(src, dst, first_delay: float) -> None:
        first = True
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                if first and first_delay:
                    time.sleep(first_delay)
                first = False
                dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (src, dst):
                try:
                    s.close()
                except OSError:
                    pass

    def close(self) -> None:
        self.sock.close()
        for s in self._open:
            try:
                s.close()
            except OSError:
                pass


def test_a_slow_dc_still_yields_the_directory_and_the_posture_read_gets_at_most_half_of_timeout_s(stub):
    """mi-1: behind a link that delays every reply by 0.6 s, the credential-free TLS posture read (48 handshakes,
    28.8 s of delays) used the whole timeout_s=20, then the target ended ``timeout`` with no Kerberos, krbtgt or
    service-account data although the DC answered every request.  Now the directory is read first, the posture read
    gets at most half of timeout_s, and what it could not finish is a coverage row, not the target's failure."""
    server = stub(mode="ldaps")
    proxy = _SlowProxy(server.port, 0.6)
    try:
        started = time.monotonic()
        ctx, status, error = _run(server, port=proxy.port, timeout_s=20)
        took = time.monotonic() - started
    finally:
        proxy.close()
    assert (status, error) == ("success", None)
    assert [(o.target, o.status) for o in ctx.outcomes] == [("localhost", "ok")]
    assets = _by_type(ctx)
    assert {"svc-sql", "krbtgt", "DC1$"} <= {a["name"] for a in assets["kerberos_account"]}
    assert assets["ad_domain"][0]["facts"]["accounts"]["service_account_total"] == 3
    assert assets["tls_endpoint"]  # what the posture read got within its share is kept
    posture = [a["facts"] for a in assets["coverage"] if a["facts"]["check"].startswith("LDAP TLS posture")]
    assert posture and posture[0]["status"] == "incomplete" and "time" in posture[0]["detail"], posture
    assert took < 20 * 0.5 + 6, took  # the directory read (a few seconds) plus at most half of timeout_s


def test_the_enctype_strength_order_comes_from_the_one_bit_table():
    """n-4: the strongest-first order was a second hand-kept table beside ENCTYPE_BITS.  It is now derived from the bit
    table (the key types, highest bit first; the -SK session-key flag is not a key type), and the backend's
    KERBEROS_ENCTYPES is checked against it (backend/tests/test_cbom_ad_followups.py)."""
    assert AD.STRENGTH == ("AES256-CTS-HMAC-SHA1-96", "AES128-CTS-HMAC-SHA1-96", "RC4-HMAC", "DES-CBC-MD5",
                           "DES-CBC-CRC")
    assert AD.STRENGTH == tuple(name for bit, name in reversed(AD.ENCTYPE_BITS) if bit not in AD.ENCTYPE_FLAGS)
    assert AD.strongest(["DES-CBC-CRC", "RC4-HMAC", "AES256-CTS-HMAC-SHA1-96-SK"]) == "RC4-HMAC"
