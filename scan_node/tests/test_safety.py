import json
import shlex
import time

import pytest

from zs_scan_node import commands as C
from zs_scan_node.collectors import ConfigError
from zs_scan_node.collectors.linux_ssh import _file_cmd
from zs_scan_node.jobctx import JobContext, _fit
from zs_scan_node.netutil import NeverScan, expand_targets, iter_line_ips
from zs_scan_node.scrub import REDACTED, Scrubber
from zs_scan_node.vault import check_prefix


# ----------------------------------------------------------------------------- scrubbing
def test_scrub_known_secrets_and_patterns():
    s = Scrubber(["hunter2-very-secret"])
    assert REDACTED in s.text("login failed for password hunter2-very-secret")
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----\nafter"
    assert s.text(pem) == REDACTED + "\nafter"
    truncated = "x -----BEGIN PRIVATE KEY-----\nMIIabcdef"  # no END line: still redacted to the end
    assert s.text(truncated) == "x " + REDACTED
    assert "zsn_" not in s.text("token zsn_ABCDEFGHIJKLMNOPQRSTUV")
    assert "hvs." not in s.text("vault hvs.CAESIJlU0123456789abcdefghijklmnop")
    nested = s.obj({"a": ["hunter2-very-secret", {"b": "ok"}]})
    assert nested == {"a": [REDACTED, {"b": "ok"}]}


def test_scrub_multiline_secret_lines():
    kubeconfig = "users:\n- name: x\n  user:\n    token: eyJhbGciOiJSUzI1NiIsImtpZCI6Ik5vdGFSZWFsVG9rZW4\n"
    s = Scrubber([kubeconfig])
    assert "eyJhbGciOiJSUzI1NiIsImtpZCI6" not in s.text("Authorization: token: eyJhbGciOiJSUzI1NiIsImtpZCI6Ik5vdGFSZWFsVG9rZW4")


# ----------------------------------------------------------------------------- command lines
def test_file_paths_are_quoted():
    cmd = _file_cmd(C.CERTS_IN_FILE, "/etc/$(touch /tmp/pwned).pem")
    assert "'/etc/$(touch /tmp/pwned).pem'" in cmd and cmd.endswith("</dev/null")
    assert shlex.split(cmd)[-2] == "/etc/$(touch /tmp/pwned).pem"
    cmd = _file_cmd(C.KEYSTORE_LIST, "/opt/a b'c.jks")
    assert shlex.split(cmd)[shlex.split(cmd).index("-keystore") + 1] == "/opt/a b'c.jks"


def test_tier1_commands_have_fixed_path():
    assert C.tier1_line(C.OS_RELEASE).startswith("PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C cat ")


def test_sudo_lines_are_exact_argv():
    line = C.sudo_line(C.TIER2["process_executables"][0])
    assert shlex.split(line) == ["/usr/bin/sudo", "-n", "/usr/bin/find", "/proc", "-maxdepth", "2", "-name", "exe", "-printf",
                                 "%h\\t%l\\n"]
    files = shlex.split(C.sudo_line(C.TIER2["key_and_certificate_files"][0]))
    assert files[-1] == "-print0" and files[-2] == C.KEY_FILE_RE and "\\.pem" in files[-2]


def test_sudoers_escaping():
    text = C.sudoers_file()
    assert "-printf %h\\\\\\\\t%l\\\\\\\\n" in text  # one literal backslash = four in sudoers
    assert "NAME\\,TYPE\\,FSTYPE\\,MOUNTPOINT" in text
    assert "zs-cbom ALL=(root) NOPASSWD: ZS_CBOM_TIER2" in text
    for wildcard in ("*", "?", "["):
        body = text.split("Cmnd_Alias", 1)[1]
        assert wildcard not in body.replace("NOPASSWD", "")


# ----------------------------------------------------------------------------- vault
def test_vault_prefix():
    with pytest.raises(ConfigError):
        check_prefix("secret/zs-cbom/linux", None)
    assert check_prefix("secret/data/zs-cbom/linux", "secret/zs-cbom") == ["secret", "zs-cbom", "linux"]
    assert check_prefix("secret/zs-cbom/linux", "secret/zs-cbom/") == ["secret", "zs-cbom", "linux"]
    for bad in ("secret/other/x", "secret/zs-cbom/../other", "secret//zs-cbom/x", "secret/zs-cbomx/y", "/etc/passwd"):
        with pytest.raises(ConfigError):
            check_prefix(bad, "secret/zs-cbom")


# ----------------------------------------------------------------------------- targets
def test_expand_dedupes_and_respects_never_scan():
    never = NeverScan(["10.0.0.0/30", "skip.example", "10.0.1.5-10.0.1.6"])
    targets, skipped = expand_targets(["10.0.0.1", "10.0.0.0/29", "10.0.0.6", "10.0.1.4-10.0.1.7", "skip.example"], never)
    ips = [t.ip for t in targets]
    assert ips == ["10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.1.4", "10.0.1.7"]
    assert "skip.example" in skipped and "10.0.0.1" in skipped


def test_ipv6_and_mapped():
    assert list(iter_line_ips("2001:db8::1-2001:db8::3")) == ["2001:db8::1", "2001:db8::2", "2001:db8::3"]
    never = NeverScan(["10.1.0.0/16"])
    assert never.blocks_ip("::ffff:10.1.2.3") and not never.blocks_ip("10.2.0.1")
    never.update([])
    assert not never.blocks_ip("10.1.2.3")
    assert never.blocks_ip("not-an-ip")


# ----------------------------------------------------------------------------- job context
def _ctx():
    return JobContext(job_id=1, attempt=1, run_id=2, kind="collect", source_kind="linux_servers",
                      scrubber=Scrubber(["topsecretpw"]), never_scan=NeverScan([]), deadline=time.monotonic() + 60)


def test_emit_scrubs_and_validates():
    ctx = _ctx()
    ctx.emit("certificate", "h", "/etc/x.pem", name="CN=\x1b[31mevil", facts={"note": "pw topsecretpw", "n": 1})
    ctx.flush()
    a = ctx.collected[0]
    assert "\x1b" not in a["name"] and a["facts"]["note"] == "pw " + REDACTED
    with pytest.raises(ValueError):
        ctx.emit("not_a_type", "h", "x")


def test_counts_exclude_endpoint_rows():
    ctx = _ctx()
    ctx.outcome("10.0.0.1", "ok")
    ctx.outcome("10.0.0.1:9001", "timeout", counted=False)
    ctx.outcome("10.0.0.2", "skipped_never_scan")
    ctx.outcome("10.0.0.3", "auth_failed", "login topsecretpw refused")
    r = ctx.result()
    assert r["counts"] == {"total": 3, "ok": 1, "failed": 1, "skipped": 1}
    assert all("topsecretpw" not in json.dumps(t) for t in r["targets"])


def test_fit_keeps_facts_under_budget():
    big = {"ciphers": ["x" * 50] * 2000, "name": "y" * 100}
    out = _fit(big, 16 * 1024)
    assert len(json.dumps(out)) <= 16 * 1024 and out["_truncated"] is True and out["name"] == "y" * 100


def test_embedded_private_key_reports_facts_only():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from zs_scan_node.collectors.kubernetes import embedded_private_keys

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                            serialization.NoEncryption()).decode()
    text = "signing:\n  private_key: |\n" + "".join("    " + line + "\n" for line in pem.splitlines())
    found = embedded_private_keys(text)
    assert found == [{"pem_type": "EC PRIVATE KEY", "encrypted": False, "key_alg": "EC", "key_size": 256,
                      "curve": "secp256r1"}]
    body = pem.splitlines()[1]
    assert body not in json.dumps(found)


def test_keystore_command_has_no_store_password():
    assert "storepass" not in C.KEYSTORE_LIST and C.tier1_line(C.KEYSTORE_LIST).endswith("</dev/null")


def test_oversize_asset_batches_are_split_never_dropped():
    """Security review 2026-10-31: a body over the server's 1 MB cap (HTTP 413) used to lose the whole batch."""
    from zs_scan_node.api import ApiError

    calls = []

    def poster(batch, batch_id):
        calls.append((batch_id, len(batch)))
        if len(batch) > 2:
            raise ApiError(413, "Request body too large")
        return {"accepted": len(batch)}

    ctx = _ctx()
    ctx.poster = poster
    for i in range(5):
        ctx.emit("certificate", "h", f"/etc/{i}.pem", facts={"n": i})
    ctx.flush()
    assert ctx.accepted == 5 and ctx.lost == 0 and not ctx.truncated
    assert ctx.result()["assets_lost"] == 0


def test_a_refused_batch_is_reported_not_silently_lost():
    from zs_scan_node.api import ApiError

    def poster(batch, batch_id):
        raise ApiError(500, "retries exhausted")

    ctx = _ctx()
    ctx.poster = poster
    ctx.emit("certificate", "h", "/etc/a.pem")
    ctx.flush()
    r = ctx.result()
    assert ctx.lost == 1 and r["assets_lost"] == 1 and r["truncated"] is True


def test_batches_are_cut_by_size():
    from zs_scan_node import jobctx as J

    sizes = []
    ctx = _ctx()
    ctx.poster = lambda batch, batch_id: sizes.append(len(json.dumps(batch))) or {"accepted": len(batch)}
    for i in range(120):
        ctx.emit("certificate", "h", f"/etc/{i}.pem", facts={f"k{j}": "x" * 4000 for j in range(3)})  # ~12 KB each
    ctx.flush()
    assert ctx.accepted == 120 and max(sizes) < 1024 * 1024 and len(sizes) >= 2
    assert J.MAX_BATCH_BYTES < 1024 * 1024


def test_passwords_go_only_to_servers_whose_identity_is_checked():
    """Product decision 2026-10-31 (verified identity only): no password to a first-seen SSH key or to WinRM HTTP."""
    from zs_scan_node.collectors import linux_ssh as L
    from zs_scan_node.collectors import windows_winrm as W
    from zs_scan_node.netutil import Target

    with pytest.raises(L.TargetFail) as err:  # raised before any connection is made (192.0.2.1 is unroutable)
        L.open_session(_ctx(), Target("192.0.2.1", "192.0.2.1"), {"host_key_policy": "tofu"}, {"password": "pw"})
    assert err.value.status == "identity_unverified"
    with pytest.raises(W._Fail) as err:
        W.endpoint(Target("win01.bank.local", "10.0.0.5"), {"port": 5985})
    assert err.value.status == "identity_unverified"
    assert W.endpoint(Target("win01.bank.local", "10.0.0.5"), {"port": 5986}) == "https://win01.bank.local:5986/wsman"
    assert W.endpoint(Target("10.0.0.5", "10.0.0.5"), {}) == "https://10.0.0.5:5986/wsman"
    with W._ca_file({"ca_pem": "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"}) as path:
        assert path and open(path).read().startswith("-----BEGIN CERTIFICATE-----")
    assert not __import__("os").path.exists(path)


def test_mysql_impostor_that_drops_tls_or_asks_for_clear_text_gets_no_password():
    """Second review, 2026-10-31: stock PyMySQL continued without TLS when the greeting left it out, and answered
    a switch to mysql_clear_password with the password."""
    import socket as _s
    import struct
    import threading

    from zs_scan_node.collectors import database as D
    from zs_scan_node.netutil import Target

    captured = {}

    def pkt(seq, payload):
        return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload

    srv = _s.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        c, _ = srv.accept()
        caps = 0x1 | 0x200 | 0x8000 | 0x80000 | 0x200000  # no CLIENT_SSL
        salt = b"abcdefghijklmnopqrst"
        greet = (b"\x0a8.0.36\x00" + struct.pack("<I", 7) + salt[:8] + b"\x00" + struct.pack("<H", caps & 0xFFFF)
                 + b"\x21" + struct.pack("<H", 2) + struct.pack("<H", caps >> 16) + bytes([21]) + b"\x00" * 10
                 + salt[8:] + b"\x00" + b"mysql_native_password\x00")
        c.sendall(pkt(0, greet))
        c.settimeout(3)
        try:
            c.recv(4096)
            c.sendall(pkt(2, b"\xfe" + b"mysql_clear_password\x00"))
            captured["data"] = c.recv(4096)
        except OSError:
            pass
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Customer DB CA")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    ca = D._CaFile(cert.public_bytes(serialization.Encoding.PEM).decode())
    try:
        with pytest.raises(D.DbFail) as err:
            D._mysql(_ctx(), Target("db.corp", "127.0.0.1"), {"port": port, "login": "zs_cbom"}, "S3cret-Pa55", ca, tls=True)
    finally:
        ca.close()
    assert err.value.status == "identity_unverified"
    assert b"S3cret-Pa55" not in captured.get("data", b"")


def test_postgres_is_held_to_scram_unless_the_ca_is_actually_checked(monkeypatch):
    import psycopg

    from zs_scan_node.collectors import database as D
    from zs_scan_node.netutil import Target

    seen = {}

    def fake_connect(**kw):
        seen.clear()
        seen.update(kw)
        raise psycopg.OperationalError("stop")

    monkeypatch.setattr(psycopg, "connect", fake_connect)

    class Ca:
        def __init__(self, path):
            self.path = path

    for cfg, ca, want in [({"require_tls": True}, None, ("require", "scram-sha-256", "require")),
                          ({"require_tls": False}, None, ("prefer", "scram-sha-256", None)),
                          ({"require_tls": True}, "/x/ca.pem", ("verify-ca", None, None)),
                          ({"require_tls": False}, "/x/ca.pem", ("prefer", "scram-sha-256", None))]:
        with pytest.raises(D.DbFail):
            D._postgres(None, Target("db", "127.0.0.1"), {**cfg, "login": "u"}, "pw", Ca(ca))
        assert (seen.get("sslmode"), seen.get("require_auth"), seen.get("channel_binding")) == want, (cfg, ca, seen)


def test_winrm_name_must_not_resolve_to_a_never_scan_address(monkeypatch):
    from zs_scan_node.collectors import windows_winrm as W
    from zs_scan_node.netutil import Target

    ctx = _ctx()
    ctx.never_scan = NeverScan(["10.0.0.6/32"])
    monkeypatch.setattr(W, "resolve", lambda name: ["10.0.0.5", "10.0.0.6"])
    with pytest.raises(W._Fail) as err:
        W.check_name(ctx, Target("winhost.corp", "10.0.0.5"))
    assert err.value.status == "skipped_never_scan"
    W.check_name(ctx, Target("10.0.0.5", "10.0.0.5"))  # an IP target is the address that was checked
    ctx.never_scan.update(["10.0.0.6/32", "10.0.0.5/32"])  # added after the job started
    with pytest.raises(W._Fail) as err:
        W.check_name(ctx, Target("10.0.0.5", "10.0.0.5"))
    assert err.value.status == "skipped_never_scan"


def test_one_rate_limiter_per_node():
    """Security review 2026-10-31: each network job had its own limiter, so N jobs ran at N x the agreed rate."""
    from zs_scan_node.netutil import node_limiter

    a = node_limiter(20, 2)
    b = node_limiter(5, 1)  # the newest job carries the team's current settings
    assert a is b and b.rate == 5 and b.per_server == 1


def test_kubernetes_paging_is_bounded_and_stops(monkeypatch):
    """A server that always answers with a 'continue' token, or a stop between pages, cannot keep the job."""
    from zs_scan_node.collectors import kubernetes as K

    api = K.Api.__new__(K.Api)
    api.ctx = _ctx()
    calls = []

    def endless(path, params=None):
        calls.append(params.get("continue"))
        return 200, {"items": [], "metadata": {"continue": f"page{len(calls)}"}}

    api.get = endless
    out = list(api.list_all("/api/v1/configmaps"))
    assert out == [("truncated", None)] and len(calls) == K.MAX_PAGES
    api.ctx.cancel.set()
    with pytest.raises(K._Skip):
        list(api.list_all("/api/v1/configmaps"))

    def too_big(path, params=None):
        raise K._TooLarge("error", "more than 32 MB")

    api.ctx = _ctx()
    api.get = too_big
    assert list(api.list_all("/api/v1/configmaps")) == [("error", "more than 32 MB")]
