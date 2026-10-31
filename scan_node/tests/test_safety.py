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
    assert shlex.split(line) == ["sudo", "-n", "/usr/bin/find", "/proc", "-maxdepth", "2", "-name", "exe", "-printf",
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
