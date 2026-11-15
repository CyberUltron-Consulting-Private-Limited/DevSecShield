"""#116 (CB-13 RC-7): the Linux source reads the .pub of every HostKey path in sshd's configuration.

sshd serves the files its HostKey lines name, so a server with non-default paths reported no host keys from the Linux
lane while the network lane read them (CB-05 run L-3df26fd8ec02-20261112T125242Z, lab .40: 0 ssh_host_key, the server
serves 3).  Tier 2 reads them from ``sudo sshd -T`` (Includes already resolved); Tier 1 reads ``/etc/ssh/sshd_config``
and the files its Include lines name.  Hostile values are refused with a coverage note and never run.
"""
import shlex
import time

from zs_scan_node import commands as C
from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

PREFIX = C.T1_ENV + " "
SUFFIX = " </dev/null"


def _keygen(bits, fp, kind):
    return f"{bits} {fp} root@lab ({kind})\n"


class FakeServer:
    """Answers the collector's commands like a server; ``files`` maps an exact path (or a glob as the shell sees it)
    to its contents.  Every command sent is kept in ``lines``."""

    def __init__(self, files=None, keys=None, sshd_t=None, denied=()):
        self.files = files or {}
        self.keys = keys or {}
        self.sshd_t = sshd_t
        self.denied = set(denied)
        self.lines = []
        self.host_key = {"key_type": "ssh-ed25519", "fingerprint": "SHA256:x", "first_use": False}

    def run(self, command, timeout=None, binary=False):
        self.lines.append(command)
        empty = b"" if binary else ""
        if command.startswith(C.SUDO):
            if "sshd" in command and self.sshd_t is not None:
                return 0, self.sshd_t, "", False
            return 1, empty, "sudo: a password is required\n", False
        assert command.startswith(PREFIX) and command.endswith(SUFFIX), command
        inner = command[len(PREFIX):-len(SUFFIX)]
        argv = shlex.split(inner, posix=True) if "*" not in inner else inner.split(" ", 1)
        if argv[:3] == ["ssh-keygen", "-l", "-f"]:
            path = argv[3]
            if path in self.denied:
                return 1, "", f"{path}: Permission denied\n", False
            if path in self.keys:
                return 0, self.keys[path], "", False
            return 1, "", f"{path}: No such file or directory\n", False
        if argv[0] == "cat":
            path = argv[1]
            if path in self.denied:
                return 1, "", f"cat: {path}: Permission denied\n", False
            if path in self.files:
                return 0, self.files[path], "", False
            return 1, "", f"cat: {path}: No such file or directory\n", False
        return 1, "", "", False

    def close(self):
        pass


def _collect(sess, tier=1):
    ctx = JobContext(job_id=1, attempt=1, run_id=2, kind="collect", source_kind="linux_servers",
                     scrubber=Scrubber([]), never_scan=NeverScan([]), deadline=time.monotonic() + 60)
    rows = []
    ctx.emit = lambda asset_type, target, location, name="", algorithm=None, key_size=None, protocol=None, \
        facts=None: rows.append({"type": asset_type, "location": location, "name": name, "algorithm": algorithm,
                                 "key_size": key_size, "facts": facts or {}})
    L.collect_on_session(ctx, sess, "10.0.0.40", {"tier": tier}, time.monotonic() + 60)
    keys = {r["location"]: r for r in rows if r["type"] == "ssh_host_key"}
    notes = [r["facts"] for r in rows if r["type"] == "coverage" and "host key" in r["facts"]["check"]]
    return keys, notes


def test_tier1_reads_hostkey_paths_from_the_file_and_its_includes():
    sess = FakeServer(
        files={"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nHostKey /srv/keys/host_ed25519\n"
                                       "Match User backup\n  PasswordAuthentication no\n",
               "/etc/ssh/sshd_config.d/*.conf": "HostKey=/srv/keys/host_rsa\nHostKey /srv/keys/host_ecdsa\n"},
        keys={"/srv/keys/host_ed25519.pub": _keygen(256, "SHA256:ed", "ED25519"),
              "/srv/keys/host_rsa.pub": _keygen(3072, "SHA256:rsa", "RSA"),
              "/srv/keys/host_ecdsa.pub": _keygen(256, "SHA256:ec", "ECDSA"),
              "/etc/ssh/ssh_host_rsa_key.pub": _keygen(2048, "SHA256:old", "RSA")})
    keys, notes = _collect(sess)
    configured = {loc: r for loc, r in keys.items() if r["facts"].get("configured") is True}
    assert set(configured) == {"/srv/keys/host_ed25519.pub", "/srv/keys/host_rsa.pub", "/srv/keys/host_ecdsa.pub"}
    assert configured["/srv/keys/host_rsa.pub"]["facts"]["fingerprint"] == "SHA256:rsa"
    assert configured["/srv/keys/host_rsa.pub"]["name"] == "RSA host key"  # CB-04 ST-10 form
    assert configured["/srv/keys/host_rsa.pub"]["key_size"] == 3072
    # a default-path key the configuration does not name is listed, but not as one sshd serves
    assert keys["/etc/ssh/ssh_host_rsa_key.pub"]["facts"]["configured"] is False
    assert notes == []


def test_tier2_reads_hostkey_paths_from_sshd_t():
    sess = FakeServer(sshd_t="port 22\nhostkey /opt/ssh/key_a\nhostkey /opt/ssh/key_b\n",
                      keys={"/opt/ssh/key_a.pub": _keygen(256, "SHA256:a", "ED25519"),
                            "/opt/ssh/key_b.pub": _keygen(4096, "SHA256:b", "RSA")})
    keys, _notes = _collect(sess, tier=2)
    assert {k for k, r in keys.items() if r["facts"].get("configured")} == {"/opt/ssh/key_a.pub", "/opt/ssh/key_b.pub"}
    assert not any(line.endswith("cat /etc/ssh/sshd_config" + SUFFIX) for line in sess.lines)


def test_default_paths_named_by_the_configuration_are_one_configured_row():
    sess = FakeServer(sshd_t="hostkey /etc/ssh/ssh_host_ed25519_key\nhostkey /etc/ssh/ssh_host_rsa_key\n",
                      keys={"/etc/ssh/ssh_host_ed25519_key.pub": _keygen(256, "SHA256:e", "ED25519"),
                            "/etc/ssh/ssh_host_rsa_key.pub": _keygen(3072, "SHA256:r", "RSA"),
                            "/etc/ssh/ssh_host_dsa_key.pub": _keygen(1024, "SHA256:d", "DSA")})
    keys, notes = _collect(sess, tier=2)
    assert keys["/etc/ssh/ssh_host_ed25519_key.pub"]["facts"]["configured"] is True
    assert keys["/etc/ssh/ssh_host_rsa_key.pub"]["facts"]["configured"] is True
    assert keys["/etc/ssh/ssh_host_dsa_key.pub"]["facts"]["configured"] is False
    assert len(keys) == 3 and notes == []
    fingerprint_runs = [line for line in sess.lines if "ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub" in line]
    assert len(fingerprint_runs) == 1  # read once, not once per lane


def test_no_hostkey_lines_reads_the_default_paths_as_before():
    sess = FakeServer(files={"/etc/ssh/sshd_config": "Port 22\n"},
                      keys={"/etc/ssh/ssh_host_ed25519_key.pub": _keygen(256, "SHA256:e", "ED25519")})
    keys, notes = _collect(sess)
    assert list(keys) == ["/etc/ssh/ssh_host_ed25519_key.pub"]
    assert "configured" not in keys["/etc/ssh/ssh_host_ed25519_key.pub"]["facts"]
    assert notes == []


def test_hostile_hostkey_values_are_refused_with_a_note_and_never_run():
    lines = ["hostkey relative/key", "hostkey /etc/ssh/evil\x1b[2Jkey"]
    lines += [f"hostkey /k/key{i}" for i in range(12)]
    sess = FakeServer(sshd_t="\n".join(lines) + "\n",
                      keys={f"/k/key{i}.pub": _keygen(256, f"SHA256:{i}", "ED25519") for i in range(12)})
    keys, notes = _collect(sess, tier=2)
    sent = "\n".join(sess.lines)
    assert "relative/key" not in sent and "evil" not in sent
    assert "/k/key10.pub" not in sent and "/k/key11.pub" not in sent  # at most 10 HostKey paths are read
    assert {k for k, r in keys.items() if r["facts"].get("configured")} == {f"/k/key{i}.pub" for i in range(10)}
    details = " | ".join(n["detail"] for n in notes)
    assert {n["status"] for n in notes} == {"refused", "truncated"}
    assert "relative/key" in details and "not an absolute path" in details
    assert "control characters" in details and "\x1b" not in details
    assert "2 more" in details


def test_hostkey_paths_with_spaces_and_shell_characters_are_quoted():
    path = "/srv/odd dir/key;$(id)"
    sess = FakeServer(sshd_t=f"hostkey {path}\n", keys={path + ".pub": _keygen(256, "SHA256:q", "ED25519")})
    keys, _notes = _collect(sess, tier=2)
    assert keys[path + ".pub"]["facts"]["configured"] is True
    assert any(shlex.quote(path + ".pub") in line for line in sess.lines)


def test_include_relative_to_etc_ssh_and_nested_includes_are_followed():
    sess = FakeServer(
        files={"/etc/ssh/sshd_config": "Include extra.conf\n",
               "/etc/ssh/extra.conf": "Include /etc/ssh/deeper.d/*.conf\n",
               "/etc/ssh/deeper.d/*.conf": "HostKey /srv/deep_key\n"},
        keys={"/srv/deep_key.pub": _keygen(256, "SHA256:deep", "ED25519")})
    keys, notes = _collect(sess)
    assert keys["/srv/deep_key.pub"]["facts"]["configured"] is True
    assert notes == []


def test_hostile_include_patterns_are_refused_and_never_run():
    sess = FakeServer(files={"/etc/ssh/sshd_config": "Include /etc/ssh/*;id>/tmp/pwn\n"
                                                     "Include /etc/ssh/$(id)*.conf\n"
                                                     "Include /etc/ssh/a\x07b.conf\n"
                                                     "HostKey /srv/k\n"},
                      keys={"/srv/k.pub": _keygen(256, "SHA256:k", "ED25519")})
    keys, notes = _collect(sess)
    sent = "\n".join(sess.lines)
    assert "pwn" not in sent and "$(id)" not in sent and "\x07" not in sent
    assert keys["/srv/k.pub"]["facts"]["configured"] is True
    assert [n["status"] for n in notes] == ["refused", "refused", "refused"]


def test_an_unreadable_include_or_pub_is_a_coverage_note():
    sess = FakeServer(files={"/etc/ssh/sshd_config": "Include /etc/ssh/private.conf\nHostKey /srv/hidden\n"},
                      denied={"/etc/ssh/private.conf", "/srv/hidden.pub"})
    keys, notes = _collect(sess)
    assert keys == {}
    assert sorted(n["status"] for n in notes) == ["denied", "denied"]
    assert any("/etc/ssh/private.conf" in n["detail"] for n in notes)
    assert any("/srv/hidden.pub" in n["detail"] for n in notes)


def test_an_include_that_matches_nothing_is_silent():
    sess = FakeServer(files={"/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\n"},
                      keys={"/etc/ssh/ssh_host_ed25519_key.pub": _keygen(256, "SHA256:e", "ED25519")})
    keys, notes = _collect(sess)
    assert list(keys) == ["/etc/ssh/ssh_host_ed25519_key.pub"] and notes == []


def test_zs_collect_allows_the_include_lines_the_collector_sends_and_nothing_wider():
    from zs_scan_node import zscollect as Z

    allowed = [C.tier1_line(C.SSHD_INCLUDE.format(file="/etc/ssh/sshd_config.d/*.conf")),
               C.tier1_line(C.SSHD_INCLUDE.format(file=shlex.quote("/etc/ssh/my extra.conf"))),
               C.tier1_line(C.SSH_KEY_FINGERPRINT.format(file=shlex.quote("/srv/odd dir/key;$(id).pub")))]
    for line in allowed:
        assert Z.allowed_line(line), line
    for arg in ("/etc/ssh/*;id", "/etc/ssh/$(id)*.conf", "/etc/ssh/*.conf /etc/shadow", "/etc/ssh/[ab]*.conf",
                "/etc/ssh/`id`*", "relative/*.conf", "/etc/ssh/a b.conf", "/etc/ssh/*\x07.conf", "/etc/shadow",
                shlex.quote("/etc/shadow"), "/etc/ssh/../shadow", shlex.quote("/etc/ssh/../shadow"), "/etc/*.conf",
                shlex.quote("/etc/ssh/a\x07b.conf")):
        assert not Z.allowed_line(C.tier1_line(C.SSHD_INCLUDE.format(file=arg))), arg


def test_an_include_outside_etc_ssh_is_left_to_tier2():
    sess = FakeServer(files={"/etc/ssh/sshd_config": "Include /opt/sshd/extra.conf ../shadow\nHostKey /srv/k\n",
                             "/opt/sshd/extra.conf": "HostKey /srv/never\n"},
                      keys={"/srv/k.pub": _keygen(256, "SHA256:k", "ED25519")})
    keys, notes = _collect(sess)
    sent = "\n".join(sess.lines)
    assert "/opt/sshd" not in sent and "shadow" not in sent
    assert list(keys) == ["/srv/k.pub"]
    assert [n["status"] for n in notes] == ["refused", "refused"]
    assert all("outside /etc/ssh" in n["detail"] for n in notes)
