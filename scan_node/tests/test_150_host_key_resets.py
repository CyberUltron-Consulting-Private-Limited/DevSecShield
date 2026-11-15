"""#150: an admin can accept a legitimately changed host key, or forget the remembered one, under trust on first use.

Trust on first use pins per scan node (``known_hosts.json``, keyed by address:port).  After a rebuild every source on
that node failed with ``host_key_changed`` and nothing in the product could clear the pin.  ZeroShield now sends the
admin's decision with the source's next job (``config.host_key_resets``); the node applies it when it connects to that
target and reports the ids it applied in the job result.

* accept: only the exact fingerprint the admin reviewed replaces the pin.  Any other key still fails.
* forget: the pins for that address:port are removed, and the next connection pins on first use again.
"""
import time

import pytest

from zs_scan_node.collectors import linux_ssh as L
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan, Target
from zs_scan_node.scrub import Scrubber

class FakeKey:
    def __init__(self, blob: bytes, name: str = "ssh-ed25519"):
        self.blob, self.name = blob, name

    def get_name(self):
        return self.name

    def get_bits(self):
        return 256

    def asbytes(self):
        return self.blob


class FakeTransport:
    """A handshake that presents ``key``; authentication always succeeds."""

    _key_info = {"ssh-ed25519": object, "ssh-rsa": object, "rsa-sha2-256": object, "rsa-sha2-512": object}

    def __init__(self, key):
        self.key, self.closed, self.offered = key, False, None
        self._opts = type("O", (), {"key_types": ()})()

    def get_security_options(self):
        return self._opts

    def start_client(self, timeout=None):
        self.offered = tuple(self._opts.key_types)

    def get_remote_server_key(self):
        return self.key

    def auth_publickey(self, user, key):
        return []

    def is_authenticated(self):
        return True

    def close(self):
        self.closed = True


def _ctx(tmp_path, kind="test_connection"):
    return JobContext(job_id=7, attempt=1, run_id=None, kind=kind, source_kind="linux_servers",
                      scrubber=Scrubber([]), never_scan=NeverScan([]), deadline=time.monotonic() + 60,
                      state_dir=str(tmp_path))


def _login(ctx, key, config, label="web1.lab", ip="10.232.0.102"):
    transport = FakeTransport(key)
    config = {"host_key_policy": "tofu", "port": 22, **config}
    sess = L._login(ctx, Target(label, ip), config, {"key": object()}, transport, 22, "zs-cbom", "tofu", f"{ip}:22")
    return sess, transport


OLD_KEY, NEW_KEY, EVIL_KEY = FakeKey(b"old"), FakeKey(b"new"), FakeKey(b"evil")


def _pin_old(ctx):
    L.save_pin(ctx.state_dir, "10.232.0.102:22", "ssh-ed25519", L._fp(OLD_KEY))


def test_a_changed_key_still_fails_without_a_decision(tmp_path):
    ctx = _ctx(tmp_path)
    _pin_old(ctx)
    with pytest.raises(L.TargetFail) as exc:
        _login(ctx, NEW_KEY, {})
    assert exc.value.status == "host_key_changed"
    assert L._fp(NEW_KEY) in exc.value.error and L._fp(OLD_KEY) in exc.value.error
    assert ctx.result().get("host_key_resets_applied", []) == []


def test_accept_replaces_the_pin_with_the_reviewed_key_only(tmp_path):
    ctx = _ctx(tmp_path)
    _pin_old(ctx)
    resets = [{"id": 31, "target": "web1.lab", "port": 22, "action": "accept", "fingerprint": L._fp(NEW_KEY)}]
    sess, _t = _login(ctx, NEW_KEY, {"host_key_resets": resets})
    assert sess.host_key["fingerprint"] == L._fp(NEW_KEY) and sess.host_key.get("accepted") is True
    assert L.load_pins(ctx.state_dir)["10.232.0.102:22"] == {"ssh-ed25519": L._fp(NEW_KEY)}
    assert ctx.result()["host_key_resets_applied"] == [31]
    # the next job (no decision) connects with the new pin
    ctx2 = _ctx(tmp_path)
    sess2, _t = _login(ctx2, NEW_KEY, {})
    assert not sess2.host_key.get("first_use")


def test_accept_does_not_trust_a_different_key(tmp_path):
    ctx = _ctx(tmp_path)
    _pin_old(ctx)
    resets = [{"id": 31, "target": "web1.lab", "port": 22, "action": "accept", "fingerprint": L._fp(NEW_KEY)}]
    with pytest.raises(L.TargetFail) as exc:
        _login(ctx, EVIL_KEY, {"host_key_resets": resets})
    assert exc.value.status == "host_key_changed"
    assert L.load_pins(ctx.state_dir)["10.232.0.102:22"] == {"ssh-ed25519": L._fp(OLD_KEY)}
    assert ctx.result().get("host_key_resets_applied", []) == []  # stays pending at ZeroShield


def test_accept_for_another_target_or_port_is_not_applied(tmp_path):
    ctx = _ctx(tmp_path)
    _pin_old(ctx)
    resets = [{"id": 1, "target": "web2.lab", "port": 22, "action": "accept", "fingerprint": L._fp(NEW_KEY)},
              {"id": 2, "target": "web1.lab", "port": 2222, "action": "accept", "fingerprint": L._fp(NEW_KEY)},
              {"id": 3, "target": "web1.lab", "port": 22, "action": "forget-everything"}]
    with pytest.raises(L.TargetFail):
        _login(ctx, NEW_KEY, {"host_key_resets": resets})
    assert ctx.result().get("host_key_resets_applied", []) == []


def test_forget_removes_the_pins_and_the_next_connection_pins_on_first_use(tmp_path):
    ctx = _ctx(tmp_path)
    _pin_old(ctx)
    L.save_pin(ctx.state_dir, "10.232.0.102:22", "ssh-rsa", "SHA256:rsa-old")
    L.save_pin(ctx.state_dir, "10.232.0.103:22", "ssh-ed25519", "SHA256:other-host")
    resets = [{"id": 40, "target": "web1.lab", "port": 22, "action": "forget"}]
    sess, transport = _login(ctx, NEW_KEY, {"host_key_resets": resets})
    assert transport.offered == ()  # no pinned type is forced any more: the server's own choice is pinned
    assert sess.host_key.get("first_use") is True
    pins = L.load_pins(ctx.state_dir)
    assert pins["10.232.0.102:22"] == {"ssh-ed25519": L._fp(NEW_KEY)}
    assert pins["10.232.0.103:22"] == {"ssh-ed25519": "SHA256:other-host"}  # other hosts keep their pins
    assert ctx.result()["host_key_resets_applied"] == [40]


def test_resets_are_ignored_for_pinned_known_hosts(tmp_path):
    ctx = _ctx(tmp_path)
    known = f"10.232.0.102 ssh-ed25519 {'A' * 68}\n"
    resets = [{"id": 5, "target": "web1.lab", "port": 22, "action": "forget"}]
    transport = FakeTransport(NEW_KEY)
    with pytest.raises(L.TargetFail):
        L._login(ctx, Target("web1.lab", "10.232.0.102"), {"host_key_policy": "pinned", "known_hosts": known,
                                                           "host_key_resets": resets},
                 {"key": object()}, transport, 22, "zs-cbom", "pinned", "10.232.0.102:22")
    assert ctx.result().get("host_key_resets_applied", []) == []


def test_the_connection_test_note_says_the_new_key_was_accepted(tmp_path, monkeypatch):
    ctx = _ctx(tmp_path)
    _pin_old(ctx)
    resets = [{"id": 31, "target": "10.232.0.102", "port": 22, "action": "accept", "fingerprint": L._fp(NEW_KEY)}]

    def fake_open(ctx_, target, config, creds):
        return _login(ctx_, NEW_KEY, config, label=target.label, ip=target.ip)[0]

    monkeypatch.setattr(L, "open_session", fake_open)
    monkeypatch.setattr(L, "_credentials", lambda c, config, secrets: {"key": object()})
    monkeypatch.setattr(L.Session, "close", lambda self: None)
    L.test(ctx, {"tier": 1, "host_key_resets": resets}, {}, {"targets": ["10.232.0.102"]})
    sample = ctx.samples[0]
    assert sample["status"] == "ready" and "accepted by a ZeroShield admin" in sample["note"]
    assert ctx.result()["host_key_resets_applied"] == [31]
