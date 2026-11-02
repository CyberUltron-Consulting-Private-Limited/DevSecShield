"""IKE probing (WP7): message formats against recorded strongSwan answers, the probe plan against a fake gateway,
key shares, the first-message-only allow-list, budgets, and the collector's network gate / spacing / never-scan."""
from __future__ import annotations

import json
import socket
import struct
import threading
import time
from pathlib import Path

import pytest

from zs_scan_node import ikeprobe as I
from zs_scan_node.collectors import network as N
from zs_scan_node.jobctx import JobContext
from zs_scan_node.netutil import NeverScan
from zs_scan_node.scrub import Scrubber

FIX = json.loads((Path(__file__).parent / "fixtures/ike/strongswan_exchanges.json").read_text())


# ----------------------------------------------------------------------------- recorded strongSwan answers
def test_recorded_ikev2_answers_parse():
    acc = FIX["v2_accepted"]
    ans = I.parse_v2(bytes.fromhex(acc["response"]), bytes.fromhex(acc["request"])[:8])
    assert ans.kind == "accepted" and ans.chosen[I.T_ENCR][0] in I.ENCR and ans.chosen[I.T_KE][0] in I.GROUPS
    pq = FIX["v2_accepted_addke"]  # strongSwan 6.0.7 with ke1_mlkem768
    ans = I.parse_v2(bytes.fromhex(pq["response"]), bytes.fromhex(pq["request"])[:8])
    assert ans.chosen[I.T_ADDKE1][0] == 36 and "INTERMEDIATE_EXCHANGE_SUPPORTED" in ans.notifies
    ike = FIX["v2_invalid_ke"]
    ans = I.parse_v2(bytes.fromhex(ike["response"]), bytes.fromhex(ike["request"])[:8])
    assert ans.kind == "invalid_ke" and ans.group in I.GROUPS
    nop = FIX["v2_no_proposal"]
    assert I.parse_v2(bytes.fromhex(nop["response"]), bytes.fromhex(nop["request"])[:8]).kind == "no_proposal"
    with pytest.raises(ValueError):  # an answer to someone else's SPI is not ours
        I.parse_v2(bytes.fromhex(acc["response"]), b"\x00" * 8)


def test_recorded_ikev1_answers_parse():
    acc = FIX["v1_accepted"]
    ans = I.parse_v1(bytes.fromhex(acc["response"]), bytes.fromhex(acc["request"])[:8])
    assert ans.kind == "accepted" and ans.transform.enc and ans.transform.group and ans.vendor_ids
    nop = FIX["v1_no_proposal"]
    assert I.parse_v1(bytes.fromhex(nop["response"]), bytes.fromhex(nop["request"])[:8]).kind == "no_proposal"


@pytest.mark.parametrize("junk", [b"", b"\x00" * 10, b"A" * 28, b"\xff" * 400])
def test_malformed_answers_raise_value_error(junk):
    spi = b"\x01" * 8
    with pytest.raises(ValueError):
        I.parse_v2(spi + junk, spi)
    with pytest.raises(ValueError):
        I.parse_v1(spi + junk, spi)


def test_truncated_recorded_answer_is_rejected():
    acc = FIX["v2_accepted"]
    raw, spi = bytes.fromhex(acc["response"]), bytes.fromhex(acc["request"])[:8]
    with pytest.raises(ValueError):
        I.parse_v2(raw[:60], spi)


# ----------------------------------------------------------------------------- key shares
def test_key_shares_are_group_elements():
    from cryptography.hazmat.primitives.asymmetric import ec

    for group, curve, size in ((19, ec.SECP256R1(), 32), (20, ec.SECP384R1(), 48), (21, ec.SECP521R1(), 66)):
        ke = I.key_share(group)
        assert len(ke) == 2 * size
        point = b"\x04" + ke  # RFC 5903: x || y; must decode as a point on the curve
        ec.EllipticCurvePublicKey.from_encoded_point(curve, point)
    for group in (22, 23, 24):  # RFC 5114 groups: y^q = 1 mod p (RFC 6989 section 2.2 check)
        p, g, q = I.RFC5114[group]
        y = int.from_bytes(I.key_share(group), "big")
        assert 1 < y < p - 1 and pow(y, q, p) == 1
    for group, n in ((1, 96), (2, 128), (14, 256), (18, 1024)):
        ke = I.key_share(group)
        assert len(ke) == n and 0 < ke[0] < 0x80
    assert len(I.key_share(31)) == 32 and len(I.key_share(32)) == 56


# ----------------------------------------------------------------------------- a fake gateway (test double)
def _parse_request_v2(pkt: bytes):
    """(spi, proposals [{type: [ids]}], ke_group, has_cookie) of one of our IKE_SA_INIT requests."""
    first = pkt[16]
    props, ke_group, cookie = [], None, False
    for ptype, body in I._payloads(pkt, first, 28):
        if ptype == I.V2_SA:
            pos = 0
            while pos < len(body):
                last, _r, plen, _num, _proto, spi_size, ntrans = struct.unpack("!BBHBBBB", body[pos:pos + 8])
                tpos, types = pos + 8 + spi_size, {}
                for _ in range(ntrans):
                    _l, _r2, tlen, ttype, _r3, tid = struct.unpack("!BBHBBH", body[tpos:tpos + 8])
                    types.setdefault(ttype, []).append(tid)
                    tpos += tlen
                props.append(types)
                pos += plen
                if last == 0:
                    break
        elif ptype == I.V2_KE:
            ke_group = struct.unpack("!H", body[:2])[0]
        elif ptype == I.V2_NOTIFY and struct.unpack("!H", body[2:4])[0] == I.N_COOKIE:
            cookie = True
    return pkt[:8], props, ke_group, cookie


class FakeGateway:
    """Accepts proposals whose transforms are all in ``allowed`` (per type); answers INVALID_KE when the KE group
    differs from the chosen group; stops answering after ``block`` accepted (half-open) exchanges, like strongSwan's
    per-IP half-open limit, until ``release()``.  IKEv1 is not spoken (no answer)."""

    def __init__(self, allowed: dict[int, set[int]], block: int = 99, cookie: bool = False):
        self.allowed, self.block, self.cookie = allowed, block, cookie
        self.half_open = 0
        self.packets: list[bytes] = []
        self.accepted = 0

    def release(self):
        self.half_open = 0

    def notify(self, spi: bytes, ntype: int, data: bytes = b"") -> bytes:
        body = struct.pack("!BBH", 0, 0, ntype) + data
        payload = struct.pack("!BBH", 0, 0, 4 + len(body)) + body
        return spi + b"\x00" * 8 + struct.pack("!BBBBII", I.V2_NOTIFY, 0x20, 34, 0x20, 0, 28 + len(payload)) + payload

    def __call__(self, pkt: bytes, ident: bytes):
        self.packets.append(pkt)
        if pkt[17] >> 4 != 2:
            return None
        spi, props, ke_group, has_cookie = _parse_request_v2(pkt)
        if self.cookie and not has_cookie:
            return self.notify(spi, I.N_COOKIE, b"C" * 16)
        if self.half_open >= self.block:
            return None
        for n, prop in enumerate(props, 1):
            chosen = {}
            for ttype, ids in prop.items():
                if ttype == I.T_INTEG and not ids:
                    continue
                pick = next((i for i in ids if i in self.allowed.get(ttype, set())), None)
                if pick is None:
                    break
                chosen[ttype] = pick
            else:
                if I.T_KE in chosen and chosen[I.T_KE] != ke_group:
                    return self.notify(spi, I.N_INVALID_KE_PAYLOAD, struct.pack("!H", chosen[I.T_KE]))
                self.half_open += 1
                self.accepted += 1
                trans = b"".join(struct.pack("!BBHBBH", 3, 0, 8, t, 0, i) for t, i in chosen.items())
                inner = struct.pack("!BBBB", n, 1, 0, len(chosen)) + trans
                sa = struct.pack("!BBH", 0, 0, 4 + len(inner)) + inner
                payload = struct.pack("!BBH", 0, 0, 4 + len(sa)) + sa
                return spi + b"\x11" * 8 + struct.pack("!BBBBII", I.V2_SA, 0x20, 34, 0x20, 0, 28 + len(payload)) + payload
        return self.notify(spi, I.N_NO_PROPOSAL_CHOSEN)


LEGACY = {I.T_ENCR: {12, 3, 2}, I.T_PRF: {5, 2}, I.T_INTEG: {12, 2, 1}, I.T_KE: {14, 2, 5}}
MODERN = {I.T_ENCR: {20}, I.T_PRF: {6}, I.T_KE: {19, 31}, I.T_ADDKE1: {36}}


def test_plan_finds_weak_classes_without_holding_half_open_sas():
    gw = FakeGateway(LEGACY, block=3)  # a gateway that goes silent after 3 half-open SAs
    facts = I.IkeProber(gw, 40, "full").run()
    v2 = facts["ikev2"]
    assert v2["supported"] and v2["chosen"]["encryption"]
    assert set(v2["weak"]["dh"]["accepted"]) == {"MODP-1024", "MODP-1536"}
    assert {"DES", "3DES"} <= set(v2["weak"]["encryption"]["accepted"])
    assert {"HMAC-SHA1-96", "HMAC-MD5-96"} <= set(v2["weak"]["integrity"]["accepted"])
    assert v2["weak"]["prf"]["accepted"] == ["HMAC-SHA1"]
    assert v2["pq"] == {"supported": False, "method": None}
    # only the baseline and the post-quantum probe were accepted (and may hold state); class probes were refusals
    assert gw.accepted <= 2 and facts["packets_used"] <= 40


def test_plan_detects_ml_kem_hybrid():
    gw = FakeGateway(MODERN)
    facts = I.IkeProber(gw, 40, "full").run()
    assert facts["ikev2"]["pq"] == {"supported": True, "method": "ML-KEM-768"}
    assert all(not s["accepted"] for s in facts["ikev2"]["weak"].values())


def test_cookie_is_returned_once_per_probe():
    gw = FakeGateway(MODERN, cookie=True)
    facts = I.IkeProber(gw, 40, "full").run()
    assert facts["cookie_required"] and facts["ikev2"]["supported"]
    retried = [p for p in gw.packets if _parse_request_v2(p)[3]]
    assert retried and all(_parse_request_v2(p)[0] == _parse_request_v2(gw.packets[i - 1])[0]
                           for i, p in enumerate(gw.packets) if _parse_request_v2(p)[3])  # same SPI on the retry


def test_half_open_limit_triggers_one_pause_then_continues():
    gw = FakeGateway(LEGACY, block=1)
    paused = []

    def pause(seconds):
        paused.append(seconds)
        gw.release()
        return True

    facts = I.IkeProber(gw, 40, "full", pause=pause).run()
    assert paused == [I.HALF_OPEN_WAIT] and facts["half_open_wait"] is True
    assert facts["ikev2"]["pq"]["supported"] is False  # answered after the pause


def test_fragile_mode_sends_at_most_six_packets_and_only_strong_plus_weakest():
    gw = FakeGateway(LEGACY)
    facts = I.IkeProber(gw, N.IKE_FRAGILE_BUDGET, "fragile").run()
    assert len(gw.packets) <= 6 and facts["packet_budget"] == 6
    first = _parse_request_v2(gw.packets[0])[1]
    assert all(set(p.get(I.T_ENCR, [])) <= {12, 20, 28} for p in first)  # the strong proposal only
    assert facts["ikev2"]["weak"]["suite"] is True
    assert facts["ikev2"]["weak"]["dh"]["accepted"]


def test_budget_is_a_hard_limit():
    gw = FakeGateway(LEGACY)
    facts = I.IkeProber(gw, 5, "full").run()
    assert len(gw.packets) == 5 and "packet budget used up" in facts["unknown"]


def test_silent_endpoint_costs_two_packets():
    sent = []
    facts = I.IkeProber(lambda p, i: sent.append(p), 40, "full").run()
    assert len(sent) == 2 and not I.answered(facts)  # one IKEv2, one IKEv1 message


def test_hostile_answers_do_not_end_the_plan():
    def hostile(pkt, ident):
        return ident + b"\xff" * 300  # our SPI, then garbage

    facts = I.IkeProber(hostile, 12, "full").run()
    assert facts["packets_used"] <= 12


# ----------------------------------------------------------------------------- allow-list: first messages only
ALLOWED_V2_PAYLOADS = {I.V2_SA, I.V2_KE, I.V2_NONCE, I.V2_NOTIFY}
ALLOWED_V2_NOTIFIES = {I.N_COOKIE, I.N_INTERMEDIATE_EXCHANGE_SUPPORTED}
ALLOWED_V1_PAYLOADS = {I.V1_SA, I.V1_KE, I.V1_NONCE, I.V1_ID}


def _assert_first_message_only(pkt: bytes) -> None:
    assert pkt[8:16] == b"\x00" * 8  # responder SPI / cookie zero: never a later message of an exchange
    _first, version, exch, flags, msgid, length = struct.unpack("!BBBBII", pkt[16:28])
    assert msgid == 0 and length == len(pkt)
    if version >> 4 == 2:
        assert exch == I.V2_IKE_SA_INIT and flags == I.V2_FLAG_I  # never IKE_AUTH (35), never a response
        for ptype, body in I._payloads(pkt, pkt[16], 28):
            assert ptype in ALLOWED_V2_PAYLOADS
            if ptype == I.V2_NOTIFY:
                assert struct.unpack("!H", body[2:4])[0] in ALLOWED_V2_NOTIFIES
    else:
        assert version == 0x10 and exch in (I.V1_MAIN, I.V1_AGGRESSIVE) and flags == 0  # never encrypted, never MM3
        for ptype, _body in I._payloads(pkt, pkt[16], 28):
            assert ptype in ALLOWED_V1_PAYLOADS  # no HASH, SIG, CERT: nothing that authenticates


def test_every_packet_is_the_first_message_of_an_exchange():
    packets = []

    class V1Too(FakeGateway):
        def __call__(self, pkt, ident):
            packets.append(pkt)
            if pkt[17] >> 4 == 1:  # answer IKEv1 with an accepted transform so Aggressive Mode is tried too
                prop = I._v1_transform(1, I.V1Transform(5, None, 2, 1, 2), True)
                body = struct.pack("!BBBB", 1, 1, 0, 1) + prop
                propp = struct.pack("!BBH", 0, 0, 4 + len(body)) + body
                sa = struct.pack("!II", 1, 1) + propp
                payload = struct.pack("!BBH", 0, 0, 4 + len(sa)) + sa
                return ident + b"\x22" * 8 + struct.pack("!BBBBII", I.V1_SA, 0x10, pkt[18], 0, 0, 28 + len(payload)) + payload
            return super().__call__(pkt, ident)

    I.IkeProber(V1Too(LEGACY, cookie=True), 40, "full").run()
    assert any(p[18] == I.V1_AGGRESSIVE for p in packets) and any(p[18] == I.V2_IKE_SA_INIT for p in packets)
    for pkt in packets:
        _assert_first_message_only(pkt)


# ----------------------------------------------------------------------------- the collector: gate, spacing, stop
def _ctx(never=None, scope_rate=50):
    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="network_range",
                      scrubber=Scrubber(), never_scan=NeverScan(never or []), deadline=time.monotonic() + 120)


class UdpGateway:
    """A local UDP responder: answers IKEv2 with NO_PROPOSAL_CHOSEN, records arrival times."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.times: list[float] = []
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65535)
            except OSError:
                return
            self.times.append(time.monotonic())
            if data[17] >> 4 == 2:
                self.sock.sendto(FakeGateway({}).notify(data[:8], I.N_NO_PROPOSAL_CHOSEN), addr)


def test_collector_spacing_rate_limiter_and_outcome():
    gw = UdpGateway()
    ctx = _ctx()
    scan = N.NetworkScan(ctx, {"rate_limits": {"connections_per_second": 50, "handshakes_per_endpoint": 12}})
    before = scan.limiter.connections
    status, _err, n = scan.scan_ike(N.Endpoint("127.0.0.1", gw.port, "ike", "IKE"), "full", primary=True)
    ctx.flush()
    assert status == "ok" and n == 1
    gaps = [b - a for a, b in zip(gw.times, gw.times[1:])]
    assert gaps and min(gaps) >= N.IKE_SPACING - 0.01
    assert scan.limiter.connections - before == len(gw.times)  # every packet took a rate-limit token
    row = next(a for a in ctx.collected if a["type"] == "ike_endpoint")
    assert row["facts"]["ikev2"]["proposals_accepted"] is False
    gw.sock.close()


def test_collector_never_scan_and_stop_send_nothing(monkeypatch):
    gw = UdpGateway()
    ctx = _ctx(never=["127.0.0.1/32"])
    scan = N.NetworkScan(ctx, {})
    assert scan.scan_ike(N.Endpoint("127.0.0.1", gw.port, "ike", ""), "full", True)[0] == "skipped_never_scan"
    ctx2 = _ctx()
    ctx2.stop_network.set()  # stop-all from the heartbeat
    scan2 = N.NetworkScan(ctx2, {})
    with pytest.raises(N._Skip) as skip:
        scan2.scan_ike(N.Endpoint("127.0.0.1", gw.port, "ike", ""), "full", True)
    assert skip.value.status == "skipped_stop"
    time.sleep(0.3)
    assert gw.times == []
    gw.sock.close()


def test_never_scan_change_mid_probe_stops_the_next_packet():
    gw = UdpGateway()
    ctx = _ctx()
    scan = N.NetworkScan(ctx, {})
    real_send = socket.socket.send

    def send_then_block(self, data):
        ctx.never_scan.update(["127.0.0.1/32"])  # the SOC adds the address while the probe runs
        return real_send(self, data)

    monkeypatch_send = pytest.MonkeyPatch()
    monkeypatch_send.setattr(socket.socket, "send", send_then_block)
    try:
        with pytest.raises(N._Skip) as skip:
            scan.scan_ike(N.Endpoint("127.0.0.1", gw.port, "ike", ""), "full", True)
    finally:
        monkeypatch_send.undo()
    assert skip.value.status == "skipped_never_scan" and len(gw.times) == 1
    gw.sock.close()


def test_ike_ports_run_in_network_scan_and_silence_ends_ike_on_the_address(monkeypatch):
    calls = []

    def fake_scan_ike(self, ep, mode, primary):
        calls.append((ep.port, mode, primary))
        return "no_answer", "no IKE answer", 0

    monkeypatch.setattr(N.NetworkScan, "scan_ike", fake_scan_ike)
    monkeypatch.setattr(N.NetworkScan, "tcp_open", lambda self, ip, port: "closed")
    ctx = _ctx()
    scope = {"ranges": [{"cidr": "192.0.2.10/32", "mode": "fragile"}],
             "ports": [{"port": 500, "protocol": "ike"}, {"port": 4500, "protocol": "ike"}]}
    N.run_network(ctx, scope)
    assert calls == [(500, "fragile", True)]  # 4500 skipped after 500 stayed silent
    assert not any(a["type"] == "coverage" and a["facts"]["check"] == "ike" for a in ctx.collected)
