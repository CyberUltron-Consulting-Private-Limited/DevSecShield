"""#126 (review of #161, integrations proven live): two SIEM follow-ups.

* UDP syslog sent a dispatcher batch (up to 200 datagrams) back to back, and a receiver with the default socket
  buffer and a thread per datagram lost some (206 of 243). The datagrams are now paced (``outbound.UDP_GAP_S``
  between two datagrams), still one datagram per message (RFC 5426) and still "sent (unconfirmed)".
* Splunk HEC tokens with indexer acknowledgement need ``X-Splunk-Request-Channel`` (else HTTP 400, code 10 "Data
  channel is missing", and the batch was dead-lettered). The HEC config takes an optional channel GUID, sent on
  every request when set; code 10 says what to do."""
from __future__ import annotations

import socket
import threading
import time
import uuid

import pytest
from pydantic import ValidationError

from backend.utilities.integrations import outbound, siem
from backend.utilities.integrations.base import Context
from backend.utilities.integrations.registry import validate_config
from test_integrations_connectors import EVENT, FakeHttp


# ----------------------------------------------------------------------------- UDP pacing
def test_udp_datagrams_are_paced_one_gap_between_two(monkeypatch):
    monkeypatch.setattr(outbound, "resolve", lambda host, port, kind=None: ["127.0.0.1"])
    sleeps: list[float] = []
    monkeypatch.setattr(outbound.time, "sleep", lambda s: sleeps.append(s))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx:
        rx.bind(("127.0.0.1", 0))
        assert outbound.send_datagrams("siem.example", rx.getsockname()[1], [b"a", b"b", b"c"]) == 3
    assert sleeps == [outbound.UDP_GAP_S] * 2  # between datagrams, none before the first or after the last
    assert 0 < outbound.UDP_GAP_S <= 0.01  # a 200-datagram batch stays under 2 s


def test_a_single_datagram_is_not_delayed(monkeypatch):
    monkeypatch.setattr(outbound, "resolve", lambda host, port, kind=None: ["127.0.0.1"])
    sleeps: list[float] = []
    monkeypatch.setattr(outbound.time, "sleep", lambda s: sleeps.append(s))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx:
        rx.bind(("127.0.0.1", 0))
        outbound.send_datagrams("siem.example", rx.getsockname()[1], [b"only"])
    assert sleeps == []


def test_a_paced_batch_reaches_a_small_buffer_receiver_whole(monkeypatch):
    """A receiver with a small socket buffer that reads as datagrams come: a paced batch of 200 x 1 KB arrives whole."""
    monkeypatch.setattr(outbound, "resolve", lambda host, port, kind=None: ["127.0.0.1"])
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(5)
    got: list[bytes] = []

    def read():
        try:
            while len(got) < 200:
                got.append(rx.recv(4096))
        except OSError:
            pass

    t = threading.Thread(target=read, daemon=True)
    t.start()
    grams = [(f"{i:04d}".encode() * 256) for i in range(200)]
    started = time.monotonic()
    outbound.send_datagrams("siem.example", rx.getsockname()[1], grams)
    t.join(10)
    rx.close()
    assert len(got) == 200 and sorted(got) == sorted(grams)
    assert time.monotonic() - started >= 199 * outbound.UDP_GAP_S * 0.9


def test_syslog_over_udp_still_reports_unconfirmed(monkeypatch):
    sent: list[bytes] = []
    monkeypatch.setattr(siem.outbound, "send_datagrams", lambda host, port, grams: sent.extend(grams) or len(grams))
    cfg = validate_config("syslog", {"host": "siem.example", "transport": "udp"})
    out = siem.syslog_send(Context(1, cfg, {}), [EVENT, EVENT])
    assert [o.status for o in out] == ["ok", "ok"] and all(o.confirmed is False for o in out) and len(sent) == 2


# ----------------------------------------------------------------------------- Splunk HEC channel
CHANNEL = "0aeeac95-ac74-4aa9-b30d-6c4c0ac581ba"


def test_the_hec_channel_is_sent_on_every_request_when_set(monkeypatch):
    fake = FakeHttp(lambda c: (200, b'{"text":"Success","code":0,"ackId":7}'))
    monkeypatch.setattr(siem.outbound, "request", fake)
    cfg = validate_config("splunk_hec", {"url": "https://splunk.corp.local:8088", "channel": CHANNEL.upper()})
    assert cfg.channel == CHANNEL  # stored lower case, the canonical GUID form
    out = siem.hec_send(Context(1, cfg, {"token": "t"}), [EVENT] * 150)
    assert [o.status for o in out] == ["ok"] * 150 and len(fake.calls) == 2
    assert all(c["headers"]["X-Splunk-Request-Channel"] == CHANNEL for c in fake.calls)


def test_no_channel_no_header(monkeypatch):
    fake = FakeHttp(lambda c: (200, b'{"text":"Success","code":0}'))
    monkeypatch.setattr(siem.outbound, "request", fake)
    cfg = validate_config("splunk_hec", {"url": "https://splunk.corp.local:8088"})
    siem.hec_send(Context(1, cfg, {"token": "t"}), [EVENT])
    assert "X-Splunk-Request-Channel" not in fake.calls[0]["headers"]
    assert validate_config("splunk_hec", {"url": "https://splunk.corp.local:8088", "channel": ""}).channel is None


@pytest.mark.parametrize("bad", ["not-a-guid", "0aeeac95ac744aa9b30d6c4c0ac581ba\n", "{" + CHANNEL + "}", "x" * 300,
                                 CHANNEL + "\r\nX-Evil: 1"])
def test_a_channel_must_be_a_guid(bad):
    with pytest.raises(ValidationError):
        validate_config("splunk_hec", {"url": "https://splunk.corp.local:8088", "channel": bad})


def test_data_channel_missing_says_what_to_set(monkeypatch):
    monkeypatch.setattr(siem.outbound, "request",
                        FakeHttp(lambda c: (400, b'{"text":"Data channel is missing","code":10}')))
    cfg = validate_config("splunk_hec", {"url": "https://splunk.corp.local:8088"})
    out = siem.hec_send(Context(1, cfg, {"token": "t"}), [EVENT])
    assert "HEC code 10" in out[0].reason and "channel" in out[0].reason.lower(), out[0].reason


def test_a_generated_channel_is_accepted():
    value = str(uuid.uuid4())
    assert validate_config("splunk_hec", {"url": "https://splunk.corp.local:8088", "channel": value}).channel == value
