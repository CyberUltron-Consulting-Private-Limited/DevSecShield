"""Inline nginx, Apache, and OpenSSH posture facts, plus DH prime sizes."""

from __future__ import annotations

from aibom.cbom.posture.dhparam import _prime_bits, prime_bits
from aibom.cbom.posture.extract_common import listener_reader
from aibom.cbom.posture.extract_servers import extract_servers
from aibom.cbom.posture.model import BasisEntry, EncryptionFact


def _basis(fact: EncryptionFact) -> dict[str, str | None]:
    return {item.name: item.value for item in fact.basis}


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(body),)) + body


def _der_integer(value: int) -> bytes:
    width = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(width, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_len(len(raw)) + raw


def _pkcs3(bits: int) -> bytes:
    """SEQUENCE of two INTEGERs: a prime of ``bits`` and base 2."""
    prime = (1 << (bits - 1)) | 1
    body = _der_integer(prime) + _der_integer(2)
    return b"\x30" + _der_len(len(body)) + body


def test_nginx_listen_without_tls_is_not_encrypted(monkeypatch) -> None:
    seen: list[tuple[bool, bool]] = []
    real = listener_reader

    def spy(*, plaintext: bool, redirect: bool):
        seen.append((plaintext, redirect))
        return real(plaintext=plaintext, redirect=redirect)

    monkeypatch.setattr(
        "aibom.cbom.posture.extract_servers.listener_reader", spy
    )
    text = "server {\n  listen 80;\n}\n"
    fact = extract_servers(text, "nginx.conf")[0]
    assert isinstance(fact, EncryptionFact)
    assert fact.layers["transport"] == "NOT_ENCRYPTED"
    assert fact.verdict == "NOT_ENCRYPTED"
    assert fact.finding_codes == ("PLAINTEXT_LISTENER",)
    assert seen == [(True, False)]


def test_nginx_redirect_is_encrypted_declared(monkeypatch) -> None:
    seen: list[tuple[bool, bool]] = []
    real = listener_reader

    def spy(*, plaintext: bool, redirect: bool):
        seen.append((plaintext, redirect))
        return real(plaintext=plaintext, redirect=redirect)

    monkeypatch.setattr(
        "aibom.cbom.posture.extract_servers.listener_reader", spy
    )
    text = "server {\n  listen 80;\n  return 301 https://example.com$request_uri;\n}\n"
    fact = extract_servers(text, "nginx.conf")[0]
    direct = listener_reader(plaintext=True, redirect=True)
    assert fact.verdict == "ENCRYPTED_DECLARED"
    assert fact.verdict == direct.verdict
    assert fact.layers["transport"] == "ENCRYPTED_DECLARED"
    assert fact.verdict != "NOT_ENCRYPTED"
    assert fact.finding_codes == ()
    assert seen == [(True, True)]
    assert _basis(fact)["redirect"] == "https"


def test_openssh_password_yes_is_disabling_and_first_wins() -> None:
    text = "PasswordAuthentication yes\nPasswordAuthentication no\n"
    fact = extract_servers(text, "sshd_config")[0]
    assert fact.kind == "ssh_service"
    assert fact.verdict == "ENCRYPTED_DECLARED"
    assert _basis(fact)["PasswordAuthentication"] == "yes"
    assert _basis(fact)["signal"] == "disabling"
    assert _basis(fact)["duplicate_key"] == "first"
    later = "PasswordAuthentication no\nPasswordAuthentication yes\n"
    kept = extract_servers(later, "sshd_config")[0]
    assert _basis(kept)["PasswordAuthentication"] == "no"
    assert "signal" not in _basis(kept)
    noisy = extract_servers("PasswordAuthentication yes\n" * 40, "sshd_config")
    assert len(noisy) == 1
    assert _basis(noisy[0])["signal"] == "disabling"
    assert _basis(noisy[0])["PasswordAuthentication"] == "yes"


def test_stream_and_tcp_passthrough_stay_unknown(monkeypatch) -> None:
    def boom(*, plaintext: bool, redirect: bool):
        raise AssertionError((plaintext, redirect))

    monkeypatch.setattr(
        "aibom.cbom.posture.extract_servers.listener_reader", boom
    )
    empty = extract_servers("stream {\n}\n", "nginx.conf")
    assert len(empty) == 1
    assert empty[0].verdict == "UNKNOWN"
    assert empty[0].layers["transport"] == "UNKNOWN"
    assert empty[0].unknown_reason == "layer_not_observable"
    assert _basis(empty[0])["context"] == "stream"
    passed = (
        "stream {\n"
        "  server {\n"
        "    listen 443;\n"
        "    ssl_preread on;\n"
        "    proxy_pass 192.0.2.10:443;\n"
        "  }\n"
        "}\n"
    )
    fact = extract_servers(passed, "nginx.conf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.layers["transport"] == "UNKNOWN"
    assert fact.unknown_reason == "layer_not_observable"
    assert fact.finding_codes == ()
    assert _basis(fact)["passthrough"] == "tcp"
    assert _basis(fact)["listen"] == "443"


def test_detail_stays_on_basis_entries() -> None:
    fact = extract_servers("server {\n  listen 80;\n}\n", "nginx.conf")[0]
    assert type(fact) is EncryptionFact
    assert fact.basis
    assert all(type(item) is BasisEntry for item in fact.basis)
    assert _basis(fact)["listen"] == "80"
    assert not hasattr(fact, "listen")
    ssh = extract_servers("PasswordAuthentication yes\n", "sshd_config")[0]
    assert type(ssh) is EncryptionFact
    assert not hasattr(ssh, "signal")
    assert all(type(item) is BasisEntry for item in ssh.basis)


def test_apache_redirect_uses_the_listener_reader() -> None:
    plain = "<VirtualHost *:80>\nServerName example.com\n</VirtualHost>\n"
    fact = extract_servers(plain, "httpd.conf")[0]
    assert fact.verdict == "NOT_ENCRYPTED"
    redirected = (
        "<VirtualHost *:80>\n"
        "Redirect permanent / https://example.com/\n"
        "</VirtualHost>\n"
    )
    secured = extract_servers(redirected, "httpd.conf")[0]
    assert secured.verdict == listener_reader(plaintext=True, redirect=True).verdict
    assert secured.verdict == "ENCRYPTED_DECLARED"


def test_dh_prime_bits_for_512_1024_and_2048() -> None:
    for bits in (512, 1024, 2048):
        blob = _pkcs3(bits)
        assert prime_bits(blob) == bits
        assert _prime_bits(blob) == bits


def test_dh_reader_rejects_short_and_garbage() -> None:
    short = (1 << 62) | 1
    body = _der_integer(short) + _der_integer(2)
    tiny = b"\x30" + _der_len(len(body)) + body
    assert _prime_bits(tiny) is None
    assert prime_bits(b"") is None
    assert prime_bits(b"\xff") is None
    assert prime_bits(b"\x02\x01\x02") is None
