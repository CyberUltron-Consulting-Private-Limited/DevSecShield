"""A minimal, read-only LDAPv3 client (RFC 4511) for the Active Directory collector.

Only what reading directory metadata needs is here: a simple bind, StartTLS, a paged search (RFC 2696) and an
unbind.  There is no encoder for Add, Modify, ModifyDN, Delete, Compare or any other extended operation, so this
client cannot change a directory whatever it is asked.  Every attribute list is checked against ``SECRET_ATTRIBUTES``
before it is sent, the wildcard ``*`` is refused, and any secret-bearing attribute a server returns anyway is dropped
while it is decoded (never stored, never logged).

BER is the subset LDAP uses (definite lengths, tags below 31).  A response larger than ``MAX_MESSAGE`` is refused, so
a hostile server cannot make the node buffer without bound.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

MAX_MESSAGE = 8 * 1024 * 1024
STARTTLS_OID = "1.3.6.1.4.1.1466.20037"
PAGED_OID = "1.2.840.113556.1.4.319"
SCOPE_BASE, SCOPE_ONE, SCOPE_SUB = 0, 1, 2
# Attributes that hold a secret or something that unlocks one: never requested, dropped if a server sends them.
SECRET_ATTRIBUTES = frozenset(a.lower() for a in (
    "unicodePwd", "userPassword", "dBCSPwd", "lmPwdHistory", "ntPwdHistory", "supplementalCredentials",
    "msDS-ManagedPassword", "msDS-ManagedPasswordId", "msDS-ManagedPasswordPreviousId",
    "ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword", "msLAPS-EncryptedPasswordHistory",
    "msLAPS-EncryptedDSRMPassword", "msLAPS-EncryptedDSRMPasswordHistory", "msFVE-RecoveryPassword",
    "msFVE-KeyPackage", "msTPM-OwnerInformation", "msDS-KeyCredentialLink", "currentValue", "priorValue",
    "trustAuthIncoming", "trustAuthOutgoing", "initialAuthIncoming", "initialAuthOutgoing", "msPKIAccountCredentials",
    "msPKIDPAPIMasterKeys", "msPKIRoamingTimeStamp", "msDS-ExecuteScriptPassword", "unixUserPassword",
    "orclCommonAttribute", "os400-password",
    # #488 review m1: a PKCS#12 with its private key, the SFU (NIS) password hash, credential-roaming tokens
    "userPKCS12", "msSFU30Password", "msPKI-CredentialRoamingTokens",
    # #488 review 6031264030 n-1: OpenLDAP ppolicy keeps old password hashes here
    "pwdHistory",
    # #493 review 6032906354 n1: the KDS root key (every gMSA password derives from it), Samba's NT / LM hashes,
    # FreeIPA / MIT Kerberos keys in LDAP, the NTDS password encryption key list
    "msKds-RootKeyData", "sambaNTPassword", "sambaLMPassword", "sambaPasswordHistory", "krbPrincipalKey", "krbMKey",
    "pekList",
))
_NUMERIC_OID = re.compile(r"^\d+(?:\.\d+)+$")
_DESCRIPTOR = re.compile(r"^[a-z][a-z0-9-]*$")  # RFC 4512 keystring (lower-cased): ASCII letter, letters/digits/'-'
_REQUEST_NAME = re.compile(r"^[A-Za-z0-9;.-]+$")  # what a requested attribute (with options) may be spelt with


def attribute_base(name: str) -> str:
    """The attribute's description without its options (``userPassword;binary`` -> ``userpassword``) and without
    an ``OID.`` prefix (``OID.2.5.4.35`` -> ``2.5.4.35``), lower-case."""
    base = str(name).split(";", 1)[0].strip().lower()
    return base[4:] if base.startswith("oid.") else base


def is_refused_attribute(name: str) -> bool:
    """A secret-bearing attribute under any spelling the protocol allows: with options (``;binary``, ``;range=``),
    with an ``OID.`` prefix, or as a numeric OID (``2.5.4.35`` is userPassword; the collector names every attribute it
    needs, so an OID is never needed and is refused whatever it names).  A name that is not a plain RFC 4512
    descriptor (a NUL, a zero-width or any non-ASCII character a server might fold away) is refused too (#488 review
    6031264030 n-1)."""
    base = attribute_base(name)
    return base in SECRET_ATTRIBUTES or bool(_NUMERIC_OID.match(base)) or not _DESCRIPTOR.match(base)
RESULT_NAMES = {0: "success", 1: "operationsError", 2: "protocolError", 3: "timeLimitExceeded",
                4: "sizeLimitExceeded", 7: "authMethodNotSupported", 8: "strongerAuthRequired", 10: "referral",
                11: "adminLimitExceeded", 12: "unavailableCriticalExtension", 13: "confidentialityRequired",
                32: "noSuchObject", 34: "invalidDNSyntax", 48: "inappropriateAuthentication",
                49: "invalidCredentials", 50: "insufficientAccessRights", 51: "busy", 52: "unavailable",
                53: "unwillingToPerform", 80: "other"}


class LdapError(Exception):
    """An LDAP-level failure (a result code, or a malformed or oversized answer).  ``code`` is the result code, or
    None for a protocol problem.  The text never holds a credential."""

    def __init__(self, message: str, code: int | None = None, diagnostic: str = "") -> None:
        super().__init__(message)
        self.code, self.diagnostic = code, diagnostic


# ----------------------------------------------------------------------------- BER
def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _len(len(value)) + value


def ber_int(n: int, tag: int = 0x02) -> bytes:
    length = max(1, (n.bit_length() + 8) // 8)
    return tlv(tag, n.to_bytes(length, "big", signed=True))


def octets(value: bytes | str, tag: int = 0x04) -> bytes:
    return tlv(tag, value.encode("utf-8") if isinstance(value, str) else value)


def seq(*parts: bytes, tag: int = 0x30) -> bytes:
    return tlv(tag, b"".join(parts))


def read_tlv(data: bytes, pos: int = 0) -> tuple[int, bytes, int]:
    """(tag, value, next position).  Raises LdapError on a truncated or indefinite-length element."""
    if pos + 2 > len(data):
        raise LdapError("truncated LDAP element")
    tag, first = data[pos], data[pos + 1]
    pos += 2
    if first & 0x80:
        n = first & 0x7F
        if n == 0 or n > 4 or pos + n > len(data):
            raise LdapError("unsupported LDAP length")
        length = int.from_bytes(data[pos:pos + n], "big")
        pos += n
    else:
        length = first
    if pos + length > len(data):
        raise LdapError("truncated LDAP element")
    return tag, data[pos:pos + length], pos + length


def children(value: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(value):
        tag, inner, pos = read_tlv(value, pos)
        out.append((tag, inner))
    return out


def as_int(value: bytes) -> int:
    return int.from_bytes(value, "big", signed=True) if value else 0


# ----------------------------------------------------------------------------- filters (RFC 4515 subset)
def _unescape(text: str) -> bytes:
    out, i = bytearray(), 0
    raw = text.encode("utf-8")
    while i < len(raw):
        if raw[i] == 0x5C:  # backslash: two hex digits follow
            try:
                out.append(int(raw[i + 1:i + 3].decode("ascii"), 16))
            except ValueError:
                raise LdapError("bad escape in filter") from None
            i += 3
        else:
            out.append(raw[i])
            i += 1
    return bytes(out)


def encode_filter(text: str) -> bytes:
    """&, |, !, presence (a=*), equality (a=v) and extensible match (a:rule:=v).  Anything else is refused."""
    encoded, end = _filter(text.strip(), 0)
    if end != len(text.strip()):
        raise LdapError("trailing text after the filter")
    return encoded


def _filter(text: str, pos: int) -> tuple[bytes, int]:
    if pos >= len(text) or text[pos] != "(":
        raise LdapError("a filter starts with (")
    pos += 1
    op = text[pos] if pos < len(text) else ""
    if op in "&|!":
        pos += 1
        parts = []
        while pos < len(text) and text[pos] == "(":
            part, pos = _filter(text, pos)
            parts.append(part)
        if pos >= len(text) or text[pos] != ")" or not parts or (op == "!" and len(parts) != 1):
            raise LdapError("malformed filter")
        tag = {"&": 0xA0, "|": 0xA1, "!": 0xA2}[op]
        return tlv(tag, b"".join(parts)), pos + 1
    close = text.find(")", pos)
    if close < 0:
        raise LdapError("malformed filter")
    item = text[pos:close]
    if ":=" in item:  # extensible match: attr:rule:=value
        left, value = item.split(":=", 1)
        attr, _, rule = left.partition(":")
        if not attr or not rule:
            raise LdapError("extensible match needs an attribute and a rule")
        return seq(octets(rule, 0x81), octets(attr, 0x82), octets(_unescape(value), 0x83), tag=0xA9), close + 1
    attr, eq, value = item.partition("=")
    if not eq or not attr or any(c in attr for c in "<>~*"):
        raise LdapError("only presence, equality and extensible match filters are supported")
    if value == "*":
        return octets(attr, 0x87), close + 1
    if "*" in value:
        raise LdapError("substring filters are not supported")
    return seq(octets(attr), octets(_unescape(value)), tag=0xA3), close + 1


def decode_filter(data: bytes) -> str:
    """The text form of an encoded filter (used by the test directory, and to log what was asked)."""
    tag, value, _ = read_tlv(data)
    if tag in (0xA0, 0xA1, 0xA2):
        op = {0xA0: "&", 0xA1: "|", 0xA2: "!"}[tag]
        inner = "".join(decode_filter(tlv(t, v)) for t, v in children(value))
        return f"({op}{inner})"
    if tag == 0x87:
        return f"({value.decode('utf-8', 'replace')}=*)"
    if tag == 0xA3:
        (_, attr), (_, val) = children(value)
        return f"({attr.decode('utf-8', 'replace')}={val.decode('utf-8', 'replace')})"
    if tag == 0xA9:
        parts = {t: v for t, v in children(value)}
        return (f"({parts.get(0x82, b'').decode()}:{parts.get(0x81, b'').decode()}:="
                f"{parts.get(0x83, b'').decode('utf-8', 'replace')})")
    raise LdapError("unsupported filter")


def check_attributes(attributes: list[str]) -> list[str]:
    """The attribute list to send: never ``*``/``+`` and never a secret-bearing attribute (raises LdapError)."""
    out = []
    for name in attributes:
        clean = str(name).strip()
        if not clean or clean in ("*", "+") or not _REQUEST_NAME.match(clean) or is_refused_attribute(clean):
            raise LdapError(f"attribute {clean or '(empty)'} is never requested")
        out.append(clean)
    return out


# ----------------------------------------------------------------------------- messages
def bind_request(message_id: int, name: str, password: str) -> bytes:
    op = seq(ber_int(3), octets(name), octets(password, 0x80), tag=0x60)
    return seq(ber_int(message_id), op)


def starttls_request(message_id: int) -> bytes:
    return seq(ber_int(message_id), seq(octets(STARTTLS_OID, 0x80), tag=0x77))


def unbind_request(message_id: int) -> bytes:
    return seq(ber_int(message_id), b"\x42\x00")


def paged_control(size: int, cookie: bytes) -> bytes:
    return seq(octets(PAGED_OID), octets(seq(ber_int(size), octets(cookie))))


def search_request(message_id: int, base: str, scope: int, filter_text: str, attributes: list[str],
                   size_limit: int = 0, time_limit: int = 0, page: tuple[int, bytes] | None = None) -> bytes:
    op = seq(octets(base), ber_int(scope, 0x0A), ber_int(0, 0x0A), ber_int(size_limit), ber_int(time_limit),
             b"\x01\x01\x00", encode_filter(filter_text),
             seq(*(octets(a) for a in check_attributes(attributes))), tag=0x63)
    controls = seq(paged_control(*page), tag=0xA0) if page else b""
    return seq(ber_int(message_id), op, controls)


@dataclass
class Message:
    message_id: int
    op_tag: int
    op: bytes
    controls: list[tuple[str, bytes]] = field(default_factory=list)


def parse_message(data: bytes) -> Message:
    tag, body, _ = read_tlv(data)
    if tag != 0x30:
        raise LdapError("not an LDAP message")
    parts = children(body)
    if len(parts) < 2 or parts[0][0] != 0x02:
        raise LdapError("not an LDAP message")
    controls: list[tuple[str, bytes]] = []
    for ctag, cval in parts[2:]:
        if ctag == 0xA0:
            for _t, control in children(cval):
                fields = children(control)
                oid = fields[0][1].decode("ascii", "replace") if fields else ""
                value = next((v for t, v in fields[1:] if t == 0x04), b"")
                controls.append((oid, value))
    return Message(as_int(parts[0][1]), parts[1][0], parts[1][1], controls)


def ldap_result(op: bytes) -> tuple[int, str, str]:
    """(result code, matched DN, diagnostic message) of an LDAPResult."""
    parts = children(op)
    if len(parts) < 3:
        raise LdapError("malformed LDAP result")
    return (as_int(parts[0][1]), parts[1][1].decode("utf-8", "replace"),
            parts[2][1].decode("utf-8", "replace")[:300])


def parse_entry(op: bytes) -> tuple[str, dict[str, list[bytes]]]:
    """(DN, {attribute: values}) of a SearchResultEntry; secret-bearing attributes are dropped here."""
    parts = children(op)
    if not parts:
        raise LdapError("malformed search entry")
    dn = parts[0][1].decode("utf-8", "replace")
    attrs: dict[str, list[bytes]] = {}
    if len(parts) > 1:
        for _tag, attr in children(parts[1][1]):
            fields = children(attr)
            if not fields:
                continue
            name = fields[0][1].decode("utf-8", "replace")
            if is_refused_attribute(name):
                continue
            values = [v for _t, v in children(fields[1][1])] if len(fields) > 1 else []
            attrs[name] = values
    return dn, attrs


# ----------------------------------------------------------------------------- client
class LdapClient:
    """One connection.  ``sock`` is connected (to an address the caller already checked against never-scan) and may
    be plain (for StartTLS) or already TLS (LDAPS).  Every read has a deadline; the whole session should be bounded by
    the caller's ``deadline`` (``time.monotonic()``)."""

    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self.sock, self.deadline, self._next = sock, deadline, 1
        self._buf = b""

    def _id(self) -> int:
        self._next += 1
        return self._next - 1

    def _send(self, data: bytes) -> None:
        self.sock.settimeout(max(0.1, self.deadline - time.monotonic()))
        self.sock.sendall(data)

    def _recv_more(self) -> None:
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("LDAP read deadline")
        self.sock.settimeout(left)
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("the server closed the LDAP connection")
        self._buf += chunk

    def read(self) -> Message:
        while True:
            if len(self._buf) >= 2:
                first = self._buf[1]
                head = 2 + (first & 0x7F if first & 0x80 else 0)
                if len(self._buf) >= head:
                    if first & 0x80:
                        n = first & 0x7F
                        if n == 0 or n > 4:
                            raise LdapError("unsupported LDAP length")
                        length = int.from_bytes(self._buf[2:head], "big")
                    else:
                        length = first
                    if head + length > MAX_MESSAGE:
                        raise LdapError("LDAP response too large")
                    if len(self._buf) >= head + length:
                        data, self._buf = self._buf[:head + length], self._buf[head + length:]
                        return parse_message(data)
            self._recv_more()

    def _reply(self, message_id: int, tag: int) -> Message:
        while True:
            msg = self.read()
            if msg.message_id == 0 and msg.op_tag == 0x78:  # notice of disconnection
                code, _m, diag = ldap_result(msg.op)
                raise LdapError(f"the server ended the session ({RESULT_NAMES.get(code, code)})", code, diag)
            if msg.message_id == message_id and msg.op_tag == tag:
                return msg

    def start_tls(self) -> None:
        """The StartTLS extended operation on a plain connection; the caller wraps the socket afterwards."""
        if self._buf:
            raise LdapError("unexpected data before StartTLS")
        mid = self._id()
        self._send(starttls_request(mid))
        code, _m, diag = ldap_result(self._reply(mid, 0x78).op)
        if code != 0:
            raise LdapError(f"StartTLS refused ({RESULT_NAMES.get(code, code)})", code, diag)
        if self._buf:  # a server must not send anything before the TLS handshake
            raise LdapError("unexpected data after StartTLS")

    def bind(self, name: str, password: str) -> None:
        """A simple bind.  Call only over TLS whose certificate was verified (the caller's rule)."""
        mid = self._id()
        self._send(bind_request(mid, name, password))
        code, _m, diag = ldap_result(self._reply(mid, 0x61).op)
        if code != 0:
            raise LdapError(f"bind refused ({RESULT_NAMES.get(code, code)})", code, diag)

    def search(self, base: str, scope: int, filter_text: str, attributes: list[str], *, page_size: int = 500,
               max_entries: int = 10_000, size_limit: int = 0) -> Iterator[tuple[str, dict[str, list[bytes]]]]:
        """Entries, paged.  Stops after ``max_entries`` (the caller sees ``self.truncated``).  Referrals are not
        followed."""
        self.truncated = False
        cookie, seen = b"", 0
        while True:
            mid = self._id()
            page = (page_size, cookie) if scope != SCOPE_BASE else None
            self._send(search_request(mid, base, scope, filter_text, attributes, size_limit=size_limit, page=page))
            cookie = b""
            while True:
                msg = self.read()
                if msg.message_id != mid:
                    continue
                if msg.op_tag == 0x64:
                    seen += 1
                    if seen > max_entries:
                        self.truncated = True
                        continue
                    yield parse_entry(msg.op)
                elif msg.op_tag == 0x73:
                    continue  # a referral to another partition: not followed
                elif msg.op_tag == 0x65:
                    code, _m, diag = ldap_result(msg.op)
                    if code == 4:  # sizeLimitExceeded: what came is kept, the rest is marked truncated
                        self.truncated = True
                    elif code != 0:
                        raise LdapError(f"search refused ({RESULT_NAMES.get(code, code)})", code, diag)
                    for oid, value in msg.controls:
                        if oid == PAGED_OID and value:
                            _t, body, _ = read_tlv(value)
                            fields = children(body)
                            cookie = fields[1][1] if len(fields) > 1 else b""
                    break
            if not cookie or self.truncated:
                return

    def unbind(self) -> None:
        try:
            self._send(unbind_request(self._id()))
        except OSError:
            pass


def first(attrs: dict[str, list[bytes]], name: str) -> str | None:
    for key, values in attrs.items():
        if key.lower() == name.lower() and values:
            return values[0].decode("utf-8", "replace")
    return None


def all_values(attrs: dict[str, list[bytes]], name: str) -> list[bytes]:
    for key, values in attrs.items():
        if key.lower() == name.lower():
            return values
    return []


def wrap_tls(sock: socket.socket, context: ssl.SSLContext, server_hostname: str | None, deadline: float) -> ssl.SSLSocket:
    sock.settimeout(max(0.1, deadline - time.monotonic()))
    return context.wrap_socket(sock, server_hostname=server_hostname)


def int_value(attrs: dict[str, list[bytes]], name: str) -> int | None:
    value = first(attrs, name)
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def any_value(attrs: dict[str, Any], name: str) -> bool:
    return bool(all_values(attrs, name))
