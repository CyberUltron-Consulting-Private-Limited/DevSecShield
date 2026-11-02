"""OPC UA endpoint discovery (opc.tcp, default port 4840): the security a server offers, read without logging in.

One TCP connection, four messages, all from OPC UA Part 6 (UA Binary, UA-TCP):
  HEL -> ACK                  transport handshake (Part 6 section 7.1.2)
  OPN (SecurityPolicy#None)   OpenSecureChannel, Issue, MessageSecurityMode None (section 6.7.4; Part 4 section 5.5.2)
  MSG GetEndpointsRequest     the Discovery service, which servers answer on an unsecured channel (Part 4 section 5.4.4)
  CLO                         CloseSecureChannel
No session is created, nothing is read or written in the address space.  Encoding ids (446/449 OpenSecureChannel,
428/431 GetEndpoints, 452 CloseSecureChannel, 397 ServiceFault) are from the OPC Foundation NodeIds.csv (the same
values asyncua generates in ua/object_ids.py).  All integers are little-endian (Part 6 section 5.2.2).

Modbus/TCP (502) has no security layer at all; the collector only records that the port accepts connections and
sends no Modbus request.  Modbus/TCP Security (802) is TLS and goes through the TLS probe.
"""
from __future__ import annotations

import socket
import struct
import time
from typing import Any

POLICY_PREFIX = "http://opcfoundation.org/UA/SecurityPolicy#"
POLICY_NONE = POLICY_PREFIX + "None"
# OPC UA 1.04 Part 7 deprecates Basic128Rsa15 and Basic256 (SHA-1, RSA PKCS#1 v1.5 key transport)
DEPRECATED_POLICIES = ("Basic128Rsa15", "Basic256")
MODES = {0: "Invalid", 1: "None", 2: "Sign", 3: "SignAndEncrypt"}
TOKEN_TYPES = {0: "Anonymous", 1: "UserName", 2: "Certificate", 3: "IssuedToken"}
ENC_OPN_REQ, ENC_OPN_RESP, ENC_GETEP_REQ, ENC_GETEP_RESP, ENC_CLO_REQ, ENC_FAULT = 446, 449, 428, 431, 452, 397
MAX_MESSAGE = 4 * 1024 * 1024
MAX_ENDPOINTS = 64
RECV_BUFFER = 65535


class UaError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code, self.detail = code, detail


# ----------------------------------------------------------------------------- encoding
def _string(text: str | None) -> bytes:
    if text is None:
        return struct.pack("<i", -1)
    raw = text.encode("utf-8")
    return struct.pack("<i", len(raw)) + raw


def _bytestring(data: bytes | None) -> bytes:
    return struct.pack("<i", -1) if data is None else struct.pack("<i", len(data)) + data


def _type_id(numeric: int) -> bytes:
    return struct.pack("<BBH", 0x01, 0, numeric)  # FourByte NodeId, namespace 0


def _now_ua() -> int:
    return int((time.time() + 11644473600) * 10_000_000)  # 100 ns since 1601-01-01


def _request_header(handle: int) -> bytes:
    return (b"\x00\x00"  # AuthenticationToken: null NodeId
            + struct.pack("<qII", _now_ua(), handle, 0) + _string(None) + struct.pack("<I", 10_000)
            + b"\x00\x00\x00")  # AdditionalHeader: null NodeId, no body


def build_hello(endpoint_url: str) -> bytes:
    body = struct.pack("<IIIII", 0, RECV_BUFFER, RECV_BUFFER, MAX_MESSAGE, 64) + _string(endpoint_url)
    return b"HELF" + struct.pack("<I", 8 + len(body)) + body


def build_open(request_id: int = 1) -> bytes:
    body = (struct.pack("<I", 0) + _string(POLICY_NONE) + _bytestring(None) + _bytestring(None)
            + struct.pack("<II", request_id, request_id) + _type_id(ENC_OPN_REQ) + _request_header(request_id)
            # ClientProtocolVersion 0, RequestType Issue (0), MessageSecurityMode None (1), no nonce, lifetime
            + struct.pack("<Iii", 0, 0, 1) + _bytestring(b"") + struct.pack("<I", 600_000))
    return b"OPNF" + struct.pack("<I", 8 + len(body)) + body


def build_get_endpoints(channel: int, token: int, endpoint_url: str, seq: int = 2) -> bytes:
    body = (struct.pack("<IIII", channel, token, seq, seq) + _type_id(ENC_GETEP_REQ) + _request_header(seq)
            + _string(endpoint_url) + struct.pack("<ii", 0, 0))
    return b"MSGF" + struct.pack("<I", 8 + len(body)) + body


def build_close(channel: int, token: int, seq: int = 3) -> bytes:
    body = struct.pack("<IIII", channel, token, seq, seq) + _type_id(ENC_CLO_REQ) + _request_header(seq)
    return b"CLOF" + struct.pack("<I", 8 + len(body)) + body


# ----------------------------------------------------------------------------- decoding
class Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise UaError("error", "truncated OPC UA message")
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("<H", self.take(2))[0]

    def u32(self) -> int:
        return struct.unpack("<I", self.take(4))[0]

    def i32(self) -> int:
        return struct.unpack("<i", self.take(4))[0]

    def i64(self) -> int:
        return struct.unpack("<q", self.take(8))[0]

    def bytestring(self, cap: int = 65536) -> bytes | None:
        n = self.i32()
        if n < 0:
            return None
        if n > cap:
            raise UaError("error", "OPC UA field too large")
        return self.take(n)

    def string(self, cap: int = 4096) -> str | None:
        raw = self.bytestring(cap)
        return None if raw is None else raw.decode("utf-8", "replace")

    def nodeid(self) -> int | None:
        """NodeId; returns the numeric id for namespace 0 numeric ids, else None (skipped)."""
        enc = self.u8()
        kind = enc & 0x3F
        if kind == 0:
            value = self.u8()
        elif kind == 1:
            ns, value = self.u8(), self.u16()
            value = value if ns == 0 else None
        elif kind == 2:
            ns, value = self.u16(), self.u32()
            value = value if ns == 0 else None
        elif kind == 3:
            self.u16()
            self.string()
            value = None
        elif kind == 4:
            self.take(18)
            value = None
        elif kind == 5:
            self.u16()
            self.bytestring()
            value = None
        else:
            raise UaError("error", "unknown NodeId encoding")
        if enc & 0x80:
            self.string()
        if enc & 0x40:
            self.u32()
        return value

    def localized_text(self) -> str | None:
        mask = self.u8()
        if mask & 0x01:
            self.string()
        return self.string() if mask & 0x02 else None

    def extension_object(self) -> None:
        self.nodeid()
        enc = self.u8()
        if enc in (1, 2):
            self.bytestring(MAX_MESSAGE)

    def diagnostic_info(self, depth: int = 0) -> None:
        if depth > 4:
            raise UaError("error", "DiagnosticInfo nested too deep")
        mask = self.u8()
        for bit in (0x01, 0x02, 0x04, 0x08):
            if mask & bit:
                self.i32()
        if mask & 0x10:
            self.string()
        if mask & 0x20:
            self.u32()
        if mask & 0x40:
            self.diagnostic_info(depth + 1)

    def string_array(self, cap: int = 64) -> list[str]:
        n = self.i32()
        if n > cap:
            raise UaError("error", "array too large")
        return [s for s in (self.string() for _ in range(max(n, 0))) if s is not None]


def _response_header(r: Reader) -> int:
    r.i64()
    r.u32()
    status = r.u32()
    r.diagnostic_info()
    r.string_array(256)
    r.extension_object()
    return status


def _short_policy(uri: str | None) -> str | None:
    if not uri:
        return None
    return uri[len(POLICY_PREFIX):] if uri.startswith(POLICY_PREFIX) else uri[:120]


def parse_endpoints(body: bytes) -> list[dict[str, Any]]:
    """GetEndpointsResponse body (after the sequence header): the endpoint list, with the server certificate DER."""
    r = Reader(body)
    type_id = r.nodeid()
    if type_id == ENC_FAULT:
        raise UaError("refused", f"ServiceFault 0x{_response_header(r):08X}")
    if type_id != ENC_GETEP_RESP:
        raise UaError("error", f"unexpected answer type {type_id}")
    status = _response_header(r)
    if status & 0x80000000:
        raise UaError("refused", f"GetEndpoints status 0x{status:08X}")
    count = r.i32()
    if count > MAX_ENDPOINTS:
        raise UaError("error", "too many endpoints")
    out = []
    for _ in range(max(count, 0)):
        ep: dict[str, Any] = {"url": r.string()}
        ep["application_uri"] = r.string()
        ep["product_uri"] = r.string()
        ep["application_name"] = r.localized_text()
        r.i32()  # ApplicationType
        r.string()  # GatewayServerUri
        r.string()  # DiscoveryProfileUri
        r.string_array()
        ep["certificate_der"] = r.bytestring(65536)
        ep["security_mode"] = MODES.get(r.i32(), "Invalid")
        ep["security_policy"] = _short_policy(r.string())
        tokens = []
        ntok = r.i32()
        if ntok > 32:
            raise UaError("error", "too many user token policies")
        for _t in range(max(ntok, 0)):
            r.string()  # PolicyId
            ttype = TOKEN_TYPES.get(r.i32(), "Unknown")
            r.string()  # IssuedTokenType
            r.string()  # IssuerEndpointUrl
            tokens.append({"type": ttype, "security_policy": _short_policy(r.string())})
        ep["user_tokens"] = tokens
        transport = r.string() or ""
        ep["transport"] = transport.rsplit("/", 1)[-1][:60]
        ep["security_level"] = r.u8()
        out.append(ep)
    return out


# ----------------------------------------------------------------------------- the exchange
def _recv_exact(sock: socket.socket, n: int, deadline: float) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        left = deadline - time.monotonic()
        if left <= 0:
            raise UaError("timeout", "the server stopped answering")
        sock.settimeout(min(left, 2.0))
        try:
            chunk = sock.recv(n - len(buf))
        except socket.timeout:
            continue
        except OSError as exc:
            raise UaError("error", f"connection error ({exc.__class__.__name__})") from None
        if not chunk:
            raise UaError("error", "the server closed the connection")
        buf += chunk
    return bytes(buf)


def _read_chunk(sock: socket.socket, deadline: float) -> tuple[bytes, bytes, bytes]:
    head = _recv_exact(sock, 8, deadline)
    mtype, ctype, size = head[:3], head[3:4], struct.unpack("<I", head[4:8])[0]
    if mtype not in (b"ACK", b"ERR", b"OPN", b"MSG", b"CLO") or size < 8 or size > MAX_MESSAGE:
        raise UaError("error", "not an OPC UA TCP answer")
    return mtype, ctype, _recv_exact(sock, size - 8, deadline)


def _err(body: bytes) -> UaError:
    r = Reader(body)
    try:
        code = r.u32()
        reason = r.string(512) or ""
    except UaError:
        code, reason = 0, ""
    return UaError("refused", f"ERR 0x{code:08X} {reason}".strip()[:200])


def get_endpoints(sock: socket.socket, endpoint_url: str, deadline: float) -> list[dict[str, Any]]:
    """HEL/ACK, OPN (None), GetEndpoints, CLO on a connected socket.  Raises UaError."""
    sock.sendall(build_hello(endpoint_url))
    mtype, _c, body = _read_chunk(sock, deadline)
    if mtype == b"ERR":
        raise _err(body)
    if mtype != b"ACK" or len(body) < 20:
        raise UaError("error", "no OPC UA Acknowledge")
    server_recv = struct.unpack("<I", body[4:8])[0]
    opn = build_open()
    if server_recv and len(opn) > server_recv:
        raise UaError("error", "the server's receive buffer is too small")
    sock.sendall(opn)
    mtype, _c, body = _read_chunk(sock, deadline)
    if mtype == b"ERR":
        raise _err(body)
    if mtype != b"OPN":
        raise UaError("error", "no OpenSecureChannel answer")
    r = Reader(body)
    channel = r.u32()
    policy = r.string()
    r.bytestring()
    r.bytestring()
    r.u32()
    r.u32()
    if policy != POLICY_NONE:
        raise UaError("error", "the server answered with another security policy")
    type_id = r.nodeid()
    if type_id == ENC_FAULT:
        raise UaError("refused", f"OpenSecureChannel refused (0x{_response_header(r):08X})")
    if type_id != ENC_OPN_RESP:
        raise UaError("error", "unexpected OpenSecureChannel answer")
    status = _response_header(r)
    if status & 0x80000000:
        raise UaError("refused", f"OpenSecureChannel status 0x{status:08X}")
    r.u32()  # ServerProtocolVersion
    channel_id, token_id = r.u32(), r.u32()
    channel = channel_id or channel
    sock.sendall(build_get_endpoints(channel, token_id, endpoint_url))
    parts = bytearray()
    for _ in range(256):
        mtype, ctype, body = _read_chunk(sock, deadline)
        if mtype == b"ERR":
            raise _err(body)
        if mtype != b"MSG" or len(body) < 16:
            raise UaError("error", "unexpected answer to GetEndpoints")
        if ctype == b"A":
            raise UaError("refused", "the server aborted the GetEndpoints answer")
        parts += body[16:]  # SecureChannelId, TokenId, SequenceNumber, RequestId
        if len(parts) > MAX_MESSAGE:
            raise UaError("error", "GetEndpoints answer too large")
        if ctype == b"F":
            break
    else:
        raise UaError("error", "too many chunks")
    endpoints = parse_endpoints(bytes(parts))
    try:
        sock.sendall(build_close(channel, token_id))
    except OSError:
        pass
    return endpoints


def summarize(endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    """Facts for the classifier (certificates are reported as their own rows by the collector)."""
    eps = []
    for ep in endpoints[:MAX_ENDPOINTS]:
        eps.append({k: ep.get(k) for k in ("url", "security_mode", "security_policy", "user_tokens", "transport",
                                           "security_level")})
    first = endpoints[0] if endpoints else {}
    return {"endpoints": eps, "application_uri": first.get("application_uri"),
            "product_uri": first.get("product_uri"), "application_name": first.get("application_name"),
            "policies": sorted({e.get("security_policy") or "?" for e in endpoints}),
            "modes": sorted({e.get("security_mode") or "?" for e in endpoints})}
