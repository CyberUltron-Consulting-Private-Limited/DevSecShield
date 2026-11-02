"""A minimal KMIP TTLV codec and the read-only requests the KMIP collector sends (no network here).

TTLV (KMIP 1.4 section 9.1 / KMIP 2.0 section 9.1): 3-byte tag, 1-byte type, 4-byte length, value padded to a multiple
of 8 bytes.  Only Discover Versions, Query, Locate and Get Attributes are built: nothing that returns key material
(Get, Export) or changes the server.  Tags and enumeration values are those of the OASIS specifications (cross-checked
against PyKMIP's enums).  The decoder bounds depth, item count and lengths so a hostile server cannot exhaust memory.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

STRUCTURE, INTEGER, LONG, BIGINT, ENUM, BOOL, TEXT, BYTES, DATETIME, INTERVAL = range(1, 11)

TAG = {
    "Activation Date": 0x420001, "Attribute": 0x420008, "Attribute Index": 0x420009, "Attribute Name": 0x42000A,
    "Attribute Value": 0x42000B, "Batch Count": 0x42000D, "Batch Item": 0x42000F, "Certificate Type": 0x42001D,
    "Compromise Date": 0x420020, "Cryptographic Algorithm": 0x420028, "Cryptographic Domain Parameters": 0x420029,
    "Cryptographic Length": 0x42002A, "Cryptographic Parameters": 0x42002B, "Cryptographic Usage Mask": 0x42002C,
    "Deactivation Date": 0x42002F, "Destroy Date": 0x420033, "Digest": 0x420034, "Initial Date": 0x420039,
    "Last Change Date": 0x420048, "Maximum Items": 0x42004F, "Maximum Response Size": 0x420050, "Name": 0x420053,
    "Name Type": 0x420054, "Name Value": 0x420055, "Object Group": 0x420056, "Object Type": 0x420057,
    "Operation": 0x42005C, "Process Start Date": 0x420067, "Protect Stop Date": 0x420068, "Protocol Version": 0x420069,
    "Protocol Version Major": 0x42006A, "Protocol Version Minor": 0x42006B, "Query Function": 0x420074,
    "Recommended Curve": 0x420075, "Request Header": 0x420077, "Request Message": 0x420078,
    "Request Payload": 0x420079, "Response Header": 0x42007A, "Response Message": 0x42007B,
    "Response Payload": 0x42007C, "Result Message": 0x42007D, "Result Reason": 0x42007E, "Result Status": 0x42007F,
    "Server Information": 0x420088, "State": 0x42008D, "Time Stamp": 0x420092, "Unique Identifier": 0x420094,
    "Vendor Identification": 0x42009D, "Original Creation Date": 0x4200BC, "Offset Items": 0x4200D4,
    "Located Items": 0x4200D5, "Sensitive": 0x420120, "Always Sensitive": 0x420121, "Extractable": 0x420122,
    "Never Extractable": 0x420123, "Attributes": 0x420125,
}
TAG_NAME = {v: k for k, v in TAG.items()}

OPERATION = {"Locate": 0x08, "Get Attributes": 0x0B, "Query": 0x18, "Discover Versions": 0x1E}
OPERATION_NAME = {0x01: "Create", 0x02: "Create Key Pair", 0x03: "Register", 0x04: "Re-key", 0x05: "Derive Key",
                  0x06: "Certify", 0x07: "Re-certify", 0x08: "Locate", 0x09: "Check", 0x0A: "Get",
                  0x0B: "Get Attributes", 0x0C: "Get Attribute List", 0x0D: "Add Attribute", 0x0E: "Modify Attribute",
                  0x0F: "Delete Attribute", 0x10: "Obtain Lease", 0x11: "Get Usage Allocation", 0x12: "Activate",
                  0x13: "Revoke", 0x14: "Destroy", 0x15: "Archive", 0x16: "Recover", 0x17: "Validate", 0x18: "Query",
                  0x19: "Cancel", 0x1A: "Poll", 0x1B: "Notify", 0x1C: "Put", 0x1D: "Re-key Key Pair",
                  0x1E: "Discover Versions", 0x1F: "Encrypt", 0x20: "Decrypt", 0x21: "Sign", 0x22: "Signature Verify",
                  0x23: "MAC", 0x24: "MAC Verify", 0x25: "RNG Retrieve", 0x26: "RNG Seed", 0x27: "Hash",
                  0x28: "Create Split Key", 0x29: "Join Split Key", 0x2A: "Import", 0x2B: "Export"}
QUERY_OPERATIONS, QUERY_OBJECTS, QUERY_SERVER_INFORMATION = 1, 2, 3
OBJECT_TYPE = {1: "Certificate", 2: "Symmetric Key", 3: "Public Key", 4: "Private Key", 5: "Split Key", 6: "Template",
               7: "Secret Data", 8: "Opaque Object", 9: "PGP Key", 10: "Certificate Request"}
ALGORITHM = {1: "DES", 2: "3DES", 3: "AES", 4: "RSA", 5: "DSA", 6: "ECDSA", 7: "HMAC-SHA1", 8: "HMAC-SHA224",
             9: "HMAC-SHA256", 10: "HMAC-SHA384", 11: "HMAC-SHA512", 12: "HMAC-MD5", 13: "DH", 14: "ECDH",
             15: "ECMQV", 16: "Blowfish", 17: "Camellia", 18: "CAST5", 19: "IDEA", 20: "MARS", 21: "RC2", 22: "RC4",
             23: "RC5", 24: "SKIPJACK", 25: "Twofish", 26: "EC", 27: "One Time Pad", 28: "ChaCha20",
             29: "Poly1305", 30: "ChaCha20Poly1305", 31: "SHA3-224", 32: "SHA3-256", 33: "SHA3-384", 34: "SHA3-512",
             35: "HMAC-SHA3-224", 36: "HMAC-SHA3-256", 37: "HMAC-SHA3-384", 38: "HMAC-SHA3-512", 39: "SHAKE-128",
             40: "SHAKE-256", 41: "ARIA", 42: "SEED", 43: "SM2", 44: "SM3", 45: "SM4", 46: "GOST R 34.10-2012",
             47: "GOST R 34.11-2012", 48: "GOST R 34.13-2015", 49: "GOST 28147-89", 50: "XMSS", 51: "SPHINCS-256",
             52: "McEliece", 53: "McEliece-6960119", 54: "McEliece-8192128", 55: "Ed25519", 56: "Ed448"}
STATE = {1: "Pre-Active", 2: "Active", 3: "Deactivated", 4: "Compromised", 5: "Destroyed", 6: "Destroyed Compromised"}
CURVE = {1: "P-192", 2: "K-163", 3: "B-163", 4: "P-224", 5: "K-233", 6: "B-233", 7: "P-256", 8: "K-283", 9: "B-283",
         10: "P-384", 11: "K-409", 12: "B-409", 13: "P-521", 14: "K-571", 15: "B-571", 25: "secp256k1"}
CURVE_BITS = {"P-192": 192, "P-224": 224, "P-256": 256, "P-384": 384, "P-521": 521, "secp256k1": 256, "K-163": 163,
              "B-163": 163, "K-233": 233, "B-233": 233, "K-283": 283, "B-283": 283, "K-409": 409, "B-409": 409,
              "K-571": 571, "B-571": 571}
USAGE = {0x1: "Sign", 0x2: "Verify", 0x4: "Encrypt", 0x8: "Decrypt", 0x10: "Wrap Key", 0x20: "Unwrap Key",
         0x40: "Export", 0x80: "MAC Generate", 0x100: "MAC Verify", 0x200: "Derive Key", 0x400: "Content Commitment",
         0x800: "Key Agreement", 0x1000: "Certificate Sign", 0x2000: "CRL Sign"}
RESULT_REASON = {1: "Item Not Found", 2: "Response Too Large", 3: "Authentication Not Successful",
                 4: "Invalid Message", 5: "Operation Not Supported", 6: "Missing Data", 7: "Invalid Field",
                 8: "Feature Not Supported", 12: "Permission Denied", 57: "Not Authorised",
                 63: "Unsupported Protocol Version", 256: "General Failure"}
SUCCESS = 0
MAX_MESSAGE = 4 * 1024 * 1024
MAX_DEPTH = 16
MAX_ITEMS = 200_000


class TTLVError(Exception):
    pass


@dataclass
class Item:
    tag: int
    type: int
    value: Any = None
    children: list["Item"] = field(default_factory=list)

    @property
    def name(self) -> str:
        return TAG_NAME.get(self.tag, f"0x{self.tag:06x}")

    def first(self, tag_name: str) -> "Item | None":
        tag = TAG[tag_name]
        return next((c for c in self.children if c.tag == tag), None)

    def all(self, tag_name: str) -> list["Item"]:
        tag = TAG[tag_name]
        return [c for c in self.children if c.tag == tag]

    def get(self, tag_name: str, default: Any = None) -> Any:
        item = self.first(tag_name)
        return default if item is None else item.value


def S(name: str, children: list[Item]) -> Item:
    return Item(TAG[name], STRUCTURE, None, list(children))


def I(name: str, value: int) -> Item:  # noqa: E743 - TTLV type letter
    return Item(TAG[name], INTEGER, int(value))


def E(name: str, value: int) -> Item:
    return Item(TAG[name], ENUM, int(value))


def T(name: str, value: str) -> Item:
    return Item(TAG[name], TEXT, str(value))


def encode(item: Item) -> bytes:
    t = item.type
    if t == STRUCTURE:
        body = b"".join(encode(c) for c in item.children)
    elif t == INTEGER:
        body = struct.pack("!i", item.value)
    elif t in (ENUM, INTERVAL):
        body = struct.pack("!I", item.value)
    elif t in (LONG, DATETIME):
        body = struct.pack("!q", item.value)
    elif t == BOOL:
        body = struct.pack("!Q", 1 if item.value else 0)
    elif t == TEXT:
        body = str(item.value).encode("utf-8")
    elif t == BYTES:
        body = bytes(item.value)
    elif t == BIGINT:
        n = int(item.value)
        size = max(8, ((n.bit_length() + 8) // 8 + 7) // 8 * 8)
        body = n.to_bytes(size, "big", signed=True)
    else:
        raise TTLVError(f"cannot encode type {t}")
    return item.tag.to_bytes(3, "big") + bytes([t]) + struct.pack("!I", len(body)) + body + b"\0" * ((-len(body)) % 8)


def decode(data: bytes) -> Item:
    counter = [0]
    item, end = _decode(data, 0, 0, counter)
    if end != len(data):
        raise TTLVError("trailing bytes after the message")
    return item


def _decode(data: bytes, pos: int, depth: int, counter: list[int]) -> tuple[Item, int]:
    if depth > MAX_DEPTH:
        raise TTLVError("structure nested too deeply")
    counter[0] += 1
    if counter[0] > MAX_ITEMS:
        raise TTLVError("too many items")
    if pos + 8 > len(data):
        raise TTLVError("truncated item header")
    tag = int.from_bytes(data[pos:pos + 3], "big")
    t = data[pos + 3]
    length = struct.unpack("!I", data[pos + 4:pos + 8])[0]
    start = pos + 8
    end = start + length
    padded = end + ((-length) % 8) if t != STRUCTURE else end
    if end > len(data) or padded > len(data):
        raise TTLVError("item length runs past the message")
    body = data[start:end]
    item = Item(tag, t)
    if t == STRUCTURE:
        p = start
        while p < end:
            child, p = _decode(data, p, depth + 1, counter)
            item.children.append(child)
        if p != end:
            raise TTLVError("structure length mismatch")
    elif t == INTEGER and length == 4:
        item.value = struct.unpack("!i", body)[0]
    elif t in (ENUM, INTERVAL) and length == 4:
        item.value = struct.unpack("!I", body)[0]
    elif t in (LONG, DATETIME) and length == 8:
        item.value = struct.unpack("!q", body)[0]
    elif t == BOOL and length == 8:
        item.value = struct.unpack("!Q", body)[0] != 0
    elif t == TEXT:
        item.value = body.decode("utf-8", "replace")
    elif t in (BYTES, BIGINT):
        item.value = bytes(body) if t == BYTES else int.from_bytes(body, "big", signed=True)
    else:
        raise TTLVError(f"bad item type {t} / length {length}")
    return item, padded


def request(version: tuple[int, int], operation: str, payload: list[Item]) -> bytes:
    header = S("Request Header", [S("Protocol Version", [I("Protocol Version Major", version[0]),
                                                         I("Protocol Version Minor", version[1])]),
                                  I("Maximum Response Size", MAX_MESSAGE), I("Batch Count", 1)])
    batch = S("Batch Item", [E("Operation", OPERATION[operation]), S("Request Payload", payload)])
    return encode(S("Request Message", [header, batch]))


@dataclass
class Response:
    status: int
    reason: int | None
    message: str | None
    payload: Item | None
    version: tuple[int, int] | None

    @property
    def ok(self) -> bool:
        return self.status == SUCCESS

    def error_text(self) -> str:
        reason = RESULT_REASON.get(self.reason or 0, str(self.reason)) if self.reason is not None else "failed"
        return f"{reason}" + (f": {self.message[:160]}" if self.message else "")


def parse_response(data: bytes) -> Response:
    msg = decode(data)
    if msg.tag != TAG["Response Message"] or msg.type != STRUCTURE:
        raise TTLVError("not a KMIP response message")
    header = msg.first("Response Header")
    version = None
    if header is not None and header.first("Protocol Version") is not None:
        pv = header.first("Protocol Version")
        version = (pv.get("Protocol Version Major", 0), pv.get("Protocol Version Minor", 0))
    batch = msg.first("Batch Item")
    if batch is None:
        raise TTLVError("response without a batch item")
    return Response(batch.get("Result Status", 1), batch.get("Result Reason"), batch.get("Result Message"),
                    batch.first("Response Payload"), version)


def discover_versions() -> list[Item]:
    return []


def query(functions: tuple[int, ...] = (QUERY_OPERATIONS, QUERY_OBJECTS, QUERY_SERVER_INFORMATION)) -> list[Item]:
    return [E("Query Function", f) for f in functions]


def locate(version: tuple[int, int], maximum: int, offset: int) -> list[Item]:
    payload = [I("Maximum Items", maximum)]
    if offset and version >= (1, 3):
        payload.append(I("Offset Items", offset))
    if version >= (2, 0):
        payload.append(S("Attributes", []))  # required in KMIP 2.0; empty matches every object
    return payload


def get_attributes(uid: str) -> list[Item]:
    return [T("Unique Identifier", uid)]  # no names / references: every attribute (never the key value)


# ----------------------------------------------------------------------------- attribute values -> facts
_DATES = ("Initial Date", "Activation Date", "Deactivation Date", "Process Start Date", "Protect Stop Date",
          "Compromise Date", "Destroy Date", "Last Change Date", "Original Creation Date")
_BOOLS = ("Sensitive", "Always Sensitive", "Extractable", "Never Extractable")


def _iso(seconds: Any) -> str | None:
    import datetime as _dt

    try:
        return _dt.datetime.fromtimestamp(int(seconds), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _put(out: dict[str, Any], name: str, value_item: Item) -> None:
    v = value_item.value
    if name == "Cryptographic Algorithm":
        out["algorithm"] = ALGORITHM.get(v, f"0x{int(v or 0):x}")
    elif name == "Cryptographic Length":
        out["length"] = v
    elif name == "Object Type":
        out["object_type"] = OBJECT_TYPE.get(v, f"0x{int(v or 0):x}")
    elif name == "State":
        out["state"] = STATE.get(v, f"0x{int(v or 0):x}")
    elif name == "Cryptographic Usage Mask":
        out["usage"] = [label for bit, label in USAGE.items() if int(v or 0) & bit]
    elif name == "Name":
        text = value_item.get("Name Value") if value_item.type == STRUCTURE else v
        if text:
            out.setdefault("names", []).append(str(text)[:128])
    elif name in _DATES:
        out[name.lower().replace(" ", "_")] = _iso(v)
    elif name in _BOOLS:
        out[name.lower().replace(" ", "_")] = bool(v)
    elif name == "Object Group":
        out.setdefault("groups", []).append(str(v)[:128])
    elif name == "Cryptographic Domain Parameters" and value_item.type == STRUCTURE:
        curve = value_item.get("Recommended Curve")
        if curve is not None:
            out["curve"] = CURVE.get(curve, f"0x{int(curve):x}")
    elif name == "Unique Identifier":
        out["uid"] = str(v)[:128]
    # everything else (Digest, Links, vendor x- attributes ...) is left out on purpose


def attributes_to_facts(payload: Item | None) -> dict[str, Any]:
    """KMIP 1.x Attribute(Name, Value) list or a KMIP 2.0 Attributes structure -> a small facts dict."""
    out: dict[str, Any] = {}
    if payload is None:
        return out
    for attr in payload.all("Attribute"):
        name, value = attr.get("Attribute Name"), attr.first("Attribute Value")
        if name and value is not None:
            _put(out, str(name), value)
    block = payload.first("Attributes")
    for child in (block.children if block is not None else []):
        _put(out, child.name, child)
    return out
