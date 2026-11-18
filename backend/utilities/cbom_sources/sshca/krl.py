"""OpenSSH key revocation list (KRL) writer, for sshd's ``RevokedKeys`` (format: OpenSSH ``PROTOCOL.krl``).

* every revoked CA key: an explicit-key section (sshd refuses any certificate that CA signed, ``ssh_krl_check_key``
  checks the certificate's signature key);
* every revoked certificate: a certificate section under its CA's key with a serial list.

Pure bytes: no database, no I/O.  ``ssh-keygen -Q -f <krl> <cert>`` reads what this writes (a test checks it).
"""
from __future__ import annotations

import struct
from typing import Iterable, Mapping

KRL_MAGIC = 0x5353484B524C0A00
KRL_FORMAT_VERSION = 1
SECTION_CERTIFICATES = 1
SECTION_EXPLICIT_KEY = 2
CERT_SERIAL_LIST = 0x20


def _u32(value: int) -> bytes:
    return struct.pack(">I", value)


def _u64(value: int) -> bytes:
    return struct.pack(">Q", value)


def _string(data: bytes) -> bytes:
    return _u32(len(data)) + data


def build(*, revoked_ca_blobs: Iterable[bytes], revoked_serials: Mapping[bytes, Iterable[int]], krl_version: int,
          generated: int, comment: str = "") -> bytes:
    """``revoked_ca_blobs``: wire blobs of revoked CA public keys.  ``revoked_serials``: CA blob -> serials (1 to
    2^64-1) of revoked certificates it signed."""
    out = bytearray()
    out += _u64(KRL_MAGIC) + _u32(KRL_FORMAT_VERSION) + _u64(max(0, krl_version)) + _u64(max(0, generated))
    out += _u64(0) + _string(b"") + _string(comment.encode()[:512])
    for ca_blob in sorted(set(revoked_serials)):
        serials = sorted({int(s) for s in revoked_serials[ca_blob] if 0 < int(s) < 2 ** 64})
        if not serials:
            continue
        body = _string(ca_blob) + _string(b"")
        body += bytes([CERT_SERIAL_LIST]) + _string(b"".join(_u64(s) for s in serials))
        out += bytes([SECTION_CERTIFICATES]) + _string(body)
    blobs = sorted(set(revoked_ca_blobs))
    if blobs:
        out += bytes([SECTION_EXPLICIT_KEY]) + _string(b"".join(_string(b) for b in blobs))
    return bytes(out)
