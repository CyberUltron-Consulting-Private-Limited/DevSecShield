"""Certificates whose algorithm OIDs OpenSSL 3.5 cannot generate (composites, HashML-DSA, GOST), for the text capture.

    python3 make_oid_only_certs.py <template.der> <out dir>

Each is the template certificate (any real X.509, e.g. rsa.der from make_capture_certs.sh) re-encoded with another
SubjectPublicKeyInfo / signature AlgorithmIdentifier. Key and signature bytes are random filler: only the
AlgorithmIdentifiers are read by anything that uses these files. Stdlib only.
"""
import os
import sys

CERTS = (("composite-mldsa65-rsa3072-pss", "1.3.6.1.5.5.7.6.41", "1.3.6.1.5.5.7.6.41"),
         ("composite-mlkem768-x25519", "1.3.6.1.5.5.7.6.58", "1.2.840.113549.1.1.11"),
         ("hashmldsa65", "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.33"),
         ("gost2012-256", "1.2.643.7.1.1.1.1", "1.2.643.7.1.1.3.2"),
         ("gost2012-512", "1.2.643.7.1.1.1.2", "1.2.643.7.1.1.3.3"))


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _len(len(body)) + body


def oid(dotted: str) -> bytes:
    parts = [int(x) for x in dotted.split(".")]
    body = bytes([40 * parts[0] + parts[1]])
    for p in parts[2:]:
        enc = [p & 0x7F]
        p >>= 7
        while p:
            enc.append(0x80 | (p & 0x7F))
            p >>= 7
        body += bytes(reversed(enc))
    return tlv(0x06, body)


def _read(der: bytes, i: int) -> tuple[int, int, int]:
    length, j = der[i + 1], i + 2
    if length & 0x80:
        n = length & 0x7F
        length, j = int.from_bytes(der[j:j + n], "big"), j + n
    return j, j + length, j + length  # body start, body end, next


def _items(der: bytes, start: int, end: int) -> list[bytes]:
    out, i = [], start
    while i < end:
        _, _, nxt = _read(der, i)
        out.append(der[i:nxt])
        i = nxt
    return out


template = open(sys.argv[1], "rb").read()
s, e, _ = _read(template, 0)
tbs = _items(template, s, e)[0]
ts, te, _ = _read(tbs, 0)
fields = _items(tbs, ts, te)  # [0] version, serial, sigalg, issuer, validity, subject, spki, [3] extensions
for name, spki_oid, sig_oid in CERTS:
    algid = tlv(0x30, oid(sig_oid))
    subject = tlv(0x30, tlv(0x31, tlv(0x30, oid("2.5.4.3") + tlv(0x0C, name.encode()))))
    spki = tlv(0x30, tlv(0x30, oid(spki_oid)) + tlv(0x03, b"\x00" + os.urandom(64)))
    body = fields[0] + fields[1] + algid + fields[3] + fields[4] + subject + spki + b"".join(fields[7:])
    der = tlv(0x30, tlv(0x30, body) + algid + tlv(0x03, b"\x00" + os.urandom(64)))
    with open(os.path.join(sys.argv[2], name + ".der"), "wb") as fh:
        fh.write(der)
