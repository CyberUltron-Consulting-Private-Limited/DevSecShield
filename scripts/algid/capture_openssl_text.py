"""Record what the `openssl` on PATH prints for each certificate's public-key and signature algorithm.

    python3 capture_openssl_text.py <dir of DER certificates>  > openssl-<major.minor>-text.json

Run it once per OpenSSL version (3.0 on the host, 3.5 inside python:3.12-slim). The command line given to OpenSSL
is fixed: the certificate goes in on stdin, so no file name or other input ever reaches the argument list.

Each row pairs the OIDs (read from the DER with a stdlib walker, no OpenSSL) with the exact text after
"Public Key Algorithm:" and "Signature Algorithm:" in `openssl x509 -inform DER -noout -text`.
"""
import json
import pathlib
import subprocess
import sys


def _tlv(der: bytes, i: int) -> tuple[int, int, int]:
    tag, length, i = der[i], der[i + 1], i + 2
    if length & 0x80:
        n = length & 0x7F
        length, i = int.from_bytes(der[i:i + n], "big"), i + n
    return tag, i, i + length


def _children(der: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    out, i = [], start
    while i < end:
        tag, s, e = _tlv(der, i)
        out.append((tag, s, e))
        i = e
    return out


def _oid(body: bytes) -> str:
    parts, val = [body[0] // 40, body[0] % 40], 0
    for b in body[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(map(str, parts))


def oids(der: bytes) -> tuple[str, str]:
    _, s, e = _tlv(der, 0)
    tbs, sigalg = _children(der, s, e)[:2]
    fields = _children(der, tbs[1], tbs[2])
    if fields[0][0] == 0xA0:  # explicit version
        fields = fields[1:]
    spki = fields[5]
    alg = _children(der, spki[1], spki[2])[0]
    spki_oid = _children(der, alg[1], alg[2])[0]
    sig_oid = _children(der, sigalg[1], sigalg[2])[0]
    return _oid(der[spki_oid[1]:spki_oid[2]]), _oid(der[sig_oid[1]:sig_oid[2]])


VERSION_CMD = ("openssl", "version")
TEXT_CMD = ("openssl", "x509", "-inform", "DER", "-noout", "-text")

rows = []
version = subprocess.run(VERSION_CMD, capture_output=True, text=True, check=True, shell=False).stdout.strip()
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.der")):
    der = path.read_bytes()
    text = subprocess.run(TEXT_CMD, input=der, capture_output=True, check=True,
                          shell=False).stdout.decode("utf-8", "replace")
    lines = {k: None for k in ("Public Key Algorithm", "Signature Algorithm")}
    for line in text.splitlines():
        key, _, value = line.strip().partition(":")
        if key in lines and lines[key] is None:
            lines[key] = value.strip()
    spki_oid, sig_oid = oids(der)
    rows.append({"cert": path.stem, "spki_oid": spki_oid, "sig_oid": sig_oid,
                 "public_key_text": lines["Public Key Algorithm"], "signature_text": lines["Signature Algorithm"]})
print(json.dumps({"openssl": version, "rows": rows}, indent=1))
