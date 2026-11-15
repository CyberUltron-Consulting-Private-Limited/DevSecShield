"""Build backend/utilities/cbom_sources/data/tls_cipher_suites.json: TLS cipher suites by IANA code, with their IANA
name and every OpenSSL name, from the vendored sources below (nothing is typed from memory).

Inputs (sources/, sha256 recorded in the output):
  iana-tls-parameters-4.csv            IANA "TLS Cipher Suites" registry (tls-parameters-4.csv), fetched 2026-11-12
  openssl-3.0.13-...-COMPLEMENTOFALL.txt  `openssl ciphers -V -stdname ALL:COMPLEMENTOFALL`, OpenSSL 3.0.13
  openssl-3.5-...-COMPLEMENTOFALL.txt     the same command, OpenSSL 3.5.7 (the scan node image's openssl; the same
                                          suites, codes and names as CB-12's scan_node/tests/fixtures/iana copy)
  openssl-1.1.1-ciphers.pod            OpenSSL_1_1_1-stable doc/man1/ciphers.pod ("CIPHER SUITE NAMES" tables)
  openssl-1.0.2-ciphers.pod            OpenSSL_1_0_2-stable doc/apps/ciphers.pod (adds EXPORT, single DES, EDH- names)

Rules: the IANA code and name always come from the registry (rows named Unassigned / Reserved are left out). An
OpenSSL name comes from a `-stdname` line (code, standard name, OpenSSL name) or from a man-page table row
(standard name, OpenSSL name; ``SSL_`` standard names are the SSLv3 spellings of the same ``TLS_`` code points). The
build fails when two sources disagree: an OpenSSL name on two codes, or a `-stdname` standard name that is not the
registry's name for its code. Every OpenSSL name is listed, also one equal to the IANA name.

This is the product's one TLS cipher suite table (CB-06 owns it; CB-12 and every other reader go through
``backend/utilities/cbom_sources/tls_suites.py``, never the JSON).

Usage: python scripts/tls_suites/build_table.py [out.json]   (deterministic: sorted, no timestamps)
"""
from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sources")
OUT = os.path.join(HERE, "..", "..", "backend", "utilities", "cbom_sources", "data", "tls_cipher_suites.json")
IANA = "iana-tls-parameters-4.csv"
STDNAME = ("openssl-3.0.13-ciphers-V-stdname-ALL-COMPLEMENTOFALL.txt", "openssl-3.5-ciphers-V-stdname-ALL-COMPLEMENTOFALL.txt")
PODS = ("openssl-1.1.1-ciphers.pod", "openssl-1.0.2-ciphers.pod")
_CODE = re.compile(r"^0x([0-9A-F]{2}),0x([0-9A-F]{2})$")
_STD = re.compile(r"^\s*0x([0-9A-F]{2}),0x([0-9A-F]{2}) - (\S+)\s+- (\S+)\s")
_POD = re.compile(r"^ ((?:SSL|TLS)_[A-Za-z0-9_]+)\s+([A-Za-z0-9][A-Za-z0-9_.-]*)\s*$")


def _sha256(name: str) -> str:
    with open(os.path.join(SRC, name), "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def build() -> dict:
    by_code: dict[str, dict] = {}
    by_name: dict[str, str] = {}
    with open(os.path.join(SRC, IANA), newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            m = _CODE.match(row["Value"].strip())
            name = row["Description"].strip()
            if not m or not name.startswith("TLS_"):  # ranges, Unassigned, Reserved, *_SCSV kept (they are TLS_)
                continue
            code = f"0x{m.group(1)},0x{m.group(2)}"
            by_code[code] = {"code": code, "iana": name, "openssl": []}
            by_name[name] = code
    owner: dict[str, str] = {}

    def add(code: str, openssl: str, where: str) -> None:
        if openssl in owner and owner[openssl] != code:
            raise SystemExit(f"{where}: OpenSSL name {openssl} on {owner[openssl]} and {code}")
        owner[openssl] = code
        if openssl not in by_code[code]["openssl"]:  # also when it equals the IANA name (the TLS 1.3 suites)
            by_code[code]["openssl"].append(openssl)

    for name in STDNAME:
        with open(os.path.join(SRC, name), encoding="utf-8") as fh:
            for line in fh:
                m = _STD.match(line)
                if not m:
                    continue
                code, std, openssl = f"0x{m.group(1)},0x{m.group(2)}", m.group(3), m.group(4)
                if code not in by_code or by_code[code]["iana"] != std:
                    raise SystemExit(f"{name}: {code} {std} is not the IANA registry's name "
                                     f"({by_code.get(code, {}).get('iana')})")
                add(code, openssl, name)
    for name in PODS:
        with open(os.path.join(SRC, name), encoding="utf-8") as fh:
            for line in fh:
                m = _POD.match(line)
                if not m or m.group(2) in ("Not", "Not implemented."):
                    continue
                std = "TLS_" + m.group(1)[4:] if m.group(1).startswith("SSL_") else m.group(1)
                code = by_name.get(std)
                if code is None:  # FORTEZZA, GOST and other names the registry does not hold under that spelling
                    continue
                add(code, m.group(2), name)
    for entry in by_code.values():
        entry["openssl"].sort()
    return {
        "about": "TLS cipher suites: IANA code (CycloneDX cipherSuites[].identifiers), IANA name, OpenSSL names. "
                 "Generated by scripts/tls_suites/build_table.py; do not edit by hand.",
        "sources": [{"file": f"scripts/tls_suites/sources/{name}", "sha256": _sha256(name)}
                    for name in (IANA, *STDNAME, *PODS)],
        "suites": sorted(by_code.values(), key=lambda e: e["code"]),
    }


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else OUT
    doc = build()
    # one suite per line: a reviewable diff when a source changes
    rows = ",\n".join(json.dumps(e, sort_keys=True, ensure_ascii=True) for e in doc["suites"])
    head = {k: v for k, v in doc.items() if k != "suites"}
    text = json.dumps(head, indent=1, sort_keys=True, ensure_ascii=True)[:-2] + ',\n "suites": [\n' + rows + "\n]\n}\n"
    json.loads(text)  # the hand-joined document is valid JSON
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {out} ({len(text)} bytes)")


if __name__ == "__main__":
    main()
