#!/usr/bin/env python3
"""Independent oracle for CT discovery: what each recorded provider answer says, read with openssl, not product code.

Standard library plus the ``openssl`` command (O-3: a tool that shares no code with the collector, which parses DER
with the Python ``cryptography`` package).  Imports nothing from backend/, aibom/, scan_node/ or frontend/.

    python3 bench/ct/oracle.py certspotter BODY_FILE > oracle.json     # one Cert Spotter answer (a JSON list)
    python3 bench/ct/oracle.py crtsh BODY_FILE > oracle.json           # one crt.sh answer

Cert Spotter: one row per issuance id with, from the DER: serial (lower hex, no leading zeros), subject and issuer
(RFC 2253), notBefore/notAfter (UTC, ``YYYY-MM-DDTHH:MM:SSZ``), signature algorithm, public-key algorithm and bits,
DNS SANs, SHA-256 of the DER and whether it carries the precertificate poison extension; plus the provider's own
tbs_sha256, cert_sha256, revoked and issuer friendly name, unchanged.
crt.sh: one row per (serial, issuer CA id), the provider's fields unchanged (crt.sh gives no DER).
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import re
import subprocess
import sys

POISON = "1.3.6.1.4.1.11129.2.4.3"


def _time(text: str) -> str:
    # openssl: "Nov 22 09:54:09 2026 GMT"
    moment = _dt.datetime.strptime(" ".join(text.split()), "%b %d %H:%M:%S %Y %Z")
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_der(der: bytes) -> dict:
    def run(*args: str) -> str:
        return subprocess.run(["openssl", "x509", "-inform", "DER", "-noout", *args], input=der, capture_output=True,
                              check=True).stdout.decode("utf-8", "replace")

    text = run("-text", "-certopt", "ext_parse")
    fields = run("-serial", "-subject", "-issuer", "-startdate", "-enddate", "-nameopt", "RFC2253")
    out: dict = {}
    for line in fields.splitlines():
        key, _, value = line.partition("=")
        if key == "serial":
            out["serial"] = value.strip().lower().lstrip("0") or "0"
        elif key == "subject":
            out["subject"] = value.strip()
        elif key == "issuer":
            out["issuer"] = value.strip()
        elif key == "notBefore":
            out["not_before"] = _time(value)
        elif key == "notAfter":
            out["not_after"] = _time(value)
    sig = re.search(r"Signature Algorithm:\s*(\S+)", text)
    out["sig_alg"] = sig.group(1) if sig else None
    pk = re.search(r"Public Key Algorithm:\s*(\S+)", text)
    out["pubkey_alg"] = pk.group(1) if pk else None
    bits = re.search(r"Public-Key:\s*\((\d+) bit\)", text)
    out["key_bits"] = int(bits.group(1)) if bits else None
    curve = re.search(r"NIST CURVE:\s*(\S+)", text)
    out["curve"] = curve.group(1) if curve else None
    sans = re.search(r"X509v3 Subject Alternative Name:\s*(?:critical)?\s*\n\s*(.+)", text)
    out["dns_names"] = sorted(n.strip()[4:] for n in (sans.group(1).split(",") if sans else []) if n.strip().startswith("DNS:"))
    out["precert_poison"] = POISON in text or "CT Precertificate Poison" in text
    out["sha256"] = hashlib.sha256(der).hexdigest()
    cn = re.search(r"(?:^|,)CN=([^,]+)", out.get("subject") or "")
    out["subject_cn"] = cn.group(1) if cn else None
    icn = re.search(r"(?:^|,)CN=([^,]+)", out.get("issuer") or "")
    out["issuer_cn"] = icn.group(1) if icn else None
    return out


def certspotter(rows: list) -> list:
    out = []
    for row in rows:
        der = base64.b64decode(row["cert_der"]) if row.get("cert_der") else None
        entry = {"id": row["id"], "tbs_sha256": row.get("tbs_sha256"), "cert_sha256": row.get("cert_sha256"),
                 "revoked": row.get("revoked"), "issuer_friendly_name": (row.get("issuer") or {}).get("friendly_name"),
                 "provider_dns_names": sorted(row.get("dns_names") or [])}
        if der:
            entry.update(read_der(der))
        out.append(entry)
    return out


def crtsh(rows: list) -> list:
    seen: dict = {}
    for row in rows:
        key = ((row.get("serial_number") or "").lower().lstrip("0"), row.get("issuer_ca_id"))
        seen.setdefault(key, {"id": row["id"], "serial": key[0], "issuer_ca_id": row.get("issuer_ca_id"),
                              "issuer": row.get("issuer_name"), "common_name": row.get("common_name"),
                              "dns_names": sorted(n for n in (row.get("name_value") or "").split("\n") if n),
                              "not_before": row.get("not_before"), "not_after": row.get("not_after")})
    return sorted(seen.values(), key=lambda r: (r["serial"], str(r["issuer_ca_id"])))


def main() -> int:
    kind, path = sys.argv[1], sys.argv[2]
    with open(path, "rb") as fh:
        rows = json.loads(fh.read())
    result = certspotter(rows) if kind == "certspotter" else crtsh(rows)
    json.dump({"kind": kind, "source": path.rsplit("/", 2)[-2] if "/" in path else path, "tool": "openssl x509",
               "rows": result}, sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
