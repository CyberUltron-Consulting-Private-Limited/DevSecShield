#!/usr/bin/env python3
"""Judge a scan-node network run (``python -m zs_scan_node.collect --out run.json``) against an SSH lab oracle.

    python3 bench/cb13_ssh/judge.py ORACLE.json RUN.json [--cb02]

ORACLE is ``sshlab.py``'s ``oracle.json`` or, with ``--cb02``, a CB-02 lab ``oracle/run1.json`` (its ssh_endpoint
rows).  Per SSH target: the KEXINIT lists (OpenSSH's strict-KEX / ext-info markers dropped, as the CB-01 harness
does), every host key as (type, bits, SHA-256 fingerprint), and every host certificate's CA fingerprint and validity.
Imports nothing from the product.  Prints one JSON row per target and exits 1 when any differs.
"""
from __future__ import annotations

import base64
import json
import re
import sys

PSEUDO = re.compile(r"^(ext-info-[cs]|kex-strict-[cs]-v00@openssh\.com)$")


def _fp_hex(value: str | None) -> str:
    text = str(value or "")
    if text.upper().startswith("SHA256:"):
        raw = text[7:]
        return base64.b64decode(raw + "=" * (-len(raw) % 4)).hex()
    return text.lower()


def _algs(values) -> list[str]:
    return sorted({v for v in values or [] if not PSEUDO.match(v)})


def _targets(oracle: dict, cb02: bool) -> list[dict]:
    if not cb02:
        return oracle["targets"]
    out = []
    for t in oracle["targets"]:
        for a in t.get("assets") or []:
            if a.get("asset_type") == "ssh_endpoint":
                e = a["expect"]
                out.append({"id": t["target_id"], "address": t["address"], "kex": e.get("kex_algorithms"),
                            "host_key_algorithms": e.get("host_key_algorithms"), "ciphers": e.get("ciphers"),
                            "macs": e.get("macs"),
                            "host_keys": [{"type": k["type"], "bits": k["bits"],
                                           "fingerprint": k.get("fingerprint_sha256") or k.get("fingerprint")}
                                          for k in e.get("host_keys") or []]})
    return out


def judge(oracle: dict, run: dict, cb02: bool = False) -> list[dict]:
    eps = {a["target"]: a for a in run["assets"] if a["type"] == "ssh_endpoint"}
    rows = []
    for t in _targets(oracle, cb02):
        ep = eps.get(t["address"])
        row = {"id": t["id"], "address": t["address"], "present": ep is not None}
        if ep is None:
            rows.append({**row, "ok": False})
            continue
        f = ep["facts"]
        row["kex"] = _algs(f.get("kex")) == _algs(t["kex"])
        row["host_key_algorithms"] = _algs(f.get("host_key_algs")) == _algs(t["host_key_algorithms"])
        row["ciphers"] = _algs((f.get("ciphers_c2s") or []) + (f.get("ciphers_s2c") or [])) == _algs(t["ciphers"])
        row["macs"] = _algs((f.get("macs_c2s") or []) + (f.get("macs_s2c") or [])) == _algs(t["macs"])
        read = f.get("host_keys")
        if read is None:  # a node before CB-13 reports one negotiated key (the CB-01 harness reads the same fallback)
            one = f.get("host_key") or {}
            read = [] if one.get("error") or not one else [{"type": one.get("key_type"), "bits": one.get("bits"),
                                                            "fingerprint_sha256": one.get("fingerprint_sha256")}]
        plain = sorted((k["type"], k.get("bits"), _fp_hex(k.get("fingerprint_sha256") or k.get("fingerprint")))
                       for k in read if not k.get("certificate"))
        want = sorted((k["type"], k["bits"], _fp_hex(k["fingerprint"])) for k in t["host_keys"])
        row["host_keys"] = plain == want
        row["host_keys_read"] = len(plain)
        row["host_keys_expected"] = len(want)
        if not row["host_keys"]:
            row["host_keys_detail"] = {"read": plain, "expected": want}
        certs_want = {f"{k['type']}-cert-v01@openssh.com": k["certificate"] for k in t["host_keys"]
                      if k.get("certificate")}
        certs = {k["type"]: k["certificate"] for k in read if k.get("certificate")}
        if certs_want or certs:
            ca = _fp_hex(oracle.get("ca", {}).get("fingerprint"))
            row["certificates"] = set(certs) == set(certs_want) and all(
                _fp_hex(c["ca"]["fingerprint"]) == ca
                and c["valid_before"][:19] == certs_want[name]["valid_to"][:19]
                and c["valid_after"][:19] == certs_want[name]["valid_from"][:19] for name, c in certs.items())
        row["endpoint_algorithm_is_a_held_key"] = ep.get("algorithm") in {k["type"] for k in t["host_keys"]}
        row["host_keys_status"] = f.get("host_keys_status")
        row["ok"] = all(v for k, v in row.items() if isinstance(v, bool))
        rows.append(row)
    return rows


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 2:
        raise SystemExit(__doc__)
    with open(args[0], encoding="utf-8") as f:
        oracle_doc = json.load(f)
    with open(args[1], encoding="utf-8") as f:
        run_doc = json.load(f)
    result = judge(oracle_doc, run_doc, cb02="--cb02" in sys.argv)
    for r in result:
        print(json.dumps(r))
    raise SystemExit(0 if all(r["ok"] for r in result) else 1)
