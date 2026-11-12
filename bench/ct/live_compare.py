#!/usr/bin/env python3
"""Row-by-row comparison of what the collector STORED (backend/scripts/ct_live_proof.py) with what the provider
answered (capture.py --cases live, fetched just before and just after the product's run), read with openssl.

Standard library + openssl only; imports nothing from the product (O-1).  A certificate that appears in the "after"
answer but not in the "before" one was logged during the run: the collector may or may not have it, and the report
says which.  Everything else must match exactly.

    python3 bench/ct/live_compare.py --collector collector.json --before DIR --after DIR --provider certspotter \\
        --report compare.md
Exit status 0 only when every row matches.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import oracle  # noqa: E402  (bench/ct/oracle.py: openssl)


def _bodies(folder: pathlib.Path, provider: str) -> dict[str, list]:
    """domain -> the listing's rows (pages joined) from capture.py --cases live."""
    manifest = json.loads((folder / "MANIFEST.json").read_text())
    out: dict[str, list] = {}
    for case in manifest["cases"]:
        name = case["case"]
        if case["status"] != "200":
            raise SystemExit(f"{name}: the provider answered {case['status']}; the oracle cannot judge this run")
        domain = name.split(f"_{provider}_", 1)[1].rsplit("_p", 1)[0] if provider == "certspotter" else name.split("_crtsh_", 1)[1]
        out.setdefault(domain, []).extend(json.loads((folder / name / "body").read_bytes()))
    return out


def _oracle_rows(bodies: dict[str, list], provider: str) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for domain, listing in bodies.items():
        for row in (oracle.certspotter(listing) if provider == "certspotter" else oracle.crtsh(listing)):
            entry = rows.setdefault(row["serial"], {**row, "domains": set()})
            entry["domains"].add(domain)
    return rows


FIELDS_CS = ("not_before", "not_after", "sig_alg", "key_bits", "dns_names", "subject_cn", "issuer_cn", "tbs_sha256",
             "revoked", "der_sha256")


def _expected(o: dict, provider: str) -> dict:
    if provider == "crtsh":
        return {"not_before": (o["not_before"] or "").split(".")[0] + "Z", "not_after": (o["not_after"] or "").split(".")[0] + "Z",
                "dns_names": sorted(o["dns_names"])[:50]}
    return {"not_before": o.get("not_before"), "not_after": o.get("not_after"), "sig_alg": o.get("sig_alg"),
            "key_bits": o.get("key_bits"), "dns_names": o.get("dns_names", [])[:50], "subject_cn": o.get("subject_cn"),
            "issuer_cn": o.get("issuer_cn"), "tbs_sha256": o.get("tbs_sha256"), "revoked": o.get("revoked"),
            "der_sha256": o.get("sha256"), "precert": o.get("precert_poison")}


def _actual(row: dict, provider: str) -> dict:
    f = row["facts"]
    import re

    cn = lambda dn: (re.search(r"(?:^|,)\s*CN=([^,]+)", dn or "") or [None, None])[1]  # noqa: E731
    if provider == "crtsh":
        return {"not_before": f.get("not_before"), "not_after": f.get("not_after"), "dns_names": sorted(f.get("san") or [])}
    return {"not_before": f.get("not_before"), "not_after": f.get("not_after"), "sig_alg": f.get("sig_alg"),
            "key_bits": row.get("key_size"), "dns_names": sorted(f.get("san") or []), "subject_cn": cn(f.get("subject")),
            "issuer_cn": cn(f.get("issuer")), "tbs_sha256": f.get("tbs_sha256"), "revoked": f.get("revoked"),
            "der_sha256": f.get("fingerprint_sha256") or f.get("precert_sha256"), "precert": f.get("precertificate_only")}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--collector", type=pathlib.Path, required=True)
    parser.add_argument("--before", type=pathlib.Path, required=True)
    parser.add_argument("--after", type=pathlib.Path, required=True)
    parser.add_argument("--provider", default="certspotter", choices=["certspotter", "crtsh"])
    parser.add_argument("--report", type=pathlib.Path, required=True)
    args = parser.parse_args()
    collected = json.loads(args.collector.read_text())
    before = _oracle_rows(_bodies(args.before, args.provider), args.provider)
    after = _oracle_rows(_bodies(args.after, args.provider), args.provider)
    stored = {r["facts"]["serial"]: r for r in collected["rows"] if r["asset_type"] == "certificate"}
    stable = set(before) & set(after)  # logged before the run and still listed after it
    moving = (set(before) | set(after)) - stable  # logged or dropped while the run was going
    problems: list[str] = []
    missing = sorted(stable - set(stored))
    extra = sorted(set(stored) - set(before) - set(after))
    problems += [f"missing from the collector: {s}" for s in missing]
    problems += [f"stored but not in the provider's answer: {s}" for s in extra]
    lines = ["| serial | domains | field checks | result |", "|---|---|---|---|"]
    checked = 0
    for serial in sorted(stable & set(stored)):
        want, got = _expected(after[serial], args.provider), _actual(stored[serial], args.provider)
        bad = [f"{k}: want {want[k]!r} got {got.get(k)!r}" for k in want if want[k] != got.get(k)]
        doms = sorted(after[serial]["domains"])
        if sorted(stored[serial]["facts"].get("matched_domains") or []) != doms:
            bad.append(f"matched_domains: want {doms} got {stored[serial]['facts'].get('matched_domains')}")
        checked += 1
        problems += [f"{serial}: {b}" for b in bad]
        lines.append(f"| {serial} | {','.join(doms)} | {len(want) + 1} | {'OK' if not bad else 'MISMATCH: ' + '; '.join(bad)[:300]} |")
    summary = {
        "provider": args.provider, "collector_job": collected["job"]["status"], "collector_outcome": collected["job"]["outcome"],
        "oracle_before": len(before), "oracle_after": len(after), "stable": len(stable),
        "logged_during_run": sorted(moving), "stored_certificates": len(stored), "rows_compared": checked,
        "missing": missing, "extra": extra, "mismatches": len(problems), "provider_calls": collected["job"]["result"].get("provider_calls"),
        "wall_s": collected["job"].get("wall_s"), "charged_credits": collected["run"]["charged_c"] / 100,
    }
    report = [f"# CT live proof ({args.provider})", "", "```json", json.dumps(summary, indent=1), "```", "", *lines]
    args.report.write_text("\n".join(report) + "\n")
    args.report.with_suffix(".json").write_text(json.dumps({"summary": summary, "problems": problems}, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    for problem in problems[:50]:
        print("PROBLEM", problem)
    return 0 if not problems and collected["job"]["status"] == "success" and checked > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
