#!/usr/bin/env python3
"""Generate bench/certin/report.md from oracle outs + matrix JSON."""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CBOM = ROOT / "bench" / "cbom"
SBOM = ROOT / "bench" / "sbom"
MATRIX = Path("/tmp/certin_phase6_matrix.json")


def main() -> int:
    lines = [
        "# CERT-In Phase 6 — Multi-BOM benchmark report",
        "",
        "> Advisory alignment to CERT-In Technical Guidelines v2.0 only.",
        "> **Does not constitute CERT-In certification.**",
        "",
        "## Claim language (evidence only)",
        "",
        "- **Oracle parity:** `true-miss == 0` vs published/frozen oracles where a",
        "  snapshot exists (CBOM: cbomkit-theia + cdxgen; SBOM: cdxgen inventory;",
        "  AIBOM: Trusera/Cisco when runnable).",
        "- **OurUnique > 0:** source-level depth the filesystem/dep oracles",
        "  structurally cannot see (algorithms in code, AI model refs, etc.).",
        "",
        "## CBOM oracle baselines",
        "",
    ]
    base = CBOM / "ci_baseline"
    for p in sorted(base.glob("*.cdx.json")):
        lines.append(f"- `{p.name}` ({p.stat().st_size} bytes)")
    lines += ["", "## SBOM inventory baselines", ""]
    sbase = SBOM / "ci_baseline"
    if sbase.is_dir():
        for p in sorted(sbase.glob("*.json")):
            lines.append(f"- `{p.name}`")
    else:
        lines.append("- _(none yet — run `bash bench/certin/run_matrix.sh --sbom-oracles`)_")

    lines += ["", "## Live product matrix", ""]
    if MATRIX.exists():
        data = json.loads(MATRIX.read_text(encoding="utf-8"))
        lines.append(f"- ok: `{data.get('ok')}`")
        lines.append(f"- cells: `{len(data.get('cells') or [])}`")
        for cell in data.get("cells") or []:
            lines.append(
                f"- `{cell.get('id')}` lane={cell.get('lane')} "
                f"status={cell.get('status')} scan_id={cell.get('scan_id')} "
                f"secs={cell.get('duration_s')} cert_in={cell.get('cert_in_ok')} "
                f"posture={cell.get('posture_ok')}"
            )
        deep = data.get("deep") or {}
        if deep:
            lines += ["", "### Deep attest/sign/VEX/pack", ""]
            for k, v in deep.items():
                lines.append(f"- `{k}`: `{v}`")
    else:
        lines.append("- `/tmp/certin_phase6_matrix.json` not present yet")

    lines += [
        "",
        "## Product UI locks",
        "",
        "- India / CERT-In chip present; `defaultGroup` remains `all`",
        "- Zero product-FE `\\bQBOM\\b`",
        "- HBOM deferred copy on CertInRollup",
        "",
    ]
    out = HERE / "report.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
