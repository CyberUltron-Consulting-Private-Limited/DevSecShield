# AI-BOM ↔ Trusera dimension parity (chroma)

Evidence that the DevSecShield AI-BOM results page is **dimension-parity (and
then some)** with Trusera's reference HTML dashboard, on the same scan target,
and is themed natively to DevSecShield. Locked by CI (`aibom-gates.yml` Gate B +
`tests/test_dimension_parity.py`).

## Method

Same target — the pinned `chroma-core/chroma` fixture (`tests/fixtures/chroma`,
commit 207de398).

- **Trusera:** `ai-bom scan tests/fixtures/chroma -f html -o trusera_chroma.html`
  (Trusera `ai-bom` 3.6.0). Its dashboard surfaces a component count, a
  risk/severity distribution, and a provider breakdown.
- **Ours:** `scan_to_devsecshield(chroma)` → `generate_scan_dashboard("ai_bom")`
  (the exact code that serves the results page), inspected for each dimension.

## Dimension coverage

| Dimension | Our chart / field | Source field | Trusera HTML |
|---|---|---|---|
| Severity distribution | Risk-Metrics radar — `severity_distribution` | `impact` | ✅ yes |
| Component-type breakdown | `asset_type_distribution` | `component_type` | ◑ count only |
| OWASP LLM Top 10 | OWASP donut — `owasp_top_10_llm_issues` | `owasp_top_10_llm` | ❌ no |
| Provider distribution | `provider_distribution` | `source` | ✅ yes |
| License distribution | `license_distribution` | `license` | ❌ no |
| Risk-per-finding | Top-risks table — `top_risks` + `risk_category_distribution` | `impact` + `risk_category` | ✅ (risk dist) |
| **Compliance readiness** (bonus) | Compliance-Controls panel — `compliance_controls` | `ai_bom_compliance` | ❌ no |

On the chroma scan, every one of our dimensions is **non-empty** (`severity` 4,
`asset_type` 3, `owasp` 3, `provider` 9, `license` 7, `risk_category` 1,
`top_risks` 10, `compliance` 4). **We cover all six named dimensions plus
OWASP-LLM, license, and compliance — three dimensions Trusera's HTML does not
surface.**

## Theme parity (visually native to DevSecShield)

Our charts are **not** a separate visual language — they reuse the platform's:

- **Chart library:** `recharts` via `@/components/ui/chart` (`ChartContainer` /
  `ChartTooltip`) — the same shadcn/Recharts stack the SBOM/SAST results pages use
  (`frontend/components/ai-bom/AiBomVisualizations.tsx`,
  `frontend/components/AiBomResults.tsx`).
- **Severity palette:** mirrors `getImpactBadgeClass` — critical `#dc2626`
  (red-600), high `#f97316` (orange-500), medium amber, low blue — and the locked
  0–100 risk bands (`AiBomVisualizations.tsx` `C` token map).
- **Components:** shadcn `Card` / `Table` / `Badge`, same tokens and spacing.

## CI lock (no regression)

`.github/workflows/aibom-gates.yml`:

- **Gate A** — `tests/test_differential.py`: model/provider/framework recall vs the
  committed Trusera/Cisco oracles must stay ≥ threshold (model-recall regression →
  red).
- **Gate B** — `tests/test_chart_data_contract.py` + `test_chart_contract_severity.py`
  + `test_dimension_parity.py`: every results-page chart dimension must stay
  non-empty, the severity chart must keep a real multi-level breakdown, and the six
  Trusera-parity dimensions must all be present (empty/dropped chart → red).
- **Gate C** — golden lock (CycloneDX / SPDX / SARIF) — emitted-BOM drift → red.

The 71 MB chroma clone is git-ignored, so CI gates on the committed
`synthetic` / `trusera-demo` fixtures (chroma cells self-skip) — where a real
regression surfaces.

## Conclusion

Dimension-parity-or-more with Trusera, themed natively to DevSecShield, with both
the detection-recall and the empty-chart regressions blocked at CI.
