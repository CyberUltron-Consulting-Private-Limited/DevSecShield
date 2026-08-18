# RBI CSF posture — findings transparency (diagnosis + plan)

> **Status:** DIAGNOSIS + PLAN ONLY — do not implement until user confirms.
> **Date:** 2026-08-09
> **Style authority:** existing BOM results pages + CERT-In posture components (`CertInRequirementDrilldown`, findings detail dialogs).

---

## Goal

Give users full transparency on **RBI CSF posture** requirements: description / why, location / related assets, how to fix, and related findings — either by enriching the CSF drilldown (CERT-In pattern) or by converting posture gaps into findings that reuse the existing finding detail card.

---

## Brainstorm — 3 architectural hypotheses (pre-code)

| # | Hypothesis | Likelihood |
|---|------------|------------|
| H1 | `rbi_posture._rollup_pillar` strips `evidence`/`refs`/`source`/`attestable` the same way pre-fix CERT-In `_rollup_dimension` did; UI only renders title+verdict. | **Confirmed** |
| H2 | Compliance blobs lack location/fix detail, so enrichment alone cannot satisfy “findings-quality” transparency without synthesizing from refs. | Partially true — blobs have why+refs+attestable; file `location` lives on finding/graph rows, not on requirements |
| H3 | Best UX is materializing synthetic finding rows into `scan_data.results` so one card serves all. | Risky — inventory/counts/attestation/export collisions |

---

## Evidence (live, team 1 Postgres)

Scans inspected directly from DB (backend HTTP was down; data is live SUCCESS scans):

| Scan | Type | Compliance blob requirement keys | Rollup requirement keys after `build_rbi_csf_rollup` |
|------|------|----------------------------------|-----------------------------------------------------|
| **#91** SBOM | `sbom_compliance` | `id, title, source, verdict, evidence, refs, attestable` | **`id, framework, title, verdict` only** |
| **#94** CBOM | `cbom_compliance` | same 7 keys | same strip |
| **#95** AIBOM | `ai_bom_compliance` | same 7 keys | same strip |

### Concrete strip examples

**SBOM #91 — identification fail (blob vs rollup)**

- Blob `FREEAI-SUPPLY-1`: `evidence='7 dependenc(ies) lack name or version'`, `refs=['sbom-dep-90',…]`, `attestable=False`, `source` present
- Rollup row: `{"id":"FREEAI-SUPPLY-1","framework":"rbi_free_ai_supply","verdict":"fail","title":"Dependency inventory: …"}` — **no evidence/refs/source**

**CBOM #94 — protection fail**

- Blob `FREEAI-PROT-3`: evidence cites **59 hardcoded keys**, refs are `crypto-material-misuse-…` bom-refs
- Rollup: title+verdict only

**AIBOM #95 — governance fail**

- Blob `FREEAI-23-1`: evidence `148 model(s) lack name or version`, refs `modelref-*`
- Rollup: title+verdict only

**NBE process controls** (e.g. `FREEAI-PROT-7`, `FREEAI-22`, `FREEAI-SUPPLY-6`): blob has `attestable=True` + process evidence text; rollup drops both → no “how to resolve / attach attestation” path in CSF UI.

### Prior art (CERT-In) — already fixed this class of bug

Ruflo memory `certin-nbe-drilldown-diagnosis`:

> root_cause: `certin_posture._rollup_dimension` strips evidence/refs/source/attestable; UI table only shows title  
> fix: enrich posture requirements + drilldown like ComplianceMatrix with attest + findings link for refs

Live CERT-In code now keeps `evidence`, `refs`, `source`, `attestable`, `resolve_hint` in `_rollup_dimension` and renders them in `CertInRequirementDrilldown` (+ “View related findings”).

RBI path did **not** get the same enrichment:

```77:84:backend/utilities/dashboard/rbi_posture.py
        sources.append(
            {
                "id": str(r.get("id")),
                "framework": str(r.get("_framework")),
                "verdict": v,
                "title": str(r.get("title") or ""),
            }
        )
```

```198:204:frontend/components/rbi/RbiCsfRollup.tsx
                {activeReqs.map((r) => (
                  <TableRow key={`${r.framework}-${r.id}`}>
                    <TableCell>{verdictBadge(r.verdict)}</TableCell>
                    <TableCell className="font-mono text-xs">{r.id}</TableCell>
                    <TableCell className="text-sm">{r.title}</TableCell>
                    <TableCell className="text-xs text-zinc-500">{r.framework}</TableCell>
                  </TableRow>
                ))}
```

### Adjacent UX (partial, not CSF)

- Per-BOM **ComplianceMatrix** / `ComplianceCoverage` already shows `evidence` (+ optional attest) for frameworks including `rbi_free_ai*` when those blobs are on the results page.
- That is **not** the CSF pillar rollup, and the **team dashboard** only mounts `RbiCsfRollup` — so team-level CSF posture has zero why/how/related.
- Findings detail dialogs (Cbom/AiBom/Sbom) already show description, location, suggested_fix, compliance tags — but those rows are **asset/vuln inventory**, not FREE-AI requirement verdicts.

### Ruflo memory search

- Hit: `rbi-csf-findings-transparency-kickoff` (goal = this work; status diagnosing)
- Hit: `certin-nbe-drilldown-diagnosis` / `verified` (identical strip→enrich pattern)

---

## UI gap map

| Capability | CERT-In drilldown | Findings detail card | RBI CSF drilldown **today** |
|------------|-------------------|----------------------|-----------------------------|
| Title / ID | ✅ | ✅ (name/title) | ✅ title+id |
| Why (evidence/description) | ✅ | ✅ description | ❌ stripped |
| How to fix / resolve_hint | ✅ | ✅ suggested_fix | ❌ |
| Citation / source | ✅ | partial | ❌ stripped |
| Related assets (refs) | ✅ count + button | via related filter | ❌ stripped |
| Location (file path) | via findings link | ✅ on finding | ❌ (not on requirement) |
| Attestation upload (NBE) | ✅ | ❌ (wrong model) | ❌ |
| Risk score / impact | n/a | ✅ | n/a |
| Appears in findings table counts | no | yes | no |

---

## Options (≥3)

### A) Enrich RBI CSF drilldown like CERT-In

**What:** Mirror `certin_posture._rollup_dimension` in `rbi_posture._rollup_pillar` (passthrough evidence/refs/source/attestable + compute `resolve_hint`). Replace thin table in `RbiCsfRollup` with shared/adapted drilldown (reuse `CertInRequirementDrilldown` or extract `PostureRequirementDrilldown`). Wire `onViewFindings` / `onAttest` on BOM results pages the same way as `CertInLanePosture`.

**Pros:** Proven fix for identical root cause; no findings inventory pollution; NBE attestation stays in compliance model; team + scan pages both benefit; small diff; style authority already exists.

**Cons:** File `location` still indirect (via related findings); does not open the findings Dialog itself; team page may lack attest/view-findings handlers unless threaded.

### B) Materialize synthetic finding rows from RBI fails/NBE

**What:** For each fail/NBE in rollup (or FREE-AI frameworks), emit a finding-shaped object (`title`, `description`←evidence, `suggested_fix`←resolve_hint, `location`←first ref or graph label, `compliance_controls`←`RBI_CSF_*` / FREEAI id) and open existing Finding detail Dialog.

**Variants:**
- **B-persist:** append into `scan_data.results` at normalize/adapter time  
- **B-virtual:** client-only list / dialog payload, never in persisted results  

**Pros:** One familiar card; users who think in “findings” get the same chrome; location can be projected from bom-ref→graph/finding.

**Cons / risks:**
- **Inventory duplication:** fails already have underlying crypto/model/CVE findings; counting posture rows inflates remediation KPIs / export / Jira.
- **ID collisions:** findings use Mongo ObjectIds; synthetic IDs must be namespaced (`rbi-req:FREEAI-PROT-3`) and never collide with ObjectIds or bom-refs.
- **Attestation mismatch:** NBE is process attestation, not finding remediation status — stuffing into findings loses upload/attest flow or forks it badly.
- **B-persist** breaks hermetic contracts / PDF fixtures / differential counts unless carefully excluded.
- SBOM finding shape lacks consistent `location`/`id` fields vs CBOM/AIBOM — card mapping is per-scanner fragile.

### C) Hybrid — enriched drilldown + “Open as finding” / deep-link

**What:** Do **A** fully. Additionally, for fail rows with `refs`, offer:
1. **View related findings** (existing `relatedFindingMatch` + filter) — already proven path for CERT-In, and  
2. Optional **Open detail** that opens a findings-style Dialog fed by a **virtual** finding mapped from the requirement (B-virtual, not persisted).

**Pros:** Maximum transparency; reuses both style authorities; no inventory pollution; attestation stays on drilldown; deep-link satisfies “reuse findings card” without B-persist risks.

**Cons:** Two surfaces (drilldown + optional dialog); slightly more FE work; must keep virtual finding out of table selection / bulk Jira.

---

## Recommendation (evidence-backed)

**Recommend Option C (Hybrid), phased: ship A first, then optional B-virtual dialog.**

### Why not B-persist / pure B

Live blobs already carry why + refs + attestable. The gap is **rollup stripping + thin UI**, not missing data. CERT-In solved the same bug without inventing findings. Persisting posture-as-findings would duplicate CBOM #94’s 59 key findings under a FREEAI-PROT-3 umbrella row and confuse remediation/attestation.

### Why not A alone forever

Users explicitly asked for findings-card parity (location / how-to-fix chrome). A virtual dialog (or deep-link into filtered findings) closes that without inventory risk.

### Phased delivery

1. **P0 — A:** backend passthrough + resolve_hint; FE drilldown parity with CERT-In; wire `onViewFindings` on scan results; team page: enrich display (attest/view optional / deferred).
2. **P1 — C extras:** “Open requirement detail” virtual finding dialog OR deep-link `?findingFilter=related&refs=…` into findings table.
3. **Out of scope unless requested:** B-persist into `results[]`; new RBI-specific attestation API (reuse existing attestations map / CERT-In attest handler if framework keys already work).

---

## Devil’s advocate / contradiction review

| Challenge | Resolution |
|-----------|------------|
| “False positive — ComplianceMatrix already shows evidence” | True for per-framework matrix on BOM pages; **false** for CSF pillar rollup + team dashboard. User asked about RBI CSF posture specifically. |
| “Maybe rollup intentionally thin for size” | Team rollup merges 3 BOMs; still only dozens of FREE-AI IDs. CERT-In already ships full evidence lists. Size not a credible constraint. |
| “Synthetic findings are what user asked for” | Honor via **B-virtual / Open detail**, not B-persist. Confirm with user before coding. |
| “Attestation on team rollup is hard (multi-scan)” | Correct — team merge crosses scans. Prefer attest only on **per-scan** RBI drilldown; team = read-only enriched why/how + link to originating scan if `_scanner` exposed (already on internal req before strip — currently dropped too). **Pass through `_scanner` as well.** |
| “resolve_hint would be generic” | Acceptable — CERT-In uses generic hints; blob `evidence` carries the specific why. Optional later: FREE-AI ledger descriptions like CERT-In ledger overlay. |

---

## Proposed implementation sketch (only after confirm)

### Backend

- Modify `backend/utilities/dashboard/rbi_posture.py` `_rollup_pillar` to mirror CERT-In enrichment fields (`source`, `evidence`, `refs`, `attestable`, `resolve_hint`, `_scanner`).
- Optionally extract shared `_resolve_hint` helper to avoid drift with `certin_posture._resolve_hint`.
- Extend `backend/tests/test_rbi_csf_rollup.py` to assert fail/NBE rows retain evidence/refs/attestable/resolve_hint.

### Frontend

- Widen `PillarRollup.requirements` type in `RbiCsfRollup.tsx`.
- Replace thin table with shared drilldown component (prefer extract `PostureRequirementDrilldown` from CERT-In, or reuse `CertInRequirementDrilldown` with generic labels).
- On `CbomResults` / `AiBomResults` / `SbomResults`: pass `onViewFindings={handleViewRelatedFindings}` and existing attest handler where FREE-AI NBE attest already works via compliance attestations.
- Team `page.tsx`: enriched read-only drilldown first; no attest unless product confirms multi-scan semantics.

### Do not

- Append synthetic rows to persisted `results`
- Change FREE-AI check predicates / YAML pillar maps (unless a mapping bug is separately found)
- `git stash` / push

---

## Verification plan (post-implement)

1. Hermetic: `backend/tests/test_rbi_csf_rollup.py` + FE typecheck on touched files.
2. Live DB/API: rebuild rollup for scans 91/94/95 — assert protection/identification fail rows include evidence + refs.
3. Dev-browser: open team 1 CBOM #94 results → click RBI CSF Protection bar → see Why / How / Related assets → View related findings filters HARDCODED_KEY-like rows.
4. Confirm findings table **count unchanged** (no synthetic persist).
5. NBE row shows attach affordance on scan page when attest wired.

---

## Verifying questions (for user / parent)

Answer these before coding:

1. **Preferred option?** Confirm **C (enrich drilldown + optional open-as-finding)**, **A only**, or **B-persist** despite inventory risks?
2. **Team dashboard:** read-only enriched drilldown OK, or must team CSF also support attestation / jump-to-scan?
3. **“Open as finding”:** virtual dialog OK, or must the row appear in the findings **table** (counts/export)?
4. **Scope of related findings:** only FREE-AI fails with refs, or also map NBE→empty related + attest only?
5. **Share CERT-In drilldown component** (genericize) vs duplicate a thin `RbiRequirementDrilldown`?
6. **Pass through `_scanner`** on team merge so multi-BOM rows show `ai_bom|cbom|sbom` source column?

---

## Confirmation gate

**STOP.** No code changes until the user answers the verifying questions and explicitly confirms an option.
