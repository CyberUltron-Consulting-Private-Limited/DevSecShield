# RBI FREE-AI + CERT-In AIBOM — finding-centric drilldown (plan)

**Date:** 2026-08-09  
**Status:** DIAGNOSED → IMPLEMENT  
**Ruflo keys (on verify):** `rbi-freeai-finding-detail-verified`, `certin-aibom-oos-finding-detail-verified`

---

## Symptom (user paste)

FREEAI-16-* / FREEAI-7-1 / FREEAI-6-1 and CERT-In T10-Model-* show:

- verdict: **out of scope**
- Why: “no AI model(s)…”
- How to resolve: “Not applicable to this scan”

User wants finding-centric **issue / description**, not OOS boilerplate, when the team has AIBOM models/findings.

---

## Evidence (team 1 Postgres)

| Scan | Inventory | `rbi_free_ai` | `cert_in_aibom` |
|------|-----------|---------------|-----------------|
| **#109** (latest SUCCESS) | 14× `ml_framework` only, **0 models** | oos=24 | oos=32 |
| **#108 / #95** | 148 models in graph | fail=11 (e.g. FREEAI-16-1: 86 lack model-card) | fail=1 (T10-Model-Version) |

Team builders `build_team_rbi_posture_from_scans` / `build_team_certin_posture_from_scans` pick **latest SUCCESS per type** → **#109** → team dashboard drilldown shows OOS for FREEAI-* and T10-* even though #108 is in-scope.

Secondary gap: AIBOM `_finding_from_component` omits `bom_ref` (CBOM normalize already emits it; `findings.py` already reads it). Related-findings join under-counts (refs are `modelref-*`).

---

## Root causes

1. **Team posture selection** — latest SUCCESS may be framework-only OOS; poisons FREEAI/T10 on team UI.  
2. **Missing `bom_ref` on AIBOM findings** — drilldown “View related findings” / counts cannot join inventory refs.  
3. **Drilldown copy** — fail/NBE already carry evidence, but UI labels everything as “Why:” and OOS copy dominates; no inline finding title/description samples.  
4. **Product policy (NOT a false OOS on #109 alone)** — applicability `models(r)` empty → OOS is correct for model governance when the scan truly has no models. Confirm: keep OOS for framework-only scans; do not broaden applicability.

---

## Fix (no applicability fork)

| # | Change | Files |
|---|--------|-------|
| A | Prefer latest SUCCESS AIBOM whose `rbi_free_ai` / `cert_in_aibom` is **not all-OOS** (pass+fail+nbe+pwe > 0); fallback to latest | `rbi_posture.py`, `certin_posture.py` + tests |
| B | Emit `bom_ref` on AIBOM finding rows | `aibom/.../devsecshield.py` + adapter test |
| C | Drilldown: fail/NBE → **Issue** + **Description** (matched findings); asset labels from graph aliases; OOS de-emphasized when findings exist | `RbiCsfRequirementDrilldown.tsx`, `CertInRequirementDrilldown.tsx` (+ tiny shared helper if needed) |
| D | Plan/verify docs + Ruflo verified keys; live check team posture FREEAI-16-1 + T10-Model-Version vs #108 |

---

## Before / after — FREEAI-16-1 (team posture)

| | Before | After |
|--|--------|-------|
| Team pick | #109 OOS “no AI model” | #108 fail “86 model(s) lack technical model-card…” |
| resolve_hint | Not applicable | Fix related assets / findings |
| Related findings | ~0–5 (no bom_ref) | Joins via bom_ref + aliases; inline Issue/Description |

---

## Out of scope

- Broadening `register_applicability` to frameworks-only (would NA/fail dishonestly).  
- Persisting synthetic posture rows into `results[]`.  
- Git push / commit.
