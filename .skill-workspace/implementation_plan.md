# CBOM Certificate Expiry Chart — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use skill-executing-plans after user confirms.

**Goal:** Make the Certificate expiry panel truthful and useful: clearer empty state on zero-cert scans, and a per-certificate validity view when certs exist (using fields already in `cbom_distributions.certificates`).

**Architecture:** Frontend-only change in `frontend/components/cbom/CbomCryptoCharts.tsx` (CertificateExpiry). Backend normalize already emits name / not_valid_after / expired / near_expiry / self_signed / weak_*. No worker restart. Extend FE types + chart-data contract comments if needed; keep hermetic aibom contract green.

**Tech stack:** React / Recharts / existing CbomCryptoCharts patterns.

---

## 0. Pre-Flight

- [x] API: card `total_certificates` == `len(cbom_distributions.certificates)` on scans 94/80/79/78/81
- [x] Normalize fixture emits cert rows
- [x] Empty message only when `certificates` empty
- [ ] User confirms scope (below)
- [ ] No coding until confirm

---

## Scope options (pick one)

### A — Recommended: FE UX + detail list (this plan)
1. Empty copy → "No X.509 certificates in this scan" (+ short hint when other crypto charts have data)
2. When certs exist: keep Valid/Expired/Self-signed bars **and** add compact list: name · not_valid_after · badges (Expired / Near expiry / Self-signed)
3. Extend FE `CbomDistributions.certificates` type with optional near_expiry / weak_* already present in payload
4. Verify: temp no-auth route OR live scan **#80** (32 certs) + scan **#78** (0 certs empty copy)
5. `tsc --noEmit` + scoped eslint; no aibom change unless contract test needs type note

### B — Do nothing (document as expected)
Only if user confirms they were on a 0-cert repo (e.g. pyopenssl #78) and empty is acceptable.

### C — Detection expansion (OUT OF SCOPE unless proven)
Investigate whether a specific repo has `.pem`/`.crt` on disk that C2 missed. Requires reproduction target + fixture; separate CBOM scanner story.

---

## Fix group A1 — Empty state copy

**Files:** `frontend/components/cbom/CbomCryptoCharts.tsx`  
**Change:** Replace `EmptyChart message="No certificates detected"` with clearer wording; optionally pass `hasOtherCrypto` if useful.  
**Verify:** Scan #78 / fixture with empty certificates array shows new copy.  
**Risk:** Low

## Fix group A2 — Per-cert expiry list

**Files:** same + type fields on `CbomDistributions.certificates`  
**Change:** Below (or instead of only) the bar chart, render sorted rows from `certificates` using `name`, `not_valid_after`, `expired`, `near_expiry`, `self_signed`. Cap list (~8) + “+N more” if large (mitmproxy 32).  
**Verify:** Scan #80 / #94 shows cert names and expiry dates; expired badge on `testkey_rsa.cer`.  
**Risk:** Low–Medium (layout density)

## Fix group A3 — Verification

1. Hermetic: existing `test_cbom_chart_data_contract` still asserts non-empty certificates on synthetic-crypto-app  
2. Live: API assert on #80 certificates length > 0; Playwright on temp route with dumped distributions OR authenticated results page  
3. Ruflo `memory_store` key `cbom-cert-expiry-verified`

## Rollback

Revert single FE file; no DB/worker migration.

---

## Explicit non-goals

- Do not change `_certificate_expiry` / scanner unless user picks C with a missed-file repro
- Do not change dashboard `total_certificates` aggregation (already matches)
- No remote git push/PR
