# CERT-In Phase 3 — Durable E2E runbook

Advisory alignment of SBOM/SCA scans to CERT-In Technical Guidelines v2.0
(`cert_in_sbom`). Store Ruflo key `certin-phase3-verified` on success (do not
overwrite phase0/1/2 keys).

## Preconditions

- Backend `:8081` (`GET /docs` 200), frontend `http://localhost:3000`.
- After any `aibom/` change, restart the scan worker:

```bash
pkill -9 -f "celery -A scan_worker.*scan_worker_queue" || true
cd RabbitMQ/worker && nohup uv run celery -A scan_worker worker -P threads \
  -Q scan_worker_queue --concurrency=4 -n scanphase3@%h --loglevel=info \
  > /tmp/scan_worker.log 2>&1 &
```

Demo user: `cbom-demo@cyberultron.com` (team 1) or `SBOM_E2E_*` overrides.

---

## Gate A — Hermetic

```bash
cd aibom
uv run pytest tests/test_certin_sbom_compliance.py \
  tests/test_certin_common.py tests/test_certin_ledger_sync.py \
  tests/test_sbom_rbi_compliance.py -q
```

---

## Gate B — Isolation + FE

Covered by `test_certin_common` (`cert_in_sbom` in `SBOM_FRAMEWORKS` only;
`compliance/__init__` must not import `cert_in.sbom`). Frontend:

```bash
cd frontend && npx tsc --noEmit
```

---

## Gate C — Live API

```bash
cd backend && uv run pytest tests/test_certin_sbom_e2e.py -q
```

Asserts `scan_metadata.sbom_compliance.cert_in_sbom` has 41 requirements + peer
`rbi_free_ai_supply`.

Fallback: patch an existing success SBOM scan’s `scan_data` via
`enrich_sbom_scan(results, duration)` then GET `/1/sbom_sca/scan/{id}`.

---

## Gate D — Browser

```bash
# Mint tokens for a success SBOM scan that includes cert_in_sbom
# Write /tmp/certin_phase3_tokens.json  { access, refresh, scan_id, team_id }
node scripts/e2e/certin_phase3_browser.cjs
```

Expect: All + India chips; T5 + 7.1 drilldown; no QBOM; refresh OK.

---

## Gate E — Defense + evidence

```bash
cd aibom && uv run pytest tests/test_certin_sbom_compliance.py::test_empty_findings_out_of_scope -q
```

Ruflo namespace `certin-compliance` key: `certin-phase3-verified`.

---

## Files

| Path | Role |
|------|------|
| `aibom/src/aibom/compliance/cert_in/sbom.py` | Table 5 + §7.1 checks |
| `aibom/src/aibom/sbom/compliance.py` | Enrichment + `SBOM_FRAMEWORKS` wire |
| `backend/tests/test_certin_sbom_e2e.py` | Live API |
| `scripts/e2e/certin_phase3_browser.cjs` | Playwright |
