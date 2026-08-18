# CERT-In Phase 2 — Durable E2E runbook

Advisory alignment of AIBOM scans to CERT-In Technical Guidelines v2.0
(`cert_in_aibom`). Store Ruflo key `certin-phase2-verified` on success (do not
overwrite phase0/1 keys).

## Preconditions

- Backend `:8081` (`GET /docs` 200), frontend `http://localhost:3000`.
- After any `aibom/` change, restart the scan worker:

```bash
pkill -9 -f "celery -A scan_worker.*scan_worker_queue" || true
cd RabbitMQ/worker && nohup uv run celery -A scan_worker worker -P threads \
  -Q scan_worker_queue --concurrency=4 -n scan@%h --loglevel=info \
  > /tmp/scan_worker.log 2>&1 &
```

Demo user: `cbom-demo@cyberultron.com` (team 1) or `AIBOM_E2E_*` overrides.

---

## Gate A — Hermetic

```bash
cd aibom
uv run pytest tests/test_certin_aibom_compliance.py \
  tests/test_certin_common.py tests/test_certin_ledger_sync.py \
  tests/test_compliance.py::test_registry_has_all_frameworks_with_expected_counts \
  tests/test_integration_devsecshield.py::test_cert_in_aibom_carried_in_run_object -q
```

---

## Gate B — Isolation + FE

Covered by `test_certin_common`. Frontend:

```bash
cd frontend && npx tsc --noEmit
```

---

## Gate C — Live API

```bash
cd backend && uv run pytest tests/test_certin_aibom_e2e.py -q
```

Asserts `scan_metadata.ai_bom_compliance.cert_in_aibom` has requirements + peer frameworks.

---

## Gate D — Browser

```bash
# Mint tokens for a success AI BOM scan that includes cert_in_aibom
# (prefer Gate-C scan id). Write /tmp/certin_phase2_tokens.json
node scripts/e2e/certin_phase2_browser.cjs
```

Expect: All + India chips; T10 + 9.4.1 drilldown; no QBOM; refresh OK.

---

## Gate E — Defense + evidence

```bash
cd aibom && uv run pytest tests/test_certin_aibom_compliance.py::test_empty_repo_out_of_scope -q
```

Ruflo namespace `certin-compliance` key: `certin-phase2-verified`.

---

## Files

| Path | Role |
|------|------|
| `aibom/src/aibom/compliance/cert_in/ai.py` | Table 10 + §9.4.1 checks |
| `aibom/src/aibom/compliance/engine.py` | FRAMEWORKS entry |
| `backend/tests/test_certin_aibom_e2e.py` | Live API |
| `scripts/e2e/certin_phase2_browser.cjs` | Playwright |
