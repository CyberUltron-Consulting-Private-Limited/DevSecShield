# CERT-In Phase 1 — Durable E2E runbook

Advisory alignment of CBOM scans to CERT-In Technical Guidelines v2.0
(`cert_in_cbom`). This runbook re-runs gates A–E. Do **not** overwrite Ruflo
`certin-phase1-verified`; on success store additive key `certin-phase1-e2e-verified`.

## Preconditions

- Postgres / Mongo / RabbitMQ up (local compose).
- Backend: `cd backend && uv run fastapi dev main.py --port 8081` → `GET /docs` 200.
- Frontend: `cd frontend && npm run dev` → `http://localhost:3000` (use **localhost**, not 127.0.0.1).
- After any `aibom/` change, **restart** the scan worker (stale-module hazard):

```bash
pkill -9 -f "celery -A scan_worker.*scan_worker_queue" || true
cd RabbitMQ/worker && nohup uv run celery -A scan_worker worker -P threads \
  -Q scan_worker_queue --concurrency=4 -n scan@%h --loglevel=info \
  > /tmp/scan_worker.log 2>&1 &
# wait until log shows: scan@… ready.
```

Demo user: `cbom-demo@cyberultron.com` (team 1), `session_active=True`.

---

## Gate A — Hermetic (aibom)

```bash
cd aibom
uv run pytest tests/test_certin_cbom_compliance.py \
  tests/test_certin_common.py \
  tests/test_certin_ledger_sync.py \
  tests/test_cbom_devsecshield_adapter.py -q
uv run pytest -k "cbom_chart_data_contract or cbom_compliance" -q
```

Adapter lock: `test_cert_in_cbom_carried_in_run_object` — 43 reqs, OID → NBE, peer `nist_800_57`.

---

## Gate B — Isolation + FE

Covered by `test_certin_common` (CERT-In in `CBOM_FRAMEWORKS` only; no `compliance/__init__` import of `cert_in.crypto`).

```bash
cd frontend && npx tsc --noEmit
```

(No FE source change required for this E2E suite.)

---

## Gate C — Live API

```bash
cd backend
uv run pytest tests/test_certin_cbom_e2e.py -q
```

Asserts `scan_metadata.cbom_compliance.cert_in_cbom` has non-empty `requirements`
and at least one pre-CERT peer framework. Self-skips if backend down.

Optional peer: `uv run pytest tests/test_cbom_e2e.py -q`.

---

## Gate D — Browser (customer)

Mint tokens + point at a success CBOM scan that includes Phase 1 compliance
(prefer the scan id created by Gate C, or refresh scan 1 with a fresh adapter run):

```bash
cd backend && uv run python - <<'PY'
import json, sys
sys.path.insert(0, "/Users/anshsinghal/Desktop/DevSecShield")
from sqlmodel import Session, select
from backend.get_db import get_db
from backend.new_models import User
from backend.utilities.auth.auth_utils import create_access_token, create_refresh_token
engine = get_db()
with Session(engine) as db:
    u = db.exec(select(User).where(User.email == "cbom-demo@cyberultron.com")).first()
    u.session_active = True
    db.add(u); db.commit()
    access = create_access_token(u.email)
    refresh = create_refresh_token(u.email)
open("/tmp/certin_phase1_tokens.json","w").write(json.dumps({
  "access": access, "refresh": refresh,
  "scan_id": int(__import__("os").environ.get("SCAN_ID", "1")),
  "team_id": 1,
}))
print("wrote /tmp/certin_phase1_tokens.json")
PY

# set SCAN_ID to the Gate-C scan before minting if available
node scripts/e2e/certin_phase1_browser.cjs
# or: cd backend && uv run pytest tests/test_certin_cbom_browser_gate.py -q
```

Expect: All + India chips; India filters to CERT-In; T9 + 8.4.1 drilldown; no QBOM; refresh OK.

---

## Gate E — Defense + evidence

```bash
cd aibom && uv run pytest tests/test_certin_cbom_compliance.py::test_empty_repo_out_of_scope -q
```

Store Ruflo memory (namespace `certin-compliance`):

- key: `certin-phase1-e2e-verified`
- value: pytest exit codes, live scan id, browser JSON summary

---

## Files

| Path | Role |
|------|------|
| `aibom/tests/test_cbom_devsecshield_adapter.py` | Adapter CERT-In contract |
| `backend/tests/test_certin_cbom_e2e.py` | Live API metadata |
| `scripts/e2e/certin_phase1_browser.cjs` | Playwright customer gate |
| `backend/tests/test_certin_cbom_browser_gate.py` | Optional pytest wrapper |
