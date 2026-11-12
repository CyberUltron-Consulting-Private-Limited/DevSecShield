# Local DevSecShield Services Status

**Checked:** 2026-08-09 14:06:11 UTC / 2026-08-09 19:36:11 IST

## Summary

| Service | URL / Port | PID(s) | Status |
|---------|------------|--------|--------|
| Postgres | `localhost:4433` → 5432 | docker | UP (pg_isready OK) |
| MongoDB | `localhost:27017` | docker | UP |
| RabbitMQ | AMQP `:4672`, Mgmt `http://127.0.0.1:10672` | docker | UP (mgmt HTTP 200, ping OK) |
| Qdrant | `localhost:7333` | docker | UP |
| MCP broker | `localhost:8311` | docker | UP (healthy) |
| Backend (FastAPI) | `http://127.0.0.1:8081` | 16299,16320 | HEALTHY (/docs=200, /health=200) |
| Frontend (Next.js) | `http://127.0.0.1:3000` | 18305 | HEALTHY (HTTP 200) |
| Celery scan_worker | queue `scan_worker_queue` | 18270,18282,18284 | READY (ready lines=2) |
| Celery guardrail_worker | queue `guardrail_worker_queue` | 34572 | RUNNING (pre-existing) |
| Celery dast_worker | queue `dast_worker_queue` | 34607 | RUNNING (pre-existing) |
| Flower | `http://127.0.0.1:5555` | 34622 | UP (HTTP 200) |

## Docker

qdrant (Up 9 hours);devsecshield-rabbitmq (Up 9 hours) devsecshield-postgres (Up 9 hours);devsecshield-mongodb (Up 9 hours) ai_mesh_mcp_broker (Up 9 hours (healthy))

## Actions this session

1. Docker infra already up — no compose restart needed.
2. Hung backend on :8081 restarted → /docs + /health = 200.
3. Started scan_worker (was missing) → `local@... ready.`
4. Cleared `frontend/.next`, started `npm run dev` → :3000 HTTP 200.
5. cicd_worker: not in repo — skipped. ZAP: skipped (optional/heavy).

## Logs

- `/tmp/backend_fastapi.log`
- `/tmp/frontend_next.log`
- `/tmp/celery_scan_worker.log`

## Blockers

None for normal local BOM/scan workflow.
