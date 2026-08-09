# CERT-In Phase 6 — Durable E2E runbook

Full multi-BOM verification gate + **15 public-repo matrix** (5 CBOM + 5 AIBOM +
5 SBOM). Store Ruflo key `certin-phase6-verified` on success (do **not**
overwrite `certin-phase0-verified` … `certin-phase5-verified`).

Advisory only — **not** CERT-In certification. Product UI must never say QBOM.

## Preconditions

- Backend `:8081`, frontend `:3000`, Celery `scan_worker_queue` (restart worker
  after any `aibom/` **or** `RabbitMQ/worker/helpers/tools/sca_sbom_agent/` change).
- Demo user `cbom-demo@cyberultron.com` (team 1).
- Docker available for CBOM cbomkit-theia freezes; `npx` for cdxgen.
- **SBOM multi-engine binaries on the worker PATH:** `syft`, `grype`, `npx`
  (`@cyclonedx/cdxgen@11`). Missing Syft/cdxgen degrades inventory (Grype still
  runs); install via Homebrew (`brew install syft grype`) for full provenance.
- Manifest: [`bench/certin/repos.tsv`](../../bench/certin/repos.tsv)
- Estimate poll budget: `ESTIMATION_POLL_MAX_ATTEMPTS=300` (~600s at 2s interval).

### SBOM pin note (Phase 6 + empty-docs fix)

Temporary swap to `pallets/itsdangerous` / `pallets/jinja` was undone after fixing
`SCASBOMAgent.populate_opensource_context`: zero Grype matches no longer call
map-reduce (was raising `Documents are not set`). Restored originals:

- s1 `psf/requests@1f6589e`
- s2 `pallets/flask@6a2f545`
- s3 `urllib3/urllib3@824d97b`
- s4 `sqlalchemy/sqlalchemy@5995834`
- s5 `pallets/click@00e592c`

---

## Gate A — Hermetic

```bash
cd aibom && uv run pytest tests/ -k "certin or cert_in" -q
cd ../backend && uv run pytest \
  tests/test_certin_posture.py \
  tests/test_certin_india_ux_lock.py \
  tests/test_certin_phase6_hermetic.py -q
cd ../frontend && npx tsc --noEmit
```

---

## Gate B/C — Oracle differentials

```bash
# CBOM freeze cryptography / mitmproxy / paramiko into ci_baseline
bash bench/certin/freeze_cbom_baselines.sh

# SBOM cdxgen inventory + freeze
bash bench/certin/run_matrix.sh --sbom-oracles

python3 bench/certin/generate_report.py
```

Pass: CBOM `true-miss==0` (where baselines exist) + `our-unique>0` on synthetic;
SBOM inventory gate non-empty ours + frozen recall.

---

## Gate D — Live 15-repo product matrix

```bash
# restart worker
pkill -9 -f 'celery -A scan_worker' || true
cd RabbitMQ/worker && nohup uv run celery -A scan_worker worker -P threads \
  -Q scan_worker_queue --concurrency=4 -n p6@%h --loglevel=info \
  > /tmp/celery_p6.log 2>&1 &

cd backend && uv run pytest tests/test_certin_phase6_e2e.py -q --tb=short
# writes /tmp/certin_phase6_matrix.json
```

Asserts: 15 SUCCESS cells with `cert_in_*` + `certin_posture`; deep
attest/sign/VEX/evidence-pack per lane; team dashboard multi-lane dims.

Timeouts: default 1200s/cell (`CERTIN_P6_TIMEOUT_S`). Soft budgets CBOM≤20m /
AIBOM≤25m / SBOM≤20m.

---

## Gate E — Browser

```bash
cd backend && uv run python - <<'PY'
import datetime, json, jwt, re
from pathlib import Path
env={}
for line in Path('.env').read_text().splitlines():
    m=re.match(r'^([A-Za-z0-9_]+)\s*=\s*(.*)$', line.strip())
    if m:
        k,v=m.group(1),m.group(2).strip().strip('"').strip("'")
        env[k]=v.split('#')[0].strip() if v else v
m=json.loads(Path('/tmp/certin_phase6_matrix.json').read_text())
deep={k:v.get('scan_id') for k,v in (m.get('deep') or {}).items()}
access=jwt.encode({'exp':datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(hours=2),
                   'sub':'cbom-demo@cyberultron.com'}, env['JWT_SECRET_KEY'], algorithm='HS256')
Path('/tmp/certin_phase6_tokens.json').write_text(json.dumps({
  'access':access,'refresh':access,'team_id':1,'deep':deep}))
print(deep)
PY

node scripts/e2e/certin_phase6_browser.cjs
```

Expect `/tmp/certin_phase6_browser.json` `"ok": true`.

---

## Gate F — Ruflo

`memory_store` key **`certin-phase6-verified`** in namespace `certin-compliance`.

## Pass criteria

A–F green with live API + Playwright + `bench/certin/report.md` evidence.
