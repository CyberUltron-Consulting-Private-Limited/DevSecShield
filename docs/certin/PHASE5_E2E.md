# CERT-In Phase 5 — Durable E2E runbook

Advisory CERT-In Technical Guidelines v2.0 **posture rollup** (team + scan
metadata) and India/CERT-In filter UX lock. Store Ruflo key
`certin-phase5-verified` on success (do **not** overwrite
`certin-phase0-verified` … `certin-phase4-verified`).

## Preconditions

- Backend `:8081` (`GET /docs` 200), frontend `http://localhost:3000`.
- Demo user: `cbom-demo@cyberultron.com` (team 1).
- At least one **success** CBOM scan whose `scan_metadata.cbom_compliance`
  includes `cert_in_cbom`. Optional: `CERTIN_P5_SCAN_ID=<id>` (falls back to
  `CERTIN_P4_SCAN_ID`).
- Restart backend after pulling Phase 5 `certin_posture` / metadata / team
  wiring.

---

## Gate A — Hermetic / unit

```bash
cd backend
uv run pytest tests/test_certin_posture.py \
  tests/test_certin_scan_metadata_posture.py \
  tests/test_certin_india_ux_lock.py -q

cd ../aibom
uv run pytest tests/test_certin_rollup_yaml_covers_ledger.py -q
```

Expect: dimension mapping, team SUCCESS case-safety, metadata surface, ledger↔YAML
1:1 cover, `defaultGroup="all"`, zero product-FE `\bQBOM\b`, HBOM deferred copy.

---

## Gate B — Isolation + FE

```bash
cd frontend && npx tsc --noEmit
```

RBI rollup / Phase 1–4 frameworks unchanged. Product UI must not say “QBOM”.

---

## Gate C — Live API

```bash
cd backend && uv run pytest tests/test_certin_phase5_e2e.py -q
```

Asserts:

1. Success CBOM metadata includes `certin_posture` with ≥1 non-empty dimension
2. Team dashboard `/team/{id}/dashboard` includes `certin_posture`
3. Optional AIBOM/SBOM peers when present
4. POST attestation on an NBE manual → GET metadata rollup
   `pass_with_evidence` increases for that dimension

Mint tokens for the browser gate:

```bash
cd backend && uv run python - <<'PY'
import datetime, json, os, re, jwt
from pathlib import Path
env = {}
for line in Path(".env").read_text().splitlines():
    m = re.match(r"^([A-Za-z0-9_]+)\s*=\s*(.*)$", line.strip())
    if m:
        k, v = m.group(1), m.group(2).strip().strip('"').strip("'")
        env[k] = v.split("#")[0].strip() if v else v
secret = env["JWT_SECRET_KEY"]
email = "cbom-demo@cyberultron.com"
exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
access = jwt.encode({"exp": exp, "sub": email}, secret, algorithm="HS256")
scan_id = int(os.environ.get("CERTIN_P5_SCAN_ID") or os.environ.get("CERTIN_P4_SCAN_ID") or "14")
Path("/tmp/certin_phase5_tokens.json").write_text(json.dumps({
    "access": access, "refresh": access, "scan_id": scan_id, "team_id": 1
}))
print("wrote /tmp/certin_phase5_tokens.json", "scan", scan_id)
PY
```

---

## Gate D — Browser (customer)

```bash
# ensure frontend :3000 (rm -rf frontend/.next if deep routes 404)
node scripts/e2e/certin_phase5_browser.cjs
```

Expect `/tmp/certin_phase5_browser.json` with `"ok": true`:

- Team page shows CertInRollup when posture present (+ HBOM deferred)
- CBOM results: CertInRollup + HBOM deferred; All + India chips; India filters
  to CERT-In; no QBOM; hard refresh keeps rollup

---

## Gate E — Defense-in-depth

- Empty/unknown compliance → `certin_posture` null (no crash) — covered by
  `test_legacy_cbom_without_cert_in_has_null_posture`
- Ruflo: `memory_store` key **`certin-phase5-verified`** (do not overwrite 0–4)

## Pass criteria

A–E all green. Do not mark complete until live API + Playwright evidence exists.
