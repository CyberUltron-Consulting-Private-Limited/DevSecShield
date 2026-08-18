# CERT-In Phase 4 — Durable E2E runbook

Advisory CERT-In Technical Guidelines v2.0 alignment for **HMAC BOM signing**,
**CycloneDX VEX**, **attestation API + compliance re-run**, and **evidence-pack
ZIP** (+ PDF CERT-In section). Store Ruflo key `certin-phase4-verified` on
success (do **not** overwrite `certin-phase0-verified` … `certin-phase3-verified`).

## Preconditions

- Backend `:8081` (`GET /docs` 200), frontend `http://localhost:3000`.
- `JWT_SECRET_KEY` in `backend/.env` (used as HMAC fallback when
  `CERTIN_HMAC_SECRET` is unset). Prefer setting `CERTIN_HMAC_SECRET` explicitly
  in production — missing both secrets returns **503** on `POST …/sign`.
- Demo user: `cbom-demo@cyberultron.com` (team 1).
- At least one **success** CBOM scan whose `scan_metadata.cbom_compliance`
  includes `cert_in_cbom` (Phase 1 gate). Optional override:
  `CERTIN_P4_SCAN_ID=<id>`.

Restart backend after pulling Phase 4 router changes:

```bash
# kill prior fastapi if needed, then:
cd backend && uv run fastapi dev main.py --port 8081
```

Worker restart is **not** required for attestation re-run (backend-side).

---

## Gate A — Hermetic / unit

```bash
cd aibom
uv run pytest tests/test_certin_sign.py tests/test_certin_vex.py -q

cd ../backend
uv run pytest tests/test_certin_attestation_api.py \
  tests/test_certin_evidence_pack_pdf.py -q
```

Expect: NBE→`pass_with_evidence` flip; VEX default `not_affected`; PDF section
carries CERT-In advisory disclaimer; aibom has **no** `cryptography` dep.

---

## Gate B — Isolation + FE

```bash
cd frontend && npx tsc --noEmit
```

Scoped eslint on changed FE files as needed. Product UI must not say “QBOM”.

---

## Gate C — Live API

```bash
cd backend && uv run pytest tests/test_certin_phase4_e2e.py -q
```

Asserts on a success CBOM scan:

1. Unknown `requirement_id` → **400**
2. POST attestation → requirement becomes `pass_with_evidence`
3. `scan_metadata.attestations` present
4. POST `/sign` → `bom_signature.signature_b64`
5. GET `/vex` → 200
6. GET `/evidence-pack` → ZIP (`PK…`)

Mint tokens for the browser gate (example):

```bash
cd backend && uv run python - <<'PY'
import datetime, json, os, re, jwt
from pathlib import Path
env = {}
for line in Path(".env").read_text().splitlines():
    m = re.match(r"^([A-Za-z0-9_]+)\s*=\s*(.*)$", line.strip())
    if m:
        env[m.group(1)] = m.group(2).strip().strip("'\"")
email = "cbom-demo@cyberultron.com"
secret = env["JWT_SECRET_KEY"]
exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)
access = jwt.encode({"exp": exp, "sub": email}, secret, algorithm="HS256")
scan_id = int(os.environ.get("CERTIN_P4_SCAN_ID", "1"))
Path("/tmp/certin_phase4_tokens.json").write_text(json.dumps({
    "access": access, "refresh": access, "scan_id": scan_id, "team_id": 1
}))
print("wrote /tmp/certin_phase4_tokens.json scan", scan_id)
PY
```

---

## Gate D — Browser

```bash
node scripts/e2e/certin_phase4_browser.cjs
```

Expect: All + India chips; Evidence pack / VEX / Signature controls; evidence-pack
download is a ZIP; no QBOM; hard refresh keeps attested compliance.

Optional: `CERTIN_P4_REQ_ID=8.4.1.1` (manual NBE id used for pre-attest).

---

## Gate E — Defense + Ruflo

- Tampered BOM fails `verify_signature` (covered by `test_certin_sign.py`).
- Unknown attestation `requirement_id` → 400 (live e2e).
- Ruflo namespace `certin-compliance` key: **`certin-phase4-verified`**.

---

## API cheat sheet

| Method | Path |
|--------|------|
| GET/POST/DELETE | `/{team}/{ai_bom\|cbom\|sbom_sca}/scan/{id}/attestations…` |
| POST | `…/sign` |
| GET | `…/vex` |
| GET | `…/evidence-pack` |

Disclaimer on packs/PDF: advisory only — never claims CERT-In certification.
