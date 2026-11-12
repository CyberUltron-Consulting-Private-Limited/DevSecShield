# What “Attest” actually does (CERT-In + RBI CSF)

**Short answer:** Attestation uploads *process evidence* for a compliance requirement that a BOM scan cannot prove. It does **not** fix or resolve scan findings. It can flip only **`not_bom_evidenceable` → `pass_with_evidence`**. Failures stay fail until the underlying assets/findings are fixed.

---

## 1. Frontend — what the user clicks

There is **no modal dialog**. In:

- `frontend/components/certin/CertInRequirementDrilldown.tsx`
- `frontend/components/rbi/RbiCsfRequirementDrilldown.tsx`
- `frontend/components/compliance/ComplianceMatrix.tsx` (shared matrix)

the control is a hidden `<input type="file">` labeled **“+ Attach attestation”**.

**When it appears**

- `onAttest` is wired, **and**
- verdict is `not_bom_evidenceable` **or** `attestable === true`, **and**
- verdict is **not** already `pass_with_evidence`, **and**
- upload is not already pending for that row.

Accepted types: `.pdf,.png,.jpg,.jpeg,.txt,.md,.json`.

**Handler chain (CERT-In and RBI share the same API)**

| Page | Handler | Call |
|------|---------|------|
| CBOM results | `handleCertInAttest` | `postCertInAttestation(tid, "cbom", sid, …)` |
| AI BOM results | `handleCertInAttest` | `postCertInAttestation(tid, "ai_bom", sid, …)` |
| SBOM results | `handleCertInAttest` | `postCertInAttestation(tid, "sbom_sca", sid, …)` |

RBI CSF rollup (`RbiCsfRollup` → `RbiCsfRequirementDrilldown`) receives the **same** `onAttest={handleCertInAttest}` — there is no separate RBI attest endpoint.

`postCertInAttestation` lives in `frontend/utils/backend_api.ts`: multipart `POST /{team_id}/{scan_type}/scan/{scan_id}/attestations` with `framework`, `requirement_id`, `file` (+ optional `note`). On success it shows toast **“Attestation uploaded”**.

Parents then `queryClient.invalidateQueries` on the conversation/results query so compliance + posture refresh.

---

## 2. Backend — endpoint, storage, recompute

**Router:** `backend/routers/certin.py`

| Method | Path | Role |
|--------|------|------|
| GET | `/{team}/{type}/scan/{id}/attestations` | List stored attestation metadata |
| POST | `/{team}/{type}/scan/{id}/attestations` | Upload + recompute compliance |
| DELETE | `/{team}/{type}/scan/{id}/attestations/{framework}/{requirement_id}` | Remove + recompute |

Allowed scan types: `ai_bom`, `cbom`, `sbom_sca` only.

**Helpers:** `backend/utilities/compliance/certin_attest.py`

### Is there an `attestations` table?

**No.** Attestations are **JSON inside `Scan.scan_data`** (`backend/new_models.py` → `Scan.scan_data` JSON column):

```text
scan_data["attestations"] = {
  "<framework>": {
    "<requirement_id>": {
      "filename": "policy.pdf",
      "note": "policy.pdf",          # or Form note
      "uploaded_at": "2026-…Z"
    }
  }
}
```

**Important:** the upload handler uses **`file.filename` only**. File **bytes are not stored** on the server (metadata / filename note only). The PDF/image is not kept as a blob for later download from this path (evidence-pack can include `attestations.json` metadata).

### Recompute after POST

1. Validate requirement id exists in the scan’s `*_compliance` blob.
2. `upsert_attestation(...)` into `scan_data["attestations"]`.
3. `recompute_compliance_for_scan(...)`:
   - Prefer full `run_sbom_compliance(results, evidence=…)` for SBOM when finding rows exist.
   - Else **in-place** `apply_evidence_to_compliance` on the persisted `ai_bom_compliance` / `cbom_compliance` / `sbom_compliance` blob.
4. Persist updated `scan_data` back onto the `Scan` row.

---

## 3. What attestation changes (and what it does not)

### Compliance verdict — yes, but only NBE

Engine contract (`aibom/src/aibom/compliance/engine.py` + `certin_attest.apply_evidence_to_compliance`):

| Before | After attest for that requirement? |
|--------|-------------------------------------|
| `not_bom_evidenceable` | **`pass_with_evidence`** (evidence string → `attested: <note/filename>`) |
| `fail` | **Unchanged** (still fail) |
| `pass` / `out_of_scope` / `na` | **Unchanged** |
| Already `pass_with_evidence` | Attach UI hidden |

Coverage math: `pass_with_evidence` counts as pass → `coverage = (pass + pass_with_evidence) / (pass + pass_with_evidence + fail)`. NBE / OOS / NA stay out of the denominator.

This matches manuals registered via `register_manual` → NBE (process evidence a BOM cannot see). Attestation is the designed path for those controls.

### Findings list — no

Attestation does **not**:

- mark findings fixed / resolved / dismissed
- mutate `scan_data["results"]`
- change severity, scores, or finding state
- clear weak-crypto / AI / SBOM inventory rows

`certin_posture` resolve hints make this explicit: **fail** → “Fix related assets / findings”; **NBE** → “Upload process attestation…”.

### Fail → pass? — no

Attesting a failed technical control does **not** turn it green. Only NBE (manual / process) requirements flip.

---

## 4. UI after a successful attest

1. Toast: **“Attestation uploaded”** (`postCertInAttestation`).
2. Drilldown briefly shows `attested: <filename> (uploading…)` then `(pending re-evaluation)` until refresh.
3. Parent invalidates React Query → refetch scan + metadata.
4. Metadata rebuilds **CERT-In posture** and **RBI CSF rollup** from the updated `*_compliance` (`get_scan_metadata` → `build_certin_posture` / `build_rbi_csf_rollup`).
5. Requirement badge becomes **pass with evidence** (teal); attach control disappears for that row.
6. Stacked posture / matrix bars recount (NBE ↓, pass_with_evidence ↑; coverage may rise).

No separate “fixed findings” toast or findings-table refresh beyond the same conversation refetch.

---

## 5. Relationship to “View related findings”

**Independent of attest.**

`onViewFindings(refs)` (e.g. `handleViewRelatedFindings` in CbomResults / AiBomResults / SbomResults):

1. Sets a client-side related-refs filter.
2. Clears search.
3. Smooth-scrolls to `#bom-findings`.

Findings stay exactly as scanned. Attesting an NBE row does not remove or alter related assets; viewing related findings on a **fail** row still shows the same inventory/weakness rows that caused the fail.

---

## 6. Mental model

```text
BOM scan findings  ──►  graph checks  ──►  pass / fail / NBE / …
                                              │
                         user uploads file    │ only if NBE
                                              ▼
                         attestations{}  ──►  pass_with_evidence
                                              │
                         results[] findings   │ untouched
```

**Attest = attach process evidence for controls the scanner cannot see.**  
**Fix findings = change code/config and re-scan (or use finding-state toggles elsewhere).** Those are different actions.

---

## Evidence pointers

| Area | Path |
|------|------|
| Drilldowns | `frontend/components/certin/CertInRequirementDrilldown.tsx`, `frontend/components/rbi/RbiCsfRequirementDrilldown.tsx` |
| API client | `frontend/utils/backend_api.ts` → `postCertInAttestation` |
| HTTP API | `backend/routers/certin.py` |
| Flip logic | `backend/utilities/compliance/certin_attest.py` |
| Engine | `aibom/src/aibom/compliance/engine.py` (`run_framework` evidence branch) |
| Manuals | `aibom/src/aibom/compliance/base.py` → `register_manual` |
| Persistence | `Scan.scan_data["attestations"]` — not a separate table |
| Tests | `backend/tests/test_certin_attestation_api.py`, `aibom/tests/test_compliance_tristate.py` |

*Explained from code — no product behavior changed for this note.*
