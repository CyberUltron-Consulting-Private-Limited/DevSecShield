# bench/cbom/ — isolated CBOM benchmark harness (NOT product code)

Live-runs IBM's `cbomkit-theia` oracle + our CBOM scanner on crypto-heavy repos
and produces a true-positive diff matrix. Nothing here is imported by `aibom/`
product code. Mirror of the AIBOM harness (`bench/normalize.py` / `diff.py` /
`ci_gate.py`), adapted for the crypto lane.

- `repos.tsv`     — the repo set (id, slug, clone URL, scan subdir, note)
- `run.sh`        — clone (shallow, record SHA) + run BOTH tools on one repo
- `run_all.sh`    — nightly: both tools × every repo, then `diff.py`
- `normalize.py`  — extract a comparable `{(canon_name, asset_class)}` set per tool
- `diff.py`       — per-repo + aggregate Misses / OurUnique / Overlap + triage + gate
- `emit_ours.py`  — run our `scan_crypto` (level 4) → schema-validated CycloneDX CBOM
- `ci_gate.py`    — hermetic `true_misses(repo_id, ours.cdx)` vs `ci_baseline/`; `[]`=pass
- `ci_repos.sh`   — representative real-repo gate (clones at HEAD, runs OURS only)
- `out/`          — raw tool outputs (`<repo>.{cbomkit.cdx,ours.cdx}.json`)
- `ci_baseline/`  — FROZEN cbomkit oracle snapshots (committed; the gate diffs vs these)
- `report.md`     — the aggregate diff matrix (the deliverable)
- `fp-exclusions.json` / `.md` — every oracle finding excluded as a false positive, justified

## The two tools (and why our-unique is large by design)

- **Oracle — IBM `cbomkit-theia`** (`ghcr.io/cbomkit/cbomkit-theia`): a
  **filesystem** scanner. It extracts crypto from certificates, OpenSSL configs,
  keys and secrets on disk. It explicitly **does not scan source code**.
- **Ours**: a **source-code** crypto scanner. It detects algorithm *usage*
  (RSA-2048 vs RSA-1024, AES-GCM vs AES-ECB), TLS/SSL **protocol** versions, the
  weak-algorithm set, **PQC** readiness grading, and **tri-state compliance** —
  none of which the filesystem oracle can see.

So `OurUnique > 0` is the whole point: ours adds the source-code algorithm
inventory + PQC + compliance the oracle structurally lacks. The `Misses` column
is where the oracle's cert/key parsing finds crypto we must also account for.

## Triage reconciliations (applied before a Miss counts as a TRUE miss)

1. **detected_under_different_class** — we inventory the same name under a
   different asset_class (the oracle lists a cert's RSA key as
   `related-crypto-material`; we list `RSA-2048` as an `algorithm`).
2. **algorithm_family_detected** — for an `algorithm` Miss we inventory the same
   FAMILY at finer granularity (the oracle's bare `RSA` vs our `RSA-2048`).
3. **cert_key_decomposition** — the oracle decomposes a *binary* cert/key file
   (`.cer`/`.pem`/`.priv`/…) into its embedded algorithm + key material; our
   source-code lane inventories that file as a `certificate` / key asset instead.

Everything that survives triage is a REAL miss → a fix task against the crypto
scanner (`fp-exclusions.md` records each oracle FP with a grep-verified reason).

## The gate

`diff.py` exits non-zero unless **true-miss == 0 for every repo AND
our-unique > 0**. The hermetic CI path runs OUR (offline, deterministic) scanner
against the FROZEN `ci_baseline/` oracle snapshots — no docker, no network:

- `aibom/tests/test_cbom_benchmark_gate.py` — synthetic fixture, hermetic.
- `bench/cbom/ci_repos.sh` — representative real repos cloned at HEAD, OURS only.

## Re-run the FULL live benchmark (needs docker + the oracle image)

```bash
# 1. pull the oracle once
docker pull ghcr.io/cbomkit/cbomkit-theia:latest
# 2. clone + run cbomkit-theia + ours on the synthetic fixture + every real repo
MAXJ=2 bash bench/cbom/run_all.sh
# 3. produce report.md + gate (exit 1 if any TRUE-positive miss survives triage)
python3 bench/cbom/diff.py
# 4. (optional) refreeze the oracle baselines the hermetic gate diffs against
cp bench/cbom/out/*.cbomkit.cdx.json bench/cbom/ci_baseline/
```

Add a repo in `repos.tsv`; its HEAD SHA is recorded in `state/shas.tsv` by
`run.sh`. Triage every new miss in `fp-exclusions.json` (oracle FP, with a
grep-verified reason) or fix the scanner (real miss).
