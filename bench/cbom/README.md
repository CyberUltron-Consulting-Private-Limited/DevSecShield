# bench/cbom/ — isolated CBOM benchmark harness (NOT product code)

Live-runs TWO independent OSS crypto/BOM oracles + our CBOM scanner on
crypto-heavy repos and produces a true-positive diff matrix. Nothing here is
imported by `aibom/` product code (OSS oracles are allowed ONLY in this isolated
harness, never on the product import path). Mirror of the AIBOM harness
(`bench/normalize.py` / `diff.py` / `ci_gate.py`), adapted for the crypto lane.

- `repos.tsv`     — the repo set (id, slug, clone URL, scan subdir, note)
- `run.sh`        — clone (shallow, record SHA) + run ALL oracles + ours on one repo
- `run_all.sh`    — nightly: every oracle × every repo, then `diff.py`
- `normalize.py`  — extract a comparable `{(canon_name, asset_class)}` set per lane
- `diff.py`       — per-(repo, oracle) + aggregate Misses / OurUnique / Overlap + triage + gate
- `emit_ours.py`  — run our `scan_crypto` (level 4) → schema-validated CycloneDX CBOM
- `ci_gate.py`    — hermetic `true_misses(repo_id, ours.cdx, oracle=…)` vs `ci_baseline/`; `[]`=pass
- `ci_repos.sh`   — representative real-repo gate (clones at HEAD, runs OURS only, all oracles)
- `out/`          — raw tool outputs (`<repo>.{cbomkit,cdxgen,ours}.cdx.json`)
- `ci_baseline/`  — FROZEN oracle snapshots (`<repo>.{cbomkit,cdxgen}.cdx.json`; the gate diffs vs these)
- `report.md`     — the aggregate multi-oracle diff matrix (the deliverable)
- `fp-exclusions.json` / `.md` — every oracle finding excluded as a false positive, justified

## The oracles (and why our-unique is large by design)

OURS is diffed against **two independent OSS oracles**, each in its own comparison
LANE (`ORACLE_LANE` in `diff.py`/`ci_gate.py`) so we compare like with like.
Adding an oracle = one frozen `ci_baseline/<repo>.<oracle>.cdx.json` snapshot + one
`ORACLE_LANE` entry + (for the nightly) one `run.sh` step.

- **Oracle 1 — IBM `cbomkit-theia`** (`ghcr.io/cbomkit/cbomkit-theia`, docker): a
  **filesystem** scanner. Extracts crypto from certificates, OpenSSL configs,
  keys and secrets on disk. Explicitly **does not scan source code**. → compared
  in the **crypto-asset lane** (`normalize.normalize`).
- **Oracle 2 — `@cyclonedx/cdxgen`** (the reference CycloneDX BOM generator, run
  via `npx` — no docker): a **dependency-graph** SBOM tool. With `--include-crypto`
  it resolves the project's library graph. Its source-level *algorithm* detection
  needs the `atom` code-slicer (unavailable headless), so here it is a **crypto-
  library** oracle → compared in the **crypto-library lane**
  (`normalize.crypto_libraries`, scoped to a known-crypto-lib allowlist so a
  non-crypto transitive dep like `typing-extensions` is out of scope, not a miss).
- **Ours**: a **source-code** crypto scanner. It detects algorithm *usage*
  (RSA-2048 vs RSA-1024, AES-GCM vs AES-ECB), TLS/SSL **protocol** versions, the
  weak-algorithm set, **PQC** readiness grading, **tri-state compliance**, AND a
  multi-ecosystem crypto-library inventory incl. the **stdlib** modules
  (`hashlib`/`ssl`) a dependency-resolver can't see.

So `OurUnique > 0` is the whole point in BOTH lanes: ours adds the source-code
algorithm inventory + PQC + compliance the filesystem oracle lacks, and the
stdlib/source-imported crypto libraries the dependency oracle lacks. The `Misses`
column is where each oracle finds crypto we must also account for.

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

`diff.py` exits non-zero unless **true-miss == 0 for every (repo, oracle) AND
our-unique > 0** (aggregated across both oracles). The hermetic CI path runs OUR
(offline, deterministic) scanner against the FROZEN `ci_baseline/` oracle
snapshots — no docker, no network, no npx — so both oracles gate offline:

- `aibom/tests/test_cbom_benchmark_gate.py` — synthetic fixture, hermetic, both oracles.
- `bench/cbom/ci_repos.sh` — representative real repos cloned at HEAD, OURS only;
  `ci_gate.py` auto-diffs every oracle that has a frozen baseline for the repo.

## Re-run the FULL live benchmark (docker for oracle 1, npx for oracle 2)

```bash
# 1. pull oracle 1 once (oracle 2, cdxgen, is fetched by npx on demand)
docker pull ghcr.io/cbomkit/cbomkit-theia:latest
# 2. clone + run cbomkit-theia + cdxgen + ours on the synthetic fixture + every repo
MAXJ=2 bash bench/cbom/run_all.sh
# 3. produce report.md + gate (exit 1 if any TRUE-positive miss survives triage)
python3 bench/cbom/diff.py
# 4. (optional) refreeze the oracle baselines the hermetic gate diffs against
cp bench/cbom/out/*.cbomkit.cdx.json bench/cbom/ci_baseline/   # oracle 1
cp bench/cbom/out/*.cdxgen.cdx.json  bench/cbom/ci_baseline/   # oracle 2
```

Add a repo in `repos.tsv`; its HEAD SHA is recorded in `state/shas.tsv` by
`run.sh`. Add an oracle = one `ORACLE_LANE` entry (`diff.py`/`ci_gate.py`) + a
frozen `ci_baseline/<repo>.<oracle>.cdx.json` snapshot + a `run.sh` step. Triage
every new miss in `fp-exclusions.json` (oracle FP, grep-verified reason) or fix
the scanner (real miss). A repo with no snapshot for an oracle just skips that
oracle (e.g. cdxgen resolved 0 deps for `01-pyjwt`, so it has no cdxgen baseline).
