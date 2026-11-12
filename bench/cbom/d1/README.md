# bench/cbom/d1: the D1 independent benchmark lane (CB-07)

How accurate is the CBOM **code lane** (the engine the scan-worker runs on a repository) at finding cryptographic
misuse? This lane answers with numbers whose expected values never come from the product: the public benchmarks'
own published labels, a corpus labelled by someone other than the product's authors, and OSV.dev's answer at test
time (round 7 CBOM plan, DEVILS-ADVOCATE.md §3, rules O-1/O-2).

| Bench | Pinned source | Ground truth | Judged cases |
|---|---|---|---|
| CryptoAPI-Bench (Java) | `CryptoGuardOSS/cryptoapi-bench@759622f` (MIT) | `CryptoAPI-Bench_details.xlsx`, column D | 170 of 171 (135 vulnerable, 35 secure) |
| OWASP Benchmark Java: `crypto`, `hash`, `weakrand` | `OWASP-Benchmark/BenchmarkJava@db99977` (GPL-2.0: fetched, never committed) | `expectedresults-1.2.csv` | 975 (477 / 498) |
| Multi-language corpus (Java, C#, Go, C, Terraform, CloudFormation, Kubernetes) | `e2e/fixtures/cbom-d1-corpus/` | `corpus/labels.json` = the corpus's own item comments | 57 vulnerable items + 1 negative |
| Crypto libraries in the corpus manifests | the same corpus | OSV.dev `querybatch` at test time | 6 |

## Run it

```bash
cd aibom && uv sync --frozen --all-extras --dev && cd ..          # the product under test
python3 bench/cbom/d1/d1.py all --work /tmp/d1 --python aibom/.venv/bin/python
# or step by step:  d1.py prepare --work W ; d1.py product --work W --python PY ; d1.py score --work W
python3 -m pytest bench/cbom/d1/tests                               # unit tests; D1_WORK=W adds the benchmark ones
```
`prepare` needs git and HTTPS to github.com and api.osv.dev (about 6 s); `product` takes 30-70 s (OWASP's 975
files dominate); `score` takes under a second. Exit codes: **0** every floor holds, **1** a floor failed,
**2** not judged (a pin, a label count, the code map, an input or the floors base does not match): never read 2 as
a pass. `d1.py check-floors --base REF` exits 1 when floors.json loosens without a record (see Floors).
CI runs it as the `cbom-d1` job (`ci.sh`): `report.md` in the job summary, the work files as the
`cbom-d1` artifact.

## How a case is judged

* **Product call.** `run_product.py` (the only file here that imports the product) calls
  `aibom.integrations.cbom_devsecshield.scan_crypto_to_devsecshield(tree, level=4)`, the scan-worker's call
  (`RabbitMQ/worker/helpers/tools/cbom_agent/main.py`), once per bench on a copy of the scanned files (no `.git`, no
  label file). It keeps the run object's `results` rows that carry finding codes. The gate (W-D1) can feed rows read
  from the API through `lane.observed.from_run_object` and get the same verdicts.
* **Benchmarks: by file.** A case is flagged when a finding on one of its files has a code that `codemap.json`
  accepts for the case's category (`matched`); the `any code` columns count any non-ignored code. Lines are not used:
  18 of CryptoAPI-Bench's line cells are Excel dates and OWASP gives none. One whole-tree scan per bench gives the
  same per-file codes as scanning each file alone (195/195 files: DA-P1's per-file scans at 83b570b against a tree
  scan at 3df26fd; no engine file changed between the two).
* **Corpus: by line.** An item is `hit` when a finding on its file has its primary `line` on one of the item's lines
  (exact first, then within `line_tolerance` 1), an accepted code, and that (finding, code) has not counted for
  another item. `listed` = the line appears only in the row's `occurrences`; it is shown, never counted, because
  occurrences are lexical (a Terraform probe: changing `min_tls_version` to TLS1_2 left line 37 in the TLS 1.0 row,
  renaming `tls_private_key` removed line 23). Findings left over are **extras**.
* **Libraries.** Vulnerable = OSV lists at least one advisory for that version, asked at run time and recorded in
  `osv.json`. No answer = NOT-RUN, never "not vulnerable".
* **Metrics** per bench and per slice (category, CryptoAPI-Bench complexity class = the sheet's own section header,
  complexity x category, language): tp/fn/fp/tn, recall, precision, specificity; `null` on an empty denominator.

## Floors (`floors.json`)

| kind | meaning | when it is met | when it is not |
|---|---|---|---|
| `non-regression` | today's numbers (baseline: dev 3df26fd), exactly: ratios, "every case detected stays detected", "no new false-positive case", "no new corpus extra" | pass | **FAIL** |
| `target` (`owner`: CB-27, CB-28, CB-29) | the exit numbers of the track that owns it | **UNEXPECTED-PASS: fails the lane** | expected-fail |

A PR that makes a target pass must, in the same PR, turn it into a `non-regression` row (and raise the ratio floors to
its new numbers): that is how the floors rise with the product. A floor that cannot be computed is NOT-RUN and fails,
unless it carries `not_run_ok` (only the OSV-backed library rows do). Today: 29 non-regression floors pass, 22
targets are expected-fail, for example the basic (BB) cases of static IV 0/1, static salts 0/1, seeds 0/2.

**The floors only rise.** `d1.py check-floors --base REF` compares floors.json with the base's copy (ci.sh: `HEAD^1`
of the job's merge-commit checkout, i.e. the PR's base; locally `origin/dev`; `D1_FLOORS_BASE` overrides), and so does
the unit test `test_floors_only_rise`. Refused unless recorded: a floor id that disappears, a lower `>=` value (a
higher `<=` value), a `superset` list that loses an id, a `subset` list that gains one, a changed `bench`, `where`,
`metric`, `mode` or `op`, a non-regression row that becomes a target, a new `not_run_ok`, and a target that goes
without a non-regression row at least as high (in place or under a new id). A deliberate loosening carries
`"lowered": {"reason": ..., "pr": ...}` on its row, or for a floor that goes, an entry in the top-level
`"removed": [{"id", "reason", "pr"}]`; the record must be new in that change, and `report.md` prints every record.
The non-regression floors must also equal the numbers of `baseline/observed-*.json` (tests
`test_nr_floors_are_tight_on_the_baseline_*`), so a PR that moves a floor updates the baseline it came from.

## The code map (`codemap.json`)

Product finding codes, read in the benchmarks' vocabulary: for each lane category, the codes (and for shared codes
such as `WEAK_ALGORITHM`, the algorithm the row names) that count as reporting that weakness. It translates output;
it states no expected value. Every code the product emits must be accepted somewhere or listed under `ignored`
(today only `QUANTUM_VULNERABLE`, a PQC posture), or the lane stops with exit 2. Categories with no product code yet
(`static_salt`, `weak_kdf_iterations`, `weak_rsa_exponent`) score 0 until the PR that adds the code adds its row; the
reviewers check that row (O-9). `TLS_VERIFICATION_DISABLED` is split on the pattern id its row names
(`tls_endpoint:<id>`): the hostname-verifier patterns count for `hostname_verification_off`, every other one (including
those that switch all verification off, such as `InsecureSkipVerify`) for `cert_validation_off`. A `WEAK_ALGORITHM` row
whose algorithm ends in `-ECB` (the product's `DES-ECB`) counts as ECB.

## Output contract (for CB-27, CB-28, CB-29 and the gate)

`report.json`, schema `zs-cbom-d1-report/1` (additive changes only; a breaking change bumps the schema):

| key | content |
|---|---|
| `verdict` | `pass` / `fail` |
| `result_sha256` | sha256 of `inputs, results, cases, extras, osv_answers, floors, floors_removed, verdict` (sorted keys), reading each library's OSV answer as its verdict (has an advisory or not; the advisory ids stay in report.json but outside the hash): equal for two runs on the same build, pins and per-library OSV verdicts |
| `product` | entry, level, `git_sha`, `aibom_dirty`, `kb_version`, scan tree digest and files |
| `lane` | lane commit, `codemap_version`/`_sha256`, `floors_version`/`_sha256`, `sources_sha256` |
| `inputs.<bench>` | `source` (repo, commit, license, label sha256, scan tree digest), `labels` (counts, `excluded` with reasons, `anomalies`), `observed_rows` |
| `results.<bench>` | `overall`, `by_category`, `by_lane_category`, `by_complexity`, `by_complexity_category` (CryptoAPI-Bench), `by_language` (corpus); each `{matched, any}` x `{cases, vulnerable, secure, tp, fn, fp, tn, recall, precision, specificity}` |
| `cases[]` | one row per case: `bench, case_id, files, category, lane_category, vulnerable, flagged_matched, flagged_any, evidence[[file, line, code, algorithm]]` (+ `complexity`, `class_no`, `cwe`, `status` for corpus/library items) |
| `extras.corpus` | corpus findings on no labelled item |
| `floors[]` | each floor row (with its `lowered` record, if any) plus `observed` and `status` (`pass`, `fail`, `expected-fail`, `unexpected-pass`, `not-run`, `not-run-ok`) |
| `floors_removed` | floors.json's `removed` records |
| `osv_answers`, `osv_asked_at`, `osv_error`, `product_seconds` | the library oracle and timings (timings are outside `result_sha256`) |

Bench names: `cryptoapi-bench`, `owasp-benchmark`, `corpus`, `libraries`. Floor `where` keys are case fields
(`category`, `lane_category`, `complexity`, `case_id`, `vulnerable`, `language`); a list means "any of".

## Label notes the benchmarks carry (reported, not corrected)

* CryptoAPI-Bench 9.8.2 names `PredictableSeedsABPMCase2.java` / `PredictableSeedsABPM2.java`, which are not in the
  tree (`PredictableSeedsABMCCase2.java` / `ABMC2.java` are, unlabelled): not judged, never remapped (O-2). CB-02
  (PR #79) reads the sheet the same way: 171 cases, 136/35, 170 judgeable, 18 date-typed line cells.
* Codes 2.1.3 and 3.1.2 name each other's category; the file's directory is used.
* The path-sensitive section (20 cases) is labelled secure: flagging them is a false positive.
* DA-P1 (round6/cbom/da-probes) counted files by name ("correct" in the name = secure): 8 of the 47 files it counted
  as detections are cases the benchmark labels secure, all in the path-sensitive section (EcbInSymmCryptoABPSCase1,
  BrokenCryptoABPSCase1-4, BrokenHashABPSCase1-3). Its 47/173 is therefore not the benchmark's number; this lane's is
  39/135 recall with 39/47 precision on dev 3df26fd (47 = 39 true positives + 8 false positives).

## Relation to `bench/cbom` (IBM cbomkit-theia + cdxgen, `cbom-nightly.yml`)

Separate lanes; this one imports, reuses and gates on nothing from it. `bench/cbom` compares the engine's crypto
**inventory** with other tools' output (no ground truth, a triage table written by the product team, `:latest`
oracle image, repositories at HEAD, a product fixture). cbomkit-theia reads certificates and keys on disk, not code:
on 2026-11-12 the image the weekly job pulled (`sha256:46a72ead...`) found **0** components in CryptoAPI-Bench and
**0** in this corpus. So it cannot measure code-lane accuracy under O-1/O-2, and this lane does not replace it as an
inventory coverage check.
