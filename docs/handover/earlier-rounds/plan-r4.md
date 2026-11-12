# Round 4 plan: in-house fix code, diff, exploit demo, dependency graph, data quality, AWS gaps

Repo: /home/claude/devsecshield, branch `ansh`, HEAD c77d215. No LLM anywhere on CBOM paths (air-gap).

## Discovered architecture (evidence)
- Code scan: worker `RabbitMQ/worker/helpers/tools/cbom_agent/main.py` -> aibom engine
  (`aibom/src/aibom/cbom/detect.py` regex/AST detectors, `scanners/algorithm_scan.py`, `protocol_scan.py`,
  `normalize.py` -> result rows, `emit/cyclonedx.py`) -> adapter `aibom/src/aibom/integrations/cbom_devsecshield.py`
  (legacy fields) -> backend `create_findings.py` stores each row in Mongo `scan_findings.finding_data`.
- The repo checkout and MinIO upload are deleted at the end of the scan (main.py:88-127, scan_worker.py ~659).
- `snippet` is hard-coded "" (cbom_devsecshield.py:207); `location` is the relative path only; detect.py has
  `line_no` (122, 773) but algorithm_scan.py:157-163 dedupes by (name, path) and drops it.
- Remediation: `POST /{team}/{type}/scan/{scan}/finding/{fid}/remediate` (backend/routers/scans.py:1132-1239);
  for CBOM it calls `kb_remediation(finding_data, "code")` (no LLM, no credits) and stores Mongo `remediation`.
  Response shape (AI-compatible): fix{description, original_code, fixed_code, language, confidence,
  validation_notes, references[]}, exploit_payload{description, payload, impact_demonstration, prerequisites,
  difficulty, attack_vector}, diff, + source/kb_version/details[].
- UI: drawer `frontend/components/CbomResults.tsx:1653-1775`; `RemediationPanel.tsx:144-149` routes CBOM to
  `CbomKnowledgePanel`, which renders only `details` (`cbom/KbFindingDetails.tsx`): fix/diff/exploit fields ignored.
- Graph: `normalize.py:428-463` nodes = components, edges only from cryptoProperties refs; `result.edges` empty,
  no CycloneDX `dependencies`; `aibom/src/aibom/graph_view.py:94-248` folds orphans into "Unlinked X (N)";
  UI `frontend/components/bom/BomGraphCard.tsx` (@xyflow/react + dagre, bundled).
- Data quality (root causes, file:line in the exploration report):
  - library / unencrypted-at-rest / TLS-verify-off rows: `asset_type` None -> type "other", strength "strong"
    (`_legacy_strength` cbom_devsecshield.py:79-92), quantum None, excluded from weak chart because
    `_WEAKNESS_CODES` (normalize.py:45) = WEAK_CRYPTO_CODES (weakness.py:74-80) + EXPIRED_CERTIFICATE only;
    risk 5.9 because VULNERABLE_CRYPTO_LIBRARY / UNENCRYPTED_AT_REST / TLS_VERIFICATION_DISABLED are missing in
    `_CBOM_FLAG_DELTA` (backend/utilities/dashboard/bom_risk_score.py:27-44).
  - IPsec FP: `protocol_scan.py:110-114` `\bstroke\b` matches SVG `stroke=`.
  - AES FP: literal patterns (detect.py:314-316) run on prose in string literals.
  - "HMAC-CBC": mode appended to any primitive (algorithm_scan.py:114-115).
  - Top risks show "No" for quantum None (`CbomResults.tsx ~1632`).
- AWS (real account run, 2026-11-01): Validate + collect pass; 21/21 lab KMS/ACM/ALB/S3/RDS objects found by
  ARN; scorer recall 3/37 because of kind names; product does not collect EC2 key pairs or SSM parameter metadata.

## Proposed changes
P1 Locations + snippets (root cause of "no fix code"): keep every occurrence (path, line) per asset in
   algorithm_scan/protocol scan (dedupe per (name, path, line), cap occurrences per asset); capture a source
   window (line +-3, max 12 lines / 2 KB, secrets redacted by the existing redactor if any, else a key/secret
   regex) at scan time while the checkout exists; emit `evidence.occurrences[{location, line, offset}]` in CycloneDX;
   adapter fills `location` = "path:line", `line`, `snippet`, `snippet_start`, `language` (by extension).
P2 Fix-code engine (new `aibom/src/aibom/cbom/fixgen.py`, pure stdlib, deterministic): rules keyed by
   (finding code / algorithm, language) with regex rewrites on the snippet: Python hashlib/Crypto/cryptography/ssl/
   requests verify/jwt; Java MessageDigest/Cipher/KeyPairGenerator/Signature/SSLContext; JS/TS crypto/createHash/
   createCipheriv/rejectUnauthorized/CryptoJS/forge; Go crypto/md5|sha1|des|rc4, InsecureSkipVerify, tls.Version*,
   rsa.GenerateKey; C# MD5/SHA1/DES/TripleDES/RC2/ECB/RSA size/certificate callbacks; C/C++ OpenSSL EVP_*,
   SSL_VERIFY_NONE, TLSv1_method; PHP md5/sha1/mcrypt/openssl_encrypt; Ruby Digest/OpenSSL::Cipher/VERIFY_NONE;
   lock files/manifests (bump to the KB's fixed version); Terraform (storage_encrypted, encrypted, ssl_policy).
   Output: fixed snippet, unified diff (difflib), confidence from the rule (exact API swap high, structural change
   like ECB->GCM medium, manual-only low), validation notes per rule (data migration, interop, nonce handling),
   references from the KB. No rule -> no fake code: return KB steps and say it needs a manual change.
P3 Exploit-demo engine (`aibom/src/aibom/cbom/exploitdemo.py`): per code an honest narrative bound to the
   finding (algorithm, file:line), difficulty, vector, prerequisites, impact, and a SAFE self-contained local PoC
   that really runs and proves the weakness without touching any system: ECB block repetition, MD5 collision
   (a verified public collision pair, checked by test), DES/RC4/short-key keyspace math + toy search, RSA small
   modulus toy factoring, disabled TLS verification accepting a self-signed local server, JWT alg=none/verify off
   on a local token, vulnerable library = installed-version check vs advisory, unencrypted storage = read-only
   describe command. Every PoC is executed by the test suite (proof it is real, not asserted).
P4 UI: `CbomKnowledgePanel` gets the AI panel's tabs: Fix code (summary, confidence, vulnerable code with
   file:line, fixed code, validation notes, references), Diff, Exploit demo (narrative, difficulty, vector, PoC,
   impact, prerequisites), plus the KB details; label "Generated in-house (no AI)". Drawer shows "Code snippet"
   with line numbers when present.
P5 Data quality: new strength value "vulnerable" for library / config rows with weakness codes; asset types
   "library" / "configuration"; weak chart categories for VULNERABLE_CRYPTO_LIBRARY, UNENCRYPTED_AT_REST,
   TLS_VERIFICATION_DISABLED (+ KPI "Weak" counts them); risk deltas from crypto-risk-weights.yaml; quantum
   "n/a" for classically broken hashes (not "Safe"); top-risks shows "—" for None; IPsec `stroke` only with
   strongSwan context (ipsec/strongswan/charon/swanctl in file or .conf/.secrets/swanctl paths); literal AES etc.
   in prose-like string literals (>=3 words, no API on line) becomes a documentation mention, not usage;
   modes only for block ciphers.
P6 Graph: emit real edges: file -> algorithm ("uses", from occurrences), library/API -> algorithm ("provides",
   from the detector's API family e.g. hashlib, javax.crypto, node:crypto, crypto/*, OpenSSL), protocol ->
   cipher suite -> algorithm, certificate -> key/sig; CycloneDX `dependencies` with dependsOn/provides;
   graph_view clusters by directory and library instead of one "Unlinked" blob; risk colouring kept.
P7 AWS gaps: collect EC2 key pairs (DescribeKeyPairs IncludePublicKey -> type, RSA bits; WEAK_KEY_SIZE,
   QUANTUM_VULNERABLE) and SSM parameter metadata (DescribeParameters: name, type, KMS key; String parameter
   whose name says key/secret/password/token/cert -> plaintext-secret finding) without any data-plane call;
   scorer maps product asset types to ground-truth kinds (kms_key->kms-key, storage_encryption->
   storage-encryption, load_balancer_tls->tls-policy).
P8 Benchmark: run our scanner on ~50 repos that have public tool-generated CBOMs, compare per algorithm family
   and location, list misses/extras, close detector gaps, re-run.
P9 Validation: unit tests per rule and per PoC (PoCs executed), regression tests for each FP, graph edge tests,
   backend API e2e on a scan with real snippets, Playwright drawer/graph checks, air-gapped re-run, egress capture.

## Risks
- Snippets put source code into Mongo/CBOM exports: size caps, secret redaction, same tenancy as findings.
- Regex rewrites can produce code that does not compile; mitigate with per-language compile/syntax checks in
  tests (python -c compile, node --check, go vet where available) and confidence < 100.
- Changing dedupe granularity increases row counts (one row per (asset, file) today) — keep rows as today,
  carry occurrences inside the row.
- Old scans have no snippets: UI must degrade (show KB steps, say "rescan to get code-level fixes").
- Exploit demos must stay non-weaponised and local-only.

## Confidence
Root causes for data-quality items: high (code lines identified). Fix-code coverage: medium (depends on how
often detectors carry enough context). Graph: medium-high. AWS gaps: high.

## Devil's-advocate decisions after reviews 1, 3, 4, 5 (review 2 pending)
- D1 Fix/exploit engines live in the backend only (backend image has no aibom; reviewer 3/1). Generated at remediate
  time from the stored snippet, so rule updates reach old findings. Remediation stamped `engine: "kb+fixgen/2"`;
  the panel ignores older stored results (shows them only after a rebuild) and shows rebuild errors even with data.
- D2 Snippets: captured in the worker while the checkout exists; redacted there (string literals >= 8 chars on
  key/IV/cipher lines, PEM/base64 runs, high-entropy tokens, AKIA/ghp_/eyJ/xox prefixes); never in CycloneDX;
  one snippet per asset (first occurrence), +-3 lines, column window +-160 chars for long lines, 2 KB cap,
  per-scan snippet budget 1.5 MB; symlinks that resolve outside the root are skipped; files with NUL bytes or a
  UTF-16 BOM decoded or skipped; minified/generated files get no snippet/fix.
- D3 `discovery:source` / `location` stay bare paths; line numbers go into new fields (`line`, `occurrences`,
  `occurrence_count`, `snippet_start`, `language`); bom_ref unchanged (rollup identity stable).
- D4 One line splitter ("\n", newline="") in detect.py so line numbers are exact; occurrences found by a late
  occurrence pass that re-runs the detectors on the file (covers AST/misuse/custom scanners that keep no line).
- D5 No new strength value: rows with VULNERABLE_CRYPTO_LIBRARY / TLS_VERIFICATION_DISABLED / UNENCRYPTED_AT_REST
  become weak (chart category + KPI); type "library" / "configuration" on the row only (never crypto:assetType);
  backend applies the same derivation on read so old scans agree; risk deltas added for the three codes.
- D6 Quantum stays "not broken by Shor" (intentional); UI shows "n/a (classically broken)" for weak hashes without
  changing the gauge maths; top-risks shows "—" for None.
- D7 Rewrites only at the detected API span; non-security MD5 (usedforsecurity=False, ETag, Content-MD5, uuid3)
  gets no rewrite; lock files never edited (command fix instead); Terraform encryption changes and password-hash
  migrations are shown with a "forces replacement / needs migration" warning and low confidence; diffs keep line
  endings, carry the real hunk offset and quote paths; Go import edits only when the import is inside the window.
- D8 PoCs: stdlib + openssl CLI only, port 0, usedforsecurity=False for MD5; nothing from the scan is pasted into
  scripts; every PoC executed by the tests.
- D9 Graph: libraries/APIs -> algorithms edges ("provides") from the detector's library and the file's imports;
  directory clusters (depth <= 2) -> algorithms ("found in") in the graph view only; parallel edges merged with
  counts; caps apply to connected nodes too; CycloneDX dependencies only between real components.
- D10 Logging: one summary log line per scan (counts by detector/code, snippets captured/skipped) and one per
  remediation (codes, language, fix rule or none, confidence, KB version, PoC family).
- D11 Goldens regenerated deliberately with a reviewed diff; tests compare via the new fields.
- Deferred with reason: worker image for AWS (pulls torch+CUDA, >10 GB; build host disk too small); unregistered
  jvm_go/native/web_native scanners (benchmark decides).
