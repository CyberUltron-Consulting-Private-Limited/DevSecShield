### Accuracy

| ID | Test | Pass when |
| --- | --- | --- |
| ACC-01 | Java JCA weak ciphers, modes, hashes, RNG, TLS versions | Recall and precision at or above baseline gates for Java items |
| ACC-02 | Python: cryptography, PyCryptodome, hashlib, ssl, random | Gates met for Python items |
| ACC-03 | JavaScript/TypeScript: node crypto, forge, jsonwebtoken | Gates met for JS items |
| ACC-04 | Go: crypto/*, tls.Config | Gates met for Go items |
| ACC-05 | C/C++ OpenSSL EVP and SSL_CTX | Gates met for C items |
| ACC-06 | C#/.NET crypto classes and cert callbacks | Gates met for C# items |
| ACC-07 | PHP openssl_*, md5, mt_rand | Gates met for PHP items |
| ACC-08 | Hard-coded keys and IVs in several encodings | Every hard-coded key and IV reported with file and line |
| ACC-09 | Certificate-validation bypass logic | All bypasses reported |
| ACC-10 | Custom crypto: XOR loop, toy Feistel, inline AES S-box | Each reported as custom crypto |
| ACC-11 | Infrastructure-as-code: Terraform, CloudFormation, K8s YAML, Helm, Ansible, Dockerfile, nginx.conf | Gates met for IaC items |
| ACC-12 | Vulnerable direct crypto dependencies | Each vulnerable library and version reported |
| ACC-13 | Vulnerable transitive-only dependency | Transitive library reported with its dependency path |
| ACC-14 | Vendored crypto source with no manifest | Reported as embedded crypto implementation |
| ACC-15 | Binaries: static Go, static C with OpenSSL, JAR with Bouncy Castle | On: binaries reported; off: none reported and no extra credits charged |
| ACC-16 | False-positive traps: non-security MD5, crypto words in comments, strong correct usage | Zero findings on no-finding traps; test fixtures marked low |
| ACC-17 | Quantum-vulnerability labels and NIST quantum security level | RSA, ECDH, ECDSA, DH, DSA labelled quantum-vulnerable; levels match the reference table |
| ACC-18 | Location and severity agreement | File and line within 2 lines for at least 95%; severity agreement reported |

### Output

| ID | Test | Pass when |
| --- | --- | --- |
| OUT-01 | CycloneDX 1.6 schema validity of the export | Zero schema errors |
| OUT-02 | cryptoProperties completeness | Fields present wherever the source states them |
| OUT-03 | Round trip: export, then Analyze CBOM file | Same inventory and findings as the original scan |
| OUT-04 | Determinism | Byte-identical normalised CBOM |
| OUT-05 | Zip and Git connector parity | Identical findings |
| OUT-06 | Deduplication | One component with many occurrences, not many components |

### Evasion

| ID | Test | Pass when |
| --- | --- | --- |
| EVA-01 | String concatenation and splitting of algorithm names | Evasion score at or above 60% |
| EVA-02 | Constant propagated across files and classes | At or above 60% |
| EVA-03 | Algorithm chosen in config (properties, YAML, .env) | At or above 60%; config line and call site both reported |
| EVA-04 | Reflection and dynamic dispatch | At or above 60% |
| EVA-05 | In-house wrapper chains (depth 1, 3, 5) | At or above 60%; depth at which detection stops recorded |
| EVA-06 | Encoded literals (base64, hex, char arrays, reversed) | At or above 60% |
| EVA-07 | Implicit defaults (Cipher.getInstance("AES") is ECB; numeric mode constants) | At or above 60% |
| EVA-08 | Import aliasing and dynamic imports | At or above 60% |
| EVA-09 | Key obfuscation: split, hex-decoded, derived from a constant, resource file, .env, notebook output, nested zip | At or above 60% |
| EVA-10 | Key present only in Git history | Product decision recorded; if history scanning is on, key reported |
| EVA-11 | Unicode: UTF-16 source, homoglyphs, zero-width characters, Trojan Source bidi | At or above 60%; bidi trick flagged |
| EVA-12 | File-level: odd or missing extensions, 6 MB minified bundle, default-excluded folders, linguist-vendored | At or above 60%; every skipped folder listed in the scan report |
| EVA-13 | Other places: Kotlin, Scala, Groovy, SQL AES_ENCRYPT and pgcrypto, shell, PowerShell, Dockerfile | At or above 60% |
| EVA-14 | Binary evasion: stripped, UPX-packed, static | At or above 60%; packed binaries at least flagged as packed |
| EVA-15 | Submodules and Git LFS objects | Product decision recorded and documented to customers |

### Hostile input

| ID | Test | Pass when |
| --- | --- | --- |
| HOS-01 | Flat zip bomb | Rejected or stopped within limits; worker memory and disk stay under caps |
| HOS-02 | Nested zip bomb | Same as HOS-01; nesting depth limit enforced |
| HOS-03 | 100k files, 2,000-level nesting, 255-byte names | Completes or is rejected with a clear limit message within 10 min |
| HOS-04 | Zip Slip (../ and absolute paths) | No file written outside the extraction directory |
| HOS-05 | Symlink entries to /etc/passwd, /proc/self/environ, SA token, AWS credentials | Symlinks not followed; no host file content in any finding, log or export |
| HOS-06 | Malformed archives: truncated, duplicate entries, encrypted, tar renamed .zip, polyglot | Clear error for each; no crash; no partial scan marked complete |
| HOS-07 | Filename injection: $( ), backticks, ;, leading --, newline | No canary callback; file names shown escaped |
| HOS-08 | Regex DoS: unterminated PEM with 5 MB base64, huge lines | Scan time within 2x a same-size benign repo |
| HOS-09 | Parser bombs: XXE in pom.xml, billion laughs, YAML alias bomb, deep JSON | No XXE callback or file read; bounded memory |
| HOS-10 | Hostile CBOM uploads: XSS and CSV-injection names, deep nesting, __proto__, schema-invalid, external refs | No script runs; formulas neutralised; no external fetch; schema errors shown |

### Platform security

| ID | Test | Pass when |
| --- | --- | --- |
| PLT-01 | Code execution from scanned repo: setup.py, npm lifecycle, Gradle, Maven, wrappers, conftest, build.rs, go generate, Makefile | Zero canary callbacks |
| PLT-02 | Uploaded .git/config with fsmonitor, sshCommand, hooksPath, hooks | Zero canary callbacks |
| PLT-03 | SSRF via repository URL field | All rejected before any connection; no request reaches metadata or internal IPs |
| PLT-04 | Git argument injection via URL and branch fields | No option injection; no file created; no callback |
| PLT-05 | SSRF via .gitmodules, .lfsconfig, .npmrc, pip index, go.mod replace | Zero callbacks; no metadata access |
| PLT-06 | PAT handling | Token never appears anywhere; write-scope tokens warned about |
| PLT-07 | Stored XSS and CSV injection via file names, cert subjects, CBOM fields | No script executes; no callback; CSV formulas prefixed |
| PLT-08 | Tenant isolation | All denied; presigned URLs expire as configured |
| PLT-09 | Retention of uploads and clones | Deleted per published policy |
| PLT-10 | Scanner sandbox | Only Git hosts reachable; metadata blocked; filesystem read-only outside workdir |

### Credits

| ID | Test | Pass when |
| --- | --- | --- |
| BIL-01 | Estimate and run race: repo grows between estimate and run | Run re-estimates or charges the true size; no free scanning |
| BIL-02 | Tampered estimate and scan-start requests | All rejected |
| BIL-03 | Concurrent scans beyond balance | At most one starts |
| BIL-04 | Refunds for failed and cancelled scans | Charges match the published refund rule |

### Code resilience

| ID | Test | Pass when |
| --- | --- | --- |
| RES-01 | Large repos: 1 GB, 50k files, 30 languages | Completes; time and memory recorded |
| RES-02 | Git host rate limits and 5xx during clone | Retries with backoff; clear error if it gives up |
| RES-04 | Worker killed mid-scan | Scan resumes or fails cleanly; never marked complete with partial data |
| RES-05 | Noisy neighbour | B's scan time rises under 20% |
