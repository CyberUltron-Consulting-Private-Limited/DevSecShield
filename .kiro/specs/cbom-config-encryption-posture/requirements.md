# Requirements Document

## Introduction

DevSecShield's CBOM scan inventories cryptographic assets from source code, certificates and a few crypto policy files. It cannot say whether the infrastructure around that code encrypts data at rest, which TLS policies the endpoints enforce, or how keys are managed. Three causes explain the gap: the infrastructure-as-code (IaC) scan is an LLM map-reduce agent with no structured encryption model, protocol detection reads only source code, and no scanner infers data-at-rest protection. Three of the 16 regulatory CBOM deliverables depend on exactly that evidence:

- Deliverable #5, Infrastructure & Cloud Encryption Posture
- Deliverable #6, Network, TLS & Crypto Protocol Assessment
- Deliverable #9, Data-at-Rest Encryption Assessment

This feature adds, inside the CBOM scan lane only, deterministic in-house extractors for configuration and IaC files, an offline importer for TLS result files that customers produce with their own tools, and three new team-wide PDFs in the existing Deliverables menu. Everything runs in an air-gapped environment: no network, no live probing, no cloud API, no LLM and no new third-party library.

The work stacks on the MEDIUM deliverables branch (`feat/cbom-team-deliverables`, commit `f7385517523212e50b20ec6f1947831a5ef19872`) as the new branch `feat/cbom-high-deliverables`. Quantum risk register Q0-Q4 (#13), crypto-agility maturity (#14) and new regulatory frameworks (#17) are separate later specs.

### Code facts that shape this work

- The scorer computes `risk_normalized` against the sum of all flag weights in `aibom/config/crypto-risk-weights.yaml` unless `scale.max_raw` is set, so adding weights would silently rescore every existing scan (Requirement 28).
- The Methodology document (#3) prints the registered CBOM scanners and a contract test pins that list to the engine registry, so registering new scanners changes that document for every team (Requirement 39).
- The team roll-up reads every key of `cbom_compliance`, so a 14th framework key would change the Board report and the assurance ledger; this feature therefore adds no framework key (Requirement 29).
- The scan worker executes tasks in threads (`celery ... -P threads`), so limits cannot rely on signals or timers (Requirement 4).
- `nmap -oX` output starts with a bare `<!DOCTYPE nmaprun>`, so a blanket DOCTYPE rejection would reject every nmap file (Requirements 3 and 24).
- CloudFormation YAML uses short-form tags such as `!Ref` that `yaml.safe_load` rejects (Requirement 3).
- The `aibom` package declares Python 3.11 or later, while the backend runs Python 3.10 (Requirement 51).
- The posture lanes run in the scan-worker image, so a production rollout needs a worker image rebuild in addition to the backend and frontend images (Requirement 52).
- Every stored scan predates this feature and carries no posture marker (Requirements 30 and 38).

### Group map

| Group | Topic | Requirements | Deliverables |
|---|---|---|---|
| A | Shared extraction foundation and encryption-facts data model | 1 to 9 | #5, #6, #9 |
| B | Infrastructure and cloud encryption posture | 10 to 15 | #5 |
| C | Data-at-rest inventory and assessment | 16 to 19 | #9 |
| D | Network, TLS and protocol assessment | 20 to 25 | #6 |
| E | CBOM representation, scoring, compliance and compatibility | 26 to 31 | #5, #6, #9 |
| F | Deliverable PDFs, roll-up, API and menu | 32 to 40 | #5, #6, #9 |
| G | Air-gap and no-LLM guarantees | 41 to 43 | #5, #6, #9 |
| H | Verification and evidence | 44 to 50 | #5, #6, #9 |
| I | Scope gates and release | 51 and 52 | #5, #6, #9 |

## Glossary

- **CBOM_Scan**: A DevSecShield scan of type `cbom`, started from a git checkout, an uploaded zip or an uploaded BOM file.
- **Scanned_Input**: The directory tree a CBOM_Scan reads: the git checkout or the extracted zip. No other path is read.
- **CBOM_Engine**: The in-house cryptographic-BOM engine in `aibom/src/aibom/cbom/` (`scan_crypto`, the registered CBOM scanners, Risk_Scorer, Compliance_Engine and Run_Object_Normalizer). It runs in the scan-worker image and from the `aibom` CLI.
- **Config_Extractor**: The new CBOM-lane scanners and parsers, registered with `cbom_register`, that read configuration, IaC and server-configuration files in the Scanned_Input and emit Encryption_Facts and crypto assets.
- **TLS_Result_Importer**: The new CBOM-lane scanner that parses testssl.sh JSON, sslyze JSON and nmap `ssl-enum-ciphers` XML files that already exist in the Scanned_Input.
- **Verdict_Engine**: The pure, deterministic logic that turns parsed attributes and Defaults_Registry rows into Verdicts.
- **Defaults_Registry**: The versioned data files packaged with the CBOM_Engine: Provider_Defaults_Table, TLS_Policy_Registry, cipher-suite and key-exchange registries, and curated pattern lists. Every row carries a public source URL and a valid-as-of date.
- **Provider_Defaults_Table**: The part of the Defaults_Registry that states, per provider resource type or software directive and attribute, the documented default and its encryption effect.
- **TLS_Policy_Registry**: The part of the Defaults_Registry that maps named TLS policies (for example load-balancer security policies) to minimum and maximum protocol versions and cipher families.
- **Coverage_Table**: The versioned list of (format, provider, native type, attributes consulted) that the Config_Extractor assesses. Requirement 10 fixes its minimum content.
- **Encryption_Fact**: One record about a declared resource or endpoint: identity, kind, provider, location, per-Layer Verdicts, key management, evidence basis and linkage (Requirement 5).
- **Verdict**: One of ENCRYPTED_DECLARED, ENCRYPTED_PROVIDER_DEFAULT, NOT_ENCRYPTED, UNKNOWN.
- **Layer**: The protection layer at which a Verdict is stated: `application`, `database`, `volume`, `service`, `backup` or `transport`.
- **Tri_State**: The existing compliance verdict vocabulary: pass or fail, NOT_BOM_EVIDENCEABLE, OUT_OF_SCOPE.
- **Coverage_Percentage**: pass divided by (pass plus fail), as defined by the existing compliance engine; null when pass plus fail is zero.
- **Diagnostic**: A record that a file or construct was skipped or only partly read, with a closed-vocabulary code and a sanitized path.
- **Finding_Catalog**: The table of posture finding codes, severities and weights defined in Requirement 15.
- **Posture_Finding**: A flag raised on an Encryption_Fact with a code from the Finding_Catalog.
- **Posture_Block**: The new run-object key `cbom_posture` carrying the Posture_Marker, Encryption_Facts, findings, imports, Diagnostics, counts and Defaults_Registry versions.
- **Posture_Marker**: The `schema_version` and `lanes` fields of the Posture_Block. Its presence means the scan ran the posture lanes, including when it found zero facts.
- **Not_Assessed**: The state of a Source whose current scan has no Posture_Marker.
- **Business_Mapping_File**: The optional in-repo YAML or JSON file that declares system, owner, data classification and data lifetime (Requirement 19).
- **Owner_Hint**: An owner derived from a CODEOWNERS file.
- **Assessor_Cell**: A table cell marked "(assessor)" that the platform leaves blank for manual completion.
- **Weights_File**: `aibom/config/crypto-risk-weights.yaml`.
- **Risk_Scorer**: `score_crypto` in `aibom/src/aibom/cbom/scorer.py`, which delegates to the shared scoring engine.
- **Compliance_Engine**: `run_cbom_compliance` in `aibom/src/aibom/cbom/compliance.py` and the shared runner it uses.
- **CBOM_Emitter**: The CycloneDX 1.6 serializer in `aibom/src/aibom/emit/cyclonedx.py`.
- **Run_Object_Normalizer**: `normalize_crypto` in `aibom/src/aibom/cbom/normalize.py` plus the adapter enrichment.
- **Worker_Adapter**: `scan_crypto_to_devsecshield` in `aibom/src/aibom/integrations/cbom_devsecshield.py`.
- **Source**: A scanned source identity as defined by the MEDIUM roll-up: repository plus branch, zip upload title, or uploaded BOM file.
- **Fidelity_Tier**: The MEDIUM roll-up classification of a stored scan as A, B or C.
- **Team_Rollup**: `backend/utilities/dashboard/cbom_team_rollup.py`.
- **Deliverable_Renderer**: A PDF builder under `backend/utilities/pdf/` together with the shared scaffolding in `cbom_deliverable_common.py` and `cbom_deliverable_text.py`.
- **Deliverables_Registry**: `backend/utilities/pdf/cbom_deliverables.py`.
- **Deliverables_Router**: `backend/routers/cbom_deliverables.py`.
- **Deliverables_Menu**: The Deliverables dropdown on the team CBOM landing page (`frontend/app/[team_id]/cbom/page.tsx`, `frontend/utils/backend_api.ts`).
- **Posture_Deliverables**: The three new PDFs: Infrastructure & Cloud Encryption Posture (#5), Network, TLS & Crypto Protocol Assessment (#6), Data-at-Rest Encryption Assessment (#9).
- **MEDIUM_Documents**: The six existing team-wide PDFs: #1, #3, #7, #10, #15 and #16.
- **Base_Commit**: `f7385517523212e50b20ec6f1947831a5ef19872`.
- **Frozen_Goldens**: The SHA-256 snapshot of the Base_Commit outputs of `scan_crypto`, `normalize_crypto` and the CycloneDX emitter on every `aibom/tests/fixtures/synthetic-crypto-*` tree, plus the pre-feature pytest suites that exist at the Base_Commit.
- **Test_Suite**: The pytest modules in `aibom/tests` and `backend/tests` and the Playwright specs in `e2e/specs` that this feature adds or retains.
- **Evidence_Directory**: `.agents/tasks/cbom-high-deliverables-evidence/`, the untracked folder that holds the videos, screenshots, downloaded PDFs, logs and indexes of the E2E_Harness run (Requirement 50).
- **Airgap_Guard**: The automated checks of Requirements 42 and 43: static import analysis, import-closure probe, runtime socket and process blocking, and the isolated-network egress check.
- **E2E_Harness**: The Docker and Playwright harness under `e2e/` (compose project `dss-e2e`).
- **Independent_Verifier**: A separate procedure that recomputes expected values from raw fixture files and downloaded PDFs without importing product code.
- **Oracle**: The hand-derived expected values committed beside each fixture tree.
- **Release_Gate**: The recorded approval step that precedes any production action.
- **Repository**: The git repository and its documentation, CI workflows and branch policy.

## Requirements

### Requirement 1: CBOM-lane-only registration and pipeline placement

**User Story:** As a platform owner, I want every new capability to run only inside the CBOM scan, so that the IaC, DAST, SAST, SBOM, AI-BOM, MCP and LLM scans behave exactly as they do today.

#### Acceptance Criteria

1. THE Config_Extractor and THE TLS_Result_Importer SHALL register every new scanner only through `cbom_register` in `aibom/src/aibom/cbom/registry.py` and SHALL import every new scanner module in `aibom/src/aibom/cbom/scanners/__init__.py`.
2. WHEN a new scanner, parser or data-loader module imports any `aibom.scan` module other than `aibom.scan.registry`, THE Test_Suite SHALL fail through a static import-graph test.
3. WHEN a module outside `aibom/src/aibom/cbom/`, `aibom/src/aibom/integrations/cbom_devsecshield.py` and the test directories imports a new scanner, parser or data-loader module, THE Test_Suite SHALL fail through the same import-graph test.
4. WHEN `ordered_cbom_scanners()` is evaluated, THE CBOM_Engine SHALL list every new scanner that emits components at an `order` below 40 and every new scanner that only raises flags at an `order` from 41 to 49 inclusive, so that the existing weakness flagger (order 40) sees the new crypto assets and the PQC grader (order 50) sees the new algorithm assets.
5. THE Config_Extractor and THE TLS_Result_Importer SHALL declare `level = 1` for every new scanner, and WHEN `scan_crypto` runs on one Scanned_Input with `level=1` and with `level=4`, THE CBOM_Engine SHALL return ScanResults with identical serialized components, flags and scores.
6. WHEN `scan_repo` of the AIBOM_Lane runs on every fixture used by the existing AIBOM tests, THE AIBOM_Lane SHALL emit output byte-identical to the Base_Commit output.
7. WHEN the Scan_Worker executes a CBOM_Scan, THE Worker_Adapter SHALL reach the new scanners only through `scan_crypto_to_devsecshield`, whose name, parameters and return type remain unchanged.

### Requirement 2: Input discovery and safe file access

**User Story:** As an operator who scans untrusted repositories, I want file access to be deterministic and confined to the scanned input, so that a hostile repository cannot read host files or stall the worker.

#### Acceptance Criteria

1. THE Config_Extractor SHALL walk the Scanned_Input in ascending byte order of the repository-relative POSIX path, so that the order of examined files does not depend on the file system.
2. THE Config_Extractor SHALL skip, at any depth, directories named `.git`, `.terraform`, `.terragrunt-cache`, `node_modules`, `vendor`, `.venv`, `venv`, `site-packages`, `__pycache__`, `dist`, `build`, `target`, `cdk.out`, `.serverless`, `.aws-sam` and `.next`.
3. THE Config_Extractor SHALL open only regular files that are not symbolic links and whose resolved path lies inside the Scanned_Input.
4. IF a directory entry is a symbolic link, FIFO, socket or device node, THEN THE Config_Extractor SHALL skip the entry without opening it and SHALL record a `special_file_skipped` Diagnostic with the sanitized path.
5. THE Config_Extractor SHALL classify each candidate file with the File Classification Table below before parsing, and SHALL ignore a file that matches no row without recording a Diagnostic.
6. IF a candidate file is larger than the per-file byte limit of the Limits Table, THEN THE Config_Extractor SHALL skip the file and SHALL record a `size_cap` Diagnostic carrying the sanitized path and the size.
7. IF the bytes read by the new scanners in one scan reach the per-scan byte limit or the parsed-file limit of the Limits Table, THEN THE Config_Extractor SHALL stop reading further files in path order and SHALL record one `scan_budget_exhausted` Diagnostic carrying the number of files not read.
8. THE Config_Extractor SHALL write every path into outputs as repository-relative POSIX text with control characters replaced by `?` and a length of at most 512 bytes.
9. WHEN the Scanned_Input contains no file that matches the File Classification Table, THE Config_Extractor SHALL complete without error and SHALL emit zero Encryption_Facts.

**File Classification Table (R2-A).** Matching is case-insensitive. A row marked "content" is decided by parsed content, not by name.

| Class | Match rule |
|---|---|
| terraform | `*.tf`, `*.tf.json`; `*.tfvars` and `*.tfvars.json` (variable values only) |
| cloudformation | content: a YAML or JSON document with top-level `AWSTemplateFormatVersion`, or a `Resources` map whose entries have a `Type` starting `AWS::` |
| kubernetes | content: YAML or JSON documents with `apiVersion` and `kind` |
| compose | `docker-compose*.yml`, `docker-compose*.yaml`, `compose*.yml`, `compose*.yaml`, or content: top-level `services` map |
| dockerfile | `Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile` |
| web-server and proxy | `nginx.conf` and `*.conf` under `nginx/`, `conf.d/`, `sites-available/`, `sites-enabled/`; `httpd.conf`, `apache2.conf`, `ssl.conf` and `*.conf` under `apache2/`, `httpd/`; `haproxy.cfg`; `envoy*.yaml`; content: Traefik YAML or TOML with `tls`, `entryPoints` or `http` roots |
| application-server | `server.xml`, `application*.properties`, `application*.yml`, `application*.yaml`, `jetty*.xml`, `ssl.ini` |
| ssh | `sshd_config`, `ssh_config`, `*.conf` under `sshd_config.d/` and `ssh_config.d/` |
| database and broker | `postgresql.conf`, `pg_hba.conf`, `my.cnf`, `*.cnf` under `mysql/`, `mariadb/`, `my.cnf.d/`; `mongod.conf`, `mongod*.conf`; `elasticsearch.yml`; `redis.conf`, `redis*.conf` |
| disk | `crypttab`; text or shell files containing a `cryptsetup` `luksFormat`, `luksOpen` or `open` invocation |
| sql | `*.sql` |
| business | the Business_Mapping_File names of Requirement 19; `CODEOWNERS` |
| tls-result | `*.json` and `*.xml` whose content matches a testssl.sh, sslyze or nmap signature (Requirement 24) |

### Requirement 3: In-house parsers and dependency boundary

**User Story:** As a security reviewer, I want every file format read by reviewed in-house code or the standard library, so that no new third-party component enters a product that must run air-gapped.

#### Acceptance Criteria

1. THE Config_Extractor SHALL parse HashiCorp Configuration Language files with an in-house parser that handles labelled blocks, attributes, string, number, boolean and null literals, lists, objects, heredocs, line comments and block comments, and that records interpolations, conditional expressions, function calls, `for` expressions and splats as unresolved expressions without evaluating them.
2. THE Config_Extractor SHALL parse `.tf.json` files with the standard-library `json` module according to the Terraform JSON syntax.
3. THE Config_Extractor SHALL parse YAML only with `yaml.safe_load_all` semantics through the `pyyaml` dependency that `aibom` already declares.
4. WHEN a YAML document contains a CloudFormation short-form tag (`!Ref`, `!GetAtt`, `!Sub`, `!Join`, `!If`, `!FindInMap`, `!ImportValue`, `!Select`, `!Split`, `!Equals`, `!And`, `!Or`, `!Not`, `!Condition`, `!Base64`, `!Cidr`, `!GetAZs`, `!Transform`), THE Config_Extractor SHALL load the tag as a tagged unresolved node and SHALL evaluate nothing.
5. THE Config_Extractor SHALL parse directive-style files (nginx, Apache httpd, HAProxy, `sshd_config`, `postgresql.conf`, `pg_hba.conf`, MySQL and MariaDB `.cnf`, `redis.conf`, `crypttab`, Java `.properties`) with in-house line parsers.
6. THE Config_Extractor SHALL parse TOML with the standard-library `tomllib` and XML with the standard-library `xml.etree.ElementTree`.
7. WHEN an XML document contains a DOCTYPE declaration with an internal subset, an ENTITY declaration or an external identifier, THE Config_Extractor SHALL reject the document before parsing and SHALL record an `unsafe_xml` Diagnostic.
8. WHEN an XML document contains a bare DOCTYPE declaration with no internal subset and no external identifier, THE Config_Extractor SHALL parse the document.
9. WHEN any parser receives any byte string, THE Config_Extractor SHALL return either a parse result or one Diagnostic and SHALL contain every internal parser error, so that none reaches the scanner.
10. THE Config_Extractor and THE TLS_Result_Importer SHALL import, in their own modules, only the Python standard library, `pydantic`, `pyyaml` and `aibom` modules.

### Requirement 4: Hostile-input robustness and diagnostics

**User Story:** As an operator, I want a malformed or malicious file to produce a diagnostic and never a crash or a hang, so that one bad file cannot fail a customer's scan.

#### Acceptance Criteria

1. IF a file is malformed, truncated, binary or unparsable, THEN THE Config_Extractor SHALL record one Diagnostic with a closed-vocabulary code and SHALL continue with the next file.
2. THE Config_Extractor SHALL enforce every limit of the Limits Table below in deterministic units (bytes, lines, tokens, nodes, nesting depth, expansions), independent of elapsed time, timers and signals.
3. IF nesting depth in an HCL, YAML, JSON or XML structure exceeds the depth limit, THEN THE Config_Extractor SHALL discard that structure and SHALL record a `depth_cap` Diagnostic.
4. IF a YAML document holds more alias references than the alias limit or expands to more nodes than the expansion limit, THEN THE Config_Extractor SHALL reject the document before it constructs Python objects and SHALL record an `alias_cap` Diagnostic.
5. IF a file contains a NUL byte within its first 8,192 bytes, THEN THE Config_Extractor SHALL skip the file and SHALL record a `binary_skipped` Diagnostic.
6. THE Config_Extractor SHALL decode UTF-8 with or without a byte-order mark and UTF-16 with a byte-order mark, and for any other byte sequence SHALL decode with replacement characters and record an `encoding_fallback` Diagnostic.
7. WHEN a line is longer than the line limit, THE Config_Extractor SHALL examine only the first bytes of that line up to the limit and SHALL record a `line_cap` Diagnostic.
8. IF a YAML document uses a tag that constructs a Python object (for example `!!python/object/apply:os.system`), THEN THE Config_Extractor SHALL reject the document, SHALL execute nothing and SHALL record an `unsafe_tag` Diagnostic.
9. WHEN a mapping contains the same key more than once, THE Config_Extractor SHALL apply the last definition and SHALL record a `duplicate_key` Diagnostic, so that a later `encrypted: false` cannot be hidden behind an earlier `encrypted: true`.
10. THE Config_Extractor SHALL use only regular expressions that finish within 1 second on every 1 MiB single-line adversarial input in the ReDoS corpus of the Test_Suite.
11. THE CBOM_Engine SHALL store at most the Diagnostic limit of the Limits Table per scan, SHALL keep exact per-code totals beyond that limit, and SHALL sort stored Diagnostics by path, line and code.
12. THE Config_Extractor SHALL put into a Diagnostic only the sanitized path, the line number and a closed-vocabulary code, so that scanned text cannot reach logs or PDFs through a Diagnostic.

**Limits Table (R4-A).** These are initial values, calibrated in the design against measured baselines (Assumption A-6).

| Limit | Value |
|---|---|
| Bytes per configuration, IaC or server-config file | 5,242,880 |
| Bytes per TLS result file | 20,971,520 |
| Bytes read per scan by the new scanners | 268,435,456 |
| Candidate files parsed per scan | 10,000 |
| Nesting depth (blocks, containers, elements) | 100 |
| YAML alias references per document | 1,000 |
| Expanded YAML nodes per document | 500,000 |
| Bytes examined per line | 1,048,576 |
| Include depth | 5 |
| Encryption_Facts per scan | 50,000 |
| Stored Diagnostics per scan | 1,000 |
| Business_Mapping_File entries | 10,000 |
| Serialized Posture_Block | 8,388,608 bytes |
| CycloneDX components added by the posture lanes | 20,000 |

### Requirement 5: Encryption fact record and secret redaction

**User Story:** As an assessor, I want every finding to point at one stable, evidenced record that never contains a secret, so that I can trace a verdict to a file and line and share the report safely.

#### Acceptance Criteria

1. THE Config_Extractor SHALL give every Encryption_Fact the fields of Table R5-A.
2. THE Config_Extractor SHALL derive the `id` of an Encryption_Fact as a SHA-256 prefix over kind, provider, native type, address and repository-relative path, so that the `id` is stable across runs, hosts and operating systems and unique within a scan.
3. THE Config_Extractor SHALL record in `basis` only attributes that the Defaults_Registry rule for the resource kind names, each as an attribute name with either its resolved literal or its `unknown_reason`.
4. THE Config_Extractor SHALL discard at parse time the value of every attribute that the rule for the resource kind does not name.
5. THE Config_Extractor SHALL exclude from every output the value of an attribute whose name contains `password`, `passwd`, `secret`, `token`, `api_key`, `access_key`, `private_key`, `credential`, `connection_string`, `encryption_key` or `key_material`, and the `data` and `stringData` of a Kubernetes `Secret`.
6. THE Test_Suite SHALL plant canary secret strings in every fixture tree and SHALL assert zero occurrences of each canary in `cbom_json`, the run-object, the Diagnostics and the text of every Posture_Deliverable.
7. THE Config_Extractor SHALL record the 1-based line of the declaring block as the evidence line.
8. THE Config_Extractor SHALL set `path_context` to `non_production_hint` when any path segment equals, ignoring case, `test`, `tests`, `__tests__`, `spec`, `fixtures`, `testdata`, `example`, `examples`, `sample`, `samples`, `docs`, `e2e`, `dev`, `local` or `sandbox`, and to `production_like` otherwise, without changing any severity.
9. THE Config_Extractor SHALL sort Encryption_Facts by kind, path, line, address and id.
10. IF the number of Encryption_Facts would exceed the fact limit, THEN THE Config_Extractor SHALL keep facts that carry findings first, SHALL drop the rest in sorted order, SHALL set `truncated` to true in the Posture_Block and SHALL record a `facts_truncated` Diagnostic with the number dropped.

**Encryption_Fact fields (R5-A).**

| Field | Content |
|---|---|
| `id` | Deterministic identifier (criterion 2) |
| `kind` | `kms_key`, `object_store`, `block_volume`, `file_system`, `relational_db`, `nosql_db`, `cache`, `search_index`, `message_queue`, `message_topic`, `data_stream`, `data_warehouse`, `backup`, `secret_store`, `log_store`, `k8s_secrets_etcd`, `k8s_storage_class`, `tls_endpoint`, `certificate_policy`, `ssh_service`, `disk_encryption` |
| `provider` | `aws`, `azure`, `gcp`, `kubernetes`, `compose`, `self_hosted`, `other` |
| `native_type` | For example `aws_s3_bucket`, `AWS::S3::Bucket`, `Ingress`, `nginx` |
| `address` | Resource address inside the file |
| `path`, `line`, `format` | Evidence location; format is one of `terraform`, `cloudformation`, `kubernetes`, `compose`, `dockerfile`, `server_config`, `db_config`, `ssh_config`, `crypttab`, `sql`, `import` |
| `layers` | Map from Layer to Verdict |
| `verdict` | Resource-level Verdict: the at-rest Verdict, or the `transport` Verdict for kinds whose only Layer is `transport` (Requirement 6) |
| `basis` | List of attribute name and resolved literal or `unknown_reason` |
| `default_row` | Defaults_Registry row id when a default was applied |
| `key_management` | `provider_managed`, `customer_managed`, `unspecified`, `not_applicable`, `unknown` |
| `key_ref` | Declared key reference and the `bom-ref` of the key asset when the key is in the Scanned_Input |
| `unknown_reason` | Closed vocabulary of Table R7-A |
| `path_context` | `production_like` or `non_production_hint` |
| `linkage` | `system`, `owner`, `data_classification`, `data_lifetime`, `owner_hint`, each with its source |
| `finding_codes` | Sorted list of Finding_Catalog codes |

### Requirement 6: Verdict policy and tri-state mapping

**User Story:** As a compliance reviewer, I want an unknown to be reported as unknown and never as a pass or a fail, so that the report cannot overstate or understate the encryption posture.

#### Acceptance Criteria

1. THE Verdict_Engine SHALL assign every Encryption_Fact exactly one resource-level Verdict from ENCRYPTED_DECLARED, ENCRYPTED_PROVIDER_DEFAULT, NOT_ENCRYPTED and UNKNOWN, and SHALL record one Verdict for each Layer that Table R6-A assigns to the kind.
2. WHEN every decisive attribute of a Layer resolves to an explicitly enabling value, THE Verdict_Engine SHALL assign ENCRYPTED_DECLARED to that Layer.
3. WHEN a decisive attribute is absent and the matching Provider_Defaults_Table row states an encrypted default, THE Verdict_Engine SHALL assign ENCRYPTED_PROVIDER_DEFAULT to that Layer and SHALL record the row id in `default_row`.
4. WHEN a decisive attribute resolves to an explicitly disabling value, or is absent and the matching row states an unencrypted default and is marked `assessable_as_unencrypted`, THE Verdict_Engine SHALL assign NOT_ENCRYPTED to that Layer and SHALL carry the caveat text of the row into the finding message.
5. IF a decisive attribute is unresolved, dynamic, templated, defined in an unreachable include, absent without a matching row, or overridden outside the Scanned_Input, THEN THE Verdict_Engine SHALL assign UNKNOWN to that Layer with one `unknown_reason`.
6. THE Verdict_Engine SHALL derive the at-rest Verdict of a resource from its `application`, `database`, `volume`, `service` and `backup` Layers: an encrypted Verdict when any of those Layers is encrypted (ENCRYPTED_DECLARED taking precedence over ENCRYPTED_PROVIDER_DEFAULT), otherwise UNKNOWN when any of them is UNKNOWN, otherwise NOT_ENCRYPTED.
7. THE Verdict_Engine SHALL keep the `transport` Layer Verdict separate from the at-rest Verdict, and SHALL use the `transport` Verdict as the resource-level Verdict for kinds whose only Layer is `transport`.
8. WHEN a self-hosted software configuration omits a native encryption or transport-security directive, THE Verdict_Engine SHALL assign UNKNOWN with reason `layer_not_observable` to that Layer, and SHALL assign NOT_ENCRYPTED only when the directive is explicitly set to a disabling value.
9. IF a Verdict is UNKNOWN or an attribute is unresolved, THEN THE Verdict_Engine SHALL leave the Posture_Finding set of that Encryption_Fact empty.
10. THE Verdict_Engine SHALL map ENCRYPTED_DECLARED and ENCRYPTED_PROVIDER_DEFAULT to Tri_State pass, NOT_ENCRYPTED to fail and UNKNOWN to NOT_BOM_EVIDENCEABLE, separately for the at-rest Verdict and for the `transport` Verdict.
11. WHEN a declared resource has a native type outside the Coverage_Table, THE Config_Extractor SHALL record the resource only as an OUT_OF_SCOPE count in the Posture_Block counts.
12. THE Verdict_Engine SHALL compute Coverage_Percentage as pass divided by (pass plus fail), SHALL report NOT_BOM_EVIDENCEABLE and OUT_OF_SCOPE as separate counts, and SHALL report null when pass plus fail is zero.
13. THE Verdict_Engine SHALL depend only on parsed attributes and Defaults_Registry rows, with no file access, no clock read and no network access.
14. THE Verdict_Engine SHALL assess the Layers that Table R6-A assigns to each kind and no others.

**Layers per kind (R6-A).**

| Kind | Layers assessed |
|---|---|
| `kms_key`, `certificate_policy` | none (inventory and governance findings only) |
| `object_store`, `file_system`, `data_warehouse`, `log_store`, `secret_store`, `message_queue`, `message_topic`, `data_stream` | `service`, `transport` |
| `relational_db`, `nosql_db`, `cache`, `search_index` as managed cloud resources | `service`, `transport` |
| the same four kinds as self-hosted services | `database`, `volume`, `transport` |
| `block_volume`, `k8s_storage_class`, `disk_encryption` | `volume` |
| `backup` | `backup` |
| `k8s_secrets_etcd` | `database` |
| `tls_endpoint`, `ssh_service` | `transport` |

### Requirement 7: Variable and expression resolution

**User Story:** As an assessor, I want values resolved only when they are certain, so that a verdict never rests on a guessed variable.

#### Acceptance Criteria

1. THE Config_Extractor SHALL resolve string, number, boolean and null literals and lists and maps of literals.
2. WHEN a Terraform attribute references `var.<name>`, the `variable` block has a literal `default`, and no `.tfvars` or `.tfvars.json` file in the Scanned_Input assigns a different value, THE Config_Extractor SHALL resolve the attribute to the default.
3. IF a `.tfvars` or `.tfvars.json` file in the Scanned_Input assigns a variable a value different from its default, THEN THE Config_Extractor SHALL resolve every attribute that references the variable to UNKNOWN with reason `variable_overridden`.
4. IF `var.<name>` has no `default`, THEN THE Config_Extractor SHALL resolve the attribute to UNKNOWN with reason `variable_no_default`.
5. IF an attribute is, or contains, a `local.*`, `data.*`, `module.*`, `each.*` or `count.*` reference, a function call, a conditional expression, a `for` expression or a splat, THEN THE Config_Extractor SHALL resolve the attribute to UNKNOWN with reason `unresolved_expression`.
6. WHEN `count` is the literal 0, THE Config_Extractor SHALL record the resource only in `disabled_resources` of the Posture_Block.
7. WHEN `count` or `for_each` is unresolved, THE Config_Extractor SHALL create the Encryption_Fact with `multiplicity` set to `unknown` and SHALL compute its Verdict from its own attributes.
8. THE Config_Extractor SHALL resolve every attribute inside a `dynamic` block to UNKNOWN with reason `dynamic_block`.
9. WHEN a `module` block is read, THE Config_Extractor SHALL record a `module_call` Diagnostic with the sanitized source string, SHALL treat the module as an unresolved boundary, and SHALL analyse module directories that exist inside the Scanned_Input as standalone configurations in which variables without defaults resolve to UNKNOWN.
10. WHEN a CloudFormation `Ref` names a Parameter with a `Default`, or an `Fn::Sub` contains only such Parameter references, THE Config_Extractor SHALL resolve the value; WHEN a value depends on `Fn::If`, `Conditions`, `Mappings`, `Fn::FindInMap`, `Fn::ImportValue` or an unresolvable `Fn::GetAtt`, THE Config_Extractor SHALL resolve it to UNKNOWN with reason `unresolved_expression`.
11. WHEN a CloudFormation value is `AWS::NoValue`, THE Config_Extractor SHALL treat the attribute as absent.
12. WHEN a Kubernetes, compose or Dockerfile value contains `{{`, `{%`, `${` or `$(`, THE Config_Extractor SHALL resolve it to UNKNOWN with reason `template_marker`.
13. WHEN a directory contains `Chart.yaml`, THE Config_Extractor SHALL skip its `templates/` subtree and record a `helm_template_skipped` Diagnostic; WHEN a `kustomization.yaml` is present, THE Config_Extractor SHALL record a `kustomize_not_applied` Diagnostic and apply no patch.

**UNKNOWN reason vocabulary (R7-A).** `variable_overridden`, `variable_no_default`, `unresolved_expression`, `dynamic_block`, `module_call`, `template_marker`, `unresolved_include`, `unresolved_reference`, `layer_not_observable`, `attribute_not_modeled`, `default_unknown`, `provider_version_dependent`, `parse_error`.

### Requirement 8: Cross-resource and include linking

**User Story:** As an assessor, I want encryption that is configured in a companion resource to count for its parent, so that modern provider syntax does not produce false findings.

#### Acceptance Criteria

1. WHEN a Terraform attribute holds a reference `<type>.<name>.<attribute>` that names a resource declared in the Scanned_Input, THE Config_Extractor SHALL link the two Encryption_Facts.
2. THE Config_Extractor SHALL support both the inline-block form and the separate companion-resource form for every resource kind whose provider moved encryption configuration into a companion resource, so that the same intent written in either form yields the same Verdict.
3. WHEN no companion resource references a parent resource, THE Verdict_Engine SHALL apply the Provider_Defaults_Table row for the absent configuration.
4. THE Config_Extractor SHALL link CloudFormation resources through `Ref` and `Fn::GetAtt` to logical IDs in the same template.
5. THE Config_Extractor SHALL link Kubernetes `PersistentVolumeClaim` to `StorageClass` through `storageClassName`, `StatefulSet.volumeClaimTemplates` to `StorageClass`, `Ingress` to `Secret` through `tls.secretName`, and `Ingress` to cert-manager `Certificate` through `secretName`.
6. WHERE a compose service bind-mounts a file that exists in the Scanned_Input, THE Config_Extractor SHALL attach the service name to the Encryption_Fact of that file.
7. IF a reference names a resource that is not declared in the Scanned_Input, THEN THE Config_Extractor SHALL resolve the dependent attribute to UNKNOWN with reason `unresolved_reference`.
8. WHEN an nginx `include`, Apache `Include` or `IncludeOptional`, or `sshd_config` `Include` directive names files inside the Scanned_Input, THE Config_Extractor SHALL read those files, expanding globs in ascending path order, to the include depth of the Limits Table and with cycle detection.
9. IF an include names a file outside the Scanned_Input or beyond the include depth, THEN THE Config_Extractor SHALL resolve the settings that depend on it to UNKNOWN with reason `unresolved_include`.
10. THE Config_Extractor SHALL produce the same set of linked facts whatever order the files are visited in.

### Requirement 9: Defaults registry with dated public sources

**User Story:** As an auditor, I want every assumed provider default to cite a public document and a date, so that I can check the assumption and see how old it is.

#### Acceptance Criteria

1. THE Defaults_Registry SHALL be packaged as versioned data files that the CBOM_Engine loads through `importlib.resources`, so that loading works from the wheel and from the source tree.
2. THE Defaults_Registry SHALL give every row these fields: provider or software, resource type or directive, attribute, documented default, encryption effect (ENCRYPTED, NOT_ENCRYPTED or UNKNOWN), `assessable_as_unencrypted`, caveat text, applicable provider or software version range, public https source URL, and `valid_as_of` as an ISO date.
3. WHEN a row lacks a field, has a non-https URL, or has a URL missing from the reviewed URL allow-list in the Test_Suite, THE Test_Suite SHALL fail.
4. THE Defaults_Registry SHALL carry for each data file a `data_version` and a `valid_as_of` date, and THE CBOM_Engine SHALL record the name, `data_version`, `valid_as_of` and SHA-256 of every data file it used in the Posture_Block.
5. WHEN a Verdict comes from a default, THE Verdict_Engine SHALL record the row id in the Encryption_Fact.
6. WHERE a row depends on an account-level or organisation-level setting that can override the default, THE Defaults_Registry SHALL name the overriding resource type, and WHEN the Scanned_Input declares that resource in the same provider scope, THE Verdict_Engine SHALL apply the override; WHEN scope equality cannot be established from the input, THE Verdict_Engine SHALL assign UNKNOWN with reason `default_unknown`.
7. THE Defaults_Registry SHALL contain at least one row for every attribute the Coverage_Table consults, and at least one TLS_Policy_Registry row for every named policy value the Coverage_Table accepts.
8. WHEN a provider or software default varies by provider or software version (for example an nginx, OpenSSH or cloud-provider default) and the Scanned_Input does not pin the version, THE Verdict_Engine SHALL assign UNKNOWN with reason `provider_version_dependent`.
9. THE CBOM_Engine SHALL read the Defaults_Registry from the installed package only, with no network refresh and no path taken from the environment or from the Scanned_Input.
10. THE Repository SHALL author every row only from the vendor or standards documentation named in its URL, and no row SHALL be derived from the rule sources of an open-source scanner.

### Requirement 10: Infrastructure-as-code coverage

**User Story:** As an assessor of a multi-cloud estate, I want the supported formats, providers and resource types to be explicit and tested, so that I know what the report covers and what it ignores.

#### Acceptance Criteria

1. THE Config_Extractor SHALL assess in version 1: Terraform (`.tf`, `.tf.json`) for AWS, Azure and GCP; CloudFormation in YAML and JSON; Kubernetes in YAML and JSON; docker-compose; Dockerfile; and the server and database configuration files of Requirements 20 and 21.
2. THE Coverage_Table SHALL contain at least every native type named in Table R10-A and, for each AWS Terraform type that has a CloudFormation equivalent, the CloudFormation type.
3. THE Coverage_Table SHALL list, for every native type, the attribute names the Verdict_Engine consults.
4. IF a Coverage_Table native type has no positive fixture resource and no negative fixture resource in the Test_Suite, THEN THE Test_Suite SHALL fail.
5. FOR EACH AWS Terraform type that has a CloudFormation equivalent, THE Test_Suite SHALL contain a Terraform and CloudFormation fixture pair that express the same intent and SHALL assert that both yield the same Verdict.
6. THE Config_Extractor SHALL treat all Terraform files in one directory as one configuration for variable and reference resolution.
7. WHEN the Scanned_Input contains a Pulumi project (`Pulumi.yaml`), an Ansible playbook (a YAML list whose items carry `hosts` and `tasks`) or Helm template sources, THE Config_Extractor SHALL parse none of them and SHALL record one `unsupported_format` Diagnostic per file class with the file count.
8. WHEN the Scanned_Input contains a `*.tfstate` file, THE Config_Extractor SHALL skip the file and SHALL record a `state_file_ignored` Diagnostic.
9. THE Posture_Block SHALL report the number of declared resources by format and provider, the number of Encryption_Facts, the number of OUT_OF_SCOPE resources and the number of disabled resources.

**Minimum coverage (R10-A).** The design may add types; it may not remove any.

| Kind | AWS Terraform | Azure Terraform | GCP Terraform | Kubernetes and compose |
|---|---|---|---|---|
| `kms_key` | `aws_kms_key`, `aws_kms_external_key`, `aws_kms_replica_key`, `aws_kms_alias`, `aws_kms_grant` | `azurerm_key_vault`, `azurerm_key_vault_key`, `azurerm_key_vault_managed_hardware_security_module` | `google_kms_key_ring`, `google_kms_crypto_key`, `google_kms_crypto_key_iam_binding`, `google_kms_crypto_key_iam_member` | none |
| `object_store` | `aws_s3_bucket`, `aws_s3_bucket_server_side_encryption_configuration`, `aws_s3_bucket_policy` | `azurerm_storage_account`, `azurerm_storage_account_customer_managed_key` | `google_storage_bucket` | none |
| `block_volume` | `aws_ebs_volume`, `aws_ebs_encryption_by_default`, `aws_ebs_default_kms_key`, `aws_instance`, `aws_launch_template`, `aws_launch_configuration` | `azurerm_managed_disk`, `azurerm_disk_encryption_set`, `azurerm_linux_virtual_machine`, `azurerm_windows_virtual_machine` | `google_compute_disk`, `google_compute_instance`, `google_compute_snapshot` | `StorageClass`, `PersistentVolumeClaim`, `StatefulSet` |
| `file_system` | `aws_efs_file_system` | none | `google_filestore_instance` | none |
| `relational_db` | `aws_db_instance`, `aws_rds_cluster`, `aws_docdb_cluster`, `aws_neptune_cluster` | `azurerm_mssql_server`, `azurerm_mssql_database`, `azurerm_mssql_server_transparent_data_encryption`, `azurerm_postgresql_flexible_server`, `azurerm_mysql_flexible_server` | `google_sql_database_instance`, `google_spanner_database` | compose services with a relational-database image |
| `nosql_db` | `aws_dynamodb_table` | `azurerm_cosmosdb_account` | `google_bigtable_instance` | compose services with a MongoDB or Cassandra image |
| `cache` | `aws_elasticache_replication_group`, `aws_memorydb_cluster` | `azurerm_redis_cache` | `google_redis_instance` | compose services with a Redis or Memcached image |
| `search_index` | `aws_opensearch_domain`, `aws_elasticsearch_domain` | none | none | compose services with an Elasticsearch or OpenSearch image |
| `message_queue`, `message_topic`, `data_stream` | `aws_sqs_queue`, `aws_sns_topic`, `aws_mq_broker`, `aws_kinesis_stream`, `aws_kinesis_firehose_delivery_stream`, `aws_msk_cluster` | `azurerm_servicebus_namespace`, `azurerm_eventhub_namespace` | `google_pubsub_topic` | compose services with a RabbitMQ or Kafka image |
| `data_warehouse` | `aws_redshift_cluster`, `aws_redshiftserverless_namespace` | `azurerm_synapse_workspace` | `google_bigquery_dataset` | none |
| `backup` | `aws_backup_vault`, `aws_ebs_snapshot_copy`, `aws_db_snapshot_copy`, `aws_ami_copy` | `azurerm_recovery_services_vault` | `google_compute_snapshot` | none |
| `secret_store` | `aws_secretsmanager_secret`, `aws_ssm_parameter` | `azurerm_key_vault_secret` | `google_secret_manager_secret` | `Secret` (name, namespace and type only) |
| `log_store` | `aws_cloudwatch_log_group`, `aws_cloudtrail` | none | `google_logging_project_bucket_config` | none |
| `k8s_secrets_etcd` | `aws_eks_cluster` | `azurerm_kubernetes_cluster` | `google_container_cluster` | `EncryptionConfiguration`, kube-apiserver static pod manifest |
| `tls_endpoint` | `aws_lb_listener`, `aws_alb_listener`, `aws_elb`, `aws_lb_ssl_negotiation_policy`, `aws_cloudfront_distribution`, `aws_api_gateway_domain_name`, `aws_apigatewayv2_domain_name` | `azurerm_application_gateway`, `azurerm_cdn_frontdoor_custom_domain`, `azurerm_api_management`, `azurerm_linux_web_app`, `azurerm_windows_web_app` | `google_compute_ssl_policy`, `google_compute_target_https_proxy` | `Ingress`, `Service` with cloud load-balancer annotations, Istio `Gateway`, `PeerAuthentication` and `DestinationRule`, Traefik `TLSOption` |
| `certificate_policy` | `aws_acm_certificate`, `aws_acmpca_certificate_authority` | `azurerm_key_vault_certificate` | `google_privateca_certificate_authority` | cert-manager `Certificate`, `Issuer`, `ClusterIssuer` |

### Requirement 11: KMS key inventory, rotation, exposure and deletion protection

**User Story:** As a key-management owner, I want every declared KMS key listed with its specification, rotation, exposure and deletion protection, so that I can review key governance without opening each cloud console.

#### Acceptance Criteria

1. WHEN the Scanned_Input declares a key of a `kms_key` type in Table R10-A, THE Config_Extractor SHALL emit an Encryption_Fact of kind `kms_key` and a linked `related-crypto-material` crypto asset of material kind `key` that carry key specification, key usage, protection level (`software`, `hsm`, `external`, `unknown`), rotation setting and period, deletion-window or purge-protection setting, and enabled state, each as declared or with an `unknown_reason`.
2. WHEN a key specification maps to an algorithm in the Defaults_Registry (symmetric, asymmetric or message-authentication), THE Config_Extractor SHALL also emit the matching `algorithm` crypto asset with algorithm family and key size or curve, so that the existing weakness, PQC and strength scanners and the existing compliance checks evaluate it without a code change.
3. WHEN a customer-managed symmetric encryption key supports automatic rotation and the Scanned_Input disables rotation, or omits it where the matching row states a disabled default, THE Config_Extractor SHALL raise `KMS_KEY_ROTATION_DISABLED`.
4. WHEN a key is asymmetric, a message-authentication key, an external-origin key, a custom-key-store key or otherwise marked `rotation_supported` false in the Defaults_Registry, THE Config_Extractor SHALL record rotation as `not_applicable` and SHALL leave the rotation finding set empty.
5. WHEN an AWS key policy (a `jsonencode` expression, a heredoc JSON string, an `aws_iam_policy_document` data source or a CloudFormation `KeyPolicy`) contains an Allow statement whose principal is `*` or `{"AWS": "*"}` and that carries none of the restricting condition keys listed in the Defaults_Registry, or WHEN a GCP IAM binding or member on a crypto key lists `allUsers` or `allAuthenticatedUsers`, THE Config_Extractor SHALL raise `KMS_KEY_POLICY_PUBLIC`.
6. WHEN an Azure Key Vault or managed HSM declares purge protection disabled, or omits it where the matching row states a disabled default, THE Config_Extractor SHALL raise `KMS_KEY_DELETION_UNPROTECTED`.
7. IF a key policy or binding cannot be reduced to statements because its content is dynamic, THEN THE Config_Extractor SHALL record exposure as UNKNOWN with reason `unresolved_expression` and SHALL leave the exposure finding set empty.
8. WHEN a resource references a key declared in the Scanned_Input through an alias, an ARN expression, a key identifier or a key URL, THE Config_Extractor SHALL set `key_ref` to the `bom-ref` of that key and `key_management` to `customer_managed`.
9. WHEN a resource references a provider-managed key alias listed in the Defaults_Registry (for example an AWS-managed alias), THE Config_Extractor SHALL set `key_management` to `provider_managed`.
10. THE Posture_Block SHALL list for each `kms_key` fact the `id` values of the facts it protects, so that the Posture_Deliverables can show key usage.

### Requirement 12: Managed data services, volumes and queues: encryption at rest and in transit

**User Story:** As a cloud security reviewer, I want every declared storage, database, queue and stream resource assessed for at-rest and in-transit encryption, so that unencrypted resources are found from the infrastructure code alone.

#### Acceptance Criteria

1. FOR EACH declared resource of the kinds `object_store`, `block_volume`, `file_system`, `relational_db`, `nosql_db`, `cache`, `search_index`, `message_queue`, `message_topic`, `data_stream`, `data_warehouse` and `log_store`, THE Config_Extractor SHALL emit an Encryption_Fact whose Layers of Table R6-A carry Verdicts derived from the Coverage_Table attributes and the Provider_Defaults_Table.
2. WHEN the resource-level Verdict of such a fact is NOT_ENCRYPTED at rest, THE Config_Extractor SHALL raise `UNENCRYPTED_AT_REST`.
3. WHEN a managed data service declares that plaintext client connections are allowed or that in-transit encryption is disabled (for example a cache with transit encryption off, a broker listener without TLS, a search domain without enforced HTTPS, a database server parameter that disables secure transport), THE Config_Extractor SHALL assign the `transport` Layer NOT_ENCRYPTED and SHALL raise `UNENCRYPTED_IN_TRANSIT`.
4. WHEN a managed data service declares a customer-managed key reference, THE Config_Extractor SHALL apply Requirement 11 criterion 8; WHEN it declares encryption enabled and no key, THE Config_Extractor SHALL set `key_management` to `provider_managed`.
5. WHEN the Scanned_Input declares an account-level or region-level default-encryption resource (for example `aws_ebs_encryption_by_default`) in the same Terraform configuration and the same provider alias as a volume that omits its own encryption attribute, THE Verdict_Engine SHALL apply the override of Requirement 9 criterion 6.
6. WHEN a CloudFormation `AWS::EC2::Volume`, `AWS::RDS::DBInstance` or other covered type omits its encryption attribute, THE Verdict_Engine SHALL apply the same Provider_Defaults_Table row that applies to the equivalent Terraform resource.
7. THE Config_Extractor SHALL record for each fact the declared key custody class (`provider_managed`, `customer_managed`, `unspecified`) so that later specs can use it without re-parsing.

### Requirement 13: Load balancer, CDN, API gateway and web-app TLS policies

**User Story:** As a network security reviewer, I want the TLS policy of every declared managed endpoint resolved to a protocol floor and cipher set, so that weak policies are reported even when only a policy name is declared.

#### Acceptance Criteria

1. WHEN the Scanned_Input declares a resource of a `tls_endpoint` type in Table R10-A, THE Config_Extractor SHALL emit an Encryption_Fact of kind `tls_endpoint` with a `transport` Layer and a linked `protocol` crypto asset of protocol type `tls`.
2. THE Config_Extractor SHALL set on that `protocol` asset `crypto:protocolVersion` to the minimum protocol version the declared policy permits, `crypto:maxProtocolVersion` where the policy states one, `crypto:cipherSuite` where the policy enumerates suites, `crypto:policyName` to the declared policy name, `crypto:policySource` to the provider policy source, and `crypto:strength` to `weak` when the minimum is below TLS 1.2 or is any SSL version.
3. WHEN a policy is declared by name, THE Config_Extractor SHALL resolve the minimum version and cipher set through the TLS_Policy_Registry, and WHEN the name is absent from the registry THE Config_Extractor SHALL assign UNKNOWN with reason `default_unknown` and SHALL derive versions only through the registry.
4. WHEN a listener or distribution omits a policy, THE Verdict_Engine SHALL apply the TLS_Policy_Registry row for the default of that resource type, and WHEN the default depends on a version the Scanned_Input does not pin, THE Verdict_Engine SHALL assign UNKNOWN with reason `provider_version_dependent`.
5. WHEN the declared viewer certificate or listener certificate is the provider's default certificate, THE Verdict_Engine SHALL apply the TLS_Policy_Registry row that the registry defines for that case.
6. WHEN a load balancer, CDN, API gateway or web-app listener serves plaintext (an HTTP protocol, a viewer protocol policy that allows HTTP, a TCP listener without TLS) and declares no redirect to HTTPS and no forced-HTTPS flag, THE Config_Extractor SHALL raise `PLAINTEXT_LISTENER`.
7. WHEN such a listener declares a redirect to HTTPS or a forced-HTTPS flag, THE Config_Extractor SHALL record the `transport` Layer as ENCRYPTED_DECLARED and SHALL leave the listener finding set empty.
8. WHEN a CDN origin connection is declared plaintext (for example an origin protocol policy of HTTP only), THE Config_Extractor SHALL raise `UNENCRYPTED_IN_TRANSIT`.
9. THE CBOM_Engine SHALL raise `WEAK_PROTOCOL` and `WEAK_CIPHER_SUITE` on these `protocol` assets through the existing predicates in `aibom/src/aibom/cbom/weakness.py`, and THE Repository SHALL keep those predicates unchanged.

### Requirement 14: Secrets, certificate provisioning and key algorithms in certificate policies

**User Story:** As a PKI owner, I want declared certificate and secret provisioning settings inventoried with their key algorithms, so that weak or quantum-vulnerable keys in certificate policies appear in the same review as the keys found in code.

#### Acceptance Criteria

1. WHEN the Scanned_Input declares a resource of a `secret_store` type in Table R10-A, THE Config_Extractor SHALL emit an Encryption_Fact with a `service` Layer Verdict and a `key_management` value, and SHALL exclude secret values as Requirement 5 criterion 5 requires.
2. WHEN a Kubernetes `Secret` is read, THE Config_Extractor SHALL record only its name, namespace and type.
3. WHEN a resource of a `certificate_policy` type declares a private-key algorithm together with a key size or curve (for example `key_algorithm`, `privateKey.algorithm`, `privateKey.size`, `key_properties`), THE Config_Extractor SHALL emit an `algorithm` crypto asset with that family, size or curve, linked to the Encryption_Fact, so that the existing WEAK_KEY_SIZE, QUANTUM_VULNERABLE and strength predicates apply.
4. WHEN a certificate policy declares whether the private key is reused or rotated on renewal (for example cert-manager `rotationPolicy`, Key Vault `reuse_key`), THE Config_Extractor SHALL record the setting as an attribute.
5. WHEN an `Ingress`, Istio `Gateway` or Traefik route terminates TLS with a secret that no `Secret`, `Certificate` or external-secret declaration in the Scanned_Input provides, THE Config_Extractor SHALL record `key_ref` as UNKNOWN with reason `unresolved_reference`.
6. WHEN a certificate authority resource declares a signing algorithm, THE Config_Extractor SHALL emit an `algorithm` crypto asset for the signing algorithm and the key algorithm.

### Requirement 15: Posture finding catalog, severities, weights and remediation

**User Story:** As a risk owner, I want a closed list of posture findings with fixed severities and remediation text, so that scores and reports are comparable across scans and teams.

#### Acceptance Criteria

1. THE Finding_Catalog SHALL define exactly the codes of Table R15-A, each with severity class, SARIF level, weight, trigger and anchor.
2. THE Config_Extractor SHALL raise a Finding_Catalog code only from an explicit declaration, an explicit imported result, or a Defaults_Registry row marked `assessable_as_unencrypted`; an UNKNOWN Verdict SHALL leave the finding set empty.
3. THE Config_Extractor SHALL map severity class High to SARIF level `error`, Medium to `warning` and Low to `note`.
4. THE Config_Extractor SHALL give every Posture_Finding a message that names the resource, the evidence path and line, and the remediation action, and that contains no excluded secret value.
5. THE CBOM_Engine SHALL export the Finding_Catalog codes as a frozen set `POSTURE_CODES` that is distinct from `WEAK_CRYPTO_CODES`.
6. THE Deliverable_Renderer SHALL take the label and remediation text of each code from the authored-text module `backend/utilities/pdf/cbom_deliverable_text.py`, each remediation carrying a `# Source:` comment with a public URL, and a contract test SHALL fail WHEN a code in a generated registry fixture lacks a label or an action.
7. WHEN new assets raise the existing codes WEAK_PROTOCOL, WEAK_CIPHER_SUITE, WEAK_KEY_SIZE, WEAK_ALGORITHM, WEAK_CERTIFICATE_SIGNATURE, WEAK_CERTIFICATE_KEY, EXPIRED_CERTIFICATE, SELF_SIGNED_LEAF, QUANTUM_VULNERABLE or HARDCODED_KEY, THE CBOM_Engine SHALL raise them through the existing predicates and weights unchanged.

**Finding catalog (R15-A).**

| Code | Trigger | Severity (SARIF) | Weight | Deliverables | Anchor |
|---|---|---|---|---|---|
| `UNENCRYPTED_AT_REST` | Resource-level Verdict NOT_ENCRYPTED for a data store, volume, backup, queue, stream, log store or Kubernetes secret storage | High (error) | 8 | #5, #9 | CWE-311, CWE-312 |
| `UNENCRYPTED_IN_TRANSIT` | Data service, database, broker, cache, search domain or CDN origin connection with plaintext transport declared or permitted | High (error) | 8 | #5, #6 | CWE-319 |
| `PLAINTEXT_LISTENER` | Web, load-balancer, ingress or mesh listener that serves plaintext with no HTTPS redirect, or a mesh mutual-TLS mode that permits plaintext | Medium (warning) | 4 | #5, #6 | CWE-319 |
| `TLS_VERIFICATION_DISABLED` | Certificate or hostname validation disabled in code, configuration, environment or a command | High (error) | 8 | #6 | CWE-295 |
| `DOWNGRADE_PROTECTION_MISSING` | An imported result shows legacy protocol versions offered and TLS_FALLBACK_SCSV not supported | Medium (warning) | 4 | #6 | RFC 7507 |
| `KNOWN_TLS_VULNERABILITY` | An imported result reports a scored named vulnerability (Requirement 25) as vulnerable | High (error) | 8 | #6 | CVE per entry |
| `KMS_KEY_ROTATION_DISABLED` | Customer-managed symmetric key that supports automatic rotation has it off | Medium (warning) | 4 | #5 | NIST SP 800-57 Part 1 cryptoperiod |
| `KMS_KEY_POLICY_PUBLIC` | Key policy or IAM binding grants key use to all principals without a restricting condition | High (error) | 8 | #5 | CWE-284 |
| `KMS_KEY_DELETION_UNPROTECTED` | Key vault or managed HSM without purge protection | Low (note) | 1 | #5 | NIST SP 800-57 Part 1 key destruction |
| `AT_REST_ENCRYPTION_WEAK` | Encryption declared with a weak algorithm, mode or key custody (for example Kubernetes `aescbc` or `aesgcm`, a local-file keyring) | Medium (warning) | 4 | #5, #9 | CWE-326 |

### Requirement 16: Data store, volume and backup inventory

**User Story:** As a data-protection officer, I want every data store, volume and backup in the scanned infrastructure inventoried with its encryption layers, so that I can see which stores are protected and which are not evidenced.

#### Acceptance Criteria

1. THE Config_Extractor SHALL inventory data stores of the kinds `object_store`, `block_volume`, `file_system`, `relational_db`, `nosql_db`, `cache`, `search_index`, `message_queue`, `data_stream`, `data_warehouse`, `backup` and `log_store` for managed cloud resources (Requirement 12) and for self-hosted services.
2. THE Config_Extractor SHALL recognise a self-hosted data-store service when a compose service image or a Kubernetes container image has a repository name in the curated data-store image list of the Defaults_Registry, matched without the registry host and without the tag.
3. WHEN a Kubernetes `StatefulSet` declares `volumeClaimTemplates`, or a compose service declares a volume, THE Config_Extractor SHALL link the service to its volume; named volumes, `emptyDir` and `hostPath` volumes SHALL receive the `volume` Layer Verdict UNKNOWN with reason `layer_not_observable`.
4. WHEN a `StorageClass` declares a provisioner and parameters, THE Verdict_Engine SHALL assign the `volume` Layer Verdict of every claim that references it from the per-provisioner rows of the Provider_Defaults_Table.
5. WHEN a backup, snapshot or copy resource declares an encryption attribute or key, THE Config_Extractor SHALL assign the `backup` Layer Verdict from it.
6. WHEN a snapshot inherits encryption from a source resource declared in the Scanned_Input, THE Verdict_Engine SHALL inherit the Verdict of the source, and WHEN the source Verdict is UNKNOWN THE Verdict_Engine SHALL assign UNKNOWN with the source's reason.
7. WHEN a data store declares backup retention or point-in-time recovery, THE Config_Extractor SHALL record the setting as an attribute.
8. THE Posture_Block SHALL report counts of Encryption_Facts by kind, provider and Verdict.

### Requirement 17: Kubernetes secrets encryption at rest

**User Story:** As a platform engineer, I want the encryption of Kubernetes secrets in etcd assessed from the cluster configuration in the repository, so that clusters that store secrets in plaintext are found.

#### Acceptance Criteria

1. WHEN an `EncryptionConfiguration` document (API group `apiserver.config.k8s.io`) is read, THE Config_Extractor SHALL emit an Encryption_Fact of kind `k8s_secrets_etcd` and SHALL evaluate the provider list of the resource entry that includes `secrets`, where the first provider governs writes.
2. IF the first provider is `identity`, or no resource entry includes `secrets`, THEN THE Verdict_Engine SHALL assign the `database` Layer NOT_ENCRYPTED and THE Config_Extractor SHALL raise `UNENCRYPTED_AT_REST`.
3. WHEN the first provider is `kms`, THE Verdict_Engine SHALL assign ENCRYPTED_DECLARED and `key_management` `customer_managed`.
4. WHEN the first provider is `secretbox`, THE Verdict_Engine SHALL assign ENCRYPTED_DECLARED and record key custody as `local_file`.
5. WHEN the first provider is `aescbc` or `aesgcm`, THE Verdict_Engine SHALL assign ENCRYPTED_DECLARED, record key custody as `local_file`, and THE Config_Extractor SHALL raise `AT_REST_ENCRYPTION_WEAK` with the rationale from the Defaults_Registry.
6. WHEN a provider entry carries a literal key value in the file, THE Config_Extractor SHALL emit a `related-crypto-material` crypto asset of material kind `secret-key` with `crypto:hardcoded` set to true and without the value, so that the existing HARDCODED_KEY predicate raises its finding.
7. WHEN a managed-cluster resource (`aws_eks_cluster`, `azurerm_kubernetes_cluster`, `google_container_cluster`) declares or omits its secrets-encryption option, THE Verdict_Engine SHALL assign the Verdict from the matching Provider_Defaults_Table row.
8. WHEN a kube-apiserver static pod manifest is read, THE Config_Extractor SHALL record whether `--encryption-provider-config` is present and SHALL link it to an `EncryptionConfiguration` file inside the Scanned_Input by path; WHEN the flag is absent, THE Verdict_Engine SHALL assign the `database` Layer NOT_ENCRYPTED only if the matching row is marked `assessable_as_unencrypted`.
9. WHEN the Scanned_Input holds no `EncryptionConfiguration`, no kube-apiserver manifest and no managed-cluster resource, THE Config_Extractor SHALL emit zero `k8s_secrets_etcd` facts.

### Requirement 18: Database-native, disk-level and SQL-declared encryption evidence

**User Story:** As a database owner, I want native at-rest settings, disk encryption and declared SQL encryption features recognised, so that encryption done below or inside the database counts as evidence.

#### Acceptance Criteria

1. WHEN a database configuration file sets a native at-rest directive listed in Table R18-A, THE Verdict_Engine SHALL assign the `database` Layer ENCRYPTED_DECLARED.
2. WHEN a directive of Table R18-A is explicitly set to a disabling value, THE Verdict_Engine SHALL assign the `database` Layer NOT_ENCRYPTED, and the resource-level Verdict SHALL follow Requirement 6 criterion 6.
3. WHEN a database configuration for PostgreSQL, Redis or Elasticsearch has no native at-rest directive, THE Verdict_Engine SHALL assign the `database` Layer UNKNOWN with reason `layer_not_observable`.
4. WHEN local-file key custody is declared (a file keyring plugin, an encryption key file), THE Config_Extractor SHALL raise `AT_REST_ENCRYPTION_WEAK`.
5. WHEN an `/etc/crypttab` file or a `cryptsetup` `luksFormat`, `luksOpen` or `open` invocation is read, THE Config_Extractor SHALL emit an Encryption_Fact of kind `disk_encryption` with the `volume` Layer ENCRYPTED_DECLARED, and SHALL emit an `algorithm` crypto asset from the declared cipher, key size and hash so that the existing weakness predicates apply.
6. WHEN a `crypttab` entry uses a random keyfile such as `/dev/urandom`, THE Config_Extractor SHALL record the volume as `ephemeral` encryption; WHEN the keyfile field is `none`, THE Config_Extractor SHALL record the key source as a passphrase prompt.
7. WHEN a `*.sql` file contains `CREATE DATABASE ENCRYPTION KEY`, `ALTER DATABASE ... SET ENCRYPTION ON`, `ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY`, a MySQL table option `ENCRYPTION='Y'`, or a PostgreSQL `pgp_sym_encrypt` or `pgp_pub_encrypt` call, THE Config_Extractor SHALL record a `database` or `application` Layer ENCRYPTED_DECLARED evidence entry that carries a closed-vocabulary statement label and the line, and no statement text.
8. WHEN a database configuration loads an extension that the Defaults_Registry lists as a native at-rest mechanism, THE Config_Extractor SHALL treat the load as evidence at the `database` Layer.
9. THE Config_Extractor SHALL take SDK-level encryption evidence from the existing algorithm and library inventory only, and that evidence SHALL leave the Verdict of every resource unchanged.

**Native at-rest directives (R18-A).** The design may add engines; it may not remove any.

| Engine | Directives |
|---|---|
| MySQL | `innodb_encrypt_tables`, `innodb_encrypt_log`, `default_table_encryption`, `binlog_encryption`, keyring plugin or component loading |
| MariaDB | `plugin_load_add` with a key-management plugin, `innodb_encrypt_tables`, `innodb_encrypt_log`, `encrypt_binlog`, `aria_encrypt_tables`, `encrypt_tmp_files` |
| MongoDB | `security.enableEncryption`, `security.encryptionCipherMode`, `security.encryptionKeyFile`, `security.kmip.*` |
| PostgreSQL, Redis, Elasticsearch | none in the community edition; extension evidence only (criterion 8) |

### Requirement 19: Business-linkage mapping file and CODEOWNERS hints

**User Story:** As a data owner, I want to declare system, owner, data classification and data lifetime in my own repository, so that the data-at-rest report shows them without any new form or database table.

#### Acceptance Criteria

1. THE Config_Extractor SHALL read an optional Business_Mapping_File from the Scanned_Input root, using the first existing file in this order: `.devsecshield/cbom-mapping.yaml`, `.devsecshield/cbom-mapping.json`, `cbom-mapping.yaml`, `cbom-mapping.json`, and SHALL record a `mapping_file_ignored` Diagnostic for each other file that exists.
2. THE Business_Mapping_File SHALL follow the schema of Table R19-A.
3. WHEN an entry gives `resource`, `path` or `kind` selectors, THE Config_Extractor SHALL apply the entry to an Encryption_Fact only when every given selector matches, and WHEN several entries match THE Config_Extractor SHALL let later entries override earlier ones field by field.
4. THE Config_Extractor SHALL accept each string value up to 256 characters after removing control characters, SHALL ignore unknown keys with a `mapping_unknown_key` Diagnostic, SHALL skip an invalid entry with a `mapping_entry_invalid` Diagnostic, and SHALL drop entries beyond the entry limit of the Limits Table.
5. THE Config_Extractor SHALL store matched values in the `linkage` field with source `mapping_file`, and THE Deliverable_Renderer SHALL print them labelled as declared in the repository mapping file and not verified.
6. THE Config_Extractor SHALL read the first existing file of `.github/CODEOWNERS`, `CODEOWNERS` and `docs/CODEOWNERS` with GitHub semantics: the last matching pattern wins, patterns are gitignore-style globs (`*`, `**`, a leading `/`, a trailing `/`), and comment lines are ignored.
7. IF a CODEOWNERS pattern uses unsupported syntax (negation, character classes), THEN THE Config_Extractor SHALL skip that pattern and record a `codeowners_pattern_unsupported` Diagnostic.
8. THE Config_Extractor SHALL set the Owner_Hint (`owner_hint`) from the owners of the last CODEOWNERS pattern that matches the evidence path of the fact, with source `codeowners`, and THE Deliverable_Renderer SHALL show the Owner_Hint separately from the owner declared in the Business_Mapping_File.
9. WHEN neither a Business_Mapping_File entry nor a CODEOWNERS pattern applies to a fact, THE Deliverable_Renderer SHALL print Assessor_Cells for system, owner, data classification and data lifetime.
10. THE Config_Extractor SHALL treat data classification and data lifetime values as free text and SHALL assign no classification grade or Q-level.
11. THE Config_Extractor SHALL obtain the mapping from the Scanned_Input alone, with zero new database tables, API fields and user-interface forms.
12. THE Repository SHALL document the schema, selector semantics, precedence and an example in `docs/cbom-posture/`.

**Mapping file schema (R19-A).**

| Field | Meaning |
|---|---|
| `version` | Integer, 1 |
| `defaults` | Optional object with `system`, `owner`, `data_classification`, `data_lifetime` applied to every fact |
| `entries[].match.resource` | Glob over the fact `address` |
| `entries[].match.path` | Glob over the repository-relative path |
| `entries[].match.kind` | One kind from Table R5-A |
| `entries[].system` | Business system name |
| `entries[].owner` | Owning team or person |
| `entries[].data_classification` | Free text from the customer's scheme |
| `entries[].data_lifetime` | Free text, for example a retention or confidentiality period |
| `entries[].notes` | Free text |

### Requirement 20: Static TLS and SSH configuration of servers, proxies, ingress and application servers

**User Story:** As a network security reviewer, I want TLS and SSH settings read from the configuration files in the repository, so that protocol and cipher weaknesses are found without probing a live system.

#### Acceptance Criteria

1. THE Config_Extractor SHALL read the settings of Table R20-A for each supported server and SHALL emit, per listener, virtual host, connector or server block, an Encryption_Fact of kind `tls_endpoint` (or `ssh_service`) with a `transport` Layer and a linked `protocol` crypto asset that carries `crypto:protocolType`, `crypto:protocolVersion` (the minimum permitted), `crypto:maxProtocolVersion`, `crypto:cipherSuite`, `crypto:strength`, `crypto:policySource` (the server name) and, when declared, the listen address and port.
2. THE Config_Extractor SHALL apply the documented scope, inheritance and override rules of each server: the `http`, `server` and `location` contexts of nginx, the global and `VirtualHost` contexts of Apache httpd, the `defaults`, `frontend`, `listen` and `bind` lines of HAProxy, and the `Connector` and `SSLHostConfig` elements of Tomcat.
3. THE Config_Extractor SHALL interpret protocol and cipher exclusions by their meaning (for example an Apache `SSLProtocol -all +TLSv1.2`, an HAProxy `no-tlsv10`, a Jetty `ExcludeProtocols`), so that a directive that disables a protocol is never recorded as use of that protocol.
4. WHEN a directive that fixes the protocol floor is absent and the server default depends on the server version, THE Verdict_Engine SHALL assign UNKNOWN with reason `provider_version_dependent`, and the `protocol` asset SHALL carry no `crypto:strength` value.
5. WHEN a server block listens without TLS and configures no redirect to HTTPS in that block, THE Config_Extractor SHALL raise `PLAINTEXT_LISTENER`, and WHEN the block redirects to HTTPS THE Config_Extractor SHALL record the `transport` Layer as ENCRYPTED_DECLARED and raise no finding.
6. WHEN an Istio `PeerAuthentication` sets mutual-TLS mode `PERMISSIVE` or `DISABLE`, THE Config_Extractor SHALL raise `PLAINTEXT_LISTENER`.
7. WHEN an OpenSSH algorithm list is written, THE Config_Extractor SHALL evaluate weakness from the algorithms the file names explicitly, counting a `+` addition as enabled and assuming no algorithm of the version-dependent default list, and SHALL pass the named algorithms in `crypto:cipherSuite` to the existing `cipher_suite_findings` predicate.
8. WHEN an explicit protocol floor of TLS 1.2 or later and an explicit cipher list that the existing predicates classify as acceptable are both declared, THE Config_Extractor SHALL set `crypto:strength` to `strong`.
9. WHEN a `Strict-Transport-Security` header is configured, THE Config_Extractor SHALL record its presence and `max-age` as an attribute, and the absence of the header SHALL leave the finding set empty.
10. WHEN a certificate or key file path is declared and the file exists in the Scanned_Input, THE Config_Extractor SHALL link the `protocol` asset to the existing certificate asset of that file.

**Supported servers and directives (R20-A).** The design may add settings; it may not remove any.

| Server | Settings read |
|---|---|
| nginx | `listen`, `ssl_protocols`, `ssl_ciphers`, `ssl_prefer_server_ciphers`, `ssl_ecdh_curve`, `ssl_dhparam`, `ssl_session_tickets`, `ssl_certificate`, `ssl_certificate_key`, `ssl_verify_client`, `proxy_ssl_verify`, `add_header Strict-Transport-Security`, `return` and `rewrite` redirects |
| Apache httpd | `SSLEngine`, `SSLProtocol`, `SSLCipherSuite`, `SSLHonorCipherOrder`, `SSLCompression`, `SSLSessionTickets`, `SSLOpenSSLConfCmd`, `SSLCertificateFile`, `SSLCertificateKeyFile`, `SSLVerifyClient`, `SSLProxyVerify`, `SSLProxyProtocol`, `Header ... Strict-Transport-Security`, `Redirect`, `RewriteRule` |
| HAProxy | `ssl-default-bind-options`, `ssl-default-bind-ciphers`, `ssl-default-bind-ciphersuites`, `ssl-default-server-options`, `bind` options `ssl`, `crt`, `ciphers`, `ciphersuites`, `ssl-min-ver`, `ssl-max-ver`, `no-sslv3`, `no-tlsv10`, `no-tlsv11`, `no-tlsv12`, `curves`, `server` option `verify none`, `redirect scheme https`, `http-response set-header Strict-Transport-Security` |
| Envoy | `tls_minimum_protocol_version`, `tls_maximum_protocol_version`, `cipher_suites`, `ecdh_curves`, `require_client_certificate`, `tls_certificates` |
| Istio | `Gateway` `tls.mode`, `tls.minProtocolVersion`, `tls.maxProtocolVersion`, `tls.cipherSuites`; `PeerAuthentication` `mtls.mode`; `DestinationRule` `trafficPolicy.tls.mode` and `insecureSkipVerify` |
| Traefik | `tls.options.<name>.minVersion`, `maxVersion`, `cipherSuites`, `curvePreferences`, `sniStrict`; entry-point redirections; `serversTransport.insecureSkipVerify` |
| Tomcat | `Connector` attributes `SSLEnabled`, `scheme`, `secure`, `sslProtocol`, `sslEnabledProtocols`, `ciphers`; `SSLHostConfig` attributes `protocols`, `ciphers`, `certificateVerification` |
| Spring Boot | `server.ssl.enabled`, `server.ssl.protocol`, `server.ssl.enabled-protocols`, `server.ssl.ciphers`, `server.ssl.client-auth`, `server.ssl.key-store-type`, `management.server.ssl.*` |
| Jetty | `IncludeProtocols`, `ExcludeProtocols`, `IncludeCipherSuites`, `ExcludeCipherSuites` of the SSL context factory |
| OpenSSH | `Ciphers`, `MACs`, `KexAlgorithms`, `HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms`, `CASignatureAlgorithms`, `RequiredRSASize`, `Protocol` |
| Kubernetes Ingress and Service | `Ingress.spec.tls`; annotations `nginx.ingress.kubernetes.io/ssl-redirect`, `force-ssl-redirect`, `ssl-protocols`, `ssl-ciphers`, `backend-protocol`; `alb.ingress.kubernetes.io/ssl-policy`, `certificate-arn`, `listen-ports`, `ssl-redirect`; `kubernetes.io/ingress.allow-http`; `appgw.ingress.kubernetes.io/ssl-redirect`; `networking.gke.io/v1beta1.FrontendConfig` `sslPolicy`; `Service` annotations `service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy`, `aws-load-balancer-ssl-cert`, `aws-load-balancer-ssl-ports`, `aws-load-balancer-backend-protocol`. Policy names resolve through the TLS_Policy_Registry (Requirement 13 criterion 3). |

### Requirement 21: Database, cache and search transport settings

**User Story:** As a database owner, I want transport-security settings of database server configurations assessed, so that servers that accept plaintext connections are reported.

#### Acceptance Criteria

1. THE Config_Extractor SHALL read the settings of Table R21-A for PostgreSQL, MySQL and MariaDB, MongoDB, Elasticsearch and Redis, and SHALL emit an Encryption_Fact of kind `relational_db`, `nosql_db`, `cache` or `search_index` with provider `self_hosted` and a `transport` Layer.
2. WHEN a configuration explicitly disables TLS (`ssl = off`, `net.tls.mode: disabled`, `xpack.security.http.ssl.enabled: false`, `skip_ssl`), THE Verdict_Engine SHALL assign the `transport` Layer NOT_ENCRYPTED and THE Config_Extractor SHALL raise `UNENCRYPTED_IN_TRANSIT`.
3. WHEN a configuration explicitly permits plaintext next to TLS (`net.tls.mode` of `allowTLS` or `preferTLS`, or a Redis `port` greater than 0 together with a non-loopback `bind`), THE Verdict_Engine SHALL assign the `transport` Layer NOT_ENCRYPTED and THE Config_Extractor SHALL raise `UNENCRYPTED_IN_TRANSIT`.
4. WHEN a PostgreSQL `pg_hba.conf` record of type `host` or `hostnossl` covers a non-loopback address, THE Verdict_Engine SHALL assign the `transport` Layer NOT_ENCRYPTED, and WHEN every non-loopback record is of type `hostssl` or `hostgssenc`, THE Verdict_Engine SHALL assign ENCRYPTED_DECLARED.
5. WHEN a setting that decides transport security is absent from a self-hosted configuration, THE Verdict_Engine SHALL apply Requirement 6 criterion 8.
6. WHEN a configuration names a protocol floor, a protocol list, a cipher list or a curve list, THE Config_Extractor SHALL emit a linked `protocol` crypto asset with the same properties as Requirement 20 criterion 1, so that the existing predicates apply.
7. WHEN a configuration switches peer-certificate validation off (`net.tls.allowInvalidCertificates: true`, `net.tls.allowInvalidHostnames: true`, `xpack.security.transport.ssl.verification_mode: none`), THE Config_Extractor SHALL raise `TLS_VERIFICATION_DISABLED`.

**Database transport settings (R21-A).**

| Engine | Settings read |
|---|---|
| PostgreSQL | `ssl`, `ssl_min_protocol_version`, `ssl_max_protocol_version`, `ssl_ciphers`, `ssl_prefer_server_ciphers`, `ssl_ecdh_curve`, `ssl_cert_file`, `ssl_key_file`; `pg_hba.conf` record types `host`, `hostssl`, `hostnossl`, `hostgssenc` |
| MySQL and MariaDB | `require_secure_transport`, `tls_version`, `ssl_cipher`, `ssl_ca`, `ssl_cert`, `ssl_key`, `skip_ssl`, `ssl` |
| MongoDB | `net.tls.mode`, `net.tls.disabledProtocols`, `net.tls.allowConnectionsWithoutCertificates`, `net.tls.allowInvalidCertificates`, `net.tls.allowInvalidHostnames`, `net.tls.CAFile`, `net.tls.certificateKeyFile`, and the legacy `net.ssl.*` equivalents |
| Elasticsearch | `xpack.security.enabled`, `xpack.security.transport.ssl.enabled`, `xpack.security.http.ssl.enabled`, `xpack.security.{transport,http}.ssl.supported_protocols`, `.cipher_suites`, `.verification_mode`, `.client_authentication` |
| Redis | `port`, `tls-port`, `tls-protocols`, `tls-ciphers`, `tls-ciphersuites`, `tls-prefer-server-ciphers`, `tls-auth-clients`, `tls-replication`, `tls-cluster` |

### Requirement 22: Offline cipher-string, curve and policy evaluation

**User Story:** As a reviewer, I want cipher lists and named policies evaluated against an offline registry, so that a configuration that merely says `HIGH:!aNULL` is judged correctly without running OpenSSL.

#### Acceptance Criteria

1. THE Config_Extractor SHALL expand OpenSSL cipher strings (nginx `ssl_ciphers`, Apache `SSLCipherSuite`, HAProxy `ciphers`, PostgreSQL `ssl_ciphers`, MySQL `ssl_cipher`, Redis `tls-ciphers`) against the cipher registry of the Defaults_Registry, supporting the cipher names, aliases, the `+`, `-` and `!` operators, `@STRENGTH`, `@SECLEVEL=n` and the colon, comma and space separators defined in the public OpenSSL cipher-list documentation.
2. WHEN a cipher string contains a token the evaluator cannot expand, THE Config_Extractor SHALL mark the cipher set UNKNOWN with reason `unresolved_expression`, SHALL not set `crypto:strength` to `strong`, and SHALL still report every suite that the string names explicitly and that the existing predicates classify as weak.
3. THE Config_Extractor SHALL map every permitted suite to its IANA name through the cipher registry and SHALL pass the result in `crypto:cipherSuite` to the existing `cipher_suite_findings` predicate, so that code-sourced and configuration-sourced suites share one classification.
4. THE Config_Extractor SHALL evaluate TLS 1.3 suite lists (`ciphersuites`, `tls-ciphersuites`, `ssl-default-bind-ciphersuites`) by name against the cipher registry.
5. THE Config_Extractor SHALL classify named curve and group lists (`ssl_ecdh_curve`, `curves`, `ecdh_curves`, `curvePreferences`) against the key-exchange registry and SHALL record each curve below 224 bits as weak.
6. WHEN `ssl_dhparam` or `SSLOpenSSLConfCmd DHParameters` names a PEM file inside the Scanned_Input, THE Config_Extractor SHALL read the prime size from it and SHALL emit a Diffie-Hellman `algorithm` crypto asset with that key size, so that the existing WEAK_KEY_SIZE predicate applies.
7. THE Config_Extractor SHALL be total and deterministic: for every string of a seeded random corpus it SHALL return a result without raising, and for every documented example string in the Oracle it SHALL return the hand-derived expansion.
8. THE Defaults_Registry SHALL derive the cipher registry from the public IANA TLS parameters registry and the public OpenSSL cipher-list documentation, each with a source URL and a `valid_as_of` date.

### Requirement 23: Disabled certificate verification and legacy protocol pins in code, environment and commands

**User Story:** As an application security reviewer, I want disabled certificate validation and pinned legacy protocol versions found in code, container definitions and scripts, so that man-in-the-middle exposure is reported next to the configuration findings.

#### Acceptance Criteria

1. THE Config_Extractor SHALL detect the patterns of the verification pattern list in the Defaults_Registry in source files of the languages in `LANGUAGE_EXTENSIONS`, in Dockerfiles, in compose `environment` and `command` entries, in Kubernetes container `env`, `command` and `args` entries, and in `*.sh` and `*.bash` files.
2. THE verification pattern list SHALL contain at least: Python `verify=False` on `requests`, `httpx` and `urllib3` calls, `ssl._create_unverified_context`, `ssl.CERT_NONE` and `check_hostname = False`; Go `InsecureSkipVerify: true`; Node.js `rejectUnauthorized: false` and `NODE_TLS_REJECT_UNAUTHORIZED=0`; Java trust-all trust managers and allow-all hostname verifiers; .NET `ServerCertificateValidationCallback` returning true; `curl -k` and `curl --insecure`; `wget --no-check-certificate`; `GIT_SSL_NO_VERIFY`; `PYTHONHTTPSVERIFY=0`; and `npm config set strict-ssl false`.
3. WHEN a pattern matches in code that is not a comment or a docstring, THE Config_Extractor SHALL emit a `protocol` crypto asset of type `tls` with `crypto:verification` set to `disabled` and SHALL raise `TLS_VERIFICATION_DISABLED`.
4. THE Config_Extractor SHALL blank comments and docstrings before matching, so that prose cannot produce a finding.
5. WHEN a Java option, Node.js option or environment variable pins a protocol version below TLS 1.2 (for example `-Dhttps.protocols=TLSv1`, `-Djdk.tls.client.protocols=TLSv1`, `--tls-min-v1.0`), THE Config_Extractor SHALL emit a `protocol` asset with that version and `crypto:strength` `weak`.
6. WHEN a match lies under a path whose `path_context` is `non_production_hint`, THE Config_Extractor SHALL still raise the finding and SHALL record the `path_context` so that the report shows it.
7. THE Config_Extractor SHALL leave the behaviour of the existing source-level `ProtocolScanner` unchanged, and SHALL produce zero additional components and flags on every Frozen_Golden fixture.
8. THE verification pattern list SHALL cite for each entry a public URL and the anchor CWE-295.

### Requirement 24: Offline import of testssl.sh, sslyze and nmap result files

**User Story:** As an assessor, I want TLS scan results that my team produced with its own tools read from the scanned repository or zip, so that the report includes live-endpoint evidence without the platform ever contacting an endpoint.

#### Acceptance Criteria

1. THE TLS_Result_Importer SHALL decide the producing tool by content signature and not by file name: testssl.sh JSON in its flat form (an array of objects with `id`, `finding`, `severity`, `ip` and `port`) and its pretty form (an object with `scanResult`), sslyze JSON (an object with `server_scan_results`), and nmap XML (a root element `nmaprun` with `script` elements whose `id` is `ssl-enum-ciphers`).
2. THE TLS_Result_Importer SHALL support every format variant that the design lists in its Format Register, and each variant SHALL have a committed sample authored by hand from the public documentation of the tool's output.
3. IF a candidate file's tool or format version is absent from the Format Register, THEN THE TLS_Result_Importer SHALL import nothing from it and SHALL record an `unsupported_result_format` Diagnostic with the tool name and version when the file states them, so that silence never reads as a clean result.
4. THE TLS_Result_Importer SHALL treat every host name, IP address, URL and port in a file as an inert string: it SHALL open no socket, resolve no name, contact no host and start no process.
5. WHEN an nmap XML file starts with a bare `<!DOCTYPE nmaprun>` declaration, THE TLS_Result_Importer SHALL parse it, and WHEN an XML file declares an internal subset, an entity or an external identifier, THE TLS_Result_Importer SHALL reject it with an `unsafe_xml` Diagnostic (Requirement 3 criteria 7 and 8).
6. THE TLS_Result_Importer SHALL apply the TLS result file size limit, the nesting depth limit and the Requirement 4 criteria on duplicate keys and control characters to every result file.
7. THE TLS_Result_Importer SHALL emit one Encryption_Fact of kind `tls_endpoint` with `format` `import` for each endpoint of a file, identified by host, port and source file, and SHALL sanitize host strings to at most 512 characters.
8. THE TLS_Result_Importer SHALL record per file the sanitized path, the tool, the tool version and the scan start and end times exactly as the file states them (null when absent), and SHALL read neither the wall clock nor the file modification time.
9. THE Test_Suite SHALL use only reserved example domains (`example.com`, `example.org`, `.test`, `.invalid`) and documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) in result-file samples.

### Requirement 25: Imported per-endpoint assertions, provenance and staleness

**User Story:** As an assessor, I want each imported endpoint reduced to protocol, cipher, key-exchange, certificate, downgrade and vulnerability facts with their provenance, so that I can see what the customer's own scan reported and when.

#### Acceptance Criteria

1. FOR EACH endpoint, THE TLS_Result_Importer SHALL extract, when the tool reports them: the protocol versions offered (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3), the cipher suites accepted per version, forward-secrecy support, Diffie-Hellman prime size, the elliptic curves or groups offered, server cipher preference, TLS compression, secure renegotiation, TLS_FALLBACK_SCSV support, the HSTS header, and the peer certificate attributes (subject, issuer, validity, signature algorithm, public-key algorithm and size, chain status as reported).
2. THE TLS_Result_Importer SHALL emit per endpoint one `protocol` crypto asset of type `tls` with `crypto:protocolVersion` set to the lowest version offered, `crypto:maxProtocolVersion` to the highest, `crypto:cipherSuite` to the union of accepted suites by IANA name, `crypto:endpoint` to host and port, `crypto:evidenceSource` to `imported:<tool>`, and `crypto:strength` to `weak` when any SSL version or a TLS version below 1.2 is offered, so that the existing predicates raise WEAK_PROTOCOL and WEAK_CIPHER_SUITE.
3. WHEN a result contains peer certificate attributes, THE TLS_Result_Importer SHALL emit a `certificate` crypto asset with the existing `crypto:` certificate properties, with `discovery:source` set to the result file and `crypto:endpoint` set, so that the existing certificate predicates apply.
4. WHEN a result reports a Diffie-Hellman or ephemeral key size below 2048 bits, THE TLS_Result_Importer SHALL emit a Diffie-Hellman `algorithm` asset with that size.
5. WHEN a result shows SSLv3, TLS 1.0 or TLS 1.1 offered and TLS_FALLBACK_SCSV reported as not supported, THE TLS_Result_Importer SHALL raise `DOWNGRADE_PROTECTION_MISSING`.
6. WHEN a result reports an entry of Table R25-A marked scored as vulnerable, THE TLS_Result_Importer SHALL raise `KNOWN_TLS_VULNERABILITY` with `crypto:vulnerability` naming the entry.
7. THE TLS_Result_Importer SHALL map every tool-reported status to the closed vocabulary `vulnerable`, `not_vulnerable`, `potentially`, `not_tested`, `error`, and SHALL raise findings only for `vulnerable`.
8. WHEN an item is `not_tested` or `error`, THE TLS_Result_Importer SHALL record UNKNOWN with reason `import_not_tested` and SHALL raise no finding.
9. WHEN the same host and port appear in more than one imported file, THE TLS_Result_Importer SHALL keep each as a separate Encryption_Fact tagged with its file.
10. WHEN a static server fact and an imported result carry the identical `host:port` string, THE Team_Rollup SHALL list both rows adjacent and SHALL flag a discrepancy when the static protocol floor is higher than the lowest version the result reports as offered.

**Named vulnerabilities (R25-A).** The design may extend the scored list; it may not remove an entry.

| Entry | Scored | Reference |
|---|---|---|
| Heartbleed | yes | CVE-2014-0160 |
| OpenSSL CCS injection | yes | CVE-2014-0224 |
| ROBOT | yes | CVE-2017-13099 and related |
| Ticketbleed | yes | CVE-2016-9244 |
| DROWN | yes | CVE-2016-0800 |
| POODLE (SSLv3) | yes | CVE-2014-3566 |
| FREAK | yes | CVE-2015-0204 |
| Logjam | yes | CVE-2015-4000 |
| SWEET32 | yes | CVE-2016-2183 |
| RC4 cipher use | yes | CVE-2013-2566 |
| BEAST | no, shown as reported | CVE-2011-3389 |
| LUCKY13 | no, shown as reported | CVE-2013-0169 |
| CRIME | no, shown as reported | CVE-2012-4929 |
| BREACH | no, shown as reported | CVE-2013-3587 |

### Requirement 26: CycloneDX 1.6 representation and schema validation

**User Story:** As a consumer of the machine-readable CBOM, I want every new fact represented as valid CycloneDX 1.6, so that downstream tools can read the BOM without special handling.

#### Acceptance Criteria

1. WHEN a ScanResult is emitted, THE CBOM_Emitter SHALL produce a document that validates against the bundled CycloneDX 1.6 schema through the existing `emit_and_validate` path, and a schema-invalid document SHALL fail the build.
2. THE CBOM_Emitter SHALL represent facts that are cryptographic assets under CycloneDX 1.6 (KMS keys, TLS and SSH protocols, algorithms, certificates, hard-coded key material) as components of type `cryptographic-asset` with the four existing `assetType` values and the existing `cryptoProperties` mapping, and SHALL add no field to `cryptoProperties`.
3. THE CBOM_Emitter SHALL represent every other Encryption_Fact as a component whose `type` is a CycloneDX 1.6 component type and whose detail is carried in namespaced `properties` using the `crypto:` namespace (and `discovery:` for provenance), with no non-spec top-level key; introducing any other namespace SHALL require an AGENTS.md convention update in the same commit.
4. WHEN a resource is protected by a key that is declared in the Scanned_Input, THE CBOM_Emitter SHALL express the link as a CycloneDX `dependencies` entry in which the resource depends on the key.
5. THE Repository SHALL list every new `crypto:` property key, its type and its allowed values in a property dictionary under `docs/cbom-posture/`, and THE Test_Suite SHALL fail WHEN an emitted key is missing from the dictionary.
6. WHEN a ScanResult holds zero Encryption_Facts and zero new crypto assets, THE CBOM_Emitter SHALL produce a document byte-identical to the Base_Commit output.
7. IF the components added by the posture lanes would exceed the component limit, THEN THE CBOM_Emitter SHALL keep the components of facts with findings first, SHALL set the BOM property `crypto:postureTruncated` to true and SHALL carry the dropped count.
8. THE Test_Suite SHALL validate the emitted BOM of every new fixture tree against the bundled schema.
9. THE CERT-In VEX builder, the BOM signer, the evidence-pack route, the single-scan CBOM PDF export and the client-side CycloneDX download SHALL accept a BOM that contains posture components, and THE Test_Suite SHALL run each of them on a posture fixture BOM.
10. WHERE a component kind is added to `aibom/src/aibom/model/component.py`, THE Repository SHALL add it as an additive change that leaves every AIBOM emit golden byte-identical.

### Requirement 27: Determinism, ordering and idempotence

**User Story:** As an auditor, I want the same input to give the same BOM and the same numbers every time, so that a report can be reproduced and compared.

#### Acceptance Criteria

1. WHEN the same Scanned_Input is scanned three times, in one process and in separate processes, THE CBOM_Engine SHALL return byte-identical `cbom_json` and Posture_Block, excluding `duration_of_scan`.
2. THE CBOM_Engine SHALL return the same output regardless of file creation order, modification times, permissions, directory-listing order, `PYTHONHASHSEED`, locale (`LC_ALL=C` and `en_US.UTF-8`) and host path separators.
3. THE Config_Extractor and THE TLS_Result_Importer SHALL read no wall clock.
4. THE Config_Extractor SHALL sort every collection it emits by the keys of Requirement 5 criterion 9, with ties broken by `id`.
5. THE Config_Extractor SHALL hold no mutable module-level state, and THE Defaults_Registry SHALL be loaded once into immutable structures.
6. FOR EACH Encryption_Fact of every fixture, encoding it into `crypto:` properties and decoding it SHALL yield an equal Encryption_Fact (round-trip property test with seeded generators).
7. THE Run_Object_Normalizer SHALL serialize the Posture_Block so that `json.dumps(..., sort_keys=True)` of equal inputs yields equal bytes.

### Requirement 28: Scoring weights and score stability

**User Story:** As a risk owner, I want the new findings weighted from configuration without changing any existing score, so that last month's scores stay comparable.

#### Acceptance Criteria

1. THE Weights_File SHALL contain an explicit entry for every code in `POSTURE_CODES` with the weight of Table R15-A, and THE Test_Suite SHALL fail WHEN a code emitted by any new scanner has no entry, so that no code silently takes the default weight 1.
2. THE Weights_File SHALL set `scale.max_raw` to the sum of the positive flag weights that the file held at the Base_Commit (112 when the Base_Commit file is summed at the time of writing), so that `risk_total`, `risk_normalized` and `risk_band` of every Frozen_Golden fixture and of every scan without posture findings stay identical.
3. THE Weights_File SHALL keep the existing `severity` thresholds and `scale.bands` unchanged.
4. THE Risk_Scorer SHALL stack the weights of all flags on one component, and a component with two posture findings SHALL show their summed weight in `scores.by_component`.
5. THE Risk_Scorer SHALL list the new codes with their counts in `scores.by_flag`.
6. THE CBOM_Engine SHALL leave the new codes out of `WEAK_CRYPTO_CODES` and out of the normalizer's weakness-distribution set, so that the five existing chart structures stay unchanged.
7. THE Risk_Scorer SHALL remain a delegate of the shared scoring engine and SHALL add no scoring algorithm.

### Requirement 29: Compliance integration without new framework keys

**User Story:** As a compliance officer, I want the new facts to use the existing tri-state vocabulary and to feed the existing checks through the assets they produce, so that no regulatory claim changes without a deliberate decision.

#### Acceptance Criteria

1. THE Compliance_Engine SHALL leave the requirement list, the verdict logic and the evidence text of all 13 frameworks in `CBOM_FRAMEWORKS` unchanged, so that `cbom_compliance` of every Frozen_Golden fixture is byte-identical to the Base_Commit output.
2. THE Compliance_Engine SHALL add no framework key to `CBOM_FRAMEWORKS` or to `cbom_compliance` in this feature.
3. WHEN a scan contains crypto assets emitted by the Config_Extractor or the TLS_Result_Importer, THE existing graph-queried checks SHALL evaluate them through the same `crypto:` property predicates without a code change, as proved by a fixture in which a configuration-derived TLS 1.0 asset turns the existing weak-protocol checks to fail.
4. THE Compliance_Engine SHALL keep reading graph properties only and SHALL never read `result.flags`, and the existing `test_compliance_never_reads_flags` SHALL pass unmodified.
5. THE Compliance_Engine SHALL keep the operational key-lifecycle requirements (the registered manual requirements for key rotation cadence, key custody and key periods) as NOT_BOM_EVIDENCEABLE even when the Scanned_Input declares automatic rotation, and THE Posture_Deliverables SHALL show the declaration as evidence only.
6. THE Run_Object_Normalizer SHALL report the Tri_State counts and Coverage_Percentage of the at-rest Verdicts and of the `transport` Verdicts in the Posture_Block, computed with the formula of Requirement 6 criterion 12.
7. WHERE an attestation exists for a requirement, THE Compliance_Engine SHALL keep its existing behaviour of flipping NOT_BOM_EVIDENCEABLE to pass-with-evidence.

### Requirement 30: Run-object carry-through and compatibility with stored scans

**User Story:** As a platform owner, I want the new data to ride along in the stored scan without breaking any existing reader, so that old and new scans coexist in the same team.

#### Acceptance Criteria

1. THE Run_Object_Normalizer SHALL add exactly one top-level key, `cbom_posture`, and WHEN given any Frozen_Golden fixture it SHALL return every other key byte-identical to the Base_Commit output, excluding `duration_of_scan`.
2. THE Posture_Block SHALL contain `schema_version` (integer 1), `lanes` (the sorted identifiers of the posture lanes executed), `data_tables` (name, `data_version`, `valid_as_of` and SHA-256 per file), `counts` (declared resources by format and provider, Encryption_Facts by kind, provider and Verdict, Tri_State counts and Coverage_Percentage for at-rest and for transport, findings by code, OUT_OF_SCOPE and disabled resources), `facts`, `findings`, `imports`, `diagnostics`, `diagnostic_totals` and `truncated`.
3. THE Run_Object_Normalizer SHALL emit the Posture_Block for every scan that ran the posture lanes, including a scan with zero Encryption_Facts, so that "assessed with zero resources" differs from Not_Assessed.
4. IF the serialized Posture_Block would exceed the size limit, THEN THE Run_Object_Normalizer SHALL drop facts without findings in reverse sorted order until the block fits, SHALL set `truncated` to true and SHALL record the number dropped.
5. THE Worker_Adapter SHALL return the Posture_Block without changing its signature, and its progress percentages SHALL not decrease.
6. THE existing worker persistence path SHALL store the Posture_Block in `Scan.scan_data` with no backend change and no database schema change.
7. THE Run_Object_Normalizer SHALL keep `results[]`, `cbom_graph`, `cbom_graph_compact`, `cbom_graph_expanded`, `cbom_graph_view` and `cbom_distributions` limited to crypto-asset content, so that Encryption_Facts without crypto-asset form appear only in the Posture_Block.
8. WHEN the CBOM results page, the findings serializer, the dashboard aggregation or the single-scan PDF export reads a run-object that contains `cbom_posture`, THEY SHALL behave as for a run-object without it, as proved by the existing backend contract tests run on a captured posture run-object.
9. THE Run_Object_Normalizer SHALL keep the Posture_Block free of excluded secret values and of unsanitized scanned text.

### Requirement 31: Research provenance, documentation and benchmark preservation

**User Story:** As a maintainer, I want every capability traced to a public source and documented for customers, so that the product stays clean-room and operable.

#### Acceptance Criteria

1. FOR EACH shipped capability (each parser family, each Coverage_Table family, each import format and each Finding_Catalog code), THE Repository SHALL contain a row in `docs/cbom-research/LEDGER.md` with a public specification or behavioural evidence URL, the original re-implementation note, the gap note, the story identifier and the status `implemented` with the product file path.
2. THE Repository SHALL cite open-source scanners (checkov, tfsec, trivy, KICS, terrascan, testssl.sh, sslyze, nmap and the CBOMkit family) only as behaviour or output-format references, and no such tool SHALL appear on the product import path.
3. WHEN a code in `POSTURE_CODES`, a Coverage_Table family or an import format has no ledger row, THE Test_Suite SHALL fail.
4. THE Repository SHALL publish `docs/cbom-posture/` containing the supported formats and resource types, the Limits Table, the UNKNOWN reasons, the Business_Mapping_File schema and example, the property dictionary, the Defaults_Registry update procedure, the air-gap statement and the known limitations.
5. THE Repository SHALL append the conventions found during this work (scanner orders used, the `max_raw` pin, the `cbom_posture` key, the registry additions, test gotchas) to the "Discovered conventions" section of `AGENTS.md`.
6. THE Repository SHALL leave the benchmark harness under `bench/cbom/` unchanged, and its CI gates (true-miss count 0 and our-unique count greater than 0 for every repository) SHALL pass.

### Requirement 32: Registry, manifest and routes for the three new documents

**User Story:** As a team member, I want the three new documents to appear in the Deliverables menu and download like the existing six, so that one familiar mechanism serves all nine.

#### Acceptance Criteria

1. THE Deliverables_Registry SHALL register the three entries of Table R32-A and SHALL list all nine documents in ascending `number` order: 1, 3, 5, 6, 7, 9, 10, 15, 16.
2. THE Deliverables_Registry SHALL mark all three new entries `data_dependent`.
3. WHEN `GET /{team_id}/cbom/deliverables` is called, THE Deliverables_Router SHALL return the manifest with nine items in the existing shape, SHALL derive `available` from scan heads only and SHALL read no `scan_data`.
4. WHEN a team member requests `GET /{team_id}/cbom/deliverables/{slug}` with one of the three new slugs, THE Deliverables_Router SHALL answer 200 with an `application/pdf` body that starts with `%PDF-`, the header `Cache-Control: no-store` and the file name `cbom-<slug>-team<id>-<YYYYMMDD>.pdf`, for every team state listed in Requirement 38.
5. THE Deliverables_Router SHALL keep its status codes (401 for a bad token, 403 for a non-member or inactive session, 404 for an unknown slug only, 429, and 500 with the generic body), its limiter budget of 30 requests per 60 seconds per token and its existing informational headers, and SHALL add the header `X-Cbom-Posture` with the value `assessed`, `mixed`, `not_assessed` or `none`.
6. THE Deliverable_Renderer SHALL print the Document IDs `CBOM-D05-...`, `CBOM-D06-...` and `CBOM-D09-...` built by the existing `document_id` function.
7. IF the frontend list `CBOM_DELIVERABLES` and the Deliverables_Registry differ in a slug, a number or a title, or a registry entry has no `REPORT_META` key, THEN THE Test_Suite SHALL fail through an extension of the existing contract test.
8. THE Deliverables_Registry, THE Deliverables_Router and the new renderers SHALL import only modules that the existing T-NOLLM allow-list permits.

**New documents (R32-A).**

| Number | Slug | Title |
|---|---|---|
| 5 | `infrastructure-cloud-encryption-posture` | Infrastructure & Cloud Encryption Posture |
| 6 | `network-tls-protocol-assessment` | Network, TLS & Crypto Protocol Assessment |
| 9 | `data-at-rest-encryption-assessment` | Data-at-Rest Encryption Assessment |

### Requirement 33: Team roll-up extension

**User Story:** As a platform owner, I want posture facts rolled up per source with the same latest-scan-wins rules as the existing documents, so that all nine documents describe the same current state.

#### Acceptance Criteria

1. THE Team_Rollup SHALL read posture data only from the scans that the MEDIUM_Documents already include, and SHALL read `cbom_posture` defensively: a bad record SHALL be skipped and counted in `warnings` without echoing scanned text.
2. THE Team_Rollup SHALL keep every existing field of `TeamCbomView`, `ScanFacts` and the aggregates with its existing meaning and SHALL add only new fields with defaults, so that the MEDIUM renderers need no change.
3. THE Team_Rollup SHALL track posture coverage as a dimension separate from Fidelity_Tier: a Source is Not_Assessed when its current scan has no Posture_Marker, and a Tier A scan without the marker SHALL remain Tier A for the MEDIUM_Documents.
4. THE Team_Rollup SHALL identify a fact within a Source by the pair of source key and fact `id`, SHALL take its attributes from the newest scan that contains it, SHALL compute first-seen, last-seen and scan count over every folded scan, and SHALL mark it `current` only when it is in the current scan of its Source.
5. THE Team_Rollup SHALL list facts seen only in older scans in a "previously seen, not in latest scan" appendix and SHALL exclude them from headline counts.
6. THE Team_Rollup SHALL compute headline posture counts from current facts of assessed Sources only and SHALL not merge facts across Sources.
7. WHEN the newest attempt of a Source failed and an older successful scan exists, THE Team_Rollup SHALL use the older scan and carry the existing failed-latest note.
8. THE Team_Rollup SHALL cap each register at 2,000 rows and SHALL carry the count of omitted rows to the renderer.
9. THE Team_Rollup SHALL leave the fingerprint formula unchanged, so that the fingerprint of any scan set is identical to its Base_Commit value.
10. THE Team_Rollup SHALL read facts only of the requesting team's successful CBOM scans, and no fact of another team, of a failed or unfinished scan, or of another scan type SHALL reach any document.
11. THE Team_Rollup SHALL expose, for each Defaults_Registry data file named in current assessed scans, the oldest `valid_as_of` date, so that the documents print the oldest reference date they relied on.
12. THE Team_Rollup SHALL stay free of network and LLM imports and compatible with Python 3.10.

### Requirement 34: Common behaviour of the three new PDFs

**User Story:** As an auditor, I want the three new documents to look and read like the six existing ones, so that one reading discipline applies to the whole pack.

#### Acceptance Criteria

1. THE Deliverable_Renderer SHALL build each Posture_Deliverable with `build_document`, so that each PDF has the existing masthead, Document-control table, Basis box, Disclaimer box, "(assessor)" legend, page chrome with its own `REPORT_META` header and footer, and fonts limited to Helvetica, Helvetica-Bold and Courier.
2. THE Deliverable_Renderer SHALL add to the Basis box the line "Posture coverage: A of B current sources assessed; C not assessed (re-scan needed)", the line "Posture facts are counted separately from crypto asset occurrences", and one line per Defaults_Registry data file with its `data_version` and `valid_as_of` date.
3. WHEN the oldest `valid_as_of` date of a data file is more than 365 days before the document's as-of date, THE Deliverable_Renderer SHALL print the notice "Reference data may be out of date".
4. THE Deliverable_Renderer SHALL replace, in the Posture_Deliverables only, the existing method-scope paragraph by a paragraph that states: analysis of declared configuration and offline import of customer-produced result files; no live probing, cloud API access, KMS or HSM inspection or data-plane inspection; a declared setting is not proof of operation.
5. THE Deliverable_Renderer SHALL pass every string derived from scanned input (resource names, paths, owners, classification text, host names, tool versions) through `pdf_text` or `pdf_plain`, so that hostile markup, control characters and non-WinAnsi characters render literally or as `?`.
6. THE Deliverable_Renderer SHALL print the four Verdicts as "Encrypted (declared)", "Encrypted (provider default)", "Not encrypted" and "Not evidenceable from BOM (unknown)", and SHALL print Tri_State words with the existing `VERDICT_LABELS`.
7. WHEN a register row is UNKNOWN, THE Deliverable_Renderer SHALL print the plain-language label of its `unknown_reason` from the authored-text module.
8. THE Deliverable_Renderer SHALL leave Assessor_Cells blank and SHALL mark their columns "(assessor)"; a value declared in the Business_Mapping_File SHALL print with the label "declared" and SHALL not appear in an Assessor_Cell.
9. THE Deliverable_Renderer SHALL produce byte-identical PDFs for the same view and the same injected time.
10. THE authored text SHALL carry a `# Source:` comment with a public URL for every standards or vendor claim, and the existing URL allow-list test SHALL fail WHEN a URL is not on the reviewed list.

### Requirement 35: Deliverable #5, Infrastructure & Cloud Encryption Posture

**User Story:** As a cloud security lead, I want one document that shows what the infrastructure code declares about key management, storage encryption, managed TLS policies and certificate provisioning, so that I can review the estate and the open questions.

#### Acceptance Criteria

1. THE Deliverable_Renderer (deliverable #5) SHALL print a KPI strip with: Encryption_Facts assessed, at-rest Verdict counts under the four labels of Requirement 34, Posture_Findings by impact, KMS keys with the share that declares rotation, and Sources assessed against Sources total.
2. THE Deliverable_Renderer (deliverable #5) SHALL print a coverage and method section with declared resources by format and provider, Encryption_Facts, OUT_OF_SCOPE and disabled resources, Diagnostic totals by code, and for each Defaults_Registry data file its name, `data_version` and `valid_as_of`.
3. THE Deliverable_Renderer (deliverable #5) SHALL print a KMS key register with the columns key, provider, specification, usage, protection level, rotation, deletion protection, exposure, resources protected, source, location, "Key custodian (assessor)" and "HSM or KMS custody evidence (assessor)".
4. THE Deliverable_Renderer (deliverable #5) SHALL print a resource encryption register grouped by provider and kind with the columns resource, native type, at-rest Verdict, transport Verdict, key management, basis, finding codes, location and path context, sorted by impact and then address.
5. THE Deliverable_Renderer (deliverable #5) SHALL print a managed TLS endpoint table with endpoint, policy name, minimum protocol version, listener behaviour (TLS, redirect, plaintext), Verdict and finding codes.
6. THE Deliverable_Renderer (deliverable #5) SHALL print a secrets and certificate provisioning table with resource, kind, key algorithm and size or curve, key management and the rotation-on-renewal setting.
7. THE Deliverable_Renderer (deliverable #5) SHALL print a findings table with, per Finding_Catalog code present, its label, count, impact, anchor and remediation text, and the resource and location of the 25 highest-impact findings.
8. THE Deliverable_Renderer (deliverable #5) SHALL print a "Not evidenceable from BOM" section that groups every UNKNOWN fact by `unknown_reason` with counts and one "what to check manually" line per reason.
9. THE Deliverable_Renderer (deliverable #5) SHALL print the previously-seen appendix, manual forms (cloud account, subscription and project inventory; environment classification; key custodian assignments) and a sign-off block, all as Assessor_Cells.
10. THE Deliverable_Renderer (deliverable #5) SHALL close with a limits statement that includes "declared configuration is not proof of operation".

### Requirement 36: Deliverable #6, Network, TLS & Crypto Protocol Assessment

**User Story:** As a network security lead, I want one document that shows the TLS and SSH posture of every endpoint the repository declares or the customer's own scans reported, so that weak protocols, ciphers, key exchange, certificates and downgrade exposure are visible per endpoint.

#### Acceptance Criteria

1. THE Deliverable_Renderer (deliverable #6) SHALL print a KPI strip with: endpoints (static and imported), endpoints that offer a legacy protocol, endpoints with weak cipher suites, certificates seen on endpoints, imported result files by tool, and Sources assessed against Sources total.
2. THE Deliverable_Renderer (deliverable #6) SHALL print an endpoint register with endpoint, evidence kind (static server or `imported:<tool>`), minimum and maximum protocol version, whether TLS 1.3 is offered (offered, not offered or unknown), weak suite count, key exchange (Diffie-Hellman size and curves), forward secrecy, HSTS, downgrade protection, certificate summary, finding codes and location.
3. THE Deliverable_Renderer (deliverable #6) SHALL print a protocol-version matrix of endpoints against SSLv3, TLS 1.0, TLS 1.1, TLS 1.2 and TLS 1.3 using the words "offered", "not offered" and "unknown".
4. THE Deliverable_Renderer (deliverable #6) SHALL print a weak cipher suite table with endpoint, suite and the attack or rationale text of the existing suite catalog.
5. THE Deliverable_Renderer (deliverable #6) SHALL print a certificate table for certificates seen on endpoints with subject, issuer, validity, signature algorithm, key size and certificate finding codes.
6. THE Deliverable_Renderer (deliverable #6) SHALL print a downgrade and vulnerability table with endpoint, item, reported status and source tool, marking the entries of Table R25-A that are not scored as "reported, not scored".
7. THE Deliverable_Renderer (deliverable #6) SHALL print a table of SSH and database transport settings and a table of disabled certificate verification with location, pattern label and `path_context`.
8. THE Deliverable_Renderer (deliverable #6) SHALL print an import provenance table with file, tool, tool version, scan start and end exactly as the file states them, and endpoint count.
9. WHEN a static server fact and an imported result share the identical `host:port` string, THE Deliverable_Renderer (deliverable #6) SHALL print both rows adjacent with the discrepancy flag of Requirement 25 criterion 10.
10. THE Deliverable_Renderer (deliverable #6) SHALL print the "Not evidenceable from BOM" section, the previously-seen appendix, manual forms (endpoint owner, exposure internet or internal, compensating controls, live verification reference, all Assessor_Cells) and a sign-off block.
11. THE Deliverable_Renderer (deliverable #6) SHALL state that the platform did not probe any endpoint and that imported results reflect the time the customer's tool ran.

### Requirement 37: Deliverable #9, Data-at-Rest Encryption Assessment

**User Story:** As a data-protection officer, I want one document that shows, per data store, how it is protected at rest, who owns it and how the data is classified, so that I can see gaps and the evidence still owed.

#### Acceptance Criteria

1. THE Deliverable_Renderer (deliverable #9) SHALL print a KPI strip with: data stores by at-rest Verdict, backups by Verdict, Kubernetes secrets status, stores with a declared data classification, and Sources assessed against Sources total.
2. THE Deliverable_Renderer (deliverable #9) SHALL print a data store register with store, kind, provider or self-hosted, Layers with Verdicts, key management, system, owner, owner hint, data classification, data lifetime and location, where each linkage value is a declared value labelled "declared" or an Assessor_Cell.
3. THE Deliverable_Renderer (deliverable #9) SHALL print a backup and snapshot register, a Kubernetes secrets-at-rest table and a database-native and disk-level evidence table (directives, `crypttab` entries, `cryptsetup` invocations and SQL statement labels).
4. THE Deliverable_Renderer (deliverable #9) SHALL print application-level encryption evidence taken from the existing algorithm and library inventory, labelled "capability evidence, not proof that stored data is protected", and that evidence SHALL not change any Verdict.
5. WHEN at least one fact carries a declared data classification, THE Deliverable_Renderer (deliverable #9) SHALL print a roll-up of counts by declared classification and at-rest Verdict, and WHEN no fact carries one it SHALL state that no classification was declared and that a Business_Mapping_File supplies it.
6. THE Deliverable_Renderer (deliverable #9) SHALL print the "Not evidenceable from BOM" section, the previously-seen appendix, manual forms (regulated-data mapping, key-management evidence reference, retention schedule, all Assessor_Cells) and a sign-off block.
7. THE Deliverable_Renderer (deliverable #9) SHALL close with the statement that the platform does not inspect stored data and that a declared setting is not proof of operation.

### Requirement 38: Degradation matrix and Not_Assessed behaviour

**User Story:** As a reader, I want every unusual team state to produce a clear document and never a false pass or an error, so that I can trust what a blank means.

#### Acceptance Criteria

1. WHEN a team has no eligible scan, THE Deliverable_Renderer SHALL produce a 200 PDF with the existing banner "NO COMPLETED CBOM SCANS", all counts zero and no verdict statement.
2. WHEN every current Source is Not_Assessed, THE Deliverable_Renderer SHALL show the banner "POSTURE NOT ASSESSED - RE-SCAN NEEDED" with each Source and its last scan date, SHALL show KPI values as "n/a" and registers as "No entries", and SHALL state that no encryption verdict can be given; a zero count SHALL never read as a pass.
3. WHEN some current Sources are assessed and some are not, THE Deliverable_Renderer SHALL print a per-Source status table with the words "assessed" and "not assessed", SHALL build registers from assessed Sources only and SHALL show the coverage line in the Basis box.
4. WHEN an assessed Source has zero Encryption_Facts, THE Deliverable_Renderer SHALL state that no in-scope infrastructure or configuration files were found in it and that this is not evidence that no cloud resources or configurations exist.
5. IF a `cbom_posture` value is malformed (not an object, an unsupported `schema_version`, wrong list types), THEN THE Team_Rollup SHALL treat the Source as Not_Assessed, count a warning and raise no error; WHEN `schema_version` is greater than the renderer supports, THE Deliverable_Renderer SHALL print the note "scan produced by a newer engine".
6. WHEN the Posture_Block is truncated, THE Deliverable_Renderer SHALL print the number of facts dropped.
7. WHEN the Posture_Block carries Diagnostics, THE Deliverable_Renderer SHALL print the total by code and a list capped at 50 entries sorted by path and line.
8. WHEN a Source's newest attempt failed, THE Deliverable_Renderer SHALL print the existing failed-latest note.
9. THE Deliverable_Renderer SHALL list Not_Assessed Sources sorted by Source label.
10. THE Deliverable_Renderer SHALL never print an encryption verdict for a Not_Assessed Source.

### Requirement 39: Board report integration and regression policy for the existing documents

**User Story:** As a board reader, I want configuration findings to feed the posture grade without changing any figure that does not involve them, so that history stays comparable.

#### Acceptance Criteria

1. WHEN no current Source is assessed, THE Deliverable_Renderer for document #16 SHALL produce bytes identical to the Base_Commit renderer for the same view and the same injected time, except for the sentences that criterion 6 allows to differ.
2. WHEN at least one assessed Source has current Posture_Findings, THE Deliverable_Renderer for document #16 SHALL add them by impact to the grade input as a separate count, SHALL print a "Configuration posture findings" line with that count and the number of Not_Assessed Sources, and SHALL extend the printed grade-input text to name the added input, leaving the grade weights and bands unchanged.
3. THE MEDIUM_Documents SHALL ignore the Posture_Block.
4. THE Deliverable_Renderer for document #3 SHALL list every registered CBOM scanner including the new ones in registry order, and the scanner contract test SHALL be regenerated from the registry fixture.
5. THE Deliverable_Renderer for document #3 SHALL add a subsection that names the posture lanes, the Defaults_Registry data files and the limits of the Limits Table.
6. WHERE the shared method-scope sentence of the six MEDIUM_Documents is amended (Open item OI-4), THE Repository SHALL change that sentence and, because it states the same limit, the fourth bullet of the method limits that documents #3 and #16 print, SHALL change no other MEDIUM text, and SHALL list both changes among the allowed differences.
7. FOR the seeds of the Base_Commit E2E world, THE MEDIUM_Documents SHALL differ from their Base_Commit text extraction only in: the scanner table and the registered-scanner count of #3, the posture subsection of #3, and the amended sentences when criterion 6 applies; the 645 Base_Commit oracle assertions SHALL pass except those that assert these items, whose expected values SHALL be updated by an explicit commit that names this requirement.
8. THE crypto assets that the new lanes emit (KMS key material, protocols, algorithms, certificates) SHALL count as crypto assets in the MEDIUM_Documents for scans that contain them.

### Requirement 40: Deliverables menu in the frontend

**User Story:** As a user, I want the new documents in the menu I already use, so that I do not learn a new screen.

#### Acceptance Criteria

1. THE Deliverables_Menu SHALL list nine items in registry order, each with `data-testid="cbom-deliverable-<slug>"` and the registry title as its label.
2. WHEN the manifest marks an item unavailable, THE Deliverables_Menu SHALL disable it and show the manifest reason as its tooltip, and WHILE the manifest loads or fails to load THE Deliverables_Menu SHALL keep every item enabled.
3. WHEN a user selects an item, THE Deliverables_Menu SHALL download the PDF with the file name `cbom-<slug>-team<id>-<YYYYMMDD>.pdf` and show the existing success toast, and SHALL show the existing error toast on failure.
4. THE change SHALL be limited to `frontend/utils/backend_api.ts` and `frontend/app/[team_id]/cbom/page.tsx`, and SHALL add no page and no route.
5. THE Deliverables_Menu SHALL request no CDN, font, analytics or other external resource.
6. WHEN `npx tsc --noEmit` runs, it SHALL exit 0, and WHEN eslint runs on the two changed files, THE Repository SHALL show no error that is absent from the Base_Commit baseline when compared by rule and source-line text.

### Requirement 41: Air-gap behaviour at scan time and render time

**User Story:** As an operator in an air-gapped environment, I want the posture lanes and the new documents to need nothing outside the product, so that they run unchanged without a network.

#### Acceptance Criteria

1. WHILE a CBOM_Scan runs and WHILE a Posture_Deliverable renders, THE CBOM_Engine, THE Team_Rollup and THE Deliverable_Renderer SHALL perform no DNS lookup, open no socket, issue no HTTP request, start no subprocess, call no cloud API, perform no OCSP, CRL or certificate-transparency lookup, make no update check, send no telemetry and call no language model.
2. THE CBOM_Engine SHALL take all reference knowledge (provider defaults, TLS policies, cipher and curve registries, OID tables, pattern lists) from the Defaults_Registry packaged in the product.
3. WHEN the CBOM_Engine and the Deliverables_Router run on a host whose only network interface is loopback, THEY SHALL produce the same scan output and the same PDF bytes as on a networked host for the same Scanned_Input and the same injected time.
4. THE posture lanes SHALL not call the optional enrichment provider interface, and no configuration switch SHALL enable a language-model call in them.
5. THE git-clone input path SHALL stay unchanged and outside this guarantee, and the supported air-gapped input SHALL be a zip upload.

### Requirement 42: Automated static and runtime enforcement

**User Story:** As a security reviewer, I want the air-gap promise enforced by tests that run on every change, so that a regression cannot slip in unnoticed.

#### Acceptance Criteria

1. THE Airgap_Guard SHALL parse with `ast` every Python module that this feature adds under `aibom/src/aibom/cbom/` and every backend module of Requirement 32, discovering new files by glob, and SHALL fail on any import (function-level, `TYPE_CHECKING`, relative and `from ... import` forms included) rooted in `boto3`, `botocore`, `openai`, `anthropic`, `instructor`, `litellm`, `langchain`, `requests`, `httpx`, `urllib3`, `aiohttp`, `socket`, `ssl`, `smtplib`, `ftplib`, `telnetlib`, `imaplib`, `poplib`, `subprocess`, `ctypes`, `xmlrpc`, `http.client`, `http.server`, `urllib.request`, `backend.utilities.ai` or `backend.routers`, and in `importlib` other than `importlib.resources`.
2. THE Airgap_Guard SHALL fail on a call to `eval`, `exec`, `compile`, `__import__`, `os.system`, `os.popen`, `os.exec*`, `os.spawn*` or `os.fork`, and on the tokens `get_llm`, `chatbedrock`, `bedrock`, `anthropic` and `openai` in source text.
3. THE Airgap_Guard SHALL permit, in the new `aibom` modules, only the standard library, `pydantic`, `yaml` and `aibom` imports, and, in the new backend modules, the existing T-NOLLM allow-list.
4. THE Airgap_Guard SHALL import the new `aibom` modules and the new backend modules in fresh interpreters and SHALL fail WHEN `sys.modules` then holds `boto3`, `botocore`, `langchain`, `openai`, `anthropic`, `instructor`, `litellm`, `requests`, `httpx`, `urllib3`, `aiohttp`, `msal`, `celery`, `kombu` or `pymongo`.
5. THE Airgap_Guard SHALL run `scan_crypto`, `normalize_crypto`, CycloneDX emission and the three PDF builders on every new fixture, including the hostile fixtures and fixtures that contain URLs, host names, IP addresses and `file://` strings in every parsed format, with `socket.socket.connect`, `connect_ex`, `socket.create_connection`, `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`, `subprocess.Popen` and `os.system` replaced by functions that raise and with tripwire modules planted for the forbidden SDKs, and SHALL assert that no replaced function was called.
6. THE Airgap_Guard SHALL include a control test for each guard that proves it fires on a deliberate violation.
7. THE Airgap_Guard SHALL run every new route test under the runtime guard through an autouse fixture.
8. THE Repository SHALL show an empty `git diff --name-only` against the Base_Commit for `backend/pyproject.toml`, `backend/uv.lock`, `frontend/package.json`, `frontend/package-lock.json`, `aibom/pyproject.toml`, `aibom/uv.lock`, `RabbitMQ/worker/pyproject.toml`, `RabbitMQ/worker/uv.lock`, `pyproject.toml` and `uv.lock`, judged against the Base_Commit and not against the working tree; `e2e/package.json` and its lockfile are test tooling and are exempt.

### Requirement 43: Isolated-network Docker proof and browser egress

**User Story:** As a release manager, I want recorded proof that the stack works with no route to the internet, so that the air-gap claim is evidence and not intent.

#### Acceptance Criteria

1. THE E2E_Harness SHALL start the backend, the database containers and the scan container of the HIGH run on a network that has no route to the internet.
2. THE E2E_Harness SHALL attempt, from inside the backend container and from inside the scan container, a TCP connection to a public IPv4 literal, a TCP connection to a public IPv6 literal and a DNS lookup of a public name, SHALL record each result in the evidence logs, and SHALL fail the run WHEN any attempt succeeds.
3. THE E2E_Harness SHALL decode `/proc/net/tcp` and `/proc/net/tcp6` of the backend container and SHALL fail the run WHEN an outbound peer is not postgres, mongo or loopback.
4. THE E2E_Harness SHALL run the scans of the posture world with the real scan engine over a local directory or extracted zip in a container with `network_mode: none`, and SHALL state in the evidence that the git-clone path was not exercised.
5. THE Playwright specs SHALL record every browser request and SHALL assert that all go to the frontend and backend loopback origins, with zero requests to another origin and zero requests for fonts or scripts from a CDN.
6. THE E2E_Harness SHALL keep the Docker safety rules of the MEDIUM harness: label guard `com.dss-e2e=1`, no prune, `safe_rm_rf`, no push of images.
7. THE E2E_Harness SHALL write the isolation proof to `logs/NN-airgap-*.txt` files in the Evidence_Directory of Requirement 50.

### Requirement 44: Test-first unit and property tests

**User Story:** As a maintainer, I want the logic proven by tests written before the code and by property tests over generated inputs, so that edge cases beyond my examples are covered.

#### Acceptance Criteria

1. WHEN a work package is completed, THE Repository SHALL hold in its work-package report the failing run of the package's new tests recorded before implementation and the passing run recorded after.
2. THE Test_Suite SHALL include property tests that use the standard-library `random` module with recorded seeds and at least 1,000 generated cases each, with no new dependency, for these properties: every parser returns a result or a Diagnostic and never raises on mutated fixture content; scan output is identical under permutation of file order; replacing a decisive attribute with an enabling value never turns an encrypted Verdict into another Verdict; an unresolved decisive attribute yields UNKNOWN and never NOT_ENCRYPTED; encoding and decoding an Encryption_Fact is the identity; scanning twice is the identity; the cipher-string evaluator agrees with a naive reference on a random corpus.
3. THE Test_Suite SHALL include completeness tests that fail WHEN a Coverage_Table row, a Defaults_Registry row, an `unknown_reason` or a Finding_Catalog code lacks at least one positive and one negative fixture case.
4. THE Test_Suite SHALL include at least 10 hand-seeded mutants of the Verdict_Engine and the resolvers (for example flipping a default effect, treating UNKNOWN as pass, ignoring `variable_overridden`), each of which SHALL make at least one test fail, and the work-package report SHALL list them.
5. THE Test_Suite SHALL include the hostile-input corpus tests of Requirement 4 and the secret-canary test of Requirement 5 criterion 6.
6. THE Test_Suite SHALL run the backend tests on the backend virtual environment's Python 3.10 and the `aibom` tests on the `aibom` virtual environment.

### Requirement 45: Fixtures with an independent hand-derived oracle

**User Story:** As a reviewer, I want expected results that were derived by reading the fixtures and not by running the product, so that a bug cannot hide behind a test that computes its own answer.

#### Acceptance Criteria

1. THE Repository SHALL add the fixture trees of Table R45-A under `aibom/tests/fixtures/`, each with an `expected_*.json` Oracle and a `SOURCE.md` that explains how each expected value was derived by reading the files.
2. THE Oracle SHALL hold, per resource, the path, line, address, kind, Verdict per Layer, key management, finding codes and `unknown_reason`, and per tree the totals, and no Oracle value SHALL be computed by product code.
3. THE Test_Suite SHALL include a manifest-consistency test, a peer of `test_crypto_fixture_manifest.py`, that checks the totals equal the sum of the per-resource entries before it compares the scanner output with the Oracle.
4. THE fixture trees SHALL contain negative controls: encrypted resources that must raise nothing and cases that must stay UNKNOWN.
5. THE Test_Suite SHALL commit the small hostile files and SHALL generate the large files, symbolic links and FIFOs in a temporary directory at test time.
6. THE fixture authors MAY use `openssl` at authoring time to craft certificates and Diffie-Hellman parameter files, and no external tool SHALL run in any gate.
7. THE result-file samples SHALL be authored by hand from the public documentation of each tool's output and SHALL use only the reserved names and address ranges of Requirement 24 criterion 9.
8. THE Repository SHALL leave every `synthetic-crypto-*` fixture and `expected_crypto.json` unmodified, as shown by an empty `git diff` against the Base_Commit.
9. THE fixture trees SHALL stay excluded from ruff and from pytest collection, as the existing fixtures are.

**Fixture trees (R45-A).**

| Tree | Purpose |
|---|---|
| `synthetic-config-aws-tf` | A positive and a negative resource for every AWS type of Table R10-A; variables with defaults, `.tfvars` overrides, `count = 0`, `dynamic` blocks, a module call; inline and companion-resource forms; KMS keys with and without rotation and with a wildcard principal |
| `synthetic-config-azure-tf`, `synthetic-config-gcp-tf` | The same for Azure and GCP |
| `synthetic-config-cfn` | CloudFormation YAML with short-form tags, CloudFormation JSON, parameters, conditions, and the Terraform and CloudFormation parity pairs of Requirement 10 |
| `synthetic-config-k8s` | `EncryptionConfiguration` with `identity` first, `aescbc`, `secretbox`, `kms` and a literal key; `StorageClass`, claims and `StatefulSet`; `Ingress` with and without TLS; cert-manager; Istio; Traefik |
| `synthetic-config-compose` | Database services with bind-mounted configuration, plaintext ports and named volumes |
| `synthetic-config-servers` | nginx with includes, Apache httpd, HAProxy, Envoy, Traefik, Tomcat, Spring Boot, Jetty and `sshd_config` with `+` and `-` lists and exclusions |
| `synthetic-config-databases` | PostgreSQL, `pg_hba.conf`, MySQL, MariaDB, MongoDB, Elasticsearch, Redis, `crypttab`, `cryptsetup` scripts and SQL DDL |
| `synthetic-config-code-tls` | Disabled-verification patterns in each language, comments that must not match, environment and command patterns, a `ssl_dhparam` file |
| `synthetic-config-tls-results` | testssl.sh flat and pretty, sslyze and nmap files, each with a clean and a weak endpoint, an unsupported version and a not-tested item |
| `synthetic-config-mapping` | A Business_Mapping_File, a CODEOWNERS file and resources with matching and non-matching selectors |
| `synthetic-config-clean` | An all-compliant negative control with zero findings |
| `synthetic-config-canary` | Secrets and canary strings in every parsed format |
| `synthetic-config-hostile` | Malformed, deeply nested, alias-bomb, binary, mixed-encoding, duplicate-key, unsafe-tag, entity-bearing and long-line files |

### Requirement 46: Regression of frozen goldens, gates and existing suites, and the CI workflow

**User Story:** As a maintainer, I want proof that nothing that worked before changed, so that the new lanes cannot silently alter existing results.

#### Acceptance Criteria

1. THE Repository SHALL commit, before any product change, a snapshot of SHA-256 digests of the Base_Commit outputs of `scan_crypto`, `normalize_crypto` and the CycloneDX emitter on every `synthetic-crypto-*` tree, and WHEN any digest differs after the change, THE Test_Suite SHALL fail, with the added `cbom_posture` key excluded from the run-object digest.
2. THE pre-feature `aibom` pytest suite SHALL pass unmodified, with pass and skip counts equal to the counts recorded at the Base_Commit.
3. THE benchmark gates of `bench/cbom` and `aibom/tests/test_cbom_benchmark_gate.py` SHALL pass with a true-miss count of 0 and an our-unique count greater than 0 for every repository.
4. THE backend suites of the MEDIUM branch (1,113 passed and 1 expected failure at the Base_Commit) and its regression suites (77 passed) SHALL pass, except for the tests that Requirements 32, 39 and 40 change, which the work-package report SHALL list.
5. WHEN `ruff check src/aibom/cbom` and `mypy` run on `aibom`, they SHALL report no finding, and WHEN ruff runs with line length 100 and target `py310` on the new backend files, it SHALL report no finding.
6. THE CI workflow `.github/workflows/cbom-posture-gates.yml` SHALL run hermetic gates, without Docker or network, on pull requests and pushes that touch `aibom/src/aibom/cbom/**`, the Weights_File, the new data files, the new fixtures and tests, the backend deliverable modules and tests, and the two frontend files, in three jobs: `aibom` (detection, scoring, emission, Frozen_Goldens, benchmark), `backend` (new suites and regression suites on Python 3.10) and `frontend` (`tsc --noEmit` and the slug contract).
7. THE existing workflows `cbom-gates.yml` and `cbom-deliverables.yml` SHALL keep running unchanged.

### Requirement 47: Per-deliverable Docker and Playwright end-to-end proof

**User Story:** As a release manager, I want each new document proven end to end in a real browser against the real stack, with video and logs, so that the evidence is independent of the unit tests.

#### Acceptance Criteria

1. THE E2E_Harness SHALL extend the MEDIUM harness under `e2e/` and not fork it, SHALL use a distinct Evidence_Directory, and SHALL leave the MEDIUM evidence directory untouched.
2. THE E2E_Harness SHALL seed the posture world into a new team, so that the Base_Commit seed numbers of team 1 stay valid, using the real scan engine over the posture fixture trees to produce each stored `scan_data`.
3. THE posture world SHALL contain: assessed Sources from the fixture trees; one Not_Assessed Source from a committed run-object without a Posture_Marker; one assessed Source with zero facts; one failed scan that carries a canary; in another team a posture canary resource with a unique name; and, for the performance team, posture blocks of 500 facts per scan.
4. FOR EACH of deliverables #5, #6 and #9, THE E2E_Harness SHALL provide its own Playwright spec, run alone and again inside the full suite, that produces: one `.webm` video of at least 10 seconds at 1440 by 900; at least 5 screenshots (menu open, download, each major section state); the downloaded PDF with its SHA-256; `pdfinfo`, `pdftotext` and `pdffonts` logs; an API log with status, the `X-Cbom-*` headers and milliseconds; one PNG per PDF page; and a pytest log.
5. THE specs SHALL assert against the PDF text, not the DOM: each seeded resource name with its Verdict label; counts per Verdict, per kind and per finding code; each `unknown_reason` label; blank Assessor_Cells; declared linkage values with the "declared" label; the Defaults_Registry as-of lines; the Document ID format; the equality of the fingerprint in the header and in the PDF; and the Basis coverage line.
6. THE E2E_Harness SHALL provide cross-cutting specs for: a team with only Not_Assessed Sources; mixed coverage; an empty team (200, banner, disabled data-dependent items); negative isolation (canaries from a failed scan, another team and another scan type absent from every PDF text); hostile strings rendered literally; style parity (fonts of the new PDFs a subset of those of the existing PDFs); performance (Requirement 49); air-gap (Requirement 43); a re-scan before and after in which a Not_Assessed Source becomes assessed and the Document ID suffix changes; and the Base_Commit six-document oracle on team 1 with the allowed differences of Requirement 39.
7. THE E2E_Harness SHALL pace PDF requests at least 1.5 seconds apart to respect the limiter, and SHALL run the full suite with one worker.
8. THE E2E_Harness SHALL write every artefact into the Evidence_Directory under the MEDIUM naming scheme with the numbers 05, 06 and 09.

### Requirement 48: Independent verifier

**User Story:** As a reviewer, I want a second, independent check of the evidence, so that a shared mistake in the product and its tests cannot pass unnoticed.

#### Acceptance Criteria

1. THE Independent_Verifier SHALL recompute the expected values of each Posture_Deliverable from the raw fixture trees and the downloaded PDFs with its own simple parsers, SHALL import no product code, and SHALL run at least 60 checks per deliverable.
2. THE Independent_Verifier SHALL include at least 10 negative controls (mutated PDF text, altered counts, a swapped team, a removed row) and SHALL fail on each of them.
3. THE Independent_Verifier SHALL check the absence of every canary in all PDFs of all teams, the absence of redaction canaries in `cbom_json`, the run-object and the Diagnostics, the style parity, and the egress and isolation proof.
4. THE Independent_Verifier SHALL check by content hash that the images under test were built from the final commit, with a negative control that reports a mismatch.
5. THE Independent_Verifier SHALL write `VERIFY.md` with the check counts per category, and any failed check SHALL block the Definition of Done.

### Requirement 49: Performance budgets

**User Story:** As an operator, I want large infrastructure trees and large teams to stay within known time and memory limits, so that scans and downloads do not stall the platform.

#### Acceptance Criteria

1. WHEN the new scanners scan the generated stress tree S1 (2,000 Terraform files holding 20,000 resources, about 40 MiB) on the reference VM (16 cores, 58 GB), THE CBOM_Engine SHALL finish within 120 seconds with a peak resident memory of at most 1 GiB.
2. WHEN the new scanners scan the generated stress tree S2 (1,000 Kubernetes YAML files holding 10,000 documents), THE CBOM_Engine SHALL finish within 60 seconds.
3. WHEN the new scanners run on the benchmark repositories of `bench/cbom/repos.tsv` that exist locally, THEY SHALL add at most 5 percent or 2 seconds, whichever is larger, to the scan time of the Base_Commit scanners.
4. WHEN the demo team of about 10 scans requests a Posture_Deliverable, THE Deliverables_Router SHALL answer within 3 seconds.
5. WHEN the performance team (200 scans, 40 sources, 500 Encryption_Facts per scan) requests a Posture_Deliverable, THE Deliverables_Router SHALL answer within 10 seconds with a peak resident memory growth of at most 512 MiB.
6. WHEN a register reaches the 2,000-row cap, THE Deliverables_Router SHALL answer within 15 seconds.
7. THE E2E_Harness SHALL record every measurement in `logs/92-perf-*.json` for the run alone and the full suite, and the Test_Suite SHALL fail WHEN a measurement exceeds its budget.

### Requirement 50: Evidence, commit binding, build report and teardown

**User Story:** As the owner of the release decision, I want one place that shows what was run, against which commit, with what result, so that I can decide with facts.

#### Acceptance Criteria

1. THE E2E_Harness SHALL write the Evidence_Directory `.agents/tasks/cbom-high-deliverables-evidence/` with the MEDIUM layout (`videos/`, `screenshots/`, `downloads/`, `pdf-pages/`, `logs/`, `reports/index.json`, `SUMMARY.md`, `FINAL-EVIDENCE.md`), and every file SHALL appear in the index with its SHA-256.
2. THE E2E_Harness SHALL produce all Docker and Playwright evidence at the final product-code commit, with the images rebuilt from it, and SHALL move any earlier evidence to a `_superseded-<sha>` folder with a README.
3. THE Repository SHALL contain a build report `.agents/tasks/cbom-high-deliverables-build-report.md` that lists the commits per work package, the test and gate results, the Definition of Done table of R50-A with evidence paths, the deviations and the known issues.
4. WHEN teardown runs, THE E2E_Harness SHALL leave no object that carries its labels, and the Docker containers, volumes and networks that do not carry them SHALL be identical before and after.
5. THE E2E_Harness SHALL run a text scan of the Evidence_Directory for secret values, with a self-test that finds every planted secret, and the result SHALL be zero hits; no `.env` file SHALL be present in any image or in the diff.
6. THE evidence SHALL contain only synthetic seed data and throw-away values of the local stack.

**Definition of Done (R50-A).**

| # | Item |
|---|---|
| 1 | All new pytest modules are green on Python 3.10 (backend) and on the `aibom` environment; existing suites are green (Requirement 46) |
| 2 | ruff, mypy, `tsc --noEmit` and eslint gates pass as defined in Requirements 40 and 46 |
| 3 | Scope gates pass: only allowed paths changed, no manifest or lockfile changed, no `.env` in the diff (Requirements 42 and 51) |
| 4 | The isolated stack is built from the worktree at the final commit, starts from clean volumes, and the seed reproduces the Oracle exactly |
| 5 | The per-deliverable evidence for #5, #6 and #9 is complete (Requirement 47 criterion 4) |
| 6 | Every PDF-text Oracle assertion passes |
| 7 | Not_Assessed, mixed, empty, hostile-string and canary behaviours are proven |
| 8 | The MEDIUM_Documents show only the allowed differences (Requirement 39) |
| 9 | The air-gap proof and the static and runtime guards pass (Requirements 42 and 43) |
| 10 | The Independent_Verifier passes and its negative controls fail as required |
| 11 | The performance budgets are met (Requirement 49) |
| 12 | Teardown leaves no residue |
| 13 | The ledger rows and `docs/cbom-posture/` are complete (Requirement 31) |
| 14 | Production verification, only after the Release_Gate (Requirement 52) |

### Requirement 51: Scope boundary gates

**User Story:** As a platform owner, I want the boundary of this change enforced mechanically, so that no other scan type, dependency, schema or screen changes with it.

#### Acceptance Criteria

1. WHEN `git diff --stat` runs between the Base_Commit and HEAD, THE Repository SHALL show no change under `RabbitMQ/worker/helpers/tools/iac_agent/`, `RabbitMQ/dast_worker/`, `RabbitMQ/worker/helpers/tools/sast_agent/`, `RabbitMQ/worker/helpers/tools/sca_sbom_agent/`, `aibom/src/aibom/scan/`, `RabbitMQ/worker/scan_worker.py`, `backend/utilities/scan/start_scan.py`, `backend/routers/scans.py`, `backend/utilities/db/` and `prod_database_migrations/`.
2. THE Repository SHALL limit changes to: `aibom/src/aibom/cbom/`, `aibom/src/aibom/integrations/cbom_devsecshield.py`, additive changes to `aibom/src/aibom/emit/cyclonedx.py` and `aibom/src/aibom/model/component.py`, `aibom/config/crypto-risk-weights.yaml`, the new Defaults_Registry data files, `aibom/tests/`, `docs/`, the backend files of Requirement 32 and 33 and their tests, `frontend/utils/backend_api.ts`, `frontend/app/[team_id]/cbom/page.tsx`, `e2e/`, `.github/workflows/cbom-posture-gates.yml`, `AGENTS.md` and `.agents/tasks/`.
3. THE Deliverables_Router SHALL add no route, since the three new slugs use the existing slug route.
4. THE Repository SHALL add no export format other than the three PDFs, no user-interface page, no database table or column, and no third-party dependency.
5. THE new backend modules SHALL compile and import on Python 3.10, and the new `aibom` modules SHALL compile and import on the `requires-python` minimum that `aibom/pyproject.toml` declares.

**Deferred scope (not built by this spec).** Live endpoint probing or any built-in TLS prober; quantum risk register Q0-Q4 grading (#13); crypto-agility taxonomy (#14); new regulatory frameworks such as RBI Q-SAFE, the RBI NBFC 2026 framework, DPDP and PCI DSS 12.3.3 (#17); Pulumi, Ansible and Helm template execution; Kafka and RabbitMQ server-configuration parsing; Terraform state files; module and remote resolution; any change to the IaC, DAST, SAST, SBOM, AI-BOM, MCP or LLM scans.

### Requirement 52: Branching and gated release

**User Story:** As the owner of the release decision, I want no production action without full local verification and my explicit approval, so that the platform is never changed on assumption.

#### Acceptance Criteria

1. THE Repository SHALL hold the work on the branch `feat/cbom-high-deliverables`, created from the Base_Commit in a separate git worktree, and SHALL commit nothing to `ansh` or `feat/cbom-team-deliverables`, push or merge neither, stage files by explicit name, use no `git stash`, and carry no `.env` file in the diff.
2. WHEN a commit changes product code after the evidence of a deliverable was collected, THE E2E_Harness SHALL re-run the affected specs and the full suite at the final commit before the build report is final.
3. THE Release_Gate SHALL block every production action until the build report shows every Definition-of-Done item PASS at the final commit and the explicit approval of the user is recorded in the Evidence_Directory.
4. THE tasks of this spec SHALL end with the evidence, the build report and a production runbook, and SHALL perform no production action.
5. THE runbook SHALL state that the posture lanes run in the scan-worker image, so that the rollout rebuilds and deploys the scan-worker image in addition to the backend and frontend images, and SHALL carry forward the safeguards of section 9 and addendum A-6 of the MEDIUM plan: rollback tags created from the digests that run, the baked-key suffix gate on both `.env` files, named-service `--no-deps --force-recreate`, and no `down -v`.
6. THE runbook SHALL list the post-deploy checks: a manifest with nine items; nine PDFs for a team with only stored scans returning 200, with the three new ones showing the "POSTURE NOT ASSESSED - RE-SCAN NEEDED" banner; and a fresh scan whose run-object carries the Posture_Marker.
7. THE build report SHALL list both the evidence commit and the final commit and, for each commit between them, whether it can change rendered output.

## Assumptions

- **A-1** Fixtures are synthetic and their Oracle is derived by hand. No external tool runs in any gate; `openssl` is used only at authoring time.
- **A-2** The backend stays on Python 3.10. New `aibom` code follows the `requires-python` minimum of `aibom/pyproject.toml` (3.11 at the time of writing, which provides `tomllib`) and adds no dependency beyond `pydantic`, `typer`, `jsonschema`, `referencing` and `pyyaml`.
- **A-3** The frozen CBOM goldens and the benchmark gates stay green, and no `synthetic-crypto-*` fixture and no `expected_crypto.json` is edited.
- **A-4** The MEDIUM branch stays at the Base_Commit while this work proceeds.
- **A-5** Version 1 formats are those of Requirement 10. Kafka and RabbitMQ server configuration, Terraform state files, Pulumi, Ansible and Helm execution are excluded.
- **A-6** The numeric limits and budgets (Requirements 4, 5, 30 and 49) are initial values. The design calibrates them against measured baselines, and any change needs a recorded rationale and an updated Test_Suite.
- **A-7** Terraform variables resolve from literals and `variable` defaults only. A variable assigned in a `.tfvars` file with a different value makes dependent attributes UNKNOWN, and `locals` are unresolved.
- **A-8** The Business_Mapping_File is optional and lives in the repository. No database table, API field or user-interface form is added.
- **A-9** Reference data (provider defaults, TLS policies, cipher and curve registries, pattern lists) is authored from public vendor and standards documents. An old `valid_as_of` date is reported but does not block a scan.
- **A-10** Posture findings appear in the Posture_Deliverables, the CycloneDX BOM and `cbom_scores`, and not in the legacy results table or the findings store.
- **A-11** The finding severity classes of Table R15-A are fixed by this spec, and their weights follow the existing bands: High 8, Medium 4, Low 1.
- **A-12** "LUKS notes" means `/etc/crypttab` entries and `cryptsetup` invocations found in text files of the Scanned_Input.
- **A-13** The existing git-clone input is unchanged. The air-gap proof uses a zip or a local directory.
- **A-14** The scan-worker was down in production at the read-only inspection of 2026-10-22. Restoring it is a precondition of any production rollout and is outside this spec.

## Open Items

- **OI-1** The exact content of the Provider_Defaults_Table and the TLS_Policy_Registry is authored during design from vendor documentation. Each row carries its URL and date.
- **OI-2** The Format Register (exact testssl.sh, sslyze and nmap versions and output shapes) is fixed during design from the public documentation of each tool.
- **OI-3** Namespace for non-crypto resource facts. The default is `crypto:`; a new namespace needs an AGENTS.md convention update in the same commit.
- **OI-4** Whether to amend the one shared method-scope sentence of the six MEDIUM_Documents, which today says the method does not include data-at-rest encryption. The recommended resolution is a one-sentence amendment, listed among the allowed differences of Requirement 39.
- **OI-5** How the isolated Docker network coexists with ports published on loopback, for example through a proxy container that is attached to both networks. Also whether the E2E stack adds RabbitMQ, the worker and local object storage to drive a real zip upload through the UI. The recommendation is to add them if the upload path runs without a cloud object store; otherwise the scan runs through the adapter inside the no-network container and the evidence states the gap.
- **OI-6** Whether to project posture findings into `results[]`, the findings store and Jira. The default here is no. Consequence: `cbom_scores.risk_normalized` includes posture flags that the legacy results table does not list.
- **OI-7** Score saturation. Because `scale.max_raw` is pinned, a scan with many posture findings reaches `risk_normalized` 100. A recalibration needs a re-baseline of stored scores and is a separate decision.
- **OI-8** Whether findings under `non_production_hint` paths should be demoted in severity. This spec labels them and keeps the severity.
- **OI-9** Honouring the precedence of auto-loaded `.tfvars` files and resolving `locals`, in a later version.
- **OI-10** Matching static server blocks to imported endpoints beyond the identical `host:port` string.
- **OI-11** The later quantum risk register (#13) will consume `key_management`, `data_classification` and `data_lifetime`. This spec grades nothing.
- **OI-12** The modules `crypto_jvm_go`, `crypto_native` and `crypto_web_native` exist in the CBOM package but are not imported by `scanners/__init__.py`, so they are not registered. They are out of scope here.
- **OI-13** The existing source-level `ProtocolScanner` records a disabling token such as `OP_NO_TLSv1` as TLS 1.0 use. It is unchanged here and is a candidate follow-up.
- **OI-14** Password-hash configuration (for example PostgreSQL `password_encryption`) and a rule that requires customer-managed keys for a declared classification are deferred.
- **OI-15** Non-Latin text prints as `?` in the PDFs because of the WinAnsi fonts; this is the existing limitation of the MEDIUM documents.

## Traceability of the settled decisions

| Settled decision | Requirements |
|---|---|
| 1 Scope boundary, CBOM lane only | 1, 51 |
| 2 Air-gap, no LLM, enforcement and proof | 41, 42, 43 |
| 3 Network and TLS without live probing | 20, 21, 22, 23, 24, 25 |
| 4 Formats, variables, parsers, no new library | 3, 7, 8, 10 |
| 5 Verdict policy and tri-state | 6, 9, 38 |
| 6 Scoring and Board grade | 15, 28, 29, 39 |
| 8 Business linkage | 19, 37 |
| 11 Outputs, PDFs, registry, menu, fidelity | 32 to 40 |
| 12 Branching and gated release | 52 |
| Verification, evidence, independent proof | 44 to 50 |
