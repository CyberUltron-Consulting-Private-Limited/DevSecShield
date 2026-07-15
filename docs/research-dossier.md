# AI Bill of Materials (AI BOM) for Clinical Imaging: Research Dossier + Claude Code Build Plan

*Pre-call briefing dossier and engineering build plan — prepared June 21, 2026*

## TL;DR
- **OpsMx does NOT sell a standalone "AI BOM" product.** Its AI BOM / MBOM / DBOM capability is a feature of **OpsMx Delivery Shield** (an ASPM/AI-security platform) built on open-source scanners (Syft, ModelScan), emits CycloneDX, and is governance/CI-CD-gate oriented — not healthcare-specific. The two GitHub tools (Cisco AI Defense `aibom`, Trusera `ai-bom`) are free, Apache-2.0 code-scanning AI BOM generators that already emit CycloneDX 1.6, SPDX 3.0, and SARIF — they are the better technical reference for what you'd build.
- **The standards are now real and convergent:** **CycloneDX 1.6/1.7 ML-BOM** (Ecma-424) and **SPDX 3.0 AI + Dataset Profiles** are the two schemas to target; the **G7/CISA "SBOM for AI – Minimum Elements"** (May 12, 2026), **FDA §524B SBOM mandate**, and **EU AI Act Annex IV** are the compliance drivers. For clinical imaging AI you are squarely in EU AI Act high-risk + FDA SaMD/PCCP + GMLP territory.
- **Recommended build:** a Python AI-BOM generator that ingests a model repo, emits schema-validated CycloneDX ML-BOM + SPDX 3.0 AI-profile JSON, plus an FDA/EU-AI-Act compliance-mapping layer — implemented in Claude Code using a **custom `aibom-generator` skill** plus the **pdf, docx, xlsx, pptx, mcp-builder, skill-creator, and frontend-design/web-artifacts-builder** skills for deliverables and dashboards.

## Key Findings

### 1. OpsMx — what's actually true vs. inferred
**Verified from OpsMx's own site/docs:**
- OpsMx's product is **Delivery Shield** (also branded "Deploy Shield"), an Application Security Posture Management (ASPM) platform now positioned as an AI security remediation platform. AI BOM is listed as a platform capability ("SBOM & AI BOMs"), not a separate SKU.
- The **AI Model Scanning** page is the most concrete AI BOM evidence: Delivery Shield "automatically detects every model, dataset, and prompt across source, registry, and runtime, building complete MBOM/PBOM/DBOM lineage," and integrates **ModelScan** to scan PyTorch, TensorFlow, ONNX, Sklearn, XGBoost; it performs "SBOM/MBOM generation," "full dependency and license inventory for every model," malware/poisoned-weight detection, and post-deployment drift detection.
- A ModelScan blog confirms Delivery Shield "generates an AI/ML Bill of Materials (AI/MLBOM) using the **CycloneDX specification**."
- SBOM generation is powered by **Syft**, output in **JSON at artifact level**, covering CVE footprint, operational risk, and license info; compliance results publish into a **Delivery Bill of Materials (DBOM)** report.
- Compliance framing: blogs map Delivery Shield to **NIST AI RMF** (Govern/Map/Measure/Manage), NIST 800-53, FedRAMP, and a banking "unified BOM" (SBOM+CBOM+AIBOM) story for the RBI. Policy-as-code via **Open Policy Agent (OPA)/Rego**; a "deployment firewall" blocks non-compliant releases.
- Deployment models: SaaS, managed service, or on-premises; plus a zero-setup **Delivery Shield On-Demand** SaaS launched July 15, 2025 (Google SSO). Pricing is **custom-quote only** (private offers via AWS Marketplace; tiered Argo/Spinnaker plans on the pricing page). The company is ~120 employees, funded by Dell Technologies Capital and Foundation Capital; customers include Google and Cisco.

**Not publicly available (ask OpsMx directly):**
- Exact AI BOM field schema / a downloadable sample AI BOM output file. No public sample AIBOM JSON, no published field dictionary, no CycloneDX version pinned in docs.
- Any **healthcare/clinical/medical-device-specific** content — none found. OpsMx's regulatory content is finance (RBI), NIST, FedRAMP. There is **no FDA §524B, EU AI Act, HIPAA, or PACS** material from OpsMx.
- Whether the AI BOM emits SPDX (only CycloneDX is mentioned).
- Pricing for the AI/AISPM tier specifically.

**Questions to put to OpsMx on the call:** (1) Can you share a sample AI BOM output file and its field schema? (2) Which CycloneDX spec version, and do you emit SPDX 3.0 AI profile? (3) Any FDA §524B / EU AI Act Annex IV report templates? (4) How do you capture model card / training-data provenance / intended-use fields needed for SaMD? (5) On-prem deployment for a HIPAA environment + BAA? (6) AI/AISPM tier pricing and per-model vs. per-pipeline metering?

### 2. The two GitHub projects (head-to-head)
**Cisco AI Defense `aibom`** (github.com/cisco-ai-defense/aibom): Apache-2.0, Python 3.11+, 79 stars, latest 1.0.0rc4 (May 5, 2026), PyPI `cisco-aibom`. "AI Bill of Materials through source code scanning." Scans codebases, container images, and cloud environments to inventory models, agents, tools, MCP servers/clients, datasets, prompts, guardrails, secrets. Supports Python (LibCST, deepest), JS/TS, Java, Go, Rust, Ruby, C# (tree-sitter). 23 built-in scanners, **30 AI component types**, three-tier detection (deterministic → cross-reference → **agentic LLM classification, which is mandatory** — `analyze` requires `--llm-model`). **10 output formats: Plaintext, JSON, CycloneDX (1.6 ML-BOM profile), SARIF v2.1.0, SPDX (3.0 with AI + Dataset profiles), HTML, Markdown, CSV, JUnit, live API.** Has a policy engine (YAML gates), compliance checks (**EU AI Act, OWASP Agentic Top 10, NIST AI RMF advisory mappings**), OSV.dev CVE scanning, Yelp detect-secrets, watch mode, diff, benchmark (precision/recall/F1), DuckDB knowledge base.

**Trusera `ai-bom`** (github.com/Trusera/ai-bom): Apache-2.0, Python 3.10+ (65.9%) + TypeScript + Go, 224 stars, v3.1.0 (Feb 12, 2026), PyPI `ai-bom`. "Discover every AI agent, model, and API." 13 auto-registering scanners, **9 output formats** incl. CycloneDX 1.6, SARIF 2.1.0, **SPDX 3.0**, HTML dashboard, Markdown, CSV, JUnit. Regex-based (speed/cross-language), Pydantic models, **0–100 risk scoring + severity**, compliance modules (EU AI Act, OWASP, licenses). **5 scan levels** (filesystem → Docker → network/env → cloud IaC → live cloud). Differentiators: **runtime interceptor SDKs** (Python/TS/Go) with **Cedar policy enforcement** + JSONL logging (works standalone, no account); n8n community node; VS Code extension; "callable models" for red-teaming (Giskard); built-in JSON Schema validation (`--validate`); GitHub Action on Marketplace. Cites **EU AI Act Article 53 (Aug 2025)** and "60%+ of AI usage is undocumented" as the shadow-AI driver. Open-source foundation of the commercial Trusera platform.

**Head-to-head verdict:** Both Apache-2.0, Python-centric, and both emit CycloneDX 1.6 + SPDX 3.0 + SARIF — so both are strong reference implementations for your build. **Cisco** is deeper on detection (more languages with real parsing, 30 component types, MCP/agent resolution, mandatory agentic LLM enrichment = higher fidelity but requires an LLM key and incurs cost). **Trusera** is broader on the operational surface (runtime interception, Cedar policies, risk scoring, dashboard, IDE, schema validation built in) and lighter weight (regex, no mandatory LLM). For a healthcare GRC engagement, Trusera's risk-scoring + runtime governance maps better to "shadow AI discovery + deployment governance," while Cisco's component taxonomy is the better template for a rich AI BOM schema. Neither is healthcare-specific; neither produces FDA/EU-AI-Act readiness reports — that's your differentiation.

### 3. Standards landscape
**CycloneDX ML-BOM (AI/ML-BOM):** OWASP CycloneDX, now **Ecma International standard ECMA-424**; current JSON schema 1.6 (1.7 in draft with worked AI examples). A model is a `component` of `type: machine-learning-model` carrying a **`modelCard`** object: `modelParameters` (approach/`type` e.g. supervised; `task` e.g. classification/regression; `architectureFamily` e.g. transformer/CNN/RNN/LSTM; `modelArchitecture` e.g. ResNet-50, GPT-1; `datasets`; inputs/outputs), **`quantitativeAnalysis`** (performance metrics), and **`considerations`** (users, use cases, technical/performance limitations, ethical considerations, fairness assessments, environmental). Supports `pedigree` (ancestors/lineage), `externalReferences` (model-card, formulation/MBOM), licenses, hashes, and `data` components. Conventional file name `*.cdx.json`. An MLBOM 2.0 work group is moving `modelParameters` fields up to the top-level `modelCard`.

**SPDX 3.0 (released April 17, 2024; ISO/IEC 5962 lineage):** modular **Profiles**. The **AI Profile** (`AI/AIPackage`) discloses model architecture, size, required compute/energy (`energyConsumption`), limitations, data preprocessing, explainability, security considerations (uses EU general + EU AI Act risk methodology), `useSensitivePersonalInformation`, and `informationAboutApplication`; every AIPackage must have exactly one concluded-license relationship. The **Dataset Profile** (`DatasetPackage`) carries `datasetType` (mandatory), `datasetSize`, `datasetAvailability`, `dataCollectionProcess`, `dataPreprocessing`, `datasetNoise`, `anonymizationMethodUsed`, `confidentialityLevel`, sensitivity indicator, known biases, and `intendedUse`. SPDX can carry multiple profiles in one document. The Linux Foundation published a dedicated **"Implementing AI Bill of Materials (AI BOM) with SPDX 3.0"** report (Oct 2024) comparing the profiles to Datasheets, Model Cards, and FactSheets — and including a medical-device section.

**G7/CISA "SBOM for AI – Minimum Elements"** (published May 12, 2026; CISA + BSI/Germany, ACN/Italy [co-lead], ANSSI/France, CSE/Canada, NCSC/UK, NCO/Japan, EU Commission): voluntary, supplemental to general SBOM minimum elements. **Seven clusters** — Metadata, System Level Properties (SLP), Models, Dataset Properties (DP), Key Performance Indicators (KPI), Security Properties (SP), Infrastructure. Element-level (per BSI PDF and corroborating coverage):
- *Metadata* — SBOM author, SBOM version, data format name+version, author signature, tool name+version, generation context, timestamp, dependency relationships.
- *SLP* — system name, components, producer, version, timestamp, data flow, data usage, input/output properties, intended application area.
- *Models* — model name, identifier, version, timestamp, producer, description, hash value, hash algorithm, properties, input/output properties, training properties, license, external references.
- *DP* — dataset name, description, content, identifier, hash, provenance, statistical properties, sensitivity, dependency relationships, license.
- *Infrastructure* — infrastructure software, infrastructure hardware (+ optional HBOM link).
- *SP* — security controls, security compliance, cybersecurity policy info, vulnerability referencing.
- *KPI* — security metrics, operational performance KPIs.

(A "level of decision-making/autonomy" element for agentic AI was discussed but deliberately excluded.) Morgan Lewis notes overlap with EU AI Act Articles 11/13 and Annex IV — so an AI SBOM helps satisfy those obligations.

**Other frameworks:** NIST AI RMF (Jan 2023; Govern/Map/Measure/Manage); ISO/IEC 42001:2023 (first certifiable AI management system standard, Dec 2023; healthcare imaging adopters exist); OWASP GenAI Security Project AIBOM Initiative + OWASP AIBOM Generator (Hugging Face → CycloneDX); MITRE ATLAS (adversarial ML).

**How AI BOM differs from SBOM:** an SBOM lists code/library components; an AI BOM adds **model weights + architecture, training/validation/test datasets + provenance + bias, prompts, fine-tuning, model cards, energy, intended use, and performance/fairness metrics** — components that change via retraining/prompts/data, not just code commits. Model cards (Google/Hugging Face) and Datasheets for Datasets fold directly into CycloneDX `modelCard`/`considerations` and the SPDX AI/Dataset profiles.

### 4. The six healthcare/compliance use cases
1. **AI traceability for clinical imaging models (radiology, PACS):** Radiology dominates FDA AI/ML authorizations — **76% of all cumulative FDA AI-enabled medical device authorizations (1,104 of 1,451 devices through end-2025) and 75% of new 2025 clearances** (The Imaging Wire, March 11, 2026). Imaging AI runs against PACS/RIS/EHR via DICOM/DICOMweb and HL7 ORU, often through an **AI orchestrator** ("traffic cop") that selects models, collects, and logs results. An AI BOM provides the model lineage (which model version, trained on which DICOM dataset, which thresholds) needed to trace a given inference back to its source — directly supporting GMLP traceability and the "day-0 validation + continuous drift monitoring" lifecycle. PACS provides the longitudinal data to monitor drift/bias.
2. **FDA / EU AI Act readiness:** FDA — imaging AI is **SaMD**; the final guidance **"Marketing Submission Recommendations for a Predetermined Change Control Plan for Artificial Intelligence-Enabled Device Software Functions," posted Dec 3, 2024** (whose appendix scenarios include feeding-tube-placement radiographic analysis software and skin-lesion image analysis), lets manufacturers pre-authorize model modifications (must stay within intended use; be focused/risk-based/evidence-based/transparent/lifecycle-oriented per the Aug 2025 FDA/Health Canada/MHRA principles). PCCP adoption is still nascent: **only 15 of 1,016 FDA-authorized AI/ML devices (1.5%) reported a PCCP** (npj Digital Medicine, 2025; 73.3% of those came after the April 2023 draft guidance), rising to roughly 10% of AI/ML clearances in 2025 (Innolitics). EU — AI-enabled medical devices are **automatically high-risk** under Article 6(1)/Annex I (MDR/IVDR). The original Aug 2, 2026 deadline for Annex I embedded high-risk was **delayed to Aug 2, 2028** by the Digital Omnibus (Council agreement; Article 6(1) for CE-marked devices was already Aug 2027); **Article 4 AI-literacy and Article 5 prohibitions apply now**. Annex IV technical documentation can be integrated into the MDR/IVDR technical file; one notified body, one CE mark, two declarations of conformity. An AI BOM is the machine-readable backbone of the Annex IV data-governance/traceability content.
3. **Shadow AI discovery:** "60%+ of AI usage is undocumented." Discovery = scanning code/dependency manifests (pip/npm/Maven/Go/Cargo/Gemfile/csproj), env vars and `.env`, API call patterns (api.openai.com, api.anthropic.com, localhost:11434), Docker/K8s for AI containers (Ollama, vLLM, Triton, ChromaDB), notebooks, MCP server configs, cloud AI services (Bedrock/SageMaker/Vertex/Azure OpenAI), and model files (.gguf/.safetensors/.onnx/.pt). Both GitHub tools do this; runtime interception (Trusera SDKs) catches models that never enter the repo.
4. **Medical device software supply chain security:** **FD&C Act §524B** (added by the Dec 2022 Omnibus §3305) requires, for "cyber devices," an **SBOM** (commercial, open-source, off-the-shelf components) in premarket submissions (510(k), PMA, PDP, De Novo, HDE); effective for submissions after March 29, 2023; FDA may **Refuse to Accept** non-compliant submissions. The current final guidance ("Cybersecurity in Medical Devices: Quality System Considerations and Content of Premarket Submissions," June 27, 2025) references the **NTIA Minimum Elements**; FDA has begun requesting **VEX** files. AI BOM extends the §524B SBOM with the model/dataset layer. IMDRF finalized its 10 GMLP guiding principles in Jan 2025.
5. **AI deployment governance across hospitals:** multi-site means model/version sprawl, with scanner/protocol/demographic differences causing drift; this needs central orchestration (e.g., vendor AI managers like Philips AI Manager), drift/bias surveillance, change control, audit trails, and per-site validation. ISO/IEC 42001 (AIMS) + NIST AI RMF are the governance frameworks; an AI BOM is the inventory backbone connecting models→data→identities→owners that Wiz/Palo Alto describe.
6. **Secure GenAI for clinical documentation (ambient scribes):** Adoption is surging — physician use of AI overall doubled from 38% in 2023 to 66% in 2024 (AMA 2025 Augmented Intelligence Research report); at The Permanente Medical Group, 66% of adult/family-medicine physicians used the ambient AI scribe 5+ days/week and 63% at every in-person visit across 2.5M+ encounters (NEJM Catalyst, Tierney et al., March 31, 2025). Clinical evidence is maturing: a UCLA randomized trial of 238 physicians across 14 specialties (NEJM AI, Nov 2025) found Nabla cut average note time ~10% vs. control, and a Mass General Brigham/Emory pilot (Rotenstein et al., JAMA Network Open, Aug 2025, n=1,430) cut burnout from 52.6% to 30.7% over 84 days. Scribes process **ePHI** (audio + transcript), making the vendor a **HIPAA Business Associate requiring a signed BAA**; generic consumer LLMs (no BAA, train on data) are a HIPAA violation. Risks: PHI leakage, audio retention, secondary/training data use, hallucinations/malpractice, consent/wiretap exposure (active litigation), and NPP updates. An AI BOM documents which LLM/scribe, data flows, retention, and guardrails — feeding the §524B/HIPAA security risk analysis.

### 5. Field/metadata comparison
| Field / concept | OpsMx Delivery Shield | CycloneDX 1.6 ML-BOM | SPDX 3.0 AI+Dataset | Cisco `aibom` | Trusera `ai-bom` | G7/CISA Min. Elements |
|---|---|---|---|---|---|---|
| Model identity/version | Yes (MBOM) | `component` ml-model, name/version | AIPackage name/version | Yes (30 types) | Yes | Models: name/id/version |
| Model architecture | Partial | `modelArchitecture`/`architectureFamily` | architecture/size | via LLM enrich | Model refs | Models: properties |
| Training/eval datasets | Yes | `modelParameters.datasets` + data comp | Dataset Profile | dataset type | dataset scanner | Dataset Properties |
| Data provenance/bias | Partial (lineage) | `considerations`/pedigree | dataCollection, biases, sensitivity | partial | partial | DP: provenance, sensitivity |
| Performance/fairness | Risk score | `quantitativeAnalysis`,`considerations` | metrics, explainability | advisory | risk 0–100 | KPI cluster |
| Licenses | Yes (Syft) | license fields | concluded license (mandatory) | Yes | Yes | Models/DP: license |
| Vulnerabilities/CVE | Yes (Trivy/NVD/KEV) | VDR/VEX | Security Profile | OSV.dev | (via Trivy combo) | SP: vuln referencing |
| Secrets/keys | Yes | n/a | n/a | detect-secrets | Yes | SP |
| Prompts/agents/MCP | Yes (PBOM) | partial | n/a | Yes (rich) | Yes | SLP |
| Energy/compute | No | partial | `energyConsumption` | No | No | Infrastructure |
| FDA/EU-AI-Act report | No (NIST/RBI only) | No | EU risk methodology fields | EU AI Act adv. | EU AI Act module | EU AI Act overlap |
| Output formats | CycloneDX/JSON (DBOM) | CycloneDX | SPDX | 10 formats | 9 formats | format-agnostic |

## Details — Claude Code Implementation Plan

### Architecture
A Python tool, **`clinithread-aibom`** (working name), with four layers:
1. **Ingest/Scan** — point at a model repo / ML project / registry / container. Reuse patterns from Cisco/Trusera: dependency-manifest parsers, code scanners (AST for Python via LibCST; regex/tree-sitter for others), model-file detectors (.safetensors/.onnx/.pt/.gguf), env/secret scanners, Docker/cloud detectors, model-card/`README`/`config.json` and dataset-card parsers, and a DICOM/PACS metadata reader for imaging context.
2. **Normalize** — a single internal `AIComponent` model (Pydantic) covering model, dataset, framework, prompt, service, infra, and secret, plus clinical-imaging extensions (intended use, body part/modality, PACS AE title, training cohort demographics, FDA product code, device class).
3. **Emit** — serializers to **CycloneDX 1.6 ML-BOM JSON** and **SPDX 3.0 AI+Dataset JSON**, each schema-validated; plus SARIF for CI and an HTML dashboard.
4. **Compliance-map** — a rules engine mapping AI-BOM fields → **FDA SaMD/§524B/PCCP** checklist and **EU AI Act Annex IV** sections + **GMLP** + **HIPAA** (for GenAI scribe) + NIST AI RMF / ISO 42001 controls; outputs readiness reports (gaps + evidence).

Plus a **Shadow-AI discovery module** (org/repo/container/cloud sweep producing an inventory + unsanctioned-model flags against an allowlist) and an optional **MCP server** so the tool is callable from Claude/agents.

### Which Claude Code skills to use, and why
- **skill-creator** — first, build a custom **`aibom-generator`** skill (SKILL.md + bundled Python scripts + the CycloneDX/SPDX JSON schemas + a clinical-imaging field map + compliance-mapping tables). This is the reusable engine; progressive disclosure keeps it cheap (~100 tokens until invoked). It encodes the workflow ("scan repo → normalize → emit validated CycloneDX+SPDX → map to FDA/EU").
- **mcp-builder** — wrap the generator as an MCP server (`generate_aibom`, `validate_bom`, `map_compliance`, `discover_shadow_ai` tools) so it's usable from Claude Code and other agents; build the eval suite the skill recommends. Use stdio locally / streamable-HTTP for a shared server.
- **xlsx** — generate the **field/compliance matrices**: the AI-BOM field dictionary, the standards crosswalk (CycloneDX↔SPDX↔G7 clusters), and the **EU AI Act Annex IV / FDA §524B traceability spreadsheet** (requirement → AI-BOM field → evidence → gap). This is the client's working artifact.
- **docx** — produce the narrative deliverables: the AI governance SOP, the SaMD/PCCP readiness memo, and the data-governance extension to the MDR technical file.
- **pdf** — render the **client-facing compliance readiness report PDF** (Annex IV gap report, §524B SBOM attestation). Matches the user's ReportLab background; the pdf skill handles forms/templated output.
- **pptx** — the **client pre-call / findings deck** (current-state shadow-AI inventory, gaps, roadmap, OpsMx-vs-build recommendation).
- **frontend-design** + **web-artifacts-builder** — an **AI-BOM dashboard** (React/Tailwind/shadcn): model inventory, risk heatmap, drift/compliance status across hospital sites — mirrors Trusera's HTML dashboard but healthcare-tuned. Use frontend-design to avoid generic "AI slop."
- (Reference) The docx/pdf/pptx/xlsx skills are Anthropic's production document skills; pair xlsx+pptx to turn a scan CSV into a board deck in one prompt.

### Project structure
```
clinithread-aibom/
  pyproject.toml            # uv/poetry; py3.11+
  src/aibom/
    scan/                   # manifest, code (libcst/tree-sitter), modelfile, env, docker, cloud, dicom
    model/                  # Pydantic AIComponent + clinical extensions
    emit/                   # cyclonedx.py, spdx.py, sarif.py, html.py
    compliance/             # fda_524b.py, eu_ai_act_annexIV.py, gmlp.py, hipaa.py, nist_rmf.py
    shadow/                 # allowlist diff, org sweep
    schemas/                # bom-1.6.schema.json, spdx-3.0 json-schema
    cli.py                  # `aibom scan|emit|validate|map|discover`
  .claude/skills/aibom-generator/SKILL.md
  mcp/                      # MCP server (from mcp-builder)
  tests/                    # pytest + schema validation + golden BOMs
  examples/clinical-imaging/  # sample model repo + golden AI-BOM
```

### Tech stack
Python 3.11+; Pydantic v2; `cyclonedx-python-lib` for CycloneDX (or hand-built dicts as Trusera does); `spdx-tools` / hand-built for SPDX 3.0; `jsonschema` for validation; LibCST + tree-sitter for code; `pydicom` for imaging metadata; ReportLab/pdf-skill for PDFs; FastAPI for the API/MCP; Typer/Click for the CLI; OPA/Rego optional for policy gates. Reuse Apache-2.0 patterns (not code wholesale) from Cisco/Trusera.

### Phased roadmap
- **Phase 0 (week 1) — spike:** run Cisco `cisco-aibom` and Trusera `ai-bom` on a sample clinical-imaging repo; capture their CycloneDX/SPDX outputs as golden references and gap-analyze against clinical needs.
- **Phase 1 (weeks 2–4) — MVP:** scan a single Python model repo → normalized model → **validated CycloneDX 1.6 ML-BOM JSON** with modelCard. CLI + pytest + schema validation. *Milestone: a valid AI BOM for a clinical imaging model.*
- **Phase 2 (weeks 5–7) — standards + datasets:** add **SPDX 3.0 AI+Dataset** emitter; dataset/provenance/bias capture; model-card and Datasheet ingestion; SARIF. *Milestone: dual-format, dual-schema-valid output.*
- **Phase 3 (weeks 8–11) — compliance layer:** FDA §524B + EU AI Act Annex IV + GMLP + HIPAA mapping → **PDF/DOCX/XLSX readiness reports** via skills. *Milestone: an Annex IV gap report and a §524B SBOM attestation from a scan.*
- **Phase 4 (weeks 12–14) — shadow AI + governance:** org/repo/container/cloud sweep, allowlist diffing, drift/multi-site fields, dashboard (frontend-design/web-artifacts-builder). *Milestone: org-wide shadow-AI inventory + dashboard.*
- **Phase 5 (weeks 15+) — productize:** MCP server (mcp-builder), CI gates (GitHub Action), policy-as-code, package the `aibom-generator` skill for reuse.

### Sample AI BOM (CycloneDX 1.6 ML-BOM skeleton, clinical imaging)
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "version": 1,
  "metadata": {
    "timestamp": "2026-06-21T00:00:00Z",
    "tools": [{ "name": "clinithread-aibom", "version": "0.3.0" }],
    "component": { "type": "application", "name": "ChestXR-Triage-SaMD", "version": "2.1.0" },
    "properties": [
      { "name": "clinical:modality", "value": "DX (chest radiograph)" },
      { "name": "regulatory:fda_product_code", "value": "QFM" },
      { "name": "regulatory:device_class", "value": "II (SaMD)" },
      { "name": "regulatory:eu_ai_act_risk", "value": "high-risk (Annex I / MDR)" }
    ]
  },
  "components": [
    {
      "bom-ref": "model-chestxr-cnn",
      "type": "machine-learning-model",
      "name": "chestxr-nodule-detector",
      "version": "2.1.0",
      "publisher": "Acme Medical AI",
      "licenses": [{ "license": { "id": "Apache-2.0" } }],
      "hashes": [{ "alg": "SHA-256", "content": "e3b0c44298fc1c149afbf4c8996fb924..." }],
      "modelCard": {
        "modelParameters": {
          "approach": { "type": "supervised" },
          "task": "classification/detection",
          "architectureFamily": "convolutional neural network",
          "modelArchitecture": "ResNet-50",
          "datasets": [{ "ref": "dataset-chestxr-train" }],
          "inputs": [{ "format": "DICOM DX image" }],
          "outputs": [{ "format": "nodule probability + bounding box" }]
        },
        "quantitativeAnalysis": {
          "performanceMetrics": [
            { "type": "AUROC", "value": "0.94", "slice": "overall" },
            { "type": "sensitivity", "value": "0.91", "slice": "age>=65" }
          ]
        },
        "considerations": {
          "users": ["board-certified radiologist (human-in-the-loop)"],
          "useCases": ["triage/prioritization of chest radiographs"],
          "technicalLimitations": ["not validated on pediatric or portable AP supine films"],
          "ethicalConsiderations": [{ "name": "demographic performance gap", "mitigationStrategy": "subgroup monitoring" }],
          "fairnessAssessments": [{ "groupAtRisk": "underrepresented scanners/sites" }]
        }
      },
      "pedigree": { "ancestors": [{ "type": "machine-learning-model", "name": "imagenet-resnet50", "version": "1.0" }] },
      "externalReferences": [
        { "type": "model-card", "url": "https://acme.example/chestxr.modelcard.json" },
        { "type": "documentation", "comment": "FDA 510(k) K2xxxx; PCCP authorized" }
      ]
    },
    {
      "bom-ref": "dataset-chestxr-train",
      "type": "data",
      "name": "chestxr-training-cohort",
      "properties": [
        { "name": "dataset:type", "value": "image (DICOM)" },
        { "name": "dataset:size", "value": "412,000 studies" },
        { "name": "dataset:provenance", "value": "3 US health systems, 2019-2024, IRB-approved, de-identified" },
        { "name": "dataset:sensitivity", "value": "PHI removed; Safe Harbor de-identification" },
        { "name": "dataset:known_bias", "value": "skews adult, 2 scanner vendors" }
      ],
      "licenses": [{ "license": { "name": "internal-restricted" } }]
    },
    { "bom-ref": "lib-pytorch", "type": "library", "name": "torch", "version": "2.3.1",
      "purl": "pkg:pypi/torch@2.3.1" }
  ],
  "dependencies": [
    { "ref": "model-chestxr-cnn", "dependsOn": ["dataset-chestxr-train", "lib-pytorch"] }
  ]
}
```

### Testing/validation strategy
- **Schema validation** of every emitted BOM against the CycloneDX 1.6 and SPDX 3.0 JSON schemas in CI (like Trusera's `--validate`).
- **Golden BOMs**: commit example clinical-imaging repos with expected AI-BOM output; diff on every change.
- **Benchmark** detection precision/recall/F1 against a labelled ground-truth (Cisco's `benchmark` pattern).
- **Round-trip/interop**: ingest outputs into OWASP Dependency-Track; cross-check CycloneDX↔SPDX field parity.
- **Compliance-map unit tests**: assert each Annex IV/§524B requirement resolves to the right AI-BOM field or a flagged gap.

### How OpsMx informs vs. contrasts with the build
OpsMx validates the market direction (AI BOM as a CI/CD-gated governance artifact, CycloneDX output, policy-as-code, MBOM/DBOM/PBOM lineage, ModelScan for weights) — adopt its **deployment-firewall/policy-gate** model and CycloneDX choice. But OpsMx is **horizontal DevSecOps** with no FDA/EU-AI-Act/HIPAA/PACS content and no public AI-BOM schema or SPDX support. Your differentiation is the **healthcare compliance-mapping layer** (FDA SaMD/§524B/PCCP, EU AI Act Annex IV, GMLP, HIPAA), clinical-imaging field extensions, and SPDX-3.0 AI-profile support — building on the open Cisco/Trusera generators rather than the closed OpsMx platform. Positioning: don't rebuild OpsMx's scanning breadth; wrap best-of-breed open generators and add the regulated-healthcare intelligence OpsMx lacks.

## Recommendations
1. **Pre-call:** Go in knowing OpsMx = Delivery Shield ASPM with AI BOM as a feature (CycloneDX, ModelScan, OPA gates), not a healthcare product. Ask the six questions in §1. Treat OpsMx as a possible **scanning/back-end partner**, not a turnkey clinical solution.
2. **Build vs. buy:** Build the thin, high-value **healthcare compliance layer** yourself; reuse Apache-2.0 Cisco/Trusera generators for the scanning/emit substrate. Don't reimplement multi-language scanning from scratch.
3. **Standards:** Target **CycloneDX 1.6 ML-BOM as primary** (broadest tool support, Ecma-424, what OpsMx/Cisco/Trusera all emit) and **SPDX 3.0 AI+Dataset as secondary** (ISO lineage, explicit EU-AI-Act risk fields). Map both to the **G7/CISA seven clusters** for procurement-proofing.
4. **Claude Code:** Start with **skill-creator → `aibom-generator` skill**, then **xlsx/pdf/docx/pptx** for deliverables, then **frontend-design/web-artifacts-builder** for the dashboard, then **mcp-builder** to make it agent-callable. Follow the phased roadmap; MVP = a validated CycloneDX ML-BOM in ~3 weeks.
5. **Sequencing benchmarks that change the plan:** if the client's primary need is **FDA submission**, prioritize the §524B SBOM + PCCP report (Phase 3) over the dashboard; if it's the **EU market**, prioritize Annex IV mapping (note the Aug 2, 2028 delayed deadline but Article 4 literacy now); if it's **internal shadow-AI/scribe risk**, prioritize Phase 4 discovery + HIPAA/BAA review first.
6. **GenAI scribe:** flag the BAA-or-bust HIPAA rule and active scribe litigation as an immediate governance item independent of the build.

## Caveats
- **OpsMx specifics are partly inferred:** no public AI-BOM sample file, field schema, SPDX support, pricing, or healthcare content exists — confirm directly. Statements about ModelScan/CycloneDX/MBOM come from OpsMx marketing/blog pages, which may overstate maturity.
- **G7/CISA element labels** are faithful paraphrases corroborated across multiple outlets; the primary BSI/CISA PDF resisted automated fetch, so verify byte-exact field names against the PDF before publishing a schema.
- **EU AI Act timelines are in flux:** the Digital Omnibus (Council agreement May 2026) pushed Annex I embedded high-risk to **Aug 2, 2028** (from 2026/2027); treat dates as moving and confirm current status at engagement time. Article 4/5 obligations are live now.
- **Regulatory mapping is advisory, not legal advice:** an AI BOM supports but does not by itself satisfy FDA/EU obligations (CISA's own caveat: "minimum elements create visibility, not assurance"). A regulatory/legal reviewer must sign off on any submission.
- **Tool maturity:** both GitHub projects are pre/early-1.0 (Cisco 1.0.0rc4; Trusera v3.1.0) and evolving; re-verify versions/features at build time.