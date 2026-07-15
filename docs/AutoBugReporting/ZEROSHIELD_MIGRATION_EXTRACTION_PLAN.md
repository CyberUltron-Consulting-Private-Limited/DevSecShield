# DevSecShield → ZeroShield: Migration & Extraction Plan

**Date:** 2026-04-11  
**Author:** Architecture Review  
**Scope:** Complete reuse audit, extraction plan, and architectural decisions for ZeroShield v4.0

---

## Table of Contents

1. [Reuse Audit — Component-by-Component](#1-reuse-audit)
2. [Code Extraction Plan — Step-by-Step](#2-code-extraction-plan)
3. [What NOT to Reuse (and Why)](#3-what-not-to-reuse)
4. [Shared Library Strategy](#4-shared-library-strategy)
5. [Frontend Decision](#5-frontend-decision)
6. [Celery Worker Architecture Comparison](#6-celery-worker-architecture-comparison)
7. [Database Schema Migration](#7-database-schema-migration)
8. [Extraction Checklist](#8-extraction-checklist)

---

## 1. Reuse Audit

### Legend
- **✅ Extract as-is** — Copy and use with minimal changes
- **🔧 Extract with modifications** — Copy but requires non-trivial adaptation
- **🔨 Rewrite inspired by** — Pattern is useful, implementation must be new
- **❌ Do not reuse** — Not applicable to ZeroShield

---

### 1.1 BaseAgent (`RabbitMQ/worker/helpers/context/base_agent.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | 🔧 Extract with modifications |
| **Effort** | 4-6 hours |
| **Transitive deps** | `BaseUtilities`, `OutputModelManager`, `schema.py` enums, `langchain-aws`, `langchain-qdrant`, `qdrant-client`, `pydantic` |
| **DevSecShield-specific logic to strip** | None inherently — BaseAgent is a clean abstract base |
| **What to keep** | `run_agent()` interface, `to_dict_list()` with deterministic sorting, `query_vector_store()` with Qdrant filter, `generate_structured_response()` with retry logic |
| **What to change** | LLM model default (`openai.gpt-oss-120b-1:0` → configurable per ZeroShield's Haiku/Sonnet pipeline), image handling (not needed for ZeroShield npm/Docker scanning) |

**Analysis:** BaseAgent is the single most valuable reuse target. It provides:
- Abstract agent pattern with `run_agent()` contract
- Deterministic output serialization (`to_dict_list` with `sort_keys=True`)
- Vector store querying with Qdrant metadata filters
- Structured LLM response generation with retry on transient Bedrock errors
- Multiple output model generation (codebase, dependency, IAC, LLM, crypto variants)

The class cleanly inherits from `OutputModelManager` and `BaseUtilities`, both of which are also reusable. The only DevSecShield coupling is the default LLM model string, which is env-configurable.

**Dependency chain:**
```
BaseAgent
├── OutputModelManager (reusable — CVE enum generation, NVD client)
│   ├── schema.py (reusable — vulnerability Pydantic models)
│   ├── enums.py (reusable — OWASP, ComplianceControls, Impact, etc.)
│   └── FallbackCVEEnum (reusable — hardcoded recent CVEs as fallback)
├── BaseUtilities (reusable — LLM init, Qdrant client, embeddings)
│   ├── langchain-aws (ChatBedrock, BedrockEmbeddings)
│   ├── langchain-qdrant (QdrantVectorStore)
│   └── SQLiteCache for LLM response caching
└── parsers/base_vuln.py (reusable — vulnerability dict parser)
```

---

### 1.2 StateUpdateWriter (`RabbitMQ/worker/helpers/context/progress_writer.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | ✅ Extract as-is |
| **Effort** | 0.5 hours |
| **Transitive deps** | `celery.Task` only |
| **DevSecShield-specific logic** | None |

**Analysis:** 18 lines of code. Wraps Celery's `task.update_state()` with three convenience methods:
- `write_progress_percentage(progress: float)`
- `write_progress_out_of_total(current: int, total: int)`
- `update_state_with_meta(meta: dict)`

Zero coupling to DevSecShield. Copy verbatim.

---

### 1.3 NVD API Client + 4-Tier Caching (`RabbitMQ/worker/helpers/context/output_model.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | 🔧 Extract with modifications |
| **Effort** | 6-8 hours |
| **Transitive deps** | `pymongo`, `requests`, `pydantic`, `schema.py` (FallbackCVEEnum) |
| **DevSecShield-specific logic** | MongoDB database name `new_devsecshield_backend_server_db`, collection names |

**Analysis:** The NVD client implements a sophisticated 4-tier caching strategy:
1. **In-memory dict** (`_cve_mem_cache`) — hot path, zero latency
2. **MongoDB persistent cache** (`cve_cache` collection) — survives worker restarts
3. **NVD API v2.0 fetch** — `services.nvd.nist.gov/rest/json/cves/2.0` with rate-limit retry
4. **FallbackCVEEnum** — hardcoded recent CVEs as last resort

This is exactly what ZeroShield needs for its SCA worker (`Worker 1: SCA`). Changes needed:
- Rename MongoDB database from `new_devsecshield_backend_server_db` → `zeroshield_db`
- Make database name configurable via env var
- Add OSV.dev + GHSA + CISA KEV sources alongside NVD (ZeroShield plan §5.3)
- Add EPSS score enrichment
- Extend `fetch_cves_for_year()` to support ecosystem-specific queries (npm/Docker)

The dynamic CVE enum generation (`create_CVE_enum()`, `create_output_model()`, `get_output_model()`) and its fallback logic is also highly reusable — it creates Pydantic models at runtime with a `cves` field constrained to real CVE IDs.

---

### 1.4 Vulnerability Pydantic Models (`RabbitMQ/worker/helpers/context/schema.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | 🔧 Extract with modifications |
| **Effort** | 4-6 hours |
| **Transitive deps** | `enums.py` (all enums) |
| **DevSecShield-specific logic** | None — these are standard security domain models |

**Models to extract:**
| Model | Reusable? | Notes |
|-------|-----------|-------|
| `BaseVulnerability` | ✅ Yes | title, description, impact, OWASP, compliance_controls, suggested_fix |
| `CodebaseVulnerability(BaseVulnerability)` | ✅ Yes | Adds location, snippet — needed for SAST findings |
| `DependencyVulnerability(BaseVulnerability)` | ✅ Yes | Adds dependency, reachability, dependency_type, license_type — core for SCA |
| `IACVulnerability(CodebaseVulnerability)` | ❌ No | ZeroShield doesn't scan IAC |
| `LLMBenchmarkingVulnerability` | ❌ No | ZeroShield doesn't do LLM benchmarking |
| `MCPVulnerability` | ❌ No | ZeroShield doesn't scan MCP servers |
| `CryptographicAssetVulnerability(BaseVulnerability)` | ❌ No | ZeroShield doesn't do CBOM |
| `LogicalComponents` / `IndividualLogicalComponent` | 🔧 Maybe | Useful if ZeroShield's AI worker does component decomposition |

**New models ZeroShield needs:**
- `DockerVulnerability(BaseVulnerability)` — image, layer, digest, base_image
- `BehavioralFinding(BaseVulnerability)` — trigger_type, hook_phase, network_indicators
- `SupplyChainFinding(BaseVulnerability)` — typosquat_target, maintainer_change, detection_method

---

### 1.5 Enums (`RabbitMQ/worker/helpers/context/enums.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | ✅ Extract as-is |
| **Effort** | 1 hour |
| **DevSecShield-specific logic** | None |

**Reusable enums (all of them):**
- `Impact` — severity levels
- `OWASPTop10` — A01-A10:2021
- `OWASPTop10LLM` — LLM01-LLM10:2025
- `MitreAtlasTactic` — MITRE ATT&CK tactics
- `ComplianceControls` — ISO 27001/27002/42001, NIST 800-53, NIST CSF, MITRE ATT&CK, CMMC, GDPR (~90+ enum members)
- `LicenseCategory` — SPDX license risk categories
- `DependencyType` — direct/transitive
- `Reachability` — reachable/potentially/not/unknown

These are industry-standard security taxonomy enums. Copy verbatim. ZeroShield needs all of them for its advisory output.

---

### 1.6 Celery Worker Config (`RabbitMQ/worker/scan_worker.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | 🔧 Extract with modifications |
| **Effort** | 3-4 hours |
| **Transitive deps** | `celery`, `pymongo`, `dotenv`, `rich` |
| **DevSecShield-specific logic** | Task definitions (sast, llm, mcp, iac, etc.), scan context validators |

**What to extract:**
- RabbitMQ + MongoDB connection bootstrap pattern (broker URL, Mongo URL, Docker/Local detection)
- Celery app configuration block:
  ```python
  app.conf.update(
      RESULT_PERSISTENT=True,
      TASK_TRACK_STARTED=True,
      task_time_limit=900,
      task_soft_time_limit=600,
      task_acks_late=True,
      task_reject_on_worker_lost=True,
      worker_prefetch_multiplier=1,
  )
  ```
- Connection error handling pattern with `sys.exit()` on credential failure

**What NOT to extract:**
- All `@app.task` definitions (ZeroShield has completely different tasks: SCA, SAST, Behavioral, AI, Docker)
- Context validators (`validate_dict_with_context`, `validate_dict_with_zip_context`, etc.)
- Agent imports (SASTAgent, MCPAgent, IACAgent, etc.)

---

### 1.7 Celery Connection Utilities — Backend Side (`backend/utilities/celery/celery_connection.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | 🔧 Extract with modifications |
| **Effort** | 3-4 hours |
| **Transitive deps** | `celery`, `pymongo`, `psycopg2`, `sqlmodel`, `dotenv` |
| **DevSecShield-specific logic** | `get_status_and_update_db()` uses DevSecShield's `Scan` model and postgres engine |

**What to extract:**
- `get_celery_app()` — creates a Celery "sender" app for the FastAPI backend to submit tasks
- Connection string construction pattern (Docker/Local detection)
- Celery conf update pattern

**What to change:**
- `get_status_and_update_db()` — rewrite entirely for ZeroShield's `scan_jobs` table
- Remove `from backend.new_models import Scan` dependency
- Remove `create_findings_in_mongo_db` import (different finding structure)

---

### 1.8 BaseUtilities (`RabbitMQ/worker/helpers/context/base_utilities.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | 🔧 Extract with modifications |
| **Effort** | 2-3 hours |
| **Transitive deps** | `langchain-aws`, `langchain-qdrant`, `qdrant-client`, `langchain-community` |
| **DevSecShield-specific logic** | SQLiteCache path, default model names |

**What to extract:**
- LLM initialization (`get_llm()` with ChatBedrock)
- Embedding initialization (BedrockEmbeddings)
- Qdrant client initialization
- LLM response caching (SQLiteCache)
- `_JsonSchemaOutputParser` with fuzzy enum matching — highly sophisticated, handles LLM output errors

**What to change:**
- Cache database path from `.devsecshield_llm_cache.db` → configurable
- Default embedding dimensions (1536 → may need 1024 for Titan v2)

---

### 1.9 BaseSummaryManager (`RabbitMQ/worker/helpers/context/base_summary_manager.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | ✅ Extract as-is |
| **Effort** | 0.5 hours |
| **DevSecShield-specific logic** | None — abstract class with format methods |

Used for map-reduce summarization of codebases. ZeroShield's AI worker (Stage 2) will need similar summarization. Copy verbatim.

---

### 1.10 BaseContext / Codebase Context (`RabbitMQ/worker/helpers/context/base_context.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | 🔧 Extract with modifications |
| **Effort** | 6-8 hours |
| **Transitive deps** | `langchain`, `pymongo`, `pydantic`, `langsmith` |
| **DevSecShield-specific logic** | MongoDB database/collection names, map-reduce cache logic |

**What to extract:**
- `_invoke_with_retry()` — transient Bedrock error retry with exponential backoff (handles `ThrottlingException`, `ServiceUnavailableException`, `ModelTimeoutException`, etc.)
- `_get_mongo_client()` — MongoDB connection helper
- `_hash_documents()` — deterministic SHA256 hashing of document content
- `BaseResult` dataclass — generic context_id + summary container

**What to change:**
- Cache collection names from `map_reduce_cache` → ZeroShield-specific
- Database name from `new_devsecshield_backend_server_db`

---

### 1.11 Qdrant Utilities (`RabbitMQ/worker/helpers/context/qdrant_utils.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | ✅ Extract as-is |
| **Effort** | 0.5 hours |
| **DevSecShield-specific logic** | Default collection names (`codebase_context`, `open_source_context`) |

Simple Qdrant CRUD: `create_collection`, `check_if_collection_exists`, `run_initialization_checks`, `delete_all_documents_from_collection`. Change default collection names for ZeroShield.

---

### 1.12 Vulnerability Parsers (`RabbitMQ/worker/helpers/parsers/`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | 🔧 Extract with modifications |
| **Effort** | 2 hours |
| **Files** | `base_vuln.py`, `codebase_vuln.py`, `dependency_vuln.py` |

These convert Pydantic vulnerability models to dicts for storage. ZeroShield needs the same pattern for its advisory output format.

---

### 1.13 S3 Utilities (`RabbitMQ/worker/helpers/context/s3_utils.py`)

| Attribute | Assessment |
|-----------|-----------|
| **Verdict** | 🔧 Extract with modifications |
| **Effort** | 1-2 hours |

Used for temp file management. ZeroShield needs S3 for tarball caching and tool binary storage.

---

## 2. Code Extraction Plan

### Extraction Order (Dependency-Aware)

Extraction must proceed bottom-up through the dependency tree:

```
Phase 1: Foundation (no internal deps)
  ├── enums.py                    → zeroshield/shared/enums.py
  ├── progress_writer.py          → zeroshield/shared/progress.py
  └── qdrant_utils.py             → zeroshield/shared/qdrant.py

Phase 2: Models (depends on enums)
  ├── schema.py                   → zeroshield/shared/models.py
  └── parsers/*                   → zeroshield/shared/parsers/

Phase 3: Utilities (depends on models)
  ├── base_utilities.py           → zeroshield/shared/llm.py
  ├── base_summary_manager.py     → zeroshield/shared/summarizer.py
  └── s3_utils.py                 → zeroshield/shared/s3.py

Phase 4: Core Logic (depends on utilities)
  ├── output_model.py             → zeroshield/shared/cve_client.py
  ├── base_context.py             → zeroshield/shared/context.py
  └── base_agent.py               → zeroshield/shared/agent.py

Phase 5: Infrastructure (depends on core)
  ├── scan_worker.py (config only) → zeroshield/worker/celery_config.py
  └── celery_connection.py         → zeroshield/api/celery_client.py
```

### Step-by-Step Extraction Process

#### Step 1: Create ZeroShield project skeleton
```
zeroshield/
├── shared/              # Extracted from DevSecShield
│   ├── __init__.py
│   ├── enums.py         # Verbatim copy
│   ├── models.py        # BaseVulnerability, CodebaseVulnerability, DependencyVulnerability
│   ├── parsers/
│   ├── llm.py           # BaseUtilities adapted
│   ├── agent.py         # BaseAgent adapted
│   ├── cve_client.py    # OutputModelManager NVD logic extracted
│   ├── progress.py      # StateUpdateWriter verbatim
│   ├── context.py       # BaseContext adapted  
│   ├── summarizer.py    # BaseSummaryManager verbatim
│   ├── qdrant.py        # Qdrant utils adapted
│   └── s3.py            # S3 utils adapted
├── scanner/             # ZeroShield-specific
├── reporter/            # ZeroShield-specific
├── orchestrator/        # ZeroShield-specific
├── triage/              # ZeroShield-specific
├── worker/              # Celery worker entry + tasks
├── api/                 # FastAPI service
├── db/                  # Schema + models
└── dashboard/           # Frontend (Phase 3+)
```

#### Step 2: Extract enums.py (Phase 1)
```bash
cp RabbitMQ/worker/helpers/context/enums.py zeroshield/shared/enums.py
```
**Changes needed:** None. All enums are industry-standard taxonomies.

#### Step 3: Extract schema.py → models.py (Phase 2)
```bash
cp RabbitMQ/worker/helpers/context/schema.py zeroshield/shared/models.py
```
**Changes needed:**
- Remove `IACVulnerability`, `LLMBenchmarkingVulnerability`, `MCPVulnerability`, `MCPResourceResponse`, `LLMModelVulnerability`, `LLMVulnerabilityPredictions`
- Keep `BaseVulnerability`, `CodebaseVulnerability`, `DependencyVulnerability`, `CryptographicAssetVulnerability`, `FallbackCVEEnum`, `LogicalComponents`
- Add new models: `DockerVulnerability`, `BehavioralFinding`, `SupplyChainFinding`
- Update import from `helpers.context.enums` → `zeroshield.shared.enums`

#### Step 4: Extract base_utilities.py → llm.py (Phase 3)
```bash
cp RabbitMQ/worker/helpers/context/base_utilities.py zeroshield/shared/llm.py
```
**Changes needed:**
- Change cache path: `_LLM_CACHE_DB = os.path.join(os.environ.get("TMPDIR", "/tmp"), ".zeroshield_llm_cache.db")`
- Make default LLM model configurable via `LLM_MODEL` env var (already partially done)
- The `_JsonSchemaOutputParser` with fuzzy enum matching is gold — keep every line

#### Step 5: Extract output_model.py → cve_client.py (Phase 4)
```bash
cp RabbitMQ/worker/helpers/context/output_model.py zeroshield/shared/cve_client.py
```
**Changes needed:**
- `_CVE_CACHE_DB` → `os.getenv("ZEROSHIELD_DB_NAME", "zeroshield_db")`
- `_CVE_CACHE_COLLECTION` → keep as `cve_cache`
- Strip `get_codebase_output_model`, `get_iac_output_model`, `get_llm_benchmarking_output_model`, `get_cryptographic_output_model`
- Keep `get_dependency_output_model`, `get_base_output_model`
- Add `get_docker_output_model()` using new `DockerVulnerability`
- Update all `helpers.context.schema` → `zeroshield.shared.models`

#### Step 6: Extract base_agent.py → agent.py (Phase 4)
```bash
cp RabbitMQ/worker/helpers/context/base_agent.py zeroshield/shared/agent.py
```
**Changes needed:**
- Update import: `helpers.context.base_utilities` → `zeroshield.shared.llm`
- Update import: `helpers.context.schema` → `zeroshield.shared.models`
- Update import: `helpers.context.output_model` → `zeroshield.shared.cve_client`
- Update import: `helpers.parsers.base_vuln` → `zeroshield.shared.parsers.base_vuln`
- Remove default `llm_model="openai.gpt-oss-120b-1:0"` → use env var

#### Step 7: Extract Celery infrastructure (Phase 5)
From `scan_worker.py` extract only the configuration pattern:
```python
# zeroshield/worker/celery_config.py
app = Celery('zeroshield_worker', broker=broker_url, backend=mongo_url)
app.conf.update(
    RESULT_PERSISTENT=True,
    TASK_TRACK_STARTED=True,
    task_time_limit=900,
    task_soft_time_limit=600,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
)
```

From `celery_connection.py` extract `get_celery_app()` pattern, strip DevSecShield model imports.

---

## 3. What NOT to Reuse (and Why)

### 3.1 Team/Credit System ❌

**Files:** `backend/new_models.py` (Team, TeamMembership, User), `backend/routers/team.py`, `backend/utilities/team/`

**Why not:** ZeroShield is a public vulnerability reporting platform, not a multi-tenant SaaS. There are no "teams" or "credits." Scanning is automated via Celery Beat, not user-initiated per-team.

**ZeroShield equivalent:** `api_keys` table for authenticated scan requests + `monitored_targets` for registry tracking. No user accounts in the DevSecShield sense.

---

### 3.2 Auth System ❌

**Files:** `backend/routers/auth.py`, `backend/utilities/auth/` (JWT, bcrypt, email verification)

**Why not:** DevSecShield has user signup/login/refresh with email verification, password hashing, and JWT sessions. ZeroShield's auth model is fundamentally different:

| Feature | DevSecShield | ZeroShield |
|---------|-------------|------------|
| Identity | User accounts (email + password) | API keys (no user accounts) |
| Auth flow | JWT with refresh token | `X-API-Key` header |
| Public access | None (all authenticated) | Most endpoints public (60/min) |
| Admin access | Superuser flag | JWT + IP allowlist + MFA |
| Signup | Self-service | Admin-issued API keys |

**Recommendation:** ZeroShield should NOT have user accounts. Use:
- **Public tier:** No auth, 60 req/min rate limit
- **Authenticated tier:** API key in `X-API-Key` header, 10 scans/hour
- **Admin tier:** JWT + IP allowlist for advisory management

---

### 3.3 Scan Model ❌

**Files:** `backend/new_models.py` (`Scan` class)

**Why not:** DevSecShield's `Scan` model is user-centric:
```python
class Scan:
    team_id, owner_user_id, credit_consumed, scan_type, title,
    task_id, scan_metadata, scan_status, scan_data, info,
    integration_settings
```

ZeroShield's equivalent is `scan_jobs`:
```sql
scan_jobs (id, target_id FK, scan_type, status, task_id,
           findings_count, duration_seconds, llm_cost_usd,
           llm_cache_hit, deobfuscation_findings, entropy_flagged,
           redownload_mismatch, error_message, created_at)
```

The schemas are incompatible. ZeroShield scan_jobs:
- Reference `monitored_targets` (not users/teams)
- Track LLM costs and cache hits
- Track deobfuscation and integrity signals
- Have no concept of "owner" or "credits"

---

### 3.4 get_db.py ❌

**Files:** `backend/get_db.py`

**Why not:** DevSecShield's `get_db.py` supports both PostgreSQL and SQLite (via SQLModel/SQLAlchemy) with Docker/Local detection. ZeroShield:
- Should be PostgreSQL-only from day 1
- Should use async SQLAlchemy (for FastAPI async endpoints)
- Should use Alembic migrations from the start
- Should not have SQLite fallback (unnecessary complexity)
- MongoDB connection can borrow the pattern but with different database name

**What to borrow:** The singleton connection pooling pattern (`_pg_engine`, `_mongo_db` globals with pool_size/max_overflow settings).

---

### 3.5 Jira Integration ❌

**Files:** `backend/utilities/integrations/`

**Why not:** ZeroShield's integration targets are GitHub Advisory API, npm security team, and PGP email — not Jira.

---

### 3.6 PDF Export ❌

**Files:** `backend/utilities/pdf/`

**Why not:** ZeroShield publishes advisories as JSON, SARIF, CycloneDX, VEX, CSAF, RSS/Atom — not PDF reports.

---

### 3.7 Guardrails System ❌

**Files:** `backend/routers/guardrails.py`, `backend/routers/guardrails_public.py`, `backend/utilities/guardrails/`, `RabbitMQ/guardrail_worker/`

**Why not:** Guardrails (LLM safety) is a completely separate product vertical.

---

### 3.8 CI/CD Integration ❌ (Rewrite)

**Files:** `backend/routers/cicd.py`, `backend/utilities/cicd/`

**Why not:** DevSecShield's CI/CD generates GitHub Actions / Jenkins / Bamboo configs for scan-on-push. ZeroShield's CI/CD integration is a GitHub Action that checks packages against ZeroShield's advisory database — fundamentally different direction. However, the general pattern of generating YAML workflow files could inspire ZeroShield's `zeroshield-action` implementation.

---

### 3.9 DAST Worker ❌

**Files:** `RabbitMQ/dast_worker/`

**Why not:** ZeroShield doesn't do dynamic application scanning. Its scanning targets are npm packages and Docker images, not live web applications.

---

### 3.10 Frontend Scan Pages ❌

**Files:** `frontend/components/SASTResults.tsx`, `LLMResults.tsx`, `MCPResults.tsx`, etc.

**Why not:** DevSecShield's result pages are tailored to per-scan-type dashboards (SAST, LLM, MCP, IAC, SCA, DAST, CBOM). ZeroShield's frontend shows advisories, disclosure timelines, and package health — completely different information architecture.

---

## 4. Shared Library Strategy

### Option A: Monorepo Shared Package
```
devsecshield-shared/
├── enums.py
├── models.py
├── llm.py
├── agent.py
├── cve_client.py
├── progress.py
├── celery_utils.py
└── pyproject.toml  (published as `devsecshield-shared`)
```

### Option B: Copy-and-Diverge
Copy files into ZeroShield. Allow independent evolution.

### Option C: Git Submodule
Shared code in a separate repo, included as submodule in both.

### Recommendation: **Option B (Copy-and-Diverge)**

**Justification:**

1. **Different evolution speeds:** DevSecShield is a mature product with stable abstractions. ZeroShield is greenfield — its agent pattern will evolve rapidly (AISLE 4-stage pipeline, behavioral analysis, supply-chain detection). Shared library versioning would create friction.

2. **Different model needs:** DevSecShield uses a single LLM model (gpt-oss-120b-1:0). ZeroShield uses Haiku (batch, cheap) + Sonnet (regular, expensive) with cost caps. The `BaseAgent` and `BaseUtilities` classes will fork significantly.

3. **Different vulnerability models:** DevSecShield has `CodebaseVulnerability`, `DependencyVulnerability`, etc. ZeroShield needs `BehavioralFinding`, `SupplyChainFinding`, `DockerVulnerability`. Shared models would become a lowest-common-denominator mess.

4. **Release cycle mismatch:** DevSecShield ships continuously. ZeroShield is in phased build-out (24+ weeks). A shared library would require coordinated releases — the #1 productivity killer for small teams.

5. **Coupling cost exceeds DRY benefit:** The shared code is ~2000 lines. The cost of maintaining a shared package (CI/CD, versioning, backward compatibility, cross-product testing) exceeds the cost of occasional copy-paste updates.

**Migration path:** If after 6 months both products stabilize and the overlap is still >80%, revisit with a shared package. But don't start there.

---

## 5. Frontend Decision

### Current State: DevSecShield Frontend
- **Framework:** Next.js 14+ with App Router
- **UI Library:** shadcn/ui (Radix primitives + Tailwind CSS)
- **Charts:** Recharts
- **State:** React hooks + SWR/React Query
- **Auth:** JWT token interceptors (Axios)
- **SSE:** Custom `use-sse.ts` hook for real-time scan progress

### ZeroShield v4.0 Plan
- **Phase 1 (Weeks 1-4):** GitHub Pages (Jekyll/Hugo) — static advisory pages
- **Phase 3+ (Weeks 17+):** Next.js with real-time dashboard, Recharts, disclosure lifecycle

### Recommendation: **Start with Next.js from Day 1, but deploy as static export initially**

**Reasoning:**

1. **"GitHub Pages first" is false economy.** Setting up Jekyll/Hugo, then migrating to Next.js 3 months later wastes ~40 hours of migration effort. Next.js supports `output: 'export'` for static HTML generation — you get "GitHub Pages" for free.

2. **DevSecShield already has:**
   - shadcn/ui component library configured (buttons, cards, dialogs, tabs, etc.)
   - Recharts integration for vulnerability charts
   - Tailwind CSS configured with custom theme
   - Axios interceptors for API calls
   - SSE hook for real-time updates
   - Error boundary component

3. **Reusable components from DevSecShield:**

| Component | Reusable? | Effort |
|-----------|-----------|--------|
| `components/ui/*` (shadcn) | ✅ Yes — entire directory | 0.5h (copy + verify) |
| `components/charts/` | 🔧 Partially — chart primitives yes, data transformation no | 2-3h |
| `components/auth/` | ❌ No — ZeroShield has no user auth UI | — |
| `utils/interceptors.js` | 🔧 Partially — API key auth instead of JWT | 1h |
| `utils/backend_api.ts` | ❌ No — different endpoints entirely | — |
| `hooks/use-sse.ts` | ✅ Yes — scan progress streaming | 0.5h |
| `components/error-boundary.tsx` | ✅ Yes | 0h (copy) |
| `components/theme-provider.tsx` | ✅ Yes | 0h (copy) |
| `next.config.ts` | 🔧 Partially — strip DevSecShield-specific rewrites | 0.5h |
| `tailwind.config` | ✅ Yes — theme colors may change | 0.5h |
| `components.json` (shadcn config) | ✅ Yes | 0h (copy) |

4. **Effort estimate for shared component library setup:**
   - Copy shadcn/ui components: 1 hour
   - Set up new Next.js project with same config: 2 hours
   - Adapt chart components for advisory data: 4 hours
   - Build advisory-specific pages: 20+ hours (new work)
   - **Total reuse savings: ~15-20 hours** vs starting shadcn/ui from scratch

### Frontend Extraction Plan
```bash
# From DevSecShield frontend, extract:
frontend/components/ui/          → zeroshield/dashboard/components/ui/
frontend/components/charts/      → zeroshield/dashboard/components/charts/ (adapt)
frontend/components/error-boundary.tsx → zeroshield/dashboard/components/
frontend/components/theme-provider.tsx → zeroshield/dashboard/components/
frontend/hooks/use-sse.ts        → zeroshield/dashboard/hooks/
frontend/components.json         → zeroshield/dashboard/
frontend/postcss.config.mjs      → zeroshield/dashboard/
frontend/tailwind.config.*       → zeroshield/dashboard/

# Don't extract:
frontend/utils/backend_api.ts    # Different API
frontend/utils/interceptors.js   # Different auth model
frontend/components/SASTResults.tsx  # DevSecShield-specific
frontend/components/auth/        # Not needed
frontend/app/                    # Routing is completely different
```

---

## 6. Celery Worker Architecture Comparison

### DevSecShield Workers
```
scan_worker (main)
├── SAST task → SASTAgent
├── SCA/SBOM task → SCASBOMAgent  
├── IAC task → IACAgent
├── LLM Benchmarking task → LLMBenchmarkingAgent
├── MCP task → MCPAgent
├── CBOM task → CBOMAgent
└── Agent Discovery task → (MCP discovery)

guardrail_worker
└── Guardrails policy evaluation

dast_worker
└── DAST scanning (Selenium-based)
```

### ZeroShield Workers (from v4.0 plan)
```
sca_worker
└── Grype + OSV.dev + NVD + GHSA + CISA KEV

sast_worker
└── Semgrep (community + 5 custom rules) + deobfuscation

behavioral_worker
└── Credential harvesting + RAT + crypto-mining + typosquat + install hooks

ai_worker
└── 4-stage AISLE pipeline (Haiku batch → Sonnet regular → Haiku batch → Sonnet PoC)

docker_worker
└── Trivy + Grype + Dockerfile analysis + layer inspection
```

### Similarity/Difference Matrix

| Aspect | DevSecShield | ZeroShield | Same? |
|--------|-------------|------------|-------|
| Broker | RabbitMQ | RabbitMQ | ✅ |
| Backend store | MongoDB (results) | MongoDB (results) | ✅ |
| Task framework | Celery | Celery | ✅ |
| Progress tracking | StateUpdateWriter | StateUpdateWriter | ✅ |
| Agent pattern | BaseAgent → per-type agents | BaseAgent → per-type agents | ✅ |
| Vector store | Qdrant | Qdrant (for AI worker caching) | ✅ |
| LLM provider | AWS Bedrock (single model) | AWS Bedrock (Haiku + Sonnet) | 🔧 Similar |
| Scan input | User-submitted repos/files | Auto-discovered npm/Docker | ❌ Different |
| Scan trigger | User API call | Celery Beat scheduler | ❌ Different |
| Result storage | MongoDB `scan_findings` | MongoDB `scan_findings` + PG `advisories` | 🔧 Similar |
| Task timeout | 15 min hard / 10 min soft | 15 min hard (configurable per worker) | ✅ |
| Concurrency | 1 worker process | 5 worker types × N instances | ❌ Different scale |

### Can the Same Infrastructure Run Both?

**RabbitMQ:** Yes, use separate vhosts:
```
rabbitmq:
  vhost: /devsecshield   # DevSecShield queues
  vhost: /zeroshield      # ZeroShield queues
```

**MongoDB:** Yes, use separate databases:
```
mongodb:
  db: new_devsecshield_backend_server_db  # DevSecShield
  db: zeroshield_db                        # ZeroShield
```

**Recommendation:** Share RabbitMQ and MongoDB instances in development. Separate in production for isolation and independent scaling. ZeroShield's behavioral_worker and ai_worker have much heavier resource requirements (gVisor sandboxing, batch API scheduling) that would interfere with DevSecShield's latency-sensitive user-facing scans.

---

## 7. Database Schema Migration

### DevSecShield Schema (PostgreSQL)
```
User (id, email, password, first_name, last_name, profile_photo, ...)
Team (id, name, description, credit_balance, integration_settings, ...)
TeamMembership (team_id, user_id, role)
Scan (id, team_id, owner_user_id, credit_consumed, scan_type, title, 
      task_id, scan_metadata, scan_status, scan_data, info, ...)
GuardrailsIntegration (id, team_id, ...)
CicdIntegration (id, team_id, ...)
VerificationCode (id, email, code, ...)
```

### ZeroShield Schema (PostgreSQL)
```
registry_state (id, registry, last_seq, last_checked_at)
monitored_targets (id, ecosystem, name, latest_version, popularity_score, 
                   popularity_tier, last_scanned_at, scan_frequency_hours,
                   is_active, opted_out, provenance_supported, created_at)
advisories (id, target_id, cve_id, ghsa_id, zeroshield_id, title, description,
            severity, cvss_score, cvss_vector, epss_score, cwe_ids, 
            affected_versions, patched_version, discovery_method, 
            confidence_score, status, proof_of_discovery_hash, ...)
scan_jobs (id, target_id, scan_type, status, task_id, findings_count,
           duration_seconds, llm_cost_usd, error_message, created_at)
scan_dlq (id, scan_job_id, worker_type, error_message, retry_count, status)
disclosure_events (id, advisory_id, event_type, channel, details, created_at)
api_keys (id, key_hash, owner_name, tier, rate_limit_per_hour, is_active)
false_positive_patterns (id, package, version, scanner, rule_id, finding_hash, ...)
webhooks (id, api_key_id, url, events, secret_hash, is_active)
```

### Mapping

| DevSecShield | ZeroShield | Relationship |
|-------------|------------|-------------|
| `User` | — | No equivalent (no user accounts) |
| `Team` | — | No equivalent (no teams) |
| `TeamMembership` | — | No equivalent |
| `Scan` | `scan_jobs` | Similar purpose, different schema |
| `Scan.task_id` | `scan_jobs.task_id` | Same — Celery task ID |
| `Scan.scan_type` | `scan_jobs.scan_type` | Similar — different scan types |
| `Scan.scan_status` | `scan_jobs.status` | Same statuses |
| — | `monitored_targets` | New — replaces user-submitted repos |
| — | `advisories` | New — entire disclosure lifecycle |
| — | `disclosure_events` | New — 90-day timeline tracking |
| — | `api_keys` | New — replaces user auth |
| — | `registry_state` | New — npm/Docker feed tracking |
| `MongoDB: scan_findings` | `MongoDB: scan_findings` | Reusable pattern, different finding shape |

### Can They Share PostgreSQL?

**Technically yes** (separate schemas within same instance), but **recommended no**:
- Different migration lifecycles (DevSecShield has Alembic, ZeroShield needs its own)
- Different backup schedules (ZeroShield advisory data is more critical)
- DevSecShield uses SQLModel; ZeroShield should use SQLAlchemy Core or async SQLModel
- Connection pool contention

**Recommended:** Same PostgreSQL cluster, different databases (`devsecshield_db`, `zeroshield_db`). Shared cluster saves infra cost while maintaining isolation.

### Migration Scripts

No migration scripts needed — ZeroShield starts with a clean database. The only data to "migrate" is:
1. **NVD CVE cache:** Already in MongoDB, can be shared across both products via same collection
2. **Semgrep rules:** Static files, copy into ZeroShield's `semgrep-rules/` directory

---

## 8. Extraction Checklist

### Phase 1: Foundation (Day 1-2)

- [ ] Create ZeroShield monorepo skeleton
- [ ] Copy `enums.py` → `zeroshield/shared/enums.py` (verbatim)
- [ ] Copy `progress_writer.py` → `zeroshield/shared/progress.py` (verbatim)
- [ ] Copy `qdrant_utils.py` → `zeroshield/shared/qdrant.py` (change collection names)
- [ ] Copy `base_summary_manager.py` → `zeroshield/shared/summarizer.py` (verbatim)
- [ ] Set up `pyproject.toml` with shared dependencies from DevSecShield worker
- [ ] Verify imports work with `python -c "from zeroshield.shared.enums import *"`

### Phase 2: Models (Day 2-3)

- [ ] Copy `schema.py` → `zeroshield/shared/models.py`
- [ ] Remove DevSecShield-only models (IAC, LLM, MCP, CBOM variants)
- [ ] Add `DockerVulnerability`, `BehavioralFinding`, `SupplyChainFinding`
- [ ] Copy `parsers/` → `zeroshield/shared/parsers/`
- [ ] Update parser imports
- [ ] Test: `from zeroshield.shared.models import BaseVulnerability, DependencyVulnerability`

### Phase 3: LLM & Utilities (Day 3-4)

- [ ] Copy `base_utilities.py` → `zeroshield/shared/llm.py`
- [ ] Change cache path to `.zeroshield_llm_cache.db`
- [ ] Verify `_JsonSchemaOutputParser` fuzzy enum matching works standalone
- [ ] Copy `s3_utils.py` → `zeroshield/shared/s3.py`
- [ ] Test: LLM init with Haiku and Sonnet model IDs

### Phase 4: Core Logic (Day 4-6)

- [ ] Extract NVD client from `output_model.py` → `zeroshield/shared/cve_client.py`
- [ ] Change MongoDB database name to `zeroshield_db`
- [ ] Add OSV.dev, GHSA, CISA KEV sources alongside NVD
- [ ] Extract retry logic from `base_context.py` → `zeroshield/shared/context.py`
- [ ] Copy `base_agent.py` → `zeroshield/shared/agent.py`
- [ ] Update all internal imports to `zeroshield.shared.*`
- [ ] Test: Create a minimal agent subclass and run `generate_structured_response()`

### Phase 5: Celery Infrastructure (Day 6-7)

- [ ] Extract Celery config pattern from `scan_worker.py` → `zeroshield/worker/celery_config.py`
- [ ] Rename Celery app from `'worker'` to `'zeroshield_worker'`
- [ ] Extract `get_celery_app()` from `celery_connection.py` → `zeroshield/api/celery_client.py`
- [ ] Remove all DevSecShield model imports from celery utilities
- [ ] Create placeholder tasks for 5 ZeroShield workers (SCA, SAST, Behavioral, AI, Docker)
- [ ] Test: Submit task to RabbitMQ and verify it's received

### Phase 6: Frontend Bootstrap (Day 7-8)

- [ ] `npx create-next-app@latest zeroshield-dashboard`
- [ ] Copy `components.json` and run `npx shadcn@latest init`
- [ ] Copy `frontend/components/ui/` directory (all shadcn components)
- [ ] Copy `frontend/components/charts/` directory (adapt data types)
- [ ] Copy `frontend/hooks/use-sse.ts`
- [ ] Copy `frontend/components/error-boundary.tsx`
- [ ] Copy `frontend/components/theme-provider.tsx`
- [ ] Copy Tailwind config
- [ ] Set `output: 'export'` in `next.config.ts` for Phase 1 static deployment
- [ ] Test: `npm run build && npm run export` produces static HTML

### Phase 7: Validation & Cleanup (Day 8-9)

- [ ] Run full import check: all `zeroshield.shared.*` modules importable
- [ ] Verify no remaining `devsecshield` or `helpers.context` references
- [ ] Verify no DevSecShield-specific MongoDB collection names
- [ ] Verify no hardcoded DevSecShield env vars
- [ ] Run type checking with mypy/pyright on extracted code
- [ ] Document which DevSecShield commit SHA was used as extraction source

---

## Effort Summary

| Category | Hours |
|----------|-------|
| Phase 1: Foundation | 3 |
| Phase 2: Models | 6 |
| Phase 3: LLM & Utilities | 5 |
| Phase 4: Core Logic | 14 |
| Phase 5: Celery Infrastructure | 7 |
| Phase 6: Frontend Bootstrap | 8 |
| Phase 7: Validation | 4 |
| **Total Extraction** | **~47 hours** |
| **Estimated without reuse (from scratch)** | **~120 hours** |
| **Time saved by extraction** | **~73 hours (61%)** |

The biggest savings come from the NVD client + caching (would take 15-20h to build from scratch), the BaseAgent + BaseUtilities pattern (15-20h), and the frontend component library (15-20h).

---

## Appendix: Dependency Matrix

```
Package                    DevSecShield  ZeroShield  Shared?
─────────────────────────  ────────────  ──────────  ───────
celery                     ✅            ✅          ✅
pydantic                   ✅            ✅          ✅
pymongo                    ✅            ✅          ✅
langchain-aws              ✅            ✅          ✅
langchain-qdrant           ✅            ✅          ✅
qdrant-client              ✅            ✅          ✅
rich                       ✅            ✅          ✅
sqlmodel                   ✅            ✅          ✅
requests                   ✅            ✅          ✅
langsmith                  ✅            ✅          ✅
fastapi                    ✅            ✅          ✅
semgrep                    ✅            ✅          ✅
nvd-client                 ✅            ✅          ✅
psycopg2-binary            ✅            ✅          ✅
bcrypt/passlib             ✅            ❌          ─
python-jose                ✅            ❌          ─
garak                      ✅            ❌          ─
selenium                   ✅            ❌          ─
reportlab                  ✅            ❌          ─
atlassian-python-api       ✅            ❌          ─
msal                       ✅            ❌          ─
grype (CLI)                ❌            ✅          ─
trivy (CLI)                ❌            ✅          ─
```
