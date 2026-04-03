# Deterministic Scan Results — Tier 1 Cache-First Architecture Plan

> **Status**: Plan Only — No code edits until approved  
> **Goal**: Same scan input → identical scan output, every time  
> **Approach**: Cache-First + Intermediate Determinism Hardening  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Why This Is the Only Permanent Solution](#2-why-this-is-the-only-permanent-solution)
3. [Architecture Overview](#3-architecture-overview)
4. [Non-Determinism Sources & Fixes](#4-non-determinism-sources--fixes)
5. [Input Hashing Strategy](#5-input-hashing-strategy)
6. [MongoDB Cache Schema](#6-mongodb-cache-schema)
7. [Cache Flow: Lookup → Compute → Store](#7-cache-flow-lookup--compute--store)
8. [Per-Scanner Implementation Details](#8-per-scanner-implementation-details)
9. [File-by-File Change List](#9-file-by-file-change-list)
10. [Cache Invalidation Strategy](#10-cache-invalidation-strategy)
11. [Performance Impact Analysis](#11-performance-impact-analysis)
12. [Risk Assessment & Mitigations](#12-risk-assessment--mitigations)
13. [Testing & Verification Strategy](#13-testing--verification-strategy)
14. [Implementation Order](#14-implementation-order)
15. [Rollback Plan](#15-rollback-plan)

---

## 1. Executive Summary

DevSecShield's scan results vary between runs even with identical input because the pipeline has **7 compounding layers of non-determinism**. The LLM API (`responses.parse()`) provides **no determinism guarantees** — no `seed` parameter, no `temperature` control, and OpenAI explicitly states outputs are "not guaranteed" to be deterministic.

**The only permanent solution is application-level caching**: hash the scan input, look up previous results in MongoDB, and return cached results for matching inputs. First-time scans still run the full AI pipeline (preserving scan quality). Subsequent identical scans return cached results instantly (guaranteeing determinism + improving performance).

Additionally, we harden all intermediate steps (document sorting, RAG result ordering, deterministic IDs) to minimize variance on cache misses and improve cache utility.

---

## 2. Why This Is the Only Permanent Solution

### Evidence Trail

| Approach | Why It Fails |
|----------|-------------|
| `temperature=0` | OpenAI: "Deterministic outputs are not guaranteed" even with temperature=0 + seed. GPU floating-point rounding varies across server instances. |
| `seed` parameter | `responses.parse()` does NOT support `seed`. Only `chat.completions.create()` does, but DevSecShield uses responses API. Even with seed, OpenAI disclaims determinism. |
| `top_p` control | `responses.parse()` does NOT support `top_p`. |
| Fix intermediate sorting only | Reduces variance but does NOT eliminate it. LLM itself still produces different outputs for identical prompts. 10+ LLM calls per scan → variance compounds exponentially. |
| Majority voting (run N times) | 3x cost, 3x latency, still NOT 100% deterministic. Intersection logic loses real vulnerabilities. |
| Remove LLM entirely (Semgrep-only) | Eliminates AI value proposition. Semgrep alone misses business logic and architectural vulnerabilities. Fundamentally changes the product. |
| Switch to local LLM with fixed seed | Requires self-hosted GPU infrastructure. Still not guaranteed across hardware. Massive operational complexity. |
| OpenAI prompt caching / stored completions | Only caches identical prompt text. Different document order → different prompt → cache miss. Doesn't solve the problem. |

### Why Cache-First Works

- **Mathematical guarantee**: `hash(input) → lookup(cache) → return(stored_result)` is deterministic by definition
- **Zero quality loss**: First scan runs the full AI pipeline at maximum quality
- **Performance bonus**: Cached results return in milliseconds instead of minutes
- **Graceful degradation**: Cache miss → full scan runs normally, result gets cached for next time
- **Open-source precedent**: `AndrewBz512/llm-configs` recommends semantic caching for "90% latency reduction" and "consistent responses" in SecOps LLM pipelines. `ThreatGateAI` uses layered caching to avoid redundant LLM calls.

---

## 3. Architecture Overview

```
                    ┌─────────────────────┐
                    │   Scan Request       │
                    │ (repo URL, config,   │
                    │  language, excludes)  │
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │  1. Compute Input    │
                    │     Content Hash     │
                    │  (SHA-256 of sorted  │
                    │   file contents +    │
                    │   scan config)       │
                    └─────────┬───────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │  2. MongoDB Cache    │◄──── Collection: `scan_result_cache`
                    │     Lookup           │
                    │  (input_hash match?) │
                    └────┬───────────┬─────┘
                         │           │
                    HIT  │           │  MISS
                         ▼           ▼
              ┌──────────────┐  ┌──────────────────┐
              │ 3a. Return   │  │ 3b. Run Full     │
              │ Cached       │  │ Scan Pipeline    │
              │ Results      │  │ (with sorting    │
              │ (instant)    │  │  hardening)      │
              └──────────────┘  └────────┬─────────┘
                                         │
                                         ▼
                                ┌──────────────────┐
                                │ 4. Store Results  │
                                │ in Cache          │
                                │ (input_hash →     │
                                │  scan_results)    │
                                └──────────────────┘
```

---

## 4. Non-Determinism Sources & Fixes

### Layer 1: Filesystem Document Loading Order (CRITICAL)

**Source**: `GenericLoader.from_filesystem(glob="**/*")` in `codebase_context.py` returns files in OS-dependent order. Different file order → different document batches → different map-reduce summaries → entirely different logical components.

**Fix**: Sort all loaded documents by their `metadata['source']` (file path) before any processing.

**File**: `RabbitMQ/worker/helpers/context/codebase_context.py`  
**Function**: `load_documents_of_extension()` — sort the `documents` list by `document.metadata['source']` after the iteration loop completes, before returning.

### Layer 2: LLM Inherent Non-Determinism (CRITICAL)

**Source**: `responses.parse()` produces different structured outputs for identical prompts. No `seed` parameter available. OpenAI GPU floating-point rounding varies.

**Fix**: Cannot be fixed at API level → **Cache-First Architecture** is the solution. Additionally, set `temperature=0` on all LangChain `ChatOpenAI` calls where supported (already done for map-reduce via `base_utilities.py`).

**File**: Multiple — the cache layer wraps the entire scan output.

### Layer 3: Qdrant RAG Tied-Score Ordering (HIGH)

**Source**: `similarity_search()` in `base_agent.py` returns documents with tied relevance scores in non-deterministic order. Different RAG context order → different LLM prompt → different output.

**Fix**: Sort RAG results by `document.metadata['source']` (file path) as a secondary sort after retrieval.

**File**: `RabbitMQ/worker/helpers/context/base_agent.py`  
**Function**: `query_vector_store()` — sort the `docs` list by `doc.metadata.get('source', '')` before returning.

### Layer 4: UUID Context IDs Per Run (MEDIUM)

**Source**: `uuid.uuid4() + datetime` in `codebase_context.py` and `open_source_context.py` generates a unique context ID every run. While this is used for Qdrant filtering (not direct non-determinism cause), it prevents cross-run Qdrant cache reuse.

**Fix**: Replace UUID with a hash-based context ID derived from the input content. `SHA-256(sorted file paths + sorted file contents)[:32]`. This makes the context ID deterministic for identical input, enabling potential Qdrant-level cache hits.

**Files**: 
- `RabbitMQ/worker/helpers/context/codebase_context.py` — `save_documents_to_vector_store_and_return_context_id()`
- `RabbitMQ/worker/helpers/context/open_source_context.py` — `save_results_to_vector_store_and_return_context_id()`

### Layer 5: Logical Component Extraction Variance (HIGH)

**Source**: Map-reduce pipeline (`base_context.py`) batches documents 10 at a time. Each batch goes through LLM → different logical components extracted. Even with sorted documents, the LLM's map step produces different component titles/descriptions.

**Fix**: This is addressed by the cache layer (identical input → cached logical components). For cache misses, sorted document order ensures consistent batching, which reduces (but doesn't eliminate) variance.

### Layer 6: No Intermediate Result Caching (HIGH)

**Source**: Every scan re-runs the entire pipeline from scratch: clone repo → load files → vector store → map-reduce → RAG queries → vulnerability analysis. Each LLM call introduces variance that compounds.

**Fix**: The cache layer stores the final scan results. For enhanced determinism, we can also cache intermediate results (logical components, map-reduce summaries) keyed by content hash, but the primary cache at the scan-result level is sufficient.

### Layer 7: Output Sorting (LOW — Already Partially Fixed)

**Source**: Final vulnerability list ordering was previously non-deterministic.

**Fix**: Already fixed in `to_dict_list()` with `sort(key=lambda row: json.dumps(row, sort_keys=True))`. No further action needed.

---

## 5. Input Hashing Strategy

### What Constitutes "Same Input"?

For a scan to be considered identical, ALL of the following must match:

| Component | How to Capture |
|-----------|---------------|
| Source code files | SHA-256 of concatenated sorted file contents |
| File paths | Sorted list of relative file paths |
| Scan type | String: `sast`, `dast`, `iac`, `sbom_sca`, `mcp`, `llm_benchmark` |
| App language | String: `python`, `javascript`, etc. |
| Exclude path arrays | JSON-serialized sorted exclude arrays |
| Include path arrays | JSON-serialized sorted include arrays |
| LLM model | String: `gpt-5-nano` (or whatever model is configured) |

### Hash Computation Algorithm

```
1. Clone/extract the repository to a temporary directory
2. Walk the directory, collecting all files matching the language filter
3. Apply exclude/include path filtering
4. Sort the remaining file paths alphabetically
5. For each file (in sorted order):
   a. Read file contents
   b. Append: f"{relative_path}\n{file_contents}\n---FILE_BOUNDARY---\n"
6. Concatenate scan config: f"{scan_type}|{app_lang}|{sorted_excludes_json}|{sorted_includes_json}|{llm_model}"
7. Compute: SHA-256(all_file_contents + scan_config)
8. The resulting hash is the cache key
```

### Per-Scanner Hash Inputs

| Scanner | Hash Input = |
|---------|-------------|
| **SAST** | sorted(file contents by path) + language + exclude_arrays + include_arrays + model |
| **IaC** | sorted(file contents by path) + language + exclude_arrays + model |
| **SCA/SBOM** | sorted(file contents by path) + language + model (Grype results are deterministic, but LLM summary varies) |
| **MCP** | MCP server config (host, port, tools) + model |
| **LLM Benchmark** | sorted(probe list) + target model config + model |
| **DAST** | target URL + scan config + scanner type (wapiti/zap) + model |

### Edge Cases

- **Git commit hash shortcut**: For Git-based scans, we can use `{repo_url}:{commit_hash}:{scan_config_hash}` as a fast cache key instead of hashing all file contents. This is faster but requires the repo to be committed (no dirty working tree).
- **Zip uploads**: For zip-based scans, hash the zip file contents directly.
- **Large repos**: For repos with 10,000+ files, use a Merkle tree approach: hash individual files, then hash the sorted list of file hashes. This avoids loading all file contents into memory at once.

---

## 6. MongoDB Cache Schema

### Collection: `scan_result_cache`

```json
{
  "_id": "ObjectId",
  "input_hash": "sha256_hex_string",           // PRIMARY LOOKUP KEY (indexed)
  "scan_type": "sast|iac|sbom_sca|mcp|llm_benchmark|dast",
  "app_lang": "python|javascript|...",
  "team_id": "string",                          // For multi-tenant isolation
  "scan_config": {                               // Stored for debugging/auditing
    "exclude_path_arrays": [...],
    "include_path_arrays": [...],
    "llm_model": "gpt-5-nano",
    "repo_url": "string|null",
    "commit_hash": "string|null"
  },
  "scan_results": {                              // The cached scan output
    "vulnerabilities": [...],                    // Exact output of to_dict_list()
    "metadata": {...},                           // Exact metadata from agent
    "dependency_diagram": "string|null",         // IaC only
    "model_vulnerabilities": [...],              // LLM Benchmark only
    "tools": [...],                              // MCP only
    "prompts": [...],                            // MCP only
    "resources": [...]                           // MCP only
  },
  "created_at": "ISODate",
  "last_accessed_at": "ISODate",                 // Updated on cache hit
  "access_count": 0,                             // Incremented on cache hit
  "ttl_days": 30,                                // Default TTL
  "cache_version": "1.0"                         // For schema migrations
}
```

### Indexes

```javascript
// Primary lookup index (unique)
db.scan_result_cache.createIndex({ "input_hash": 1 }, { unique: true })

// TTL index for automatic expiration
db.scan_result_cache.createIndex({ "created_at": 1 }, { expireAfterSeconds: 2592000 }) // 30 days

// Query by team + type (for cache management UI)
db.scan_result_cache.createIndex({ "team_id": 1, "scan_type": 1 })
```

---

## 7. Cache Flow: Lookup → Compute → Store

### Phase A: Pre-Scan Cache Check (New Code)

```
Location: Each agent's `run_agent()` method, BEFORE any processing

1. Agent receives scan input (context, zip_context, config)
2. Clone/extract repo to temp directory (this step already exists)
3. NEW: Compute input_hash using the strategy from Section 5
4. NEW: Query MongoDB scan_result_cache: find_one({"input_hash": input_hash})
5. IF cache hit:
   a. Update last_accessed_at and increment access_count
   b. Return cached scan_results directly (skip all LLM/vector store work)
   c. Clean up temp directory
   d. Done — instant deterministic result
6. IF cache miss:
   a. Continue with full scan pipeline (existing code)
   b. After scan completes (BEFORE returning), store results in cache
   c. Return results normally
```

### Phase B: Store Results After Scan (New Code)

```
Location: Each agent's `run_agent()` method, AFTER scan completes but BEFORE cleanup

1. Scan has completed normally
2. Serialize scan results into the cache schema format
3. Insert into scan_result_cache with input_hash as key
4. Use upsert to handle race conditions (two workers scanning same input)
5. Proceed with normal cleanup and return
```

### Phase C: Cache Bypass Option (New Code)

```
Location: Scan start endpoint and worker task

1. Add optional `force_rescan: bool = False` parameter to scan start API
2. If force_rescan=True:
   a. Skip cache lookup
   b. Run full scan
   c. Store new results (overwriting previous cache entry)
3. This allows users to explicitly request fresh analysis when needed
```

---

## 8. Per-Scanner Implementation Details

### 8.1 SAST Agent

**Current flow**: `populate_opensource_context()` → `populate_codebase_context()` → loop logical components → `analyze_logical_component_and_append_vulnerabilities()` → return

**Cache integration point**: `run_agent()` in `RabbitMQ/worker/helpers/tools/sast_agent/main.py`

**Hash inputs**: 
- All `.py` (or language-specific) files after exclusion, sorted by path
- `app_lang`, `exclude_path_arrays`, LLM model

**Cached output shape**:
```python
{
  "vulnerabilities": [...],  # Output of self.to_dict_list(self.vulnerabilities)
  "metadata": {...}          # self.metadata (included/excluded document lists)
}
```

**Additional hardening**:
1. Sort documents in `load_documents_of_extension()` by `metadata['source']` before returning
2. Sort RAG results in `query_vector_store()` by `metadata['source']` before returning
3. Sort `logical_components.logical_components` by `title` before the analysis loop

### 8.2 IaC Agent

**Current flow**: `prepare_context()` for vulnerabilities → `prepare_context()` for dependency diagram → return

**Cache integration point**: `run_agent()` in IaC agent's main file

**Hash inputs**:
- All IaC files (`.tf`, `.yaml`, `.yml`, `.json`, etc.) sorted by path
- `app_lang`, `exclude_path_arrays`, LLM model

**Cached output shape**:
```python
{
  "vulnerabilities": [...],           # Output of to_dict_list()
  "dependency_diagram": "string",     # Mermaid diagram
  "metadata": {...}
}
```

### 8.3 SCA/SBOM Agent

**Current flow**: Run Grype → chunk findings → map-reduce summary → return

**Cache integration point**: `run_agent()` in SCA/SBOM agent's main file

**Hash inputs**:
- All dependency files (package.json, requirements.txt, Gemfile, etc.) sorted by path
- Grype version (if available), LLM model

**Cached output shape**:
```python
{
  "vulnerabilities": [...]  # Output of to_dict_list()
}
```

**Note**: Grype scan itself IS deterministic. The non-determinism comes from the LLM summary. Caching the final LLM-summarized output solves this.

### 8.4 MCP Agent

**Current flow**: Connect to MCP server → enumerate tools/prompts/resources → LLM analyze each → return

**Cache integration point**: `run_agent()` in MCP agent's main file

**Hash inputs**:
- MCP server configuration (host, port, protocol)
- Enumerated tool/prompt/resource schemas (sorted by name)
- LLM model

**Cached output shape**:
```python
{
  "tools": [...],
  "prompts": [...],
  "resources": [...]
}
```

### 8.5 LLM Benchmark Agent

**Current flow**: Run Garak probes → map-reduce → summarize vulnerabilities + model vulnerabilities → return

**Cache integration point**: `run_agent()` in LLM Benchmark agent's main file

**Hash inputs**:
- Probe configuration (sorted probe list)
- Target model configuration
- LLM model for analysis

**Cached output shape**:
```python
{
  "vulnerabilities": [...],
  "model_vulnerabilities": [...]
}
```

### 8.6 DAST Agent (Separate Worker)

**Current flow**: Run Wapiti/ZAP against target URL → LLM analyze results → return

**Cache integration point**: `run_agent()` in DAST agent's main file (`RabbitMQ/dast_worker/`)

**Hash inputs**:
- Target URL
- Scanner type (wapiti/zap)
- Scan configuration
- LLM model

**Cached output shape**:
```python
{
  "vulnerabilities": [...]
}
```

**Special consideration**: DAST scans target live URLs. The target application may change between scans even with the same URL. Cache should use a shorter TTL (e.g., 1 hour) or require explicit opt-in for DAST caching.

---

## 9. File-by-File Change List

### New Files to Create

| # | File | Purpose |
|---|------|---------|
| 1 | `RabbitMQ/worker/helpers/cache/scan_cache.py` | Core cache module: `ScanResultCache` class with `compute_hash()`, `lookup()`, `store()`, `invalidate()` methods |
| 2 | `RabbitMQ/worker/helpers/cache/__init__.py` | Package init |
| 3 | `RabbitMQ/dast_worker/helpers/cache/scan_cache.py` | Cache module for DAST worker (same logic, different import paths) |
| 4 | `RabbitMQ/dast_worker/helpers/cache/__init__.py` | Package init |

### Existing Files to Modify

| # | File | Change | Lines Affected (Approx) |
|---|------|--------|------------------------|
| 1 | `RabbitMQ/worker/helpers/context/codebase_context.py` | Sort documents by `metadata['source']` in `load_documents_of_extension()` after the for loop | ~2 lines added |
| 2 | `RabbitMQ/worker/helpers/context/base_agent.py` | Sort RAG results by `metadata.get('source', '')` in `query_vector_store()` before return | ~1 line added |
| 3 | `RabbitMQ/worker/helpers/tools/sast_agent/main.py` | Add cache lookup at start of `run_agent()`, cache store before cleanup, sort logical components by title before loop | ~30 lines added |
| 4 | IaC agent main file | Add cache lookup/store in `run_agent()` | ~25 lines added |
| 5 | SCA/SBOM agent main file | Add cache lookup/store in `run_agent()` | ~25 lines added |
| 6 | MCP agent main file | Add cache lookup/store in `run_agent()` | ~25 lines added |
| 7 | LLM Benchmark agent main file | Add cache lookup/store in `run_agent()` | ~25 lines added |
| 8 | `RabbitMQ/dast_worker/` DAST agent main file | Add cache lookup/store in `run_agent()` | ~25 lines added |
| 9 | `RabbitMQ/worker/scan_worker.py` | Pass `force_rescan` flag from task args to agent | ~5 lines per task |
| 10 | `backend/routers/scans.py` | Accept `force_rescan` parameter in scan start endpoint | ~3 lines added |
| 11 | `backend/new_models.py` | Add `force_rescan` field to scan data model (optional, default False) | ~1 line added |

### Files NOT Modified (Confirmed Safe)

| File | Why No Change Needed |
|------|---------------------|
| `base_context.py` | Map-reduce batching order is deterministic IF input documents are sorted (fixed in `codebase_context.py`) |
| `base_utilities.py` | `get_llm()` already uses `temperature=0.0`. No further tuning possible. |
| `summary_manager.py` | Prompts are static strings. No non-determinism source. |
| `schema.py` | Pydantic models are structural. No ordering issues. |
| `semgrep_util.py` | Semgrep is inherently deterministic. No change needed. |
| `open_source_context.py` | The UUID context ID doesn't affect determinism when cache is in place. Optional future optimization. |

---

## 10. Cache Invalidation Strategy

### Automatic Invalidation

| Trigger | Action |
|---------|--------|
| Code content changes | Different input hash → automatic cache miss → fresh scan |
| Scan config changes | Different input hash → automatic cache miss → fresh scan |
| TTL expiration | MongoDB TTL index auto-deletes entries after 30 days |
| LLM model change | Model name is part of hash input → automatic cache miss |

### Manual Invalidation

| Trigger | Action |
|---------|--------|
| `force_rescan=True` | Skip cache lookup, run full scan, overwrite cached result |
| Admin cache clear | API endpoint to clear cache by team_id, scan_type, or all |
| Model version update | Bump `cache_version` field → existing cache entries with old version are ignored |

### Cache Versioning

- Include a `CACHE_VERSION = "1.0"` constant in `scan_cache.py`
- Store it in every cache entry
- On lookup, only return entries matching current `CACHE_VERSION`
- Bump version when: scan prompts change, output schema changes, major model update

---

## 11. Performance Impact Analysis

### Cache Hit Path (Deterministic + Fast)

| Metric | Before (No Cache) | After (Cache Hit) |
|--------|-------------------|-------------------|
| Latency | 60-180 seconds | < 500ms |
| LLM API calls | 10-30 per scan | 0 |
| OpenAI cost | $0.02-0.15 per scan | $0 |
| Qdrant queries | 20-40 per scan | 0 |
| Deterministic? | No | **Yes (guaranteed)** |

### Cache Miss Path (First Scan)

| Metric | Before | After (Cache Miss) |
|--------|--------|-------------------|
| Latency | 60-180 seconds | 60-180 seconds + ~50ms (hash + store) |
| LLM API calls | Same | Same |
| Deterministic? | No | No (but result gets cached for next time) |

### Storage Overhead

- Average cache entry size: ~5-50 KB (JSON vulnerability data)
- 10,000 cached scans ≈ 50-500 MB in MongoDB
- MongoDB handles this easily with proper indexing

---

## 12. Risk Assessment & Mitigations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Cache returns stale results for changed code | LOW | Input hash includes ALL file contents — any code change = cache miss |
| Cache grows unbounded | LOW | MongoDB TTL index auto-expires after 30 days. Rarely-accessed entries expire first. |
| Race condition: two workers scan same input simultaneously | LOW | Use MongoDB `upsert` — last writer wins, both produce valid results |
| Hash collision (different inputs, same hash) | NEGLIGIBLE | SHA-256 collision probability is ~10^-77. Not a practical concern. |
| Cache entry corruption | LOW | Validate cache entry structure on read. On validation failure, treat as cache miss. |
| `force_rescan` abuse by users | LOW | Rate-limit force_rescan to N per team per hour. Log all force_rescan requests. |
| MongoDB connection failure during cache check | MEDIUM | Wrap cache lookup in try/except. On failure, proceed with full scan (graceful degradation). |
| New vulnerability patterns missed due to caching | LOW | 30-day TTL ensures periodic refresh. `force_rescan` available for immediate refresh. Admin can bump cache version to invalidate all. |

---

## 13. Testing & Verification Strategy

### Test 1: Determinism Proof (PRIMARY)

```
1. Select a test repository (small, 10-20 files)
2. Run SAST scan 5 times with identical configuration
3. Compare all 5 results: they MUST be byte-identical JSON
4. First run may take 60+ seconds (cache miss)
5. Runs 2-5 MUST complete in < 1 second (cache hit)
6. All 5 results MUST be identical
```

### Test 2: Cache Invalidation

```
1. Run SAST scan on test repo → cache stored
2. Modify one file in the repo
3. Run SAST scan again → MUST be cache miss (different hash)
4. New result MAY differ from previous (expected — code changed)
5. Run same scan again → MUST hit cache, identical to step 3
```

### Test 3: Force Rescan

```
1. Run SAST scan → result A (cached)
2. Run same scan with force_rescan=True → result B (fresh)
3. Result B MAY differ from A (LLM non-determinism on fresh run)
4. Run same scan again (no force) → result = B (new cache entry)
```

### Test 4: Cross-Scanner Verification

```
Repeat Test 1 for each scanner type:
- SAST ✓
- IaC ✓
- SCA/SBOM ✓
- MCP ✓
- LLM Benchmark ✓
- DAST ✓ (with URL-based hash)
```

### Test 5: Sorting Hardening Verification

```
1. Disable cache (or use fresh test)
2. Run SAST scan 3 times
3. Compare logical components extracted → should be MORE consistent
   than before sorting fix (may still vary due to LLM, but batching is stable)
4. Compare RAG context passed to LLM → should be identical order
```

### Test 6: Performance Regression

```
1. Measure: scan latency without cache (baseline)
2. Measure: scan latency first run with cache enabled (should be baseline + ~50ms)
3. Measure: scan latency on cache hit (should be < 500ms)
4. Verify: no memory leaks from hash computation on large repos
```

---

## 14. Implementation Order

### Phase 1: Core Cache Module (Day 1)

| Step | Task | File |
|------|------|------|
| 1.1 | Create `ScanResultCache` class with `compute_hash()`, `lookup()`, `store()` | `RabbitMQ/worker/helpers/cache/scan_cache.py` |
| 1.2 | Unit test the cache module with mock MongoDB | Test file |
| 1.3 | Create MongoDB collection and indexes | MongoDB init script |

### Phase 2: Intermediate Determinism Hardening (Day 1-2)

| Step | Task | File |
|------|------|------|
| 2.1 | Sort loaded documents by file path | `codebase_context.py` |
| 2.2 | Sort RAG results by metadata source | `base_agent.py` |
| 2.3 | Verify sorting with logging | Test run |

### Phase 3: SAST Agent Integration (Day 2)

| Step | Task | File |
|------|------|------|
| 3.1 | Add cache lookup at start of `run_agent()` | `sast_agent/main.py` |
| 3.2 | Add cache store before cleanup | `sast_agent/main.py` |
| 3.3 | Sort logical components by title before analysis loop | `sast_agent/main.py` |
| 3.4 | Run Test 1 (5x determinism proof) | Manual verification |
| 3.5 | Run Test 2 (cache invalidation) | Manual verification |

### Phase 4: Other Scanner Integration (Day 3)

| Step | Task | File |
|------|------|------|
| 4.1 | Integrate cache into IaC agent | IaC agent main file |
| 4.2 | Integrate cache into SCA/SBOM agent | SCA/SBOM agent main file |
| 4.3 | Integrate cache into MCP agent | MCP agent main file |
| 4.4 | Integrate cache into LLM Benchmark agent | LLM Benchmark agent main file |
| 4.5 | Run Test 4 for each scanner | Manual verification |

### Phase 5: DAST Worker Integration (Day 3-4)

| Step | Task | File |
|------|------|------|
| 5.1 | Create DAST cache module | `dast_worker/helpers/cache/scan_cache.py` |
| 5.2 | Integrate cache into DAST agent | DAST agent main file |
| 5.3 | Test DAST caching with shorter TTL | Manual verification |

### Phase 6: API Layer Integration (Day 4)

| Step | Task | File |
|------|------|------|
| 6.1 | Add `force_rescan` to scan start endpoint | `backend/routers/scans.py` |
| 6.2 | Pass `force_rescan` through Celery task | `scan_worker.py` |
| 6.3 | Add frontend toggle (optional) | Frontend scan config UI |

### Phase 7: Full System Test (Day 5)

| Step | Task |
|------|------|
| 7.1 | Run all 6 test scenarios |
| 7.2 | Performance benchmark (cache hit vs miss) |
| 7.3 | Docker image rebuild and push |
| 7.4 | Deploy to production |
| 7.5 | Production smoke test (5x same scan) |

---

## 15. Rollback Plan

### If Cache Causes Issues

1. **Quick disable**: Set environment variable `SCAN_CACHE_ENABLED=false`
   - Cache module checks this flag
   - When disabled, all scans run full pipeline (pre-change behavior)
   - No code changes needed to rollback

2. **Cache corruption**: Run `db.scan_result_cache.drop()` in MongoDB
   - All scans will run fresh on next request
   - Cache rebuilds naturally

3. **Full rollback**: Revert the Git commits
   - Sorting hardening changes are harmless (sorting is always safe)
   - Cache module is isolated — removing it has zero impact on scan logic
   - Worker code changes are additive (cache check + store) with try/except guards

### Feature Flag Design

```python
# In scan_cache.py
import os

SCAN_CACHE_ENABLED = os.getenv("SCAN_CACHE_ENABLED", "true").lower() == "true"

class ScanResultCache:
    def lookup(self, input_hash: str) -> dict | None:
        if not SCAN_CACHE_ENABLED:
            return None  # Always cache miss when disabled
        # ... normal lookup logic

    def store(self, input_hash: str, results: dict) -> bool:
        if not SCAN_CACHE_ENABLED:
            return True  # No-op when disabled
        # ... normal store logic
```

---

## Appendix A: `ScanResultCache` Class Design

```python
class ScanResultCache:
    """
    MongoDB-backed cache for deterministic scan results.
    
    Usage:
        cache = ScanResultCache(mongo_client)
        
        # Compute hash from scan inputs
        input_hash = cache.compute_input_hash(
            file_contents=sorted_file_dict,
            scan_type="sast",
            app_lang="python",
            scan_config=config_dict,
        )
        
        # Check cache
        cached = cache.lookup(input_hash)
        if cached:
            return cached["scan_results"]
        
        # Run full scan...
        results = agent.run_agent()
        
        # Store results
        cache.store(
            input_hash=input_hash,
            scan_type="sast",
            app_lang="python",
            team_id=team_id,
            scan_config=config_dict,
            scan_results=results,
        )
    """

    CACHE_VERSION = "1.0"
    COLLECTION_NAME = "scan_result_cache"
    DEFAULT_TTL_DAYS = 30

    def __init__(self, mongo_client):
        self.db = mongo_client.get_database("new_devsecshield_backend_server_db")
        self.collection = self.db[self.COLLECTION_NAME]

    def compute_input_hash(self, file_contents: dict, scan_type: str, 
                           app_lang: str, scan_config: dict) -> str:
        """Compute SHA-256 hash of sorted file contents + scan configuration."""
        ...

    def lookup(self, input_hash: str) -> dict | None:
        """Look up cached results. Returns None on miss."""
        ...

    def store(self, input_hash: str, scan_type: str, app_lang: str,
              team_id: str, scan_config: dict, scan_results: dict) -> bool:
        """Store scan results in cache. Uses upsert for thread safety."""
        ...

    def invalidate(self, input_hash: str) -> bool:
        """Delete a specific cache entry."""
        ...

    def invalidate_by_team(self, team_id: str) -> int:
        """Delete all cache entries for a team. Returns count deleted."""
        ...
```

---

## Appendix B: Open-Source Research Evidence

| Source | Key Insight | Applied To |
|--------|------------|------------|
| [ThreatGateAI](https://github.com/vvoffsec/ThreatGateAI) | Three-layer detection: deterministic → Semgrep → LLM. LLM is NOT source of truth. Result caching avoids redundant LLM calls. | Validates that caching is the industry-accepted approach. We keep LLM as source of truth but cache its output. |
| [llm-configs](https://github.com/AndrewBz512/llm-configs) | SecOps LLM templates use `temp=0.0-0.1` + semantic caching for "90% latency reduction" and "consistent responses — same query = same output". | Directly validates Tier 1 approach. Semantic caching = same concept as our input-hash cache. |
| OpenAI API Documentation | `responses.parse()` does NOT support `seed`, `temperature`, or `top_p`. Even `chat.completions.create()` with `seed` does NOT guarantee determinism. | Proves no API-level solution exists. Application-level caching is the only option. |
| GitHub Code Search | Zero results for "openai responses.parse seed deterministic" across ALL of GitHub. | Confirms no one has solved this at the API level. |

---

## Appendix C: Decision Log

| Decision | Rationale |
|----------|-----------|
| Cache at scan-result level, not intermediate level | Simpler implementation, single cache lookup per scan, covers all non-determinism sources at once |
| Use MongoDB (not Redis) for cache | MongoDB already exists in stack, supports TTL indexes, handles large JSON documents, no new dependency |
| SHA-256 for hashing | Cryptographically strong, collision-resistant, fast enough for file content hashing |
| 30-day default TTL | Balances freshness (new vulnerability patterns) with determinism (cached results) |
| Include LLM model in hash | Model updates change outputs. Forces cache miss when model changes. |
| Feature flag for cache | Enables instant rollback without code changes. Essential for production safety. |
| Sort documents by path | Ensures consistent batching in map-reduce. Reduces (but doesn't eliminate) first-scan variance. |
| Sort RAG results by source | Ensures consistent prompt construction. Minor improvement but zero-cost to implement. |
| `force_rescan` parameter | Gives users explicit control when they need fresh analysis. Required for trust. |

---

*End of Plan*
