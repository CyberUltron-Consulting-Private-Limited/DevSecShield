# F1.2 inventory and tag policies: spec

Binding design: `$R6/f1/CONTRACT.md` (sections 2, 3, 5, 6, 7, 9). This spec records how F1.2 implements it and how
each acceptance criterion is proven. Branches: `feat/f1-inventory-scaffold` (PR #34, F1.2-a0) then `feat/f1-inventory`.

## Acceptance criteria (PARALLEL-PLAN.md, F1.2) and proof
| # | Criterion | Proof |
|---|---|---|
| A1 | AWS discovery through DevSecShieldScannerReadOnlyRole (EC2, RDS, EKS, ELB/ACM, KMS, Secrets Manager), across regions | moto `mock_aws` tests over 3 regions, every service, denied service = coverage gap, external-ID pre-check; live sandbox run |
| A2 | CSV/JSON import | API tests (CSV header forms, JSON list/object, errors capped at 100, 10 MB / 10,000-row caps, dry run) |
| A3 | An API | `PUT /inventory/targets` tests (≤ 1,000 per call, the "API" inventory source) |
| A4 | 1,000 targets imported in < 2 min; re-import idempotent (updates, never duplicates) | `bench/f1_inventory/import_bench.py` on PostgreSQL (1,000 and 10,000; second import 0 created / 0 updated), tests for update-not-duplicate and concurrent imports |
| A5 | Tag policies (`env=prod` → schedule, transport, never-scan) | policy CRUD + preview + materializer tests |
| A6 | Deterministic evaluation | property test: shuffled policies and targets give identical Decisions; precedence priority desc, id asc |
| A7 | UI shows which policy won when several match | target detail and list show `policy_id` (won) + `matched_policy_ids`; preview lists conflicts; screenshot |
| A8 | Live: 3–5 tagged t3.micro / db.t4g.micro (+KMS key, ACM cert) discovered, shown in UI, torn down | ledger + discovery output + screenshot + deletion confirmation |
| A9 | Scale with moto/recorded responses for 1,000 | `bench/f1_inventory/aws_bench.py`: 1,000 EC2 instances across 3 regions in moto, discovered and imported, timed |

## Design
* **Data model** (`fleet/models.py`, migrations `r6f12inv001` / `r6f12pol001`): `cbominventorysource`,
  `cbominventorytarget`, `cbomfleetpolicy`, `cbomcredential` as in contract §2; `cbomcollectionsource`
  + `managed_by_policy_id`, `credential_id`, `batch_key`; `cbomcollectionschedule` + `policy_id`. No FKs across parts.
* **Target identity**: `(team_id, external_id)` unique. AWS external id = the resource ARN. `fingerprint` = SHA-256 of
  the canonical normalised target (tags keys lower-cased, sorted lists). Upsert: unchanged fingerprint and same
  owner source and not missing → only `last_seen_at` (one bulk UPDATE per chunk); otherwise update. Inserts use
  `ON CONFLICT DO NOTHING` (PostgreSQL / SQLite) and conflicted rows go through the update pass, so two concurrent
  imports never duplicate. File import and AWS sync are snapshots of their inventory source: targets of that source
  not seen are marked `missing_since` (AWS: only for region/service scopes that were read completely). `PUT` upserts
  only; `DELETE` marks one target missing.
* **AWS discovery** (`fleet/aws_inventory.py`): config `aws_account_source_id` (an `aws_account` source of the team that
  passed validation), `regions[]`, `services[]`. Same safety rules as `aws_collect`: ZeroShield principal only
  (`_boto`), the role must refuse AssumeRole without the team's external ID, identity in the role's account. Uses
  `aws_collect._Account`. Per (region, service) status in `coverage`; denied/throttled/not enabled = gap, never silence.
* **Sync**: `POST /inventory/sources/{id}/sync` → 202 `{sync_id}` (status `queued`); `backend/workers/cbom_inventory_sync.py`
  thread (started by the cloud worker only when `CBOM_FLEET_INVENTORY` is on) claims due sources with a guarded
  UPDATE + `lease_until`, runs discovery without a DB session open, then upserts.
* **Policy engine** (`fleet/policy.py`): contract §3 grammar and rules. Never-scan list (any address or the hostname)
  wins; then enabled, non-deleted policies by priority desc, id asc; first match wins; every match reported.
  Collect decisions only for `linux_host` targets with an address; other kinds are `unmanaged` with the reason. A
  missing/deleted credential, transport (F1.3 seam) or CA (F1.4 seam) gives `unmanaged` with the reason.
* **Materializer** (`fleet/materialize.py`, flag `CBOM_FLEET_MATERIALIZE`): sticky batches keyed
  (policy, transport, transport/credential, node/segment, kind) → managed `linux_servers` sources (name
  `fleet-<policy>-<n>`), config built through `ServersConfig` with the credential's non-secret fields and checked with
  `credential_target_problem`; a managed source with an open job is never edited (deferred); one managed schedule per
  policy with a schedule; own cap `CBOM_MAX_MANAGED_SOURCES` (2,000). Credits unchanged (`queue_run`).
* **Claim plugin** (`fleet/claim.py`): `credential_id` → secrets, for F1.1's `secret_refs.PLUGINS`.
* **Shared-file edits** (contract §5 anchors): `new_models.py` columns; `cleanup.py` `_ORDER`; `serialize.public_source`
  (`managed_by_policy_id`, `credential_id`); `cbom_cloud_worker.py` thread start; `cbom_ops.py` schedule cap ignores
  `policy_id` rows; after F1.1 merges: `planning.py` (group runs skip managed sources) and `cbom_sources.py` (managed
  sources excluded from the count; PATCH/DELETE refused); frontend `backend_api.ts` `managed_by_policy_id?`,
  `ServersTab.tsx` "Managed by policy" badge.
* **API**: contract §3 table, prefix `/{team_id}/cbom/sources/fleet`; inventory routes behind `CBOM_FLEET_INVENTORY`,
  policies / credentials / reconcile behind `CBOM_FLEET_POLICIES` (404 when off).
* **UI**: Fleet tab sections Inventory (sources, import, sync, targets with filters and the decision), Policies
  (precedence-ordered list, form with a selector builder, preview with conflicts, reconcile), Credentials.

## Risks
* Managed sources are visible to group runs until `planning.py` is edited (after F1.1): materialize stays off.
* Password / SSH-cert credentials reach the node only through F1.1's `secret_refs` plugin; until then only
  `node_key` credentials materialise usefully.
* The sandbox role has no `sts:ExternalId` condition: the production pre-check refuses it (correctly). The live proof
  shows that refusal, then runs the discovery step below the pre-check with the same `_Account` code.
