# F1 fleet onboarding: architecture contract (F1-ARCH)

Base: `dev` at 3399452 (merge of PR #16). Alembic head on dev: `rv6p1nodename001`. Written 2026-11-11 by the F1 architect
(read-only pass). Binding for F1.1 (lean node API), F1.2 (inventory and tag policies), F1.3 (transports and zs-collect)
and F1.4 (SSH CA). To change anything in it, ask the coordinator, who updates this file. All paths are repo-relative.
"Owner decisions" are fixed: agentless through the customer's AWX/AAP, SSM and Salt (salt-api); inventory and tag
policies; typed credentials; credits per run; signed read-only `zs-collect`; SSH CA with short-lived certificates;
no bundled Salt, Puppet or Chef.

---

## 1. Current architecture (dev, with evidence)

**Request flow (team UI).** Browser → `/{team_id}/cbom/sources/...` (`backend/routers/cbom_sources.py`, `BASE` at :105).
Every handler calls `http.authorize()` (`backend/utilities/cbom_sources/http.py:117`, member check), then
`require_admin` / `require_owner_or_admin` (:132-146). Refusals inside a team are **400, never 403** (the frontend
signs out on 403; router docstring :1-13). Limiters: `read_limiter`/`write_limiter` (:110-111, in-memory per worker,
`backend/utilities/ratelimit.py`). Schedules, drift and remediation routes: `backend/routers/cbom_ops.py`. Agent pools:
`backend/routers/cbom_node_pools.py`. Routers are registered in `backend/main.py:124-143`.

**Run creation.** `POST /runs` (`cbom_sources.py:1318`) → `runs.queue_run` (`utilities/cbom_sources/runs.py:32`) →
`planning.plan_run` (`planning.py:140`, loop :166; skip reasons :187-210; rates `RATES_C` :24-26) → `jobs.charge_team`
(`jobs.py:70`, one guarded UPDATE on `team.credit_balance`) → **one `collect` job per source** (`runs.py:84-98`), pinned to
`source.node_id`, or `node_id=None` for node-less kinds (cloud worker). Schedules take the same path:
`workers/cbom_scheduler.py:24` → `schedules.fire_one` (`schedules.py:175`) → `queue_run`.

**Job lifecycle** (`backend/utilities/cbom_sources/jobs.py`; table `cbomcollectionjob`, `new_models.py:418-446`).
`pending` → `claimed` (lease 15 min `LEASE` :36, attempts ≤ 3 :37, max runtime :43-44) → `success|failure|cancelled|expired`.
Every transition is a guarded `UPDATE … WHERE status=… AND lease_id=…`.
* Claim: node `claim_loop` polls every 5 s (`scan_node/zs_scan_node/agent.py:48, :294-308`) →
  `POST /cbom/node/jobs/claim` (`routers/cbom_node.py:377`) → `_authenticate` (:109; per-request nonce INSERT,
  `node_auth.py:192-199`) → `J.claim_next` (`jobs.py:519`): `reap` (:147), `_pending_for_node` (:497-516,
  `FOR UPDATE SKIP LOCKED`, **only `node_id = this node`**), `_invalid_reason` (:456), window check, guarded UPDATE
  (:552-557), `recompute_run` (:111-143, **loads every job of the run**), payload (:567-577) with
  `decrypt_secrets(source.secret_encrypted)`.
* Run: `collectors.run_job` (`scan_node/zs_scan_node/collectors/__init__.py:36`) → `JobContext.emit`
  (`jobctx.py:199`) → `POST /cbom/node/jobs/{id}/assets` (`cbom_node.py:408` → `J.add_assets` :839) →
  `POST …/result` (:428 → `J.finish_job` :753; refund :789; `recompute_run` again).
* Heartbeat every 30 s, every 5 s while busy (`cbom_node.py:53-54, :303-350`): nonce sweep, `renew_leases` (:593),
  `reap(node)`, `cancel_ids_for_node` (:648), a pending count, a busy probe.
* Cloud worker (`backend/workers/cbom_cloud_worker.py`): one job at a time; `claim_cloud_job` (`jobs.py:951`, only
  `node_id IS NULL AND kind='collect'`); kind dispatch at :100-121; `reap_all` every `REAP_EVERY_S`; starts the
  scheduler and the integration dispatcher threads (:198-203).

**Data model** (`backend/new_models.py`). `cbomscannode` :271-312 (`segment`, `mode`, `capabilities` JSON with
`collectors` list, `ssh_public_key` of the node's Ed25519 key, `signing_public_key`); `cbomnodepool` :322;
`cbomnodenonce` :342; `cbomcollectionsource` :360-386 (`kind`, `node_id`, `config` JSON, `secret_encrypted`,
`row_version`, `source_uid`); `cbomcollectionrun` :389-415; `cbomcollectionjob` :418-446; `cbomcollectedasset`
:449-473 (full copy per run); `cbomcollectionsettings` :476-503 (`network_exclusions` = never-scan list);
`cbomcollectionschedule` :562-588 (`MAX_SCHEDULES=20`, `schedules.py:42`); `cbomcollectionauditevent` :548.

**Sources and typed credentials.** Kinds registry `KINDS` (`kinds.py:771-815`, `KindSpec` :738-748: `model`,
`secret_fields`, `needs_node`, `collectable`, `where_fields`, `node_less`). Linux/Windows `credential_type`
`node_key | ssh_cert | vault | password` (`kinds.py:165, :200`); `credential_target_problem` (:215) refuses passwords
to unverified servers. Secrets: one Fernet token over a JSON object per source (`crypto.py:51-62`, key
`ENCRYPTION_KEY`), write-only in the API, decrypted at claim (`jobs.py:576, :1001`) and for scrubbing node output
(:761, :872). Changing a non-metadata config field or the secret changes `connection_version` (`jobs.py:258-277`),
which **cancels open jobs** of that source.

**Credits ledger.** No ledger table. `team.credit_balance` (float, `new_models.py:49`); per run
`credits_charged_c` / `credits_refunded_c` (:401-402, centi-credits); per job `weight_c` / `refunded` (:430-431).
Charge `jobs.py:70`; refund once per job `jobs.py:83-107` (failed, cancelled, expired, or all targets skipped).
Server targets cost 0.2 per target (`RATES_C["server"]=20`).

**Caps today.** 50 agentless nodes and 500 sources (`cbom_sources.py:107-108`, checks :267, :512-516); 500 sources
again in CMDB import (`utilities/integrations/cmdb.py:37`); 1,000 agent nodes / 50 pools (`agents.py:39-42`);
1,000 target lines per source (`targets.py:13`); 50k assets per attempt (`jobs.py:49`).

**Migrations.** Hand-written, linear, `prod_database_migrations/migrations/versions/` (14 files); applied by
`backend/docker-entrypoint.sh` (`alembic upgrade head`). No CI check for a single head today.

**Frontend.** `frontend/app/[team_id]/cbom/sources/page.tsx` (`TABS` :21-29; tab bodies :101-121);
`components/cbom/sources/*Tab.tsx` (Scan nodes = `ScanNodesTab.tsx`, Servers = `ServersTab.tsx`, `CredType` :94);
query keys `components/cbom/sources/keys.ts`; API client and CBOM types in `frontend/utils/backend_api.ts`
(5,002 lines; `CbomSourceKind` :4154-4157, `CbomSource` :4233-4258) plus per-feature files `frontend/utils/api/cbom_*.ts`.

**Where each part plugs in**

```
 inventory sources ─► [F1.2] cbominventorytarget ─► PolicyEngine ─► materializer ─► managed cbomcollectionsource
 (AWS role, CSV/JSON, API)       (tags, addresses)     (decision)     (sticky batches)   + managed schedule
                                                                                            │ existing queue_run,
                                                                                            ▼ credits, plan_run
 [F1.1] lean node API: claim by node OR node_segment (SKIP LOCKED), lease re-queue, O(1) run counters,
        no per-request INSERT, configurable caps, claim plugins (secret_refs) and capability gate
            │ claim payload {job, scope, source{config, secrets}}  (shape unchanged; additive only)
            ▼
 scan node collectors ── linux_servers (SSH; [F1.4] credential_type=ssh_ca: node key + 5-min cert)
                      └─ awx_hosts / salt_hosts ([F1.3] Transport on the node) ─► customer AWX / salt-api ─► zs-collect
 cloud worker ───────── ssm_hosts ([F1.3] Transport in the cloud worker) ─► customer SSM ─► zs-collect ─► customer S3
```

---

## 2. Data model and migration ownership

**Rules for every part.**
* New tables go in the part's **own model module** (not `new_models.py`). Columns on existing tables go in
  `new_models.py` at the anchors in section 5.
* Every new table: `id` PK, `team_id` FK `team.id` `ondelete="CASCADE"` + index, `row_version`, `created_at`,
  `last_updated` (naive UTC via `_cbom_utcnow`). Secrets only as `secret_encrypted` + `secret_fields`
  (`crypto.encrypt_secrets`), never returned (`secrets_set` instead).
* **No foreign keys across parts.** A reference to another part's row is a plain `int` validated in code, so the
  migrations of different parts can be applied in any order. Referenced rows are soft-deleted (`deleted_at`) and a
  decision that points at a deleted row says so ("transport deleted") instead of failing.
* Revision ids: F1.1 `r6f11node001…`, F1.2 `r6f12inv001…` and `r6f12pol001…`, F1.3 `r6f13trn001…`,
  F1.4 `r6f14sshca001…`; file `<revision>_<slug>.py`. Within a part, chain linearly. **At merge time each part's
  first migration re-chains its `down_revision` to whatever `alembic heads` shows on `origin/dev`** (merge dev into
  the branch, edit, re-run CI). F1.1 adds `backend/tests/test_alembic_single_head.py` (parses `versions/`, asserts
  exactly one head and no duplicate revision ids); the release manager also runs `alembic heads`.

### F1.1 (lean node API), `r6f11node*`
| Table | Change |
|---|---|
| `cbomcollectionjob` | `node_segment varchar(64) NULL`; index `(team_id, status, node_segment, id)`. Semantics below. |
| `cbomcollectionsource` | `node_segment varchar(64) NULL` (placed right after `node_id`). |
| `cbomcollectionrun` | incremental counters (`jobs_total`, `jobs_open`, `jobs_success`, `jobs_failed`, `jobs_cancelled`, `jobs_partial`, `ever_claimed`); internal to F1.1. |
| nonce / heartbeat | F1.1's choice (in-memory window + LRU, or a per-node counter column); internal. |

Claim semantics others rely on: `node_id` set → pinned (today's behaviour); `node_id NULL` and `node_segment` set →
any **agentless** node of the team whose `cbomscannode.segment == node_segment` may claim (SKIP LOCKED); on claim
`job.node_id` is set to the claimer; on lease expiry the job goes back to `pending` with `node_id` cleared if it was a
segment job; both NULL → cloud worker. A source with `node_segment` and no `node_id` is "has a node" for `plan_run`
when at least one online node is in that segment.

### F1.2 (inventory, policies, credentials), module `backend/utilities/cbom_sources/fleet/models.py`
| Table | Columns (beyond the common ones) |
|---|---|
| `cbominventorysource` (`r6f12inv001`) | `kind` (`aws`\|`csv`\|`json`\|`api`), `name`, `config` JSON (aws: `aws_account_source_id`, `regions[]`, `services[]`), `sync_every_min` (default 60, min 15), `enabled`, `last_sync_at`, `last_sync_status`, `last_sync_summary`, `coverage` JSON, `lease_until`, `deleted_at` |
| `cbominventorytarget` (`r6f12inv001`) | `inventory_source_id`, `external_id varchar(255)` (unique with `team_id`), `kind varchar(24)` (`linux_host`, `windows_host`, `database`, `k8s_cluster`, `load_balancer`, `certificate`, `kms_key`, `secret`, `other`), `address`, `addresses` JSON (every IPv4/IPv6), `hostname`, `tags` JSON (keys lower-cased), `account_id`, `region`, `platform`, `handles` JSON (`{"ssm": "i-…", "salt": "<minion>", "awx": "<host>"}`), `attributes` JSON, `fingerprint char(64)`, `first_seen_at`, `last_seen_at`, `missing_since`, `decision` JSON (cached Decision), `managed_source_id int NULL` (sticky batch) |
| `cbomfleetpolicy` (`r6f12pol001`) | `name`, `enabled`, `priority int`, `selector` JSON, `action` JSON (`never_scan`, `transport` `ssh\|awx\|salt\|ssm`, `transport_id`, `credential_id`, `node_id`\|`node_segment`, `tier`, `batch_size` 25-1000 default 100, `schedule` {frequency, time_of_day, weekday, monthday} or null), `owner_user_id`, `updated_by_user_id`, `deleted_at` |
| `cbomcredential` (`r6f12pol001`) | `name`, `credential_type` (`node_key`\|`password`\|`ssh_cert`\|`vault`\|`ssh_ca`), `config` JSON (the same non-secret fields `ServersConfig` has: `login_user`, `port`, `host_key_policy`, `known_hosts`, `vault`, plus `ssh_ca_id`, `ssh_principals` for `ssh_ca`), `secret_encrypted`, `secret_fields`, `deleted_at` |
| `cbomcollectionsource` (new_models) | `managed_by_policy_id int NULL` (index), `credential_id int NULL`, `batch_key varchar(64) NULL`, appended **after `source_uid`** |
| `cbomcollectionschedule` (new_models) | `policy_id int NULL` (index), appended **after `last_updated`** |

### F1.3 (transports), module `backend/utilities/cbom_sources/transports/models.py`, `r6f13trn001`
| Table | Columns |
|---|---|
| `cbomtransport` | `kind` (`awx`\|`salt`\|`ssm`), `name`, `enabled`, `config` JSON (section 3), `secret_encrypted`, `secret_fields`, `last_validated_at`, `last_validation_status`, `last_validation_summary`, `owner_user_id`, `deleted_at` |
| `cbomzscollectrelease` | `version`, `manifest` JSON, `manifest_sig`, `sha256_amd64`, `sha256_arm64`, `verified_at`, `active bool` (one active per deployment, `team_id` NULL = deployment-wide; this one table has no team FK) |

New source kinds (rows live in `cbomcollectionsource`, no new table): `awx_hosts`, `salt_hosts` (node-run) and
`ssm_hosts` (`node_less=True`), group `servers`, config `FleetHostsConfig(_Source)`: `transport_id`, `targets[]`
(inventory addresses, ≤ `targets.MAX_LINES`), `handles` {address → transport handle}, `tier` 1|2, `timeout_s`,
`window`, `custom_window`, `exclusions[]`. Same credits as Linux servers (0.2 per target), no change to `RATES_C`.

### F1.4 (SSH CA), module `backend/utilities/cbom_sources/sshca/models.py`, `r6f14sshca001`
| Table | Columns |
|---|---|
| `cbomsshca` | `name`, `provider` (`builtin`\|`vault`), `key_alg` (`ed25519` default, `ecdsa-p256`), `public_key` (OpenSSH line), `private_key_encrypted` (builtin), `key_wrap` (`fernet` = `ENCRYPTION_KEY` \| `aws_kms` = KMS data key, `kms_key_ref` ARN), `vault_config` JSON (`addr`, `mount`, `role`, `namespace`, `ca_pem`), `secret_encrypted` (Vault token or AppRole), `state` (`next`\|`active`\|`retired`\|`revoked`), `default_ttl_s` 300 (60-3600), `serial_next bigint`, `rotated_from_id`, `revoked_at`, `revoked_reason` |
| `cbomsshcertissued` | `ca_id`, `serial bigint` (unique with `ca_id`), `key_id`, `principals` JSON, `valid_after`, `valid_before`, `cert_public_key_sha256`, `node_id`, `job_id`, `source_id`, `issued_at` (index with `team_id`), `revoked_at` |

`ServersConfig` (`kinds.py:158-195`) gains `credential_type` value `ssh_ca` and fields `ssh_ca_id: int | None`,
`ssh_principals: list[str]` (both `where` fields, required when `ssh_ca`); `_server_secrets` (:240) returns `set()` for
`ssh_ca` (nothing stored: the certificate is minted per claim).

---

## 3. API contracts and internal interfaces

**Common rules.** New team routes live under `/{team_id}/cbom/sources/fleet/...`, use `route_class=CbomRoute`,
`authorize()`, `read_limiter`/`write_limiter`, 400 (never 403) for in-team refusals, 404 for other teams' rows, 409 on a
stale `expected_version`, and `common.audit(...)` on every write (`object_type` ≤ 24 chars, `action` ≤ 48).
Each route declares its permission for F4's route-coverage test as
`openapi_extra={"x-zs-permission": "<name>"}` and enforces it today with the existing helpers:

| Permission | Today's check | Routes |
|---|---|---|
| `cbom.fleet.read` | member | every GET below |
| `cbom.inventory.write` | admin | import, upsert, delete target, inventory-source CRUD, sync |
| `cbom.policies.write` | admin | policy CRUD, reconcile |
| `cbom.credentials.write` | admin | credential CRUD |
| `cbom.transports.write` | admin | transport CRUD, validate |
| `cbom.sshca.admin` | admin | CA create, rotate, promote, revoke |

A disabled feature flag (section 6) makes its routes answer 404.

### F1.1: node API (paths unchanged)
`/cbom/node/enroll`, `/heartbeat`, `/jobs/claim`, `/jobs/{id}/assets`, `/jobs/{id}/result` keep their request and
response shapes; any new field is optional, and a node on today's image must keep working. F1.1 publishes for the others:
* `backend/routers/cbom_node.py`: public `authenticate_node(session, token, req, raw, now) -> CbomScanNode` (today's
  `_authenticate`, keep the alias).
* `jobs.leased_job(session, node, job_id, lease_id) -> CbomCollectionJob` (404 not this node's, 409 lease lost).
* Claim payload: `{"job": {...}, "scope": {...}, "source": {"id","kind","name","config","secrets"}}`, additive only.
* **`backend/utilities/cbom_sources/secret_refs.py`** (created by F1.1; nobody else edits it). Every place that today
  calls `decrypt_secrets(source.secret_encrypted)` for a job (claim, cloud claim, `finish_job`, `add_assets`) and the
  secret part of `connection_version` goes through it:
  ```python
  PLUGINS = ("backend.utilities.cbom_sources.fleet.claim",       # F1.2: credential_id -> secrets
             "backend.utilities.cbom_sources.transports.claim",  # F1.3: transport_id -> config.transport + secrets
             "backend.utilities.cbom_sources.sshca.claim")       # F1.4: ssh_ca -> config.ssh_ca + secrets.ssh_certificate
  # each plugin module (missing module = skipped) exposes:
  def claim_extras(session, source, node, now, acc: dict) -> dict | None  # acc = {"config": {...}, "secrets": {...}}
  def version_input(session, source) -> str | None   # cheap (one row read); never mints anything
  def known_secrets(session, source) -> list[str]     # for scrubbing node output
  def source_secrets(session, source, node, now) -> tuple[dict, dict]  # (config, secrets), plugins applied in order
  ```
* **`backend/utilities/cbom_sources/capabilities.py`** (F1.1): claim skips (leaves pending) jobs whose
  `required_capabilities(kind, config)` is not a subset of `node.capabilities["collectors"]`. The table is fixed here:
  `awx_hosts → transport_awx`, `salt_hosts → transport_salt`, `config.credential_type == "ssh_ca" → ssh_ca`.
* **Limits** (`backend/utilities/cbom_sources/limits.py`, env with defaults): `CBOM_MAX_AGENTLESS_NODES` 500,
  `CBOM_MAX_SOURCES` 5,000 (hand-made sources only), `CBOM_MAX_AGENT_NODES` 20,000, `CBOM_MAX_POOLS` 200. The CMDB cap
  (`cmdb.py:37`) reads the same limit.

### F1.2: inventory, policies, credentials
| Method and path (prefix `/{team_id}/cbom/sources/fleet`) | Body → response |
|---|---|
| `GET /status` | → `{"inventory": bool, "policies": bool, "transports": bool, "ssh_ca": bool}` (reads the four env flags directly) |
| `GET /inventory/targets?kind=&tag=k:v&q=&missing=&cursor=&limit≤500` | → `{targets[], next_cursor, total}` |
| `GET /inventory/targets/{id}` | → `{target, decision: {action, policy_id, matched_policy_ids[], transport, reason}}` |
| `POST /inventory/import` | `{format: "csv"\|"json", content ≤ 10 MB, inventory_source_id?, dry_run}` → `{created, updated, unchanged, missing, errors[≤100], digest}`; ≤ 10,000 rows; upsert on `(team_id, external_id)` |
| `PUT /inventory/targets` | `{source_name, targets[≤1000] of Target}` → same counts (the API source) |
| `DELETE /inventory/targets/{id}` | soft: marks missing, unassigns the batch |
| `GET\|POST /inventory/sources`, `PATCH\|DELETE /inventory/sources/{id}` | AWS / CSV / API source config |
| `POST /inventory/sources/{id}/sync` | → 202 `{sync_id}`; the sync runs on the inventory thread (section 6) |
| `GET\|POST /policies`, `PATCH\|DELETE /policies/{id}` | policy CRUD; `expected_version` on PATCH |
| `POST /policies/preview` | `{policy}` (a draft) or `{policy_id}` → `{matched, would_collect, never_scan, conflicts[], sample[≤50]}` (no writes) |
| `POST /reconcile` | → `{sources_created, sources_updated, deferred, targets_assigned}` |
| `GET\|POST /credentials`, `PATCH\|DELETE /credentials/{id}` | typed credential; `secrets` write-only, `secrets_set` returned |

Interfaces (module paths are binding; code against these before the other part merges):
```python
# backend/utilities/cbom_sources/fleet/inventory_sources.py
@dataclass(frozen=True)
class Target:
    external_id: str; kind: str; address: str | None; addresses: tuple[str, ...]; hostname: str | None
    tags: Mapping[str, str]; account_id: str | None; region: str | None; platform: str | None
    handles: Mapping[str, str]; attributes: Mapping[str, Any]
class InventorySource(Protocol):
    kind: ClassVar[str]                       # "aws" | "csv" | "json" | "api"
    def discover(self) -> Iterable[Target]: ...  # raises InventoryError(code, detail); gaps in .coverage
# AwsInventorySource reuses aws_collect._Account for role assumption; it does not modify aws_collect.py.

# backend/utilities/cbom_sources/fleet/policy.py
@dataclass(frozen=True)
class Decision:
    action: Literal["collect", "never_scan", "unmanaged"]
    policy_id: int | None; matched_policy_ids: tuple[int, ...]
    transport: Literal["ssh", "awx", "salt", "ssm"] | None; transport_id: int | None; credential_id: int | None
    node_id: int | None; node_segment: str | None; tier: int; schedule: dict | None; batch_size: int; reason: str
class PolicyEngine:
    def __init__(self, policies: Sequence[CbomFleetPolicy], settings: CbomCollectionSettings, *, transports=None, cas=None): ...
    def evaluate(self, target: Target | CbomInventoryTarget) -> Decision: ...
```
Evaluation rules: (1) the team never-scan list wins (any of `target.addresses` listed → `never_scan`, the T1 rule);
(2) enabled policies by `priority` descending, then `id` ascending; the first match wins, all matches are reported;
(3) selector grammar `{"all":[…]}`, `{"any":[…]}`, `{"not":{…}}`, leaves `{"tag": k, "op": "eq|ne|in|exists|prefix", "value": …}` and
`{"field": "kind|account_id|region|platform", "op": …, "value": …}`; no regex; at most 20 leaves; (4) a transport or
CA that is missing, disabled, deleted or behind an off flag gives `unmanaged` with that reason. The same inputs always
give the same Decision (a property test shuffles the input order).

Materializer (`fleet/materialize.py`): a `collect` Decision becomes a target line of a **managed source**: kind
`linux_servers` for `ssh`, or `awx_hosts`/`salt_hosts`/`ssm_hosts`; config built through `KINDS[kind].model`, with the
credential's non-secret config copied in, and checked with `credential_target_problem`; `node_id` or `node_segment`
from the Decision; batches of ≤ `batch_size`, keyed `(policy, transport, transport_id|credential_id, segment, kind)`.
**Assignment is sticky**: a target keeps `managed_source_id` while the key matches. A managed source with an open job is
**never edited** (that would cancel it through `connection_version`); its changes are deferred to the next reconcile.
One managed `cbomcollectionschedule` per policy with a schedule (`policy_id`, `source_ids` = its managed sources);
managed schedules and managed sources do not count toward `MAX_SCHEDULES` or `CBOM_MAX_SOURCES` (own cap
`CBOM_MAX_MANAGED_SOURCES`, default 2,000). Group runs (`include` without `source_ids`) **skip managed sources**;
they run from their policy's schedule or an explicit `source_ids`. Credits: unchanged (`queue_run`).

Seams to other parts (optional imports, removed in the F1 integration PR):
`transports.registry.get_transport(session, team_id, transport_id) -> TransportRef | None` (F1.3) and
`sshca.registry.usable_ca(session, team_id, ca_id) -> bool` (F1.4).

### F1.3: transports and zs-collect
| Method and path | Body → response |
|---|---|
| `GET\|POST /{team_id}/cbom/sources/fleet/transports`, `PATCH\|DELETE …/{id}` | `{kind, name, enabled, config, secrets?}`; soft delete refused while a non-deleted source uses it (409, names them) |
| `POST …/transports/{id}/validate` | SSM: synchronous (STS assume, document exists, `DescribeInstanceInformation` once permitted). AWX/Salt: 400 "test a source that uses this transport" (the control plane is only reachable from a node) |
| `GET …/transports/artifacts/{name}` | `ssm-document`, `ssm-role-cfn`, `salt-state`, `ansible-collection`, `zs-collect-manifest`, `zs-collect-pubkey` |
| Sources of kind `awx_hosts\|salt_hosts\|ssm_hosts` | existing `/items` routes (create, edit, test, run); test = control-plane login + up to 5 sample targets |

Transport config: **awx** `{base_url (https), job_template_id, verify_tls, ca_pem?, timeout_s, max_hosts_per_launch ≤ 200}`,
secrets `{token}`. **salt** `{base_url (https), eauth, client: "local"|"local_async"|"ssh", mode: "state"|"cmd",
batch_size, timeout_s}`, secrets `{username, password}`. **ssm** `{role_arn, regions[], document_name ^devsecshield-,
output_s3_bucket, output_s3_prefix, max_concurrency "10%", max_errors "100%"}`, no stored secret (the team's external
id). The SSM role is a **separate run-command role** (`ssm:SendCommand` on `document/devsecshield-*`, `GetCommandInvocation`,
`s3:GetObject` on the output prefix): the read-only reader role must stay read-only, and it explicitly denies
`s3:GetObject` (`templates.py:24`). Output goes to S3 because `GetCommandInvocation` truncates stdout at 24,000 chars.

Claim payload for fleet kinds: `source.config.transport` = the transport's non-secret config, `source.secrets` = its
secrets, `scope.targets` = the batch's addresses, `source.config.handles` = address → handle.

```python
# scan_node/zs_scan_node/transports/base.py  (canonical); byte-identical copy at
# backend/utilities/cbom_sources/transports/base.py (a backend test compares the two files)
@dataclass(frozen=True)
class CollectTarget:
    label: str                      # the inventory address; becomes asset.target, same as the SSH path
    handle: str                     # awx host | salt minion id | ec2 instance id | address (ssh)
    addresses: tuple[str, ...] = ()
@dataclass(frozen=True)
class TransportCredential:
    kind: str                       # "ssh" | "awx_token" | "salt_eauth" | "aws_role"
    config: Mapping[str, Any]; secrets: Mapping[str, str]
@dataclass(frozen=True)
class CollectOptions:
    tier: int; run_nonce: str; deadline: float; timeout_per_target_s: int
    max_concurrency: str; zs_collect_sha256: Mapping[str, str]; should_stop: Callable[[], str | None]
@dataclass
class TargetResult:
    target: CollectTarget; status: str; error: str | None; document: dict | None   # validated zs-collect/1
class Transport(Protocol):
    name: ClassVar[str]             # "ssh" | "awx" | "salt" | "ssm"
    def check(self, credential: TransportCredential, sample: Sequence[CollectTarget]) -> list[TargetResult]: ...
    def run_collect(self, targets: Sequence[CollectTarget], credential: TransportCredential,
                    options: CollectOptions) -> Iterator[TargetResult]: ...   # streams as targets finish
```
Adapters: node `transports/{ssh,awx,salt}.py`, cloud `backend/utilities/cbom_sources/transports/ssm.py`. The node
glue `collectors/fleet.py` checks never-scan before dispatch (any address of the target listed → `skipped_never_scan`;
the tool never sees it), replays each document's assets through `ctx.emit` with `target` forced to `target.label`, and
records `ctx.outcome`. Statuses come from `jobs.TARGET_STATUSES` (`jobs.py:50-56`) only; transport detail goes in `error`
(minion or instance not answering → `unreachable`, tool auth → `auth_failed`, tool refused → `refused`, nonce or
schema mismatch → `error`).

### F1.4: SSH CA
| Method and path (prefix `/{team_id}/cbom/sources/fleet/ssh-ca`) | Body → response |
|---|---|
| `GET` / `POST` | list / create `{name, provider, key_alg, key_wrap, kms_key_ref?, vault_config?, secrets?, default_ttl_s}` |
| `POST /{id}/rotate`, `/{id}/promote`, `/{id}/revoke` | rotate creates a `next` CA; promote makes it `active` (old → `retired`); revoke `{reason}` |
| `GET /trusted-keys` (text/plain) | every `next`/`active`/`retired` public key, for `TrustedUserCAKeys` |
| `GET /revoked` (text/plain) | revoked CA keys (and KRL, see open question 4), for `RevokedKeys` |
| `GET /certificates?ca_id=&node_id=&job_id=&before_id=` | issued-certificate audit, newest first |
| `GET /templates/{sshd-config\|principals}` | `TrustedUserCAKeys` / `AuthorizedPrincipalsFile` snippets |
| Node: `POST /cbom/node/jobs/{job_id}/ssh-cert` | `{lease_id}` → `{certificate, serial, valid_before}`; `authenticate_node` + `jobs.leased_job`; `node_limiter` |

```python
# backend/utilities/cbom_sources/sshca/ca.py
@dataclass(frozen=True)
class IssuedCert:
    certificate: str; serial: int; key_id: str; principals: tuple[str, ...]; valid_after: datetime; valid_before: datetime
class CertificateAuthority(Protocol):
    def issue(self, principal: str | Sequence[str], ttl: timedelta, *, public_key: str, key_id: str,
              source_addresses: Sequence[str] = (), node_id: int | None = None, job_id: int | None = None) -> IssuedCert: ...
    def public_keys(self) -> list[str]: ...
def ca_for(session, team_id: int, ca_id: int) -> CertificateAuthority   # BuiltinCA | VaultCA
```
Issue rules: certify `node.ssh_public_key` (the node's private key never leaves it); `valid_after = now - 60 s`,
`ttl` default 300 s, clamp 60-3600; principals from the source or credential (`ssh_principals`, convention
`zs-<team_id>-<group>`); critical option `source-address` = the node's `source_ips` when known; **no extensions** (no
pty, forwarding, agent or user-rc; exec works without them); `key_id = "zs:<team>:<node>:<job>:<serial>"`; one
`cbomsshcertissued` row per certificate in the caller's transaction; `serial_next` taken with
`UPDATE … RETURNING`. Agent-mode nodes never get certificates. Minted at claim by the `sshca.claim` plugin, refreshed
by the node route when < 120 s remain. Vault: `POST /v1/<mount>/sign/<role>` with `cert_type=user`.
Builtin keys: `cryptography` `SSHCertificateBuilder` (no new dependency); KMS-wrapped keys are unwrapped once per
worker and cached for at most 10 minutes.

---

## 4. zs-collect output format, signing and read-only guarantees

**Schema (reused, not new).** zs-collect emits exactly the document `python -m zs_scan_node.collect` prints today
(`scan_node/zs_scan_node/collect.py:60`): `{"status", "error", "result", "assets", "elapsed_s"}`, where
* `assets[]` are the dicts built by `JobContext.emit` (`scan_node/zs_scan_node/jobctx.py:199-221`) = the backend's
  `AssetIn` (`backend/utilities/cbom_sources/schemas.py:376-396`): `type, target, location, name, algorithm,
  key_size, protocol, facts`;
* `result` is `JobContext.result()` (`jobctx.py:305-335`): `summary, counts{total,ok,failed,skipped}, asset_count,
  targets[], truncated, assets_lost, duration_s`.

zs-collect/1 adds an envelope: `format: "zs-collect/1"`, `collector_version`, `run_nonce` (echoed from
`--nonce`), `target_label`, `tier`, `host {hostname, os_id, machine_id_sha256}`, `started_at`, `finished_at`.
F1.3 commits the JSON Schema at `scan_node/zs_scan_node/schemas/zs-collect-1.schema.json`; a backend test checks
that every asset validates as `AssetIn`. Size: at most 50,000 assets (`MAX_ASSETS_PER_ATTEMPT`); transports may
gzip + base64 it (AWX events in ≤ 512 KB chunks, open question 11).

**Parity with SSH.** zs-collect runs the same code: F1.3 splits `linux_ssh.collect_target` (`linux_ssh.py:370`)
into session setup and `collect_on_session(ctx, sess, label, config)`, and adds a `LocalSession` with the same
`run()` contract as `Session.run` (`linux_ssh.py:170`), running `commands.py` strings with `T1_ENV`, stdin closed and
the same timeouts and output cap. Tier 2 goes through the identical `sudo -n` lines. Started as root, it drops to
`--run-as` (default `zs-cbom`) first, so sudoers decide Tier 2 exactly as on the SSH path. The parity normaliser
(`bench/f1_transports/normalize.py`) drops timings, `host_key.first_use` and the envelope, accepts
`host_key.fingerprint` if it equals any local host key's fingerprint, and compares assets sorted by the
`jobs._asset_key` formula. "Identical" means an empty normalised diff.

**Signing and verification.**
* Build: a PyInstaller one-file binary per arch (`zs-collect-<ver>-linux-{amd64,arm64}`) from `scan_node`,
  in a pinned builder image; `zs-collect-<ver>.manifest.json` `{format, version, git_commit, files[{name, arch,
  sha256, size}]}`; `manifest.json.sig` is a raw Ed25519 signature, base64.
* Key: an offline ZeroShield release Ed25519 key. Only the public key is in the repo
  (`scan_node/zs_collect/zs-release-ed25519.pub`), shown with its fingerprint in the UI. CI uses a test key.
* The backend verifies the manifest signature when a release is imported (`cbomzscollectrelease.verified_at`).
* Every wrapper (SSM document, Salt state, Ansible role) is generated per release with the sha256 baked in. It runs
  `sha256sum -c` before exec and refuses on mismatch. It also runs `openssl pkeyutl -verify -rawin` on the manifest
  when OpenSSL ≥ 3 is present.
* The node, or the cloud worker for SSM, refuses a document whose `run_nonce` or `collector_version` does not match
  the job.

**Read-only guarantees** (each has a test):
* It only executes command strings from `zs_scan_node.commands` (a test patches `subprocess` and asserts every argv
  is on the allow-list).
* It has no network listener and makes no outbound connection: run under `unshare -rn`, the output is identical,
  and an optional `strace -e trace=socket,connect,bind,listen` sees nothing.
* It writes only inside `--tmp-dir` (`mktemp -d`, mode 0700, also used as `TMPDIR` for PyInstaller extraction),
  removed at exit. A test runs it in `docker run --read-only --tmpfs /tmp`.
* Private keys never leave the host: as on the SSH path, only `pkey -pubout` and fingerprints are read.
* Output passes the same `Scrubber`.

---

## 5. Ownership and conflict map

**Exclusive files** (only the owner edits them; others read and import).
| Part | Files |
|---|---|
| F1.1 | `backend/routers/cbom_node.py`, `utilities/cbom_sources/{jobs,node_auth,runs,secret_refs,capabilities,limits}.py`, `utilities/ratelimit.py`, `scan_node/zs_scan_node/{agent,state}.py`, `bench/f1_node_api/**`, `backend/tests/test_alembic_single_head.py`, migrations `r6f11*` |
| F1.2 | `utilities/cbom_sources/fleet/**`, `backend/routers/cbom_fleet.py` (aggregator, see below), `backend/workers/cbom_inventory_sync.py`, `frontend/components/cbom/sources/fleet/{FleetTab,sections,InventorySection,PoliciesSection,CredentialsSection,keys}.tsx/ts`, `frontend/utils/api/cbom_fleet.ts`, `bench/f1_inventory/**`, migrations `r6f12*` |
| F1.3 | `utilities/cbom_sources/transports/**`, `utilities/cbom_sources/kinds_fleet.py`, `backend/routers/cbom_transports.py`, `scan_node/zs_scan_node/{transports/**,zscollect.py,schemas/**,collectors/fleet.py}`, `scan_node/zs_collect/**`, `frontend/components/cbom/sources/fleet/{TransportsSection,FleetHostsSourceForm}.tsx`, `frontend/utils/api/cbom_transports.ts`, `bench/f1_transports/**`, migrations `r6f13*` |
| F1.4 | `utilities/cbom_sources/sshca/**`, `backend/routers/{cbom_sshca,cbom_node_sshca}.py`, `frontend/components/cbom/sources/fleet/SshCaSection.tsx`, `frontend/utils/api/cbom_ssh_ca.ts`, `bench/f1_sshca/**`, migrations `r6f14*` |

**Shared files: additive edits at fixed anchors only.** Line numbers are on dev 3399452. Keep both sides in a
conflict; never reorder another part's lines.
| File | F1.1 | F1.2 | F1.3 | F1.4 |
|---|---|---|---|---|
| `backend/main.py` | none | one import after :17 and `include_router(cbom_fleet_router)` after :135 | none (through the aggregator) | none (through the aggregator) |
| `backend/routers/cbom_fleet.py` (F1.2 creates it with marker comments `# F1.3 routers` and `# F1.4 routers`) | none | creates it | `include_router` lines under its marker | the same, both its routers including the node route |
| `backend/new_models.py` | `node_segment` after `node_id` (:371, :425); run counters after :415 | source columns after :386; schedule column after :588 | none | none |
| `utilities/cbom_sources/kinds.py` | none | none | 2 lines after :814: `from …kinds_fleet import FLEET_KINDS` and `KINDS.update(FLEET_KINDS)` (before `KIND_NAMES`) | `ServersConfig` :158-195 and `_server_secrets` :240-246 only |
| `utilities/cbom_sources/planning.py` | node/segment status :176-200 | first statement inside the loop (after :166): skip managed sources for group runs | none | none |
| `routers/cbom_sources.py` | caps :107-108, :267, :512-516 | after F1.1 merges: exclude managed sources from the count (:512-513), refuse PATCH/DELETE of managed sources (first line of `_update_source` :603 / `_delete_source` :714) | none | none |
| `routers/cbom_ops.py` | none | schedule cap ignores `policy_id` rows (:318) | none | none |
| `utilities/cbom_sources/cleanup.py` `_ORDER` | none | its models after `TeamIntegration,` (:28); import after :4 | after `CbomCollectionSettings,` (:38); import after :5 | after `CbomEvidenceArea,` (:40); import after :6 |
| `utilities/cbom_sources/serialize.py` `public_source` (:67) | `node_segment` | `managed_by_policy_id`, `credential_id` | none | none |
| `backend/workers/cbom_cloud_worker.py` | reap cadence (:205-209) | start the inventory-sync thread after :203 | `elif kind == "ssm_hosts"` after the `idp` branch (:121) | none |
| `scan_node/zs_scan_node/collectors/__init__.py` | none | none | `SUPPORTED`, dispatch branch before `except` (:105) and `CAPABILITIES += ["transport_awx","transport_salt","zs_collect"]` after :28 | `CAPABILITIES += ["ssh_ca"]` between :26 and :27 |
| `scan_node/zs_scan_node/collectors/linux_ssh.py` | none | none | split `collect_target` (:370-516) | `_credentials` (:124-163) and the auth part of `open_session` (:212) |
| `scan_node/zs_scan_node/api.py` | `claim`/`heartbeat` (:244-250) | none | none | new `ssh_cert()` method after `result` (:259-262) |
| `scan_node/zs_scan_node/jobctx.py` | as F1.1 needs | none | none | field `cert_refresher` after `_progress_refused` (:158) |
| `scan_node/zs_scan_node/agent.py` | owner | none | none | one line after :360: `ctx.cert_refresher = …` |
| `frontend/app/[team_id]/cbom/sources/page.tsx` | none | adds the `fleet` tab before `review` (:28) and its `TabsContent` before :119 | none | none |
| `frontend/components/cbom/sources/fleet/sections.tsx` (F1.2 creates it with markers `// F1.3` and `// F1.4`) | none | creates it | one entry at its marker | one entry at its marker |
| `frontend/utils/backend_api.ts` | `node_segment` on `CbomScanNode`/`CbomSource` if shown | `managed_by_policy_id?` after `last_updated` of `CbomSource` (:4256) | `\| "awx_hosts" \| "salt_hosts" \| "ssm_hosts"` on `CbomSourceKind` (:4157) | none (types in `utils/api/cbom_ssh_ca.ts`) |
| `frontend/components/cbom/sources/ServersTab.tsx` | none | list row: "Managed by policy" badge, edit disabled | none | `CredType` (:94), creds list (:110), labels (:117), form block after the `ssh_cert` block (:1218) |
| `frontend/components/cbom/sources/ScanNodesTab.tsx` | segment display if needed | none | none | none |
| `backend/pyproject.toml`, `uv.lock`, `scan_node/requirements*.txt` | none | none | none | none: **no new runtime dependency in F1** (moto is already injected in backend CI with `--with moto==5.2.5`; node tests use `httpx.MockTransport` and `botocore.stub.Stubber`). A part that needs one asks the coordinator first, because F4 (SAML) also edits the lock. |

**Never touch:** `utilities/cbom_sources/aws_collect.py` (import `_Account`), `utilities/integrations/cmdb.py`
(F1.1 only, for the cap), `templates.py` (each part serves its own templates from its own routes), `.github/**`
(a CI change needs the security label).

**Cross-track conflicts.**
* T1 (never-scan, `fix/never-scan-dual-stack`) edits `scan_node/zs_scan_node/netutil.py` and
  `linux_ssh.open_session`. F1.3 and F1.4 merge dev after T1 lands, before they touch `linux_ssh.py`, and use T1's
  `netutil.resolve_checked` rule for names.
* F4 (RBAC) will put a permission on every route. F1 routes declare `x-zs-permission` now (section 3).
* F3 and F4 also edit `main.py` and `new_models.py`; the anchors above keep F1's hunks apart from theirs.

---

## 6. Integration order and feature flags

| Flag (env, default `0`) | Read in | When off |
|---|---|---|
| `CBOM_FLEET_INVENTORY` | `fleet/flags.py` | `/fleet/inventory/*` → 404; the sync thread is not started |
| `CBOM_FLEET_POLICIES` | `fleet/flags.py` | `/fleet/policies*`, `/fleet/credentials*`, `/fleet/reconcile` → 404 |
| `CBOM_FLEET_MATERIALIZE` | `fleet/flags.py` | policies evaluate and preview only; no managed sources or schedules are written |
| `CBOM_FLEET_TRANSPORTS` | `transports/flags.py` | transport routes 404; fleet kinds refused at create; `collectable()` false → "Transports are turned off" |
| `CBOM_SSH_CA` | `sshca/flags.py` | CA routes 404; `ssh_ca` refused at save; the claim plugin is a no-op |

F1.1 has no product flag. Its compatibility gate is the node version: the old endpoints and payloads stay.
The frontend hides a section whose `/fleet/status` flag is false, and hides the Fleet tab when all are false.

**Order.**
1. T0, then T1.
2. **F1.1** (`secret_refs`, `capabilities`, `limits`, `node_segment`, single-head test).
3. **F1.2-a0 scaffold**, a small PR opened first: the empty `cbom_fleet.py` aggregator with markers, its `main.py`
   lines, `/fleet/status`, `fleet/flags.py`, the Fleet tab, `sections.tsx` with markers, and `fleet/keys.ts`. It does not
   wait for F1.1.
4. In any order after their prerequisites:
   * **F1.3-a** (zs-collect, schema, `LocalSession` split, signing, parity harness; `scan_node/` only): after T1.
   * **F1.4** (CA, plugin, node route, node cert use): after F1.1 and F1.2-a0.
   * **F1.2-a** (inventory, AWS/CSV/API discovery): after F1.2-a0.
5. **F1.2-b** (policies, credentials, materializer; materialize flag off): after F1.1.
   **F1.3-b** (transport table, AWX and Salt adapters, fleet kinds): after F1.1 and F1.2-a0.
6. **F1.3-c** (SSM in the cloud worker; recorded responses; live test marked pending): after F1.3-b.
7. Integration QA on dev with every flag on; then remove the optional-import seams.

F1.3 does **not** depend on F1.2: fleet sources can be created by hand, and policies reference transports by id.

---

## 7. Test strategy

| Part | Unit and integration | Fakes and recordings | Live and scale |
|---|---|---|---|
| F1.1 | Postgres (`CBOM_TEST_PG_URL`, already in CI) multi-process claim races (the `test_cbom_wp10_schedules.py` pattern); segment claim; lease expiry re-queue with a killed node; nonce replay still refused; `recompute_run` cost does not grow with N; caps from env; current node image against the new API | none | `bench/f1_node_api/`: 10,000 simulated signed nodes, 60 s heartbeat ± 20 % jitter, 10 min; p50/p95/p99, errors, CPU, DB QPS; a 10,000-job run under 5 min of scheduling; under `flock heavy-tests.lock` |
| F1.2 | selector grammar; determinism (shuffled input gives the same Decision); never-scan precedence (T1 rule); sticky batches; no edit of a source with an open job; idempotent re-import (second import: 0 created, 0 updated); managed sources skipped by group runs; credits unchanged | `moto` `mock_aws` for EC2, RDS, EKS, ELBv2, ACM, KMS, Secrets Manager and STS across 3 regions; 1,000-target fixtures | 1,000 targets imported in < 2 min on Postgres (`bench/f1_inventory/`), also 10,000; **sandbox:** 3 tagged t3.micro + 1 db.t4g.micro (tags `Project=DevSecShield`, `zs-lab=sandbox`, `zs-owner=f1-2`, test tags `env=prod`/`env=stage`), discovered through DevSecShieldScannerReadOnlyRole, torn down the same day, under $0.50; EKS with moto only |
| F1.3 | zs-collect schema; allow-list; `unshare -rn`; read-only root fs; nonce echo; never-scan before dispatch; status mapping; the two `base.py` copies identical | AWX API fake (`httpx.MockTransport`: launch, job status, events with chunked outputs, 401/403/404, timeouts); salt-api fake (`/login`, `local`/`local_async`/`ssh`, jobs lookup, minion not answering); SSM via `botocore.stub.Stubber` with recorded `SendCommand`/`ListCommandInvocations` + an S3 output fake | parity on 20 local sshd containers (`flock stack.lock`), SSH path vs zs-collect, empty normalised diff; **200-target proof** for AWX and for Salt (`client: ssh` for all 200, plus 20 real minions) on one sandbox EC2 (t3.xlarge, ≤ 2 h, about $0.35, coordinator OK first); SSM live test `@pytest.mark.live_ssm`, skipped until the owner attaches the SSM policy |
| F1.4 | cert fields (principals, `source-address`, no extensions, TTL clamp, serial uniqueness, `valid_after` skew); one audit row per cert; rotation and revocation; KMS wrap with moto KMS; agent nodes never get certificates | Vault dev-server container (the `test_ca_vault_live.py` pattern) for the Vault SSH engine | a real sshd container with `TrustedUserCAKeys` + `AuthorizedPrincipalsFile`: a valid certificate collects; an **expired certificate is refused**; a **principal mismatch is refused**; a revoked CA is refused; a 2-hour job keeps working through refresh (accelerated clock); 10,000 issues timed |

AWS rules: source `$R6/secrets/aws-dev.env`, tag everything, append to `$R6/aws/ledger.txt` under
`flock $L/aws-ledger.lock`, delete the same day. SSM is not permitted, so no part runs `SendCommand` live.

---

## 8. Open questions, with recommended answers

1. **Where does SSM run?** In the cloud worker, with a separate run-command role (recommended): AWS fleets need no
   scan node. Risk: the worker runs one job at a time, so run 2+ replicas for big fleets (`SKIP LOCKED` already allows it).
2. **Managed sources, or jobs per target batch without a source?** Managed sources (recommended). They reuse
   planning, credits, claim, drift (`source_uid`) and posture, and keep `jobs.py` with F1.1 alone. Revisit above
   2,000 batches.
3. **Where does the CA key live?** Server-side: builtin wrapped by `ENCRYPTION_KEY` or AWS KMS, or Vault
   (recommended; it gives central audit). A node-side CA (the research's "keep it on the node") is an option for later.
   SaaS then holds a login-capable key, which is the same trust as stored passwords today. Tell the owner.
4. **Revocation format?** Publish revoked CA keys as a plain `RevokedKeys` list in v1. With a 5-minute TTL,
   per-serial revocation is rarely needed. Add a KRL writer (OpenSSH PROTOCOL.krl) only on demand.
5. **Host-key trust through a host CA (`@cert-authority`).** Paramiko 3.5 support for host *certificates* is
   unverified. F1.4 spikes it first; the fallback is to parse the host cert blob with `cryptography`
   (`load_ssh_public_identity`), else keep `pinned`/`tofu`.
6. **Pricing for inventory syncs?** Free (no crypto is collected); collection runs charge as today.
7. **CMDB import vs inventory import?** Keep `cmdb.py` (it creates sources) unchanged in F1; a follow-up feeds CMDB
   rows into inventory.
8. **Inventory retention.** `missing_since` after a sync misses the target; no new collection after 7 days missing;
   hard delete after 90 days. Certificate audit is kept 13 months.
9. **zs-collect packaging.** PyInstaller one-file (parity by construction), not a Go rewrite, until evidence says
   otherwise.
10. **Air-gapped distribution.** The customer mirrors the release (binary, manifest, signature). The backend serves
    the wrappers and the manifest, never a binary it has not verified.
11. **Large AWX outputs.** gzip + base64 in ≤ 512 KB `debug` events (AWX truncates larger event data), reassembled by
    (host, chunk). Salt and SSM return whole documents (SSM through S3).
12. **The 200-target Salt proof.** 200 minions do not fit in 7 GB. Use salt-api `client: ssh` for 200 targets plus 20
    real minions, on the sandbox EC2.
13. **TEAM-PROCESS contradicts itself.** The ledger is `aws/inventory.txt` (line 79) and `aws/ledger.txt` (lines 94,
    126); use `ledger.txt`. The VPC "has a NAT gateway" (line 75) and is "air-gapped" (line 90); the coordinator should
    confirm before F1.3 plans a pull of images onto a sandbox EC2.
14. **RBAC.** F4 owns enforcement. F1 declares `x-zs-permission` and keeps the 400-not-403 convention until F4
    changes it everywhere.
15. **AWS organisations.** F1.2 v1 discovers per `aws_account` source. Fan-out past the 200-account cap
    (`aws_collect.py:1169-1216`) is a follow-up.

## 9. Coordinator decisions on section 8 (Nov 11, about 11:30); these are binding
* **CA key:** server-side, wrapped by AWS KMS when one is configured, otherwise by the deployment key; HashiCorp Vault SSH
  engine is optional. This is documented to customers as the same trust level as stored credentials today, with a
  short-lived, address-bound and audited mitigation. A customer-held CA (the scan node signs with a key the customer
  provides) is a follow-up issue, not this PR.
* **Host certificates:** F1.4 first proves that paramiko can verify host certificates. If it cannot, F1.4 ships
  known_hosts pinning plus the user certificate and files an issue.
* **Salt scale proof:** salt-ssh roster mode for 200 targets, plus 20 real minions behind salt-api, all as containers
  under `flock stack.lock`, or a small EC2 if local RAM is not enough (coordinator OK needed).
* **AWX output:** gzip it, split it into chunks of 512 KB or less, and reassemble it on the node with checksums.
* **Network:** the sandbox VPC has egress through NAT (it is not air-gapped). SSM is now permitted, for `devsecshield-*`
  documents on `Project=DevSecShield` instances only. Production instances in the account are SSM-managed: target only
  instance ids you created.
* **TEAM-PROCESS contradictions:** fixed. The ledger is `aws/ledger.txt`.
