#!/usr/bin/env bash
# Collect the database rows and container logs of one or more CBOM runs into a run directory (G11 db/, G16 logs/).
# Also the owner's OA-7 tool for staging: run it where the database and the containers are reachable and return the
# directory (no secret is written: credentials stay inside the database container's environment).
#
#   e2e/cbom/collect-evidence.sh <team_ids> <run_ids> <since_utc> [run_dir]
#     team_ids   comma-separated team ids (customer A, customer B)
#     run_ids    comma-separated collection run ids ("" for none)
#     since_utc  RFC 3339 time for `docker logs --since` (the gate's G0 time)
#     run_dir    default: $CBOM_E2E_RUN_DIR
#
# Environment:
#   CBOM_E2E_PG          database container (default dss-staging-postgres-1)
#   CBOM_E2E_PSQL        a command that runs psql reading SQL on stdin, overriding the docker exec (staging: e.g.
#                        "psql service=cbom-readonly"); it must accept -X -q -v ON_ERROR_STOP=1 style flags itself
#   CBOM_E2E_CONTAINERS  extended regex of container names whose logs to save
#                        (default: dss-staging-(backend|cbom-cloud-worker|scan-worker|cicd-worker|nginx|postgres)|zs-scan-node-|cbom-e2e-)
# Every query runs inside BEGIN READ ONLY. Exit 0 = everything collected; 1 = something could not be collected.
set -euo pipefail

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
[ $# -ge 3 ] || usage
TEAMS=$1 RUNS=$2 SINCE=$3 RUN=${4:-${CBOM_E2E_RUN_DIR:-}}
[ -n "$RUN" ] && [ -d "$RUN" ] || { echo "run directory missing: '$RUN'" >&2; exit 2; }
[[ $TEAMS =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo "team ids must be digits and commas" >&2; exit 2; }
[[ -z $RUNS || $RUNS =~ ^[0-9]+(,[0-9]+)*$ ]] || { echo "run ids must be digits and commas" >&2; exit 2; }
PG=${CBOM_E2E_PG:-dss-staging-postgres-1}
CONTAINERS=${CBOM_E2E_CONTAINERS:-'^(dss-staging-(backend|cbom-cloud-worker|scan-worker|cicd-worker|nginx|postgres)-1|zs-scan-node-.*|cbom-e2e-.*)$'}
mkdir -p "$RUN/db" "$RUN/logs"
status=0

psql_ro() {  # SQL on stdin -> CSV on stdout, read-only
  if [ -n "${CBOM_E2E_PSQL:-}" ]; then
    bash -c "$CBOM_E2E_PSQL"
  else
    docker exec -i "$PG" sh -c 'exec psql -X -q -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
  fi
}

RUNS_SQL=${RUNS:-0}
declare -A Q=(
  [team]="SELECT id, name, credit_balance FROM team WHERE id IN ($TEAMS) ORDER BY id"
  [assets]="SELECT id, team_id, run_id, job_id, source_id, attempt, asset_key, asset_type, cdx_type, target, location, name, algorithm, key_size, protocol, quantum_vulnerable, impact, finding_codes, finding, facts, created_at FROM cbomcollectedasset WHERE team_id IN ($TEAMS) AND run_id IN ($RUNS_SQL) ORDER BY id"
  [runs]="SELECT id, team_id, owner_user_id, client_request_id, status, include, breakdown, credits_charged_c, credits_refunded_c, kb_version, classifier_version, engine_version, soc_ack_at, created_at, finished_at FROM cbomcollectionrun WHERE team_id IN ($TEAMS) ORDER BY id"
  [jobs]="SELECT id, team_id, run_id, source_id, node_id, kind, status, outcome, weight_c, refunded, attempts, asset_count, created_at, claimed_at, finished_at, error, result FROM cbomcollectionjob WHERE team_id IN ($TEAMS) ORDER BY id"
  [nodes]="SELECT id, team_id, name, segment, deployment, node_version, hostname, source_ips, enrolled_at, last_heartbeat_at, last_seen_ip, mode, created_at FROM cbomscannode WHERE team_id IN ($TEAMS) ORDER BY id"
  [sources]="SELECT id, team_id, kind, name, node_id, enabled, config, secret_encrypted, secret_fields, last_test_status, row_version FROM cbomcollectionsource WHERE team_id IN ($TEAMS) ORDER BY id"
  [audit]="SELECT * FROM cbomcollectionauditevent WHERE team_id IN ($TEAMS) ORDER BY id"
  [alembic]="SELECT version_num FROM alembic_version"
)
: > "$RUN/db/queries.sql"
for name in team assets runs jobs nodes sources audit alembic; do
  sql="BEGIN READ ONLY;
\\copy (${Q[$name]}) TO STDOUT WITH CSV HEADER
COMMIT;"
  printf -- '-- %s.csv\n%s\n\n' "$name" "$sql" >> "$RUN/db/queries.sql"
  if ! psql_ro <<<"$sql" > "$RUN/db/$name.csv" 2> "$RUN/db/$name.err"; then
    # a column this database does not have (older schema): keep the error, try the columns it has
    echo "collect-evidence: $name.csv failed: $(head -c 300 "$RUN/db/$name.err")" >&2
    status=1
  fi
  [ -s "$RUN/db/$name.err" ] || rm -f "$RUN/db/$name.err"
done

if command -v docker >/dev/null 2>&1; then
  # lab containers come from the lab's own lab.json (INTERFACES v7 §A.6: never assume a name prefix)
  lab=""
  if [ -f "$RUN/lab/lab.json" ]; then
    lab=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("\n".join(sorted({x.get("container") for x in (d.get("targets") or [])+(d.get("listeners") or []) if x.get("container")})))' "$RUN/lab/lab.json")
  fi
  { docker ps -a --format '{{.Names}}' | grep -E "$CONTAINERS"; [ -n "$lab" ] && printf '%s\n' "$lab"; } | sort -u | while read -r name; do
    [ -n "$name" ] || continue
    short=$name
    case $name in dss-staging-*) short=${name#dss-staging-}; short=${short%-1} ;; esac
    docker logs --timestamps --since "$SINCE" "$name" > "$RUN/logs/$short.log" 2>&1 || echo "collect-evidence: logs of $name failed" >&2
  done
fi
echo "collect-evidence: db $(ls "$RUN/db" | tr '\n' ' ')"
echo "collect-evidence: logs $(ls "$RUN/logs" | tr '\n' ' ')"
exit "$status"
