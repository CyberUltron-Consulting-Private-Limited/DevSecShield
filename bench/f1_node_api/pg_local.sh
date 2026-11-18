#!/usr/bin/env bash
# A throwaway local PostgreSQL (initdb, no docker) for the F1.1 node-API bench, with the same settings stack.sh gives the
# docker one: max_connections=100, log_lock_waits=on, deadlock_timeout=100ms, pg_stat_statements (V5).
#
#   bench/f1_node_api/pg_local.sh up   <datadir> <port> <password-file> <db>
#   bench/f1_node_api/pg_local.sh down <datadir>
#
# PG_BIN (default /usr/lib/postgresql/16/bin) picks the server version.  The cluster runs as the OS user ``postgres``
# when this script runs as root (the server refuses root); <datadir> must be on a path that user can reach (/tmp).
# Its log is <datadir>/pg.log.  Password auth (scram) on 127.0.0.1 only; nothing listens on other interfaces.
set -euo pipefail
cmd=${1:?up|down}
data=${2:?datadir}
PG_BIN=${PG_BIN:-/usr/lib/postgresql/16/bin}
as_pg() { if [[ $(id -u) == 0 ]]; then runuser -u postgres -- "$@"; else "$@"; fi; }

if [[ $cmd == down ]]; then
  [[ -f $data/PG_VERSION ]] && as_pg "$PG_BIN/pg_ctl" -D "$data" -m fast -w stop >/dev/null 2>&1 || true
  rm -rf "$data"
  echo "local postgres down"
  exit 0
fi

port=${3:?port}; pwfile=${4:?password file}; db=${5:?db}
rm -rf "$data"
mkdir -p "$data"
[[ $(id -u) == 0 ]] && chown postgres "$data"
chmod 700 "$data"
tmp_pw=$(mktemp); cp "$pwfile" "$tmp_pw"; chmod 644 "$tmp_pw"
as_pg "$PG_BIN/initdb" -D "$data" -U postgres --auth-local=trust --auth-host=scram-sha-256 --pwfile="$tmp_pw" \
  -E UTF8 --locale=C.UTF-8 >/dev/null
rm -f "$tmp_pw"
as_pg "$PG_BIN/pg_ctl" -D "$data" -l "$data/pg.log" -w -t 60 \
  -o "-p $port -c listen_addresses=127.0.0.1 -c unix_socket_directories=$data -c max_connections=100 \
      -c shared_buffers=256MB -c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.track=top \
      -c log_lock_waits=on -c deadlock_timeout=100ms -c track_io_timing=on" start >/dev/null
as_pg "$PG_BIN/psql" -h "$data" -p "$port" -U postgres -qc "CREATE DATABASE $db" >/dev/null
as_pg "$PG_BIN/psql" -h "$data" -p "$port" -U postgres -d "$db" -qc "CREATE EXTENSION IF NOT EXISTS pg_stat_statements" >/dev/null
echo "local postgres up: $("$PG_BIN/postgres" --version) on 127.0.0.1:$port"
