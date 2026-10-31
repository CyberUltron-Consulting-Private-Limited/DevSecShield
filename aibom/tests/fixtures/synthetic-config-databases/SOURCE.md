# synthetic-config-databases

Hand-derived 2026-10-27 from the PostgreSQL and Redis cases in
`test_cbom_posture_settings_databases.py` (`extract_postgresql` /
`extract_redis` decision table). Values were not taken from a product scan.

- `postgres-declared/` — `ssl = on` with `hostssl all all 0.0.0.0/0` in
  `pg_hba.conf` sets transport to `ENCRYPTED_DECLARED` when conf and hba are
  read together (oracle models that pairing).
- `postgres-ssl-unknown/` — `ssl = on` only; transport is not
  `ENCRYPTED_DECLARED` and carries `layer_not_observable`.
- `redis-plaintext/` — `tls-port 6379`, `port 6379`, and `bind 0.0.0.0` mark
  transport `NOT_ENCRYPTED` with TLS also enabled.

No secrets are planted in this tree.
