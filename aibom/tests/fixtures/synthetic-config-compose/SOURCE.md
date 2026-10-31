# synthetic-config-compose

Hand-derived 2026-10-27. Single-service Compose file verified with
`scan_crypto`.

- Service `db` uses image `postgres:15`, which resolves to the `postgres`
  datastore row in `datastore_images.json`.
- Bind mount `./pgdata:/var/lib/postgresql/data` keeps database, volume, and
  transport layers `layer_not_observable`; rollup verdict `UNKNOWN` with no
  posture finding codes.

No environment passwords or commands are planted (compose extractor must not
read them).
