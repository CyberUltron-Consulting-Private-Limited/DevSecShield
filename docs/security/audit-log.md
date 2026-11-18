# Audit log: guarantees, retention, erasure, database role

Table `auditevent` (`backend/access_models.py`), written by `backend/utilities/rbac/audit.py`.

## What is guaranteed
* **Fail closed.** An audited request (every team write, platform-admin writes, API-key scan starts) is written as
  `attempted` *before* its handler runs. If that write fails, the request answers 503 and nothing changes.
* **Outcome.** After the response the middleware writes `success`, `denied` (403/409 decided by the handler, with
  its reason) or `failed`, with `details.attempt_id`. This row is best effort: a worker killed after the response
  loses it, and the `attempted` row then stands without an outcome.
* **Domain events** (role changes, removals, ownership claim/assignment, invitations, team create, `team.delete.started`
  then `team.delete`, sign-ins) are written in the same transaction as the change.
* **Chains.** One SHA-256 chain per team and one for platform events (`team_id` NULL). `GET /admin/audit/verify`
  (`team_id`, `from_id`, `to_id`) finds a changed, inserted or removed row *inside* a chain.

## What is not guaranteed (yet)
* The hash is unkeyed, and the application's database role owns the table. Whoever holds that credential can
  disable the triggers, rewrite a chain with recomputed hashes, or drop a chain's newest rows; `verify_chain` cannot
  see that. On compose and staging the backend connects as the cluster superuser.
* **Proposed fix (follow-up):** a NOLOGIN role owns `auditevent` (`ALTER TABLE auditevent OWNER TO zs_audit_owner`);
  the app role gets `INSERT, SELECT` on it and `USAGE` on its sequence, and loses `UPDATE, DELETE, TRUNCATE,
  TRIGGER`; the erasure runs as a separate maintenance role. Migrations then run as the owner role, not as the app.
  Optionally anchor each chain head periodically outside the database (signed checkpoint).

## Retention
* Retention period: **13 months**, as CONTRACT section 8.8 sets for the F1.4 certificate audit.
* Today rows are never deleted (the triggers refuse DELETE and TRUNCATE for everyone). Follow-up: range-partition
  `auditevent` by month and drop partitions older than the retention period through the maintenance role, after
  recording each team chain's head at the cut as a platform event (the next row's `prev_hash` is the anchor that
  `verify_chain(from_id=...)` starts from). Partitioning an append-only, trigger-protected table later means a
  rewrite, so it should land before the table is large.

## Erasure (DPDPA / GDPR requests)
* `actor_email`, `ip` and `user_agent` are outside the hash. `audit.erase_personal_data(engine, email)` sets them to
  NULL for every event by that address; the PostgreSQL trigger allows exactly that update, only inside a
  transaction that switched `zs.audit_erasure` on. The account id stays, so the trail still says which account
  acted. The erasure is itself recorded (`audit.erasure`, platform chain, without the address).
* Not covered: `details.email` of events *about* a person (a role change names the member); those are inside the
  hash. Follow-up: store the subject's account id in details instead of the address.
