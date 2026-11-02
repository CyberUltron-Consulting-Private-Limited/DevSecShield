# Secret rotation

## Why

These files are committed to git, so every value in them is readable by anyone with access to the repository,
including its full history, and (until the `.dockerignore` changes of round 5) they were also copied into the
backend and worker images:

| Exposed in git | What it holds (names only) |
|---|---|
| `backend/.env`, `backend/utilities/ai/.env`, `prod_database_migrations/.env` | backend settings: database, Mongo, RabbitMQ, JWT, mail, AWS |
| `RabbitMQ/.env`, `RabbitMQ/worker/.env`, `RabbitMQ/worker/helpers/context/.env`, `RabbitMQ/worker/helpers/tests/.env` | scan worker settings |
| `RabbitMQ/dast_worker/.env`, `RabbitMQ/dast_worker/helpers/agent/.env`, `RabbitMQ/dast_worker/helpers/tests/.env` | DAST worker settings |
| `RabbitMQ/guardrail_worker/.env` | guardrail worker settings |
| `compose/.env`, `compose/vector-db/.env` | infrastructure passwords |
| `cu-devsecshield-key.pem` | an SSH private key |
| `compose/worker-compose/docker-compose.yml`, `compose/container-test/docker-compose.yml` (history) | the Mongo URL with its password, inline |
| `backend/utilities/auth/auth_utils.py` (history) | two accounts that accepted a fixed sign-in code |
| `.skill-workspace/prod_loadtest_30*.py` | production host, one of those accounts, its password and code |

Decision D2 keeps the tracked files tracked (removing them would delete teammates' local copies on `git pull`), so
the values stay readable. **Rotation is the only remedy.** Treat every non-empty value in the files above as
known to an attacker, rotate it, and only then consider rewriting history (`git filter-repo`), which is a separate
decision. `aibom/examples/shadow-demo/.env` and `aibom/tests/fixtures/**` hold planted test values, not secrets.

What stops it happening again: `.gitignore` refuses new `.env*` (except `.env.example`) and `*.pem` / `*.key`
files; every image build context excludes them (`scripts/deploy/check_image_contexts.sh` proves it, and
`scripts/deploy/build_images.sh` fails an image that contains one); secrets are passed at run time
(`deploy/staging/.env` and `backend.env` on the host, mode 600); each service documents its variables in a
`.env.example` with placeholders only.

## Order

1. Set the values that would otherwise be derived from the JWT secret (step 2) **before** rotating it.
2. Rotate the infrastructure passwords (PostgreSQL, Mongo, RabbitMQ) one at a time; each needs a short restart.
3. Rotate the external credentials (AWS, mail, Graph, tokens). Create the new one, deploy it, then revoke the old.
4. Revoke the SSH key and reset the two fixed-code accounts.
5. Rotate CI/CD API keys that appear in scripts or documents.

## What to rotate and how

### JWT secrets: `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`
Generate two different values of at least 32 bytes (`openssl rand -hex 32`; with the round-5 authentication
change the backend refuses equal or shorter secrets outside dev mode) and set them on every backend-image container (API, migrate, CBOM cloud worker, DAST scheduler). Every
session ends; users sign in again.

Before that, freeze what is derived from the old secret:
* `ENCRYPTION_KEY` unset means stored credentials (CBOM source secrets, DAST login passwords, Jira tokens) are
  encrypted with a key derived from `JWT_SECRET_KEY`. Set `ENCRYPTION_KEY` to that derived key first, so stored
  values stay readable:
  `python3 -c "import base64,hashlib,os; print(base64.urlsafe_b64encode(hashlib.sha256(os.environ['OLD'].encode()).digest()).decode())"`
  with the old JWT secret in `OLD`.
* `CERTIN_HMAC_SECRET` unset falls back to `JWT_SECRET_KEY`: set it to the old JWT secret first so existing
  CERT-In attestation hashes still verify, or to a new value if those attestations can be re-issued.

### `ENCRYPTION_KEY`
One key at a time; the code has no multi-key decryption. If the key itself was exposed, rotating it makes every
stored credential unreadable: rotate it, then ask each team to re-enter its CBOM source secrets, DAST profile
logins and Jira tokens. There is no re-encryption tool yet.

### PostgreSQL: `PG_USER_PASS`
`ALTER ROLE <PG_USER> WITH PASSWORD '<new>';` (with `password_encryption = scram-sha-256`), then update
`PG_USER_PASS` for the backend-image containers and restart them. `POSTGRES_PASSWORD` in a compose file only
applies when the data directory is first created; changing it later changes nothing.

### MongoDB: `MONGO_INITDB_ROOT_PASSWORD`, `RABBIT_MONGO_CONNECTION_URL`
`mongosh -u <user> -p --authenticationDatabase admin --eval 'db.getSiblingDB("admin").changeUserPassword("<user>", passwordPrompt())'`,
then update the variables on the backend and every worker and restart them. Like PostgreSQL, the `MONGO_INITDB_*`
variables only apply to an empty database. The old password is in git history of the two compose files above.

### RabbitMQ: `RABBIT_ADMIN_PASSWORD`
`rabbitmqctl change_password <RABBIT_ADMIN_USERNAME> '<new>'`, then update the backend and every worker.
`RABBITMQ_DEFAULT_PASS` only applies at first boot.

### Mail: `SMTP_PASSWORD`, `CLIENT_SECRET` (Microsoft Graph), `EMAIL_PASSWORD`
SMTP relay: issue a new credential in the relay's console. Graph: add a new client secret to the app registration
(`TENANT_ID`/`CLIENT_ID`), deploy it, delete the old one. Gmail `EMAIL_PASSWORD`: revoke the app password and
create a new one.

### AWS: `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`, `CBOM_AWS_ACCESS_KEY_ID` / `CBOM_AWS_SECRET_ACCESS_KEY`
For each IAM user: create a second access key, deploy it, then deactivate and delete the old key. Check CloudTrail
for calls made with the old key id since it was committed. Prefer instance or task roles over keys.

### The SSH key `cu-devsecshield-key.pem`
On a trusted machine, derive its public key (`ssh-keygen -y -f cu-devsecshield-key.pem`) and remove that line
from `~/.ssh/authorized_keys` of every user on every host that accepted it (staging, production, bastions). If it
is an EC2 key pair, also delete the key pair in EC2 (that alone does not remove it from running instances). Issue
one key per person instead, and review `auth.log` for logins with the old key's fingerprint.

### The two fixed-code accounts
With the round-5 authentication change, fixed sign-in codes work only with `DSS_DEV_MODE=1` (never set on staging
or production) and never for a password reset. Change both accounts' passwords anyway: the code and, for one of them, the password were readable in the repository.

### CI/CD API keys (`cicd-api-key`)
Recreate any integration whose key appears in a script, document or chat log, update the pipeline secret
(`CICD_API_KEY`), and delete the old integration.

### Everything else
Any other non-empty value in the files listed above (vector-store keys, LLM provider keys, `GITHUB_TOKEN`,
`NVD_API_KEY`, `QDRANT_API_KEY`, ...): rotate it at its issuer. The variable names each service reads are in
`backend/.env.example`, `RabbitMQ/*/.env.example`, `compose/.env.example`, `compose/worker-compose/.env.example`
and `scan_node/.env.example`.
