# DevSecShield Chola production (runbook)

One command from the owner's machine deploys a commit to the Chola production instance:

```sh
scripts/deploy/chola-prod.sh deploy --sha <commit>
```

The owner runs it with his own AWS credentials. Nothing in this folder holds a secret; the kit reads them from AWS
Secrets Manager at run time and never prints a value.

```
browser --HTTPS--> ALB devsec-chola-prod-alb (ACM, both host names) --HTTP :80--> i-0b7fe756ebfd4d1e6 (10.60.10.108)
                                                                                    nginx :80 (only published port)
                    chola.zeroshield.ai      -> frontend:3000  (edge network)
                    chola-api.zeroshield.ai  -> backend:8080   (edge + data networks)
                    /nginx-health            -> 200 "ok" (ALB health check, any Host)
  data network (internal, no route out): postgres, mongo, rabbitmq, qdrant
  workers (data + egress): scan-worker, cicd-worker, dast-worker, cbom-cloud-worker, dast-scheduler; migrate (one-shot)
  volumes: /var/lib/docker/volumes = the 200 GB data volume vol-02a57fae6510bb790
```

| File | What |
|---|---|
| `scripts/deploy/chola-prod.sh` | the owner's command (preflight, host-setup, secrets, images, infra, backup, deploy, verify, rollback, smtp-test, admin, status, logs; `--dry-run`) |
| `deploy/chola-prod/docker-compose.yml` | the stack (project `dss-chola`) |
| `deploy/chola-prod/nginx/` | site template + entrypoint script (host routing, real IP and scheme from the ALB subnets only, security headers) |
| `deploy/chola-prod/remote.sh` | the instance side (copied to `/opt/devsecshield-chola/deploy/chola-prod/`; run over SSH by chola-prod.sh) |
| `deploy/chola-prod/kit.py` | secret merge, env rendering (stdlib only) |
| `deploy/chola-prod/smtp_check.py` | SMTP login test (authenticates, sends nothing) |
| `backend/tests/test_chola_prod_kit.py` | tests of all of the above (run by CI's backend job) |

## 0. Before the first deploy: rotate what was shared in chat

The IAM access key of `AnshSinghal-Cyberultron` and the SSH private key of `devsec-chola/prod/ssh-admin` were pasted
into a chat. Treat both as exposed:

* IAM: create a second access key for the user, switch your AWS profile to it, `aws sts get-caller-identity`, then
  deactivate and delete the old key; check CloudTrail for calls made with the old key id.
* SSH: generate a new key pair on a trusted machine (`ssh-keygen -t ed25519 -f chola-admin -N ''`), replace
  `ubuntu`'s `~/.ssh/authorized_keys` entry on the instance (through the current key, with this kit's tunnel:
  `chola-prod.sh status` proves the tunnel works), store the new private key in `devsec-chola/prod/ssh-admin`
  field `private_key_pem` (infra team, or whoever may write that secret), delete the local copies.

## 1. Prerequisites (owner's machine)

* **AWS CLI v2.12+** (`aws ec2-instance-connect open-tunnel`), credentials of `AnshSinghal-Cyberultron` (profile:
  `export AWS_PROFILE=<profile>`). Region and account are fixed in the script (ap-south-1, 935951870001); the
  script refuses another account.
* **Docker** with **buildx** (Docker Desktop is fine). On Apple Silicon the frontend is built for linux/amd64 under
  emulation (10-20 min). About 15 GB free for images and the release archive.
* **gh** signed in with the `read:packages` scope (`gh auth refresh -s read:packages`): the backend and worker
  images come from GHCR. Without gh, run `docker login ghcr.io` yourself with a token that has `read:packages`.
* **git**: a checkout of this repository that contains this folder, with `origin` able to fetch `ansh` (the mail
  login is read at run time from `git show origin/ansh:backend/.env`: `OUTLOOK_EMAIL`, `OUTLOOK_PASSWORD`; it is
  copied only into a 0700 scratch directory that is deleted on exit, never into the repository).
* **python3** 3.8+, **ssh**, **curl**, **bash** (macOS's bash 3.2 works).
* The commit to deploy must have green **Publish images (GHCR)** for it (every push to `dev` or `staging` does:
  `dev-<sha12>` / `staging-<sha12>`). Pass `--ghcr-tag <tag>` for another tag.

Asks for the infra team (the owner's IAM user is read-only for these; preflight reports them):

* **IMDS**: `HttpTokens=required` and `HttpPutResponseHopLimit=1` on the instance. The application does not use the
  instance role (S3 and Bedrock are called with the app-user keys, see "Decisions"); with hop limit 2 any container
  (the DAST worker drives a browser against customer targets) could obtain the role's credentials, which read every
  `devsec-chola/prod/*` secret. `remote.sh preflight` also probes it from a container.
* **ALB idle timeout**: 60 s by default. CI/CD scan calls hold the request until the worker answers and the AI chat
  streams (server-sent events); raise it to 600 s (nginx allows 600 s) or such calls end with a 504 from the ALB.
* The instance security group: port 80 from the ALB subnets 10.60.1.0/24 and 10.60.2.0/24 only.

## 2. Deploy

```sh
cd <your DevSecShield checkout> && git fetch origin
export AWS_PROFILE=<profile of AnshSinghal-Cyberultron>

scripts/deploy/chola-prod.sh preflight --sha <commit>        # read-only, plus copying the kit files to the instance
scripts/deploy/chola-prod.sh host-setup                       # ONLY if preflight says the instance has no AWS CLI
scripts/deploy/chola-prod.sh deploy --sha <commit> --dry-run  # every step it will take, nothing is run
scripts/deploy/chola-prod.sh deploy --sha <commit>            # asks you to type 'chola' (or --yes)
```

`deploy` runs, in order, stopping at the first failure:

1. **preflight**: tools, AWS identity (account 935951870001), instance running, IMDS options, target group
   (HTTP 80, `/nginx-health`), the four secrets visible, the four ECR repositories, the backup vault; the kit files are
   copied to `/opt/devsecshield-chola`; on the instance: Docker + Compose, AWS CLI and the instance role (STS),
   `/var/lib/docker` on its own volume (refused when it is on the root disk), free disk, IMDS from a container.
2. **secrets**: `devsec-chola/prod/app-secrets` (empty at first) gets every missing value generated with the OS CSPRNG
   (`JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `ENCRYPTION_KEY` (Fernet), `CERTIN_HMAC_SECRET`, `PG_USER_PASS`,
   `MONGO_INITDB_ROOT_PASSWORD`, `RABBIT_ADMIN_PASSWORD`, `QDRANT_API_KEY`) and the mail login (`SMTP_USERNAME`,
   `SMTP_PASSWORD`, `MAIL_FROM` from `OUTLOOK_EMAIL` / `OUTLOOK_PASSWORD`). **Every value already there is kept**:
   `put-secret-value` replaces the whole JSON, so the kit reads, merges and writes only when something changed (key
   names and "kept / generated / set" are printed, never values). An unusable stored value is refused, not replaced.
   If the secret is empty but the instance already has a database volume, it refuses (new passwords would lock the
   application out of its data; restore the `AWSPREVIOUS` version instead).
3. **images**: backend, scan-worker and dast-worker are pulled from GHCR for linux/amd64 (`<prefix>-<sha12>`; the OCI
   revision label must be the commit), the frontend is **built** from the commit's own tree (`git archive`) for
   linux/amd64 with `NEXT_PUBLIC_BACKEND_URL=https://chola-api.zeroshield.ai`; all four are pushed to
   `935951870001.dkr.ecr.ap-south-1.amazonaws.com/devsec-chola/{devsecshield-backend,devsecshield-frontend,scan-worker,dast-worker}:<sha12>`.
   A tag already in ECR is not pushed again.
4. **files and env on the instance**: the kit files and the commit's `compose/aibom-config-overlay`; then
   `remote.sh render` writes `.env` and `backend.env` from Secrets Manager **with the instance role** (mode 600, owner
   ubuntu, in `/opt/devsecshield-chola/deploy/chola-prod/`); ECR login with the instance role; `docker pull` of the
   four images (linux/amd64 checked; at least 15 GB free required).
5. **infra**: if the instance lacks postgres, mongo, rabbitmq, nginx or qdrant, they are pulled here for linux/amd64,
   `docker save`d to `s3://devsecshield-storage/releases/release.tar`, downloaded on the instance to
   `/var/lib/docker/releases/`, checked against their sha256, `docker load`ed and deleted. Skipped when present.
6. **backup**: `pg_dump` and `mongodump` into `/var/lib/docker/dss-backups/` (on the data volume; last 3 kept), then the
   on-demand AWS Backup job of `vol-02a57fae6510bb790` (14 days, the production tags); waits for `COMPLETED`, stops on
   `FAILED` / `ABORTED` / `EXPIRED` / `PARTIAL` or after 2 h (`CHOLA_BACKUP_TIMEOUT_S`).
7. **deploy** (`remote.sh deploy <sha12>`): refuses a commit whose migrations do not contain the database's Alembic
   revision (older than the database: use rollback); records the deploy files and the Alembic head in
   `/opt/devsecshield-chola/state/releases/<sha12>/`; switches `DSS_TAG`; `docker compose up --wait` (the `migrate`
   one-shot runs `alembic upgrade head` under a Postgres advisory lock first; everything that uses the database waits
   for it); checks every service runs the tag and is healthy, `/nginx-health`, `GET /health` and the login page
   through nginx (production chunks, no `next dev`, `https://chola-api.zeroshield.ai` baked in); runs the idempotent
   CBOM estate backfill and agility heal; keeps the images of this tag, the rollback target and the last good one.
8. **smtp-test**: from a backend container with the deployed `backend.env`: connect to smtp.office365.com:587,
   STARTTLS, AUTH, QUIT. Sends nothing. A failure is reported (see Troubleshooting) but does not undo the deploy.
9. **verify**: the ALB target is `healthy` (waits up to 5 min), `curl http://localhost/nginx-health` on the instance
   is `ok`, `https://chola.zeroshield.ai/login` is 200 (with HSTS), `https://chola-api.zeroshield.ai/health` is 200
   `healthy`. Then a summary.

**Downtime**: one instance, so the containers that change are recreated in place; expect a minute or two of 502/503
from the ALB while the backend restarts. A change to `nginx/` or the aibom overlay alone also recreates nginx and the
backend-image services (a content hash label; bind mounts are otherwise invisible to Compose).

Single steps can be run on their own: `secrets`, `images --sha S`, `infra [--force-infra]`, `backup`, `verify`,
`smtp-test`, `status`, `logs [--service backend] [--tail 500]`.

## 3. First administrator (ansh@zeroshield.ai)

The application has no bootstrap account and no admin-creation endpoint that works without an existing administrator
(`POST /admin/create_admin_user` needs one). Every account is created by sign-up with an e-mailed code, gets its own
team as owner, and the first platform administrator is set in the database (the same step as `deploy/local/README.md`
section 5). Mail must work first (`chola-prod.sh smtp-test` says OK).

1. Open https://chola.zeroshield.ai/register, enter name, `ansh@zeroshield.ai` and a password (8-128 characters),
   press **Send Verification Code**, enter the code from the mailbox, finish.
2. `scripts/deploy/chola-prod.sh admin --email ansh@zeroshield.ai` (sets `is_superuser` for that address,
   case-insensitive; refuses if the account does not exist yet).
3. Sign out and in again; https://chola.zeroshield.ai/admin opens. New teams start with 0 credits and scans spend
   credits: **Update Credits** for the team there.
4. Further users: invite them from the team settings (mail) or let them register.

Never set `DSS_DEV_MODE` or `LOCAL_DEV_VERIFICATION_*` here (the fixed sign-in code of development): `kit.py` never
writes them and `remote.sh` refuses to start if either env file contains them.

## 4. Verify (any time)

```sh
scripts/deploy/chola-prod.sh verify
scripts/deploy/chola-prod.sh status        # containers, deployed tag, history, images, disk, ALB target health
```

By hand: `aws elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:ap-south-1:935951870001:targetgroup/devsec-chola-prod-tg/3c35d6b360c5c80a`,
`curl -I https://chola.zeroshield.ai`, `curl https://chola-api.zeroshield.ai/health` (`{"status":"healthy",...}`).
`/health` is the backend's own route (backend/main.py); it does not name the build (`DSS_EXPOSE_BUILD=0`); signed-in
users read the build from `GET /version`.

## 5. Rollback

```sh
scripts/deploy/chola-prod.sh rollback [--allow-downgrade]
```

Takes a backup first, then goes back to the tag that was running before the current one (`state/deploy-history`,
also after a failed deploy) with that release's own deploy files, and verifies. When the older release's migrations do
not contain the database's revision, the current image first runs `alembic downgrade <older head>`, which **drops the
tables and columns the newer migrations added, with their data**: it lists those migrations and needs
`--allow-downgrade` (or typing `downgrade` in a terminal); otherwise nothing is changed. When there is no downgrade
path, or the downgrade fails (the current release is started again), restore instead. Going forward again:
`deploy --sha <newer>`. Users whose password a newer release rehashed may need a password reset on an older image.

**Restore**: logical dumps are in `/var/lib/docker/dss-backups/` (`pg_restore -d ...` / `mongorestore --archive
--gzip`); the whole data volume: restore the pre-deployment recovery point from vault `devsec-chola-prod-backup-vault`
to a new volume and have the infra team swap it in at `/var/lib/docker` (stop Docker first).

## 6. Where the secrets live, and rotation

| Secret (Secrets Manager, ap-south-1) | Holds | Read by |
|---|---|---|
| `devsec-chola/prod/ssh-admin` | `private_key_pem` | owner's machine (SSH key, temp file 0600, deleted on exit) |
| `devsec-chola/prod/app-secrets` | the generated keys above + `SMTP_USERNAME`, `SMTP_PASSWORD`, `MAIL_FROM` | written by the owner (`secrets`), read by the instance role (`render`) |
| `devsec-chola/prod/app-user` | the app IAM user's access key (S3 `devsecshield-storage` + Bedrock) | instance role -> `.env` `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` |
| `devsec-chola/prod/cbom-collector` | the CBOM collector's access key (sts:AssumeRole only) | instance role -> `backend.env` `CBOM_AWS_*` (its principal ARN from the secret, else from STS) |

On the instance, `.env` and `backend.env` (mode 600) are rendered on every deploy; never copy them anywhere.
`.env` (every application container): images, host names, infrastructure credentials, AWS app-user keys, Qdrant,
`LLM_MODEL`. `backend.env` (backend-image containers only): JWT, `ENCRYPTION_KEY`, `CERTIN_HMAC_SECRET`, CORS and app
URL, SMTP, CBOM collector and AI settings.

Rotation (details: `docs/security/secret-rotation.md`): change the value in Secrets Manager, then
`chola-prod.sh deploy --sha <the running commit>` re-renders the files and recreates the containers. Order matters:
* `PG_USER_PASS`, `MONGO_INITDB_ROOT_PASSWORD`, `RABBIT_ADMIN_PASSWORD` only take effect on an empty volume: change the
  password **inside** the database / broker first (`ALTER ROLE`, `changeUserPassword`, `rabbitmqctl change_password`),
  then in the secret, then deploy.
* `ENCRYPTION_KEY`: one key at a time; rotating it makes stored credentials unreadable (teams re-enter them).
* JWT secrets: every session ends. Mail: update the mailbox password in `origin/ansh` or in the secret, then
  `chola-prod.sh secrets --refresh-mail` and deploy.
* app-user / cbom-collector keys: new key, update the secret, deploy, delete the old key.
* Never delete `app-secrets`: Secrets Manager keeps the previous version as `AWSPREVIOUS`.

## 7. Troubleshooting

* **EICE tunnel** (`SSH to i-0b7fe756ebfd4d1e6 failed`): `aws ec2-instance-connect open-tunnel --region ap-south-1
  --instance-id i-0b7fe756ebfd4d1e6 --local-port 2222` in one terminal shows the tunnel's own error (no endpoint in the
  VPC, missing `ec2-instance-connect:OpenTunnel`, the endpoint's security group not allowed to port 22 of the
  instance). AWS CLI older than 2.12 has no `open-tunnel`. A changed host key (instance rebuilt) is refused: remove the
  line from `~/.ssh/known_hosts_devsec_chola` (the first connection records it). EICE connections are time-limited;
  the kit opens a new tunnel whenever the shared one has closed, so a long frontend build or backup wait is fine.
* **"another chola-prod command is running"**: a deploy, rollback or render holds `/opt/devsecshield-chola/state/.lock`
  on the instance; wait for it (or, if its SSH session died, the lock is released when its process ends).
* **ECR login** on your machine fails: wrong profile or region; on the instance (`remote.sh ecr-login`): the instance
  role lacks `ecr:GetAuthorizationToken` or ECR is not reachable (VPC endpoint / egress). `docker pull` "not found":
  the image was not pushed (`chola-prod.sh images --sha S`).
* **SMTP AUTH disabled** (`smtp-test` exit 2): Office 365 refuses Basic-auth SMTP for the tenant or the mailbox. Fix in
  Exchange Online: `Set-CASMailbox -Identity <mailbox> -SmtpClientAuthenticationDisabled $false` (mailbox) and, if
  the tenant switch is on, `Set-TransportConfig -SmtpClientAuthenticationDisabled $false`; Security Defaults or a
  Conditional Access policy that blocks legacy authentication also block it. Microsoft is retiring Basic auth for
  SMTP AUTH: per Message Center MC786329 it is disabled by default for existing tenants at the end of December 2026
  (admins can turn it back on for now), with final removal to be announced. Plan a relay that does not depend on it
  (an SMTP relay with its own credentials, or Amazon SES SMTP on 587 from the instance) and set `SMTP_*` accordingly.
  Exit 3: the password was refused (wrong, expired, or MFA on the mailbox). Exit 4: no TCP 587 from the instance.
  The backend's own log says the same without values: `docker compose logs backend | grep -i smtp`.
* **Target unhealthy**: `status` (is nginx up?); on the instance `curl -i http://localhost/nginx-health`; the target
  group must use HTTP, port 80 (traffic port), path `/nginx-health`; the security group must allow port 80 from the
  ALB subnets. `nginx` exits at start when `DSS_REAL_IP_FROM` holds a /0 or a host name (`logs --service nginx`).
* **Login page check fails** ("no login-page chunk contains https://chola-api.zeroshield.ai"): the frontend in ECR was
  built for another API URL; delete that tag in ECR and run `images --sha S` again (or `--frontend-image` with a
  correctly built image).
* **migrate fails** with "Can't locate revision": the database is newer than the commit; use `rollback`, or deploy a
  newer commit.
* **Disk**: `status` shows free space; images live in `/var/lib/containerd` (root disk) with Docker 29's containerd
  store and volumes in `/var/lib/docker` (data volume). Each deploy keeps three releases' images.

## 8. Decisions (why it is built this way)

* **S3 and Bedrock use the app-user keys, not the instance role.** The code builds its S3 client and every Bedrock
  client from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` explicitly and fails without them
  (`backend/utilities/db/s3_utils.py`, `backend/utilities/ai/llm.py`, `RabbitMQ/worker/helpers/context/s3_utils.py`,
  `base_utilities.py`, `base_agent.py`), so the instance role cannot be used without code changes; the IMDS hop limit
  then only matters for security (keep it at 1). The CBOM AI assistant uses the same keys (`CBOM_AI_AWS_CREDENTIALS=env`).
  No MinIO: real S3, bucket `devsecshield-storage` (the code's default bucket).
* **Bedrock models**: every AI feature in the code calls `openai.gpt-oss-120b-1:0` (`LLM_MODEL`, `CBOM_AI_MODEL`
  default); `global.anthropic.claude-haiku-4-5-20251001-v1:0` is used only by the nightly AIBOM benchmark workflow.
* **Frontend built by the kit**: `NEXT_PUBLIC_BACKEND_URL` is inlined at `next build` (frontend/Dockerfile), and GHCR's
  dev/staging frontends carry `http://localhost:8000` (`.github/ci/ghcr_meta.py`). `CORS_ORIGINS` and
  `CBOM_PUBLIC_APP_URL` are runtime (backend.env). Sign-in tokens travel in headers, so there is no cookie domain.
* **Mail over SMTP**, not Graph: the instance cannot reach graph.microsoft.com; with `SMTP_HOST` set the backend never
  tries Graph (`backend/utilities/auth/auth_utils.py`).
* **Qdrant is part of this stack** (it is not in deploy/staging): SAST / IaC / SCA AI analysis needs it.
* `DSS_SBOM_REGISTRY=0`: the instance cannot reach public package registries. `DSS_ENV=production` (lab mode refused).
  The dast-worker gets `UV_NO_SYNC=1` / `UV_OFFLINE=1` (its image lacks them; the instance cannot reach PyPI).

## 9. Known limitations under the instance's egress rules (not fixed by this kit)

* **SAST AI (RAG)**: the scan worker embeds code with `amazon.titan-embed-text-v2:0`
  (`RabbitMQ/worker/helpers/context/base_utilities.py`), which is not one of the two Bedrock models this account may
  call: expect `AccessDeniedException` in SAST/IaC scans until the model is allowed or the code changes.
* **Semgrep rules**: the SAST step runs `semgrep --config p/<language>` (`RabbitMQ/worker/helpers/tools/sast_agent/semgrep_util.py`),
  which downloads rules from semgrep.dev; the instance cannot reach it, so that step fails ("SAST scan failed").
  Allow semgrep.dev in the egress rules or vendor the rules.
* **Scan-node downloads** (Add scan node wizard): not shipped (`CBOM_NODE_ARTIFACT_DIR` unset); the wizard says they
  are not available. deploy/staging has the machinery (`staging.sh node-artifacts`) if they are needed here.
* **CBOM / AI-BOM code scans, DAST, CBOM cloud sources, sign-in, S3 uploads and the CBOM AI assistant** need nothing
  beyond the allowed egress (GitHub/GitLab/Bitbucket, Grype DB, S3, Bedrock gpt-oss, STS, SMTP).
