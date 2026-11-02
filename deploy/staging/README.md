# Staging deploy (production images)

Staging runs the same images as production: `next build` (never `next dev`), gunicorn, the workers, behind nginx.
Images are built on a connected machine, shipped as one archive, loaded on the staging host and started with
`docker-compose.yml` in this folder. `scripts/deploy/staging.sh` does every step; the **Deploy staging** GitHub
workflow runs it from CI.

| Service | Image | Notes |
|---|---|---|
| nginx | `nginx:1.27-alpine` | only service with published ports; `FRONTEND_HOST` -> frontend, `API_HOST` -> backend; TLS when `certs/fullchain.pem` + `certs/privkey.pem` exist, plain HTTP otherwise |
| frontend | `<prefix>/devsecshield-frontend:<tag>` | the API URL is baked in at build time |
| migrate | backend image | one-shot `alembic upgrade head` under a Postgres advisory lock; everything that uses the database waits for it |
| backend | backend image | gunicorn, `BACKEND_WORKERS` workers; port not published; trusts `X-Forwarded-For` only from nginx (`FORWARDED_ALLOW_IPS` = `DSS_PROXY_IP`) |
| cbom-cloud-worker, dast-scheduler | backend image | |
| scan-worker, cicd-worker | `<prefix>/scan-worker:<tag>` | queues `scan_worker_queue`, `cicd_worker_queue` |
| dast-worker | `<prefix>/dast-worker:<tag>` | |
| postgres, mongo (auth on), rabbitmq | stock images | volumes `pgdata`, `mongodata`, `rabbitmq` |
| minio + minio-init | profile `minio` | optional S3 stand-in; otherwise real S3 |

## Staging host, first time

1. Docker 24+ with the compose plugin; ports 80/443 free; DNS for both host names pointing at the host.
2. A directory, e.g. `/opt/devsecshield-staging`. `staging.sh push` copies `deploy/staging/`,
   `compose/aibom-config-overlay/` and the scripts into it; the host's own files are never overwritten:
   ```sh
   cd /opt/devsecshield-staging/deploy/staging
   cp .env.example .env && cp backend.env.example backend.env && chmod 600 .env backend.env
   # set every value (names and meaning are in the two files and in backend/.env.example)
   mkdir -p certs   # fullchain.pem + privkey.pem for both host names; without them nginx serves plain HTTP
   ```
   Set `ENCRYPTION_KEY` before the first start (see `docs/security/secret-rotation.md`).
   **`DSS_DEV_MODE` and `LOCAL_DEV_VERIFICATION_*` must never be set here**; `staging.sh` refuses to deploy if
   they are.
3. Optional local S3: `AWS_ENDPOINT_URL_S3=http://minio:9000` in `.env` and `COMPOSE_PROFILES=minio`.

## Deploy (build machine)

```sh
scripts/deploy/staging.sh release deploy@staging-host /opt/devsecshield-staging
```
= `build` (all images, tag = short commit; the frontend gets `NEXT_PUBLIC_BACKEND_URL=https://<API_HOST>`),
`save` (`deploy/staging/images/dss-staging-<tag>.tar.gz` + `.sha256`), `push` (scp of the bundle and the archive,
then `staging.sh deploy <tag>` on the host over ssh). On the host, `deploy` verifies the checksum, `docker load`s
the archive, writes `DSS_TAG` into `.env`, runs `docker compose up -d --wait`, then the checks below. The previous
tag's images are kept and recorded in `deploy-history`.

Without registry access on the host, add `STAGING_INCLUDE_INFRA=1` to ship the postgres, mongo, rabbitmq and nginx
images in the same archive. Behind a TLS-intercepting proxy, build with `UV_BASE_IMAGE` / `NODE_BASE_IMAGE` set to
base images that trust the proxy CA. Plain-HTTP staging (no certificates): build with
`NEXT_PUBLIC_BACKEND_URL=http://<API_HOST>` and set `CORS_ORIGINS=http://<FRONTEND_HOST>`.

## Checks

`staging.sh check` (run by `deploy` and `rollback`) talks to nginx on this host with the real host names:
* `GET https://<API_HOST>/health` answers 200 `healthy`;
* `GET https://<FRONTEND_HOST>/login` answers 200, references `/_next/static/chunks/*.js` that all load, and
  carries no `next dev` marker (HMR client chunk, `"development"` build id, `webpack-hmr`, `react-refresh`). A
  Next.js 16 production build does reference a `turbopack-<hash>.js` runtime chunk; that is not a dev marker;
* one of those chunks contains `<API_HOST>`: the frontend was built for this API.

From any machine with Python Playwright, a real-browser check (types an e-mail, presses "Send Verification Code"
and requires the resulting `POST /send_code`):
```sh
python3 scripts/deploy/staging_browser_check.py --frontend-url https://<FRONTEND_HOST> --api-url https://<API_HOST>
```

## Rollback

```sh
scripts/deploy/staging.sh rollback     # on the host
```
Switches `DSS_TAG` back to the previous deployed tag, `up -d`, checks. Two warnings it also prints:
* **Migrations are not reversed.** The older code runs on the newer schema (fine for the additive migrations this
  project writes; check the revision list before rolling back across a destructive one).
* **Argon2.** After the round-5 password change, a sign-in rehashes bcrypt passwords to Argon2id. An image from
  before that change cannot verify Argon2 hashes: those users cannot sign in after a rollback to it until they
  reset their password.

## Environment (names only)

`.env` (shared, also read by compose): `DSS_IMAGE_PREFIX`, `DSS_TAG`, `FRONTEND_HOST`, `API_HOST`, `HTTP_PORT`,
`HTTPS_PORT`, `HTTP_BIND`, `TLS_CERT_DIR`, `DSS_EDGE_SUBNET`, `DSS_PROXY_IP`, `BACKEND_WORKERS`, `DAST_MEM_LIMIT`,
`IS_DOCKER_CONTAINER`, `PG_HOST`, `PG_PORT`, `PG_USER`, `PG_USER_PASS`, `PG_DB`, `MONGO_HOST`, `MONGO_PORT`,
`MONGO_INITDB_ROOT_USERNAME`, `MONGO_INITDB_ROOT_PASSWORD`, `RABBITMQ_HOST`, `RABBITMQ_PORT`,
`RABBIT_ADMIN_USERNAME`, `RABBIT_ADMIN_PASSWORD`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_DEFAULT_REGION`, `AWS_ENDPOINT_URL_S3`, `GIT_ALLOWED_HOSTS`, optional `MINIO_IMAGE`.

`backend.env` (backend-image containers only): `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `ENCRYPTION_KEY`,
`CERTIN_HMAC_SECRET`, `CORS_ORIGINS`, `CBOM_PUBLIC_APP_URL`, mail (`SMTP_*`, `MAIL_FROM` or `TENANT_ID`,
`CLIENT_ID`, `CLIENT_SECRET`, `EMAIL_SENDER`), `CBOM_AWS_*`, `CBOM_IDP_ALLOWED_PRIVATE`, `CBOM_EXTRA_CA_FILE`;
the full list is `backend/.env.example`.

Air-gapped sites: `GIT_ALLOWED_HOSTS` (self-hosted Git; same value for backend and workers),
`CBOM_IDP_ALLOWED_PRIVATE` + `CBOM_EXTRA_CA_FILE` (identity provider on a private network with a private CA),
`DSS_SBOM_REGISTRY=0` (no public registry lookups).

## GitHub workflow

**Deploy staging** (manual): builds, checks the image contexts, saves the archive as an artifact; with `deploy`
ticked it also pushes to the host. Configure in the repository's `staging` environment: secrets
`STAGING_SSH_KEY`, `STAGING_SSH_KNOWN_HOSTS`, `STAGING_SSH_TARGET`; variable `STAGING_DIR`. Nothing of that is in
the repository.
