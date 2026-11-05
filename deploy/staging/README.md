# Staging deploy (production images)

Staging runs the same images as production: `next build` (never `next dev`), gunicorn, the workers, behind nginx.
Images are built on a connected machine, shipped as one archive, loaded on the staging host and started with
`docker-compose.yml` in this folder. `scripts/deploy/staging.sh` does every step; the **Deploy staging** GitHub
workflow runs it from CI.

| Service | Image | Notes |
|---|---|---|
| nginx | `nginx:1.27-alpine` | only service with published ports; `FRONTEND_HOST` -> frontend, `API_HOST` -> backend; TLS when `certs/fullchain.pem` + `certs/privkey.pem` exist, plain HTTP otherwise; `DSS_REAL_IP_FROM` behind a load balancer (below) |
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
the archive, writes `DSS_TAG` into `.env`, runs `docker compose up -d --wait`, then the checks below; a failed
`compose up` fails the deploy (recorded as `FAILED` in `deploy-history`). The previous tag's images are kept and
recorded in `deploy-history`; each tag's deploy files (compose file, nginx config, rollup overlay, `staging.sh`) and
the head of its migrations are kept in `releases/<tag>/` for a rollback. `deploy` refuses a tag whose migrations do
not contain the database's revision (an older tag than the one that migrated it): that is what `rollback` is for.

Without registry access on the host, add `STAGING_INCLUDE_INFRA=1` to ship the postgres, mongo, rabbitmq and nginx
images in the same archive. Behind a TLS-intercepting proxy, build with `UV_BASE_IMAGE` / `NODE_BASE_IMAGE` set to
base images that trust the proxy CA. Plain-HTTP staging (no certificates): build with
`NEXT_PUBLIC_BACKEND_URL=http://<API_HOST>` and set `CORS_ORIGINS=http://<FRONTEND_HOST>`.

## Checks

`staging.sh check` (run by `deploy` and `rollback`) first asks compose: every service (or each of
`STAGING_SERVICES`) has a container from `DSS_TAG`'s images that is running, and healthy when it has a health check;
the one-shots (`migrate`, `minio-init`) exited 0. Then it talks to nginx on this host with the real host names:
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
scripts/deploy/staging.sh rollback [--allow-downgrade]     # on the host
make rollback-staging HOST=user@host [ALLOW_DOWNGRADE=1]    # from the build machine (rollback-prod: production)
```
Goes back to the tag that was running before the current one (`deploy-history`; also after a failed deploy) with
that release's own deploy files from `releases/<tag>/`: puts them back in place, switches `DSS_TAG`, `up -d`, checks.
* **Migrations.** An older image cannot start on a database a newer release migrated: its `migrate` one-shot fails
  with "Can't locate revision identified by ..." and the backend, cloud worker and DAST scheduler wait for it
  forever. So when the older tag's migrations do not contain the database's revision, rollback first stops the
  application services and runs `alembic downgrade <older head>` with the **current** image (its migrations contain
  both revisions), then starts the older tag. The downgrade **drops the tables and columns the newer migrations
  added, with their data**: rollback lists the migrations it reverses and asks you to type `downgrade`, or takes
  `--allow-downgrade` (`ALLOW_DOWNGRADE=1` for make); without a terminal and without the flag it refuses and changes
  nothing. Take a database backup first. When the current image has no path down to the older head (squashed
  migrations) rollback refuses and changes nothing: restore a backup instead. When the downgrade fails (Alembic runs
  it in one transaction), the current release is started again.
* **Argon2.** After the round-5 password change, a sign-in rehashes bcrypt passwords to Argon2id. An image from
  before that change cannot verify Argon2 hashes: those users cannot sign in after a rollback to it until they
  reset their password.
* A tag deployed before `releases/` existed has no recorded files: rollback starts it with the current files and
  says so.
* To go forward again, push the newer release from the build machine, or run `staging.sh deploy <tag>` on the host:
  it puts that tag's recorded files back in place.

## Behind a load balancer

The backend logs and rate-limits the address nginx hands it. When nginx faces the clients directly that is the
client. Behind a load balancer that terminates TLS (AWS ALB, Azure Application Gateway, a corporate reverse proxy)
every request reaches nginx from the balancer, so without more configuration **every client shares one address and
one rate-limit budget** (sign-in, codes, API). Set `DSS_REAL_IP_FROM` in `.env` to the addresses or networks the
balancer's requests come from (space or comma separated, e.g. its subnets `10.0.1.0/24,10.0.2.0/24`), then
`docker compose up -d nginx`. `40-dss-site.sh` turns that into `set_real_ip_from` lines plus
`real_ip_header X-Forwarded-For; real_ip_recursive on;` at the top of the site: nginx takes the right-most
`X-Forwarded-For` entry that is not one of those addresses, so a client cannot choose its own address by sending the
header itself, and a request that reaches nginx without passing the balancer keeps its TCP address. The startup log
line names the trusted sources. Empty (the default) adds nothing. A `/0` network, a host name or anything that is
not an address is refused and nginx does not start. The balancer must append the client to `X-Forwarded-For` (ALB
and Application Gateway do); the backend side (`FORWARDED_ALLOW_IPS` = nginx) is unchanged.

## Environment (names only)

`.env` (shared, also read by compose): `DSS_IMAGE_PREFIX`, `DSS_TAG`, `FRONTEND_HOST`, `API_HOST`, `HTTP_PORT`,
`HTTPS_PORT`, `HTTP_BIND`, `TLS_CERT_DIR`, `DSS_EDGE_SUBNET`, `DSS_PROXY_IP`, `DSS_REAL_IP_FROM`, `BACKEND_WORKERS`, `DAST_MEM_LIMIT`,
`IS_DOCKER_CONTAINER`, `PG_HOST`, `PG_PORT`, `PG_USER`, `PG_USER_PASS`, `PG_DB`, `MONGO_HOST`, `MONGO_PORT`,
`MONGO_INITDB_ROOT_USERNAME`, `MONGO_INITDB_ROOT_PASSWORD`, `RABBITMQ_HOST`, `RABBITMQ_PORT`,
`RABBIT_ADMIN_USERNAME`, `RABBIT_ADMIN_PASSWORD`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_DEFAULT_REGION`, `AWS_ENDPOINT_URL_S3`, `GIT_ALLOWED_HOSTS`, optional `MINIO_IMAGE`.

`backend.env` (backend-image containers only): `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `ENCRYPTION_KEY`,
`CERTIN_HMAC_SECRET`, `CORS_ORIGINS`, `CBOM_PUBLIC_APP_URL`, mail (`SMTP_*`, `MAIL_FROM` or `TENANT_ID`,
`CLIENT_ID`, `CLIENT_SECRET`, `EMAIL_SENDER`), `CBOM_AWS_*`, `CBOM_IDP_ALLOWED_PRIVATE`, `CBOM_EXTRA_CA_FILE`;
the full list is `backend/.env.example`.

Scan-node mTLS (optional): put the CA that issues scan-node client certificates at
`$TLS_CERT_DIR/node-client-ca.pem`; nginx then asks the API host's clients for a certificate
(`ssl_verify_client optional`), refuses one that does not chain to that CA, and ALWAYS overwrites
`X-ZS-Client-Verify` / `X-ZS-Client-Cert` before proxying (the plain-HTTP site blanks them). In `backend.env` set
`CBOM_MTLS_HEADER_TRUSTED=1` so the backend reads them (safe only because the backend port is published nowhere
and nginx is the only way in), `CBOM_MTLS_REQUIRED=1` to refuse node calls without a verified certificate, and
optionally `CBOM_MTLS_PIN=1` to hold each node to the certificate it enrolled with (a new certificate then needs a
node reset). Browsers are asked for a certificate only if they hold one from that CA. Nodes set `ZS_CLIENT_CERT`,
`ZS_CLIENT_KEY` and, for a private server CA, `ZS_CA_FILE`. Refusals are 403 with `X-ZS-Refused`; every node
answer carries `X-ZS-Deployment` (one id per deployment, created by migration `wp5a0node001`; a migration
downgrade and upgrade makes a new one, which nodes adopt from their next successful request).

Air-gapped sites: `GIT_ALLOWED_HOSTS` (self-hosted Git; same value for backend and workers),
`CBOM_IDP_ALLOWED_PRIVATE` + `CBOM_EXTRA_CA_FILE` (identity provider on a private network with a private CA),
`DSS_SBOM_REGISTRY=0` (no public registry lookups).

Integrations (Settings > Integrations: ServiceNow, syslog / Splunk HEC, signed webhooks, OSCAL push). Every
connection goes through one SSRF guard (`backend/utilities/integrations/outbound.py`): loopback, link-local / cloud
metadata and CGNAT addresses are never contacted; an on-premises destination (Splunk, a syslog collector, an internal
ServiceNow) must be listed in `INTEGRATION_ALLOWED_PRIVATE` in `backend.env` (comma-separated CIDRs and/or exact host
names, e.g. `10.20.0.0/16,splunk.corp.local`). Events are delivered by a dispatcher thread in the cloud worker
(`INTEGRATION_DISPATCHER=0` turns it off there; run `python -m backend.workers.integration_dispatcher` as its own
service instead); events not delivered within `INTEGRATION_MAX_AGE_HOURS` (default 24) of a failing destination are
dead-lettered, and admins retry them from the delivery log.

## GitHub workflow

**Deploy staging** (manual): builds, checks the image contexts, saves the archive as an artifact; with `deploy`
ticked it also pushes to the host. Configure in the repository's `staging` environment: secrets
`STAGING_SSH_KEY`, `STAGING_SSH_KNOWN_HOSTS`, `STAGING_SSH_TARGET`; variable `STAGING_DIR`. Nothing of that is in
the repository.
