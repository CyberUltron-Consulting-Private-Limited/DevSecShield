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
3. Optional local S3: `AWS_ENDPOINT_URL_S3=http://minio:9000` in `.env` and `COMPOSE_PROFILES=minio`. The default
   `MINIO_IMAGE` is no longer on Docker Hub (MinIO removed the repository): set `MINIO_IMAGE` to an image you have
   loaded (mirrored, or built from the MinIO source). MinIO's root credentials are `AWS_ACCESS_KEY_ID` /
   `AWS_SECRET_ACCESS_KEY` from `.env`, read inside the container (a shell's exported AWS variables do not apply).

## Deploy (build machine)

```sh
scripts/deploy/staging.sh release deploy@staging-host /opt/devsecshield-staging
```
= `build` (all images, tag = short commit; the frontend gets `NEXT_PUBLIC_BACKEND_URL=https://<API_HOST>`),
`save` (`deploy/staging/images/dss-staging-<tag>.tar.gz` + `.sha256` + `.need`, what loading it needs), `push` (scp
of the bundle, `staging.sh disk-check <tag>` on the host, scp of the archive and of the scan node downloads when
`staging.sh node-artifacts` made them (see "Scan node downloads"), then `staging.sh deploy <tag>` on the host over
ssh). On the host,
`deploy` verifies the checksum, checks the disk (below), `docker load`s the archive, writes `DSS_TAG` into `.env`,
runs `docker compose up -d --wait`, then the checks below; a failed `compose up` fails the deploy (recorded as
`FAILED` in `deploy-history`). After a successful deploy the images of the new tag, the previous tag (recorded in
`deploy-history`) and the last release that passed its checks are kept, and the new tag's archive only; this
deployment's other images and archives are removed (see "Disk space"); each tag's deploy files (compose file, nginx config, rollup overlay, `staging.sh`) and the head of its
migrations are kept in `releases/<tag>/` for a rollback. `deploy` refuses a tag whose migrations do not contain the
database's revision (an older tag than the one that migrated it): that is what `rollback` is for.

Without registry access on the host, add `STAGING_INCLUDE_INFRA=1` to ship the postgres, mongo, rabbitmq and nginx (and, with the minio profile, MinIO)
images in the same archive. Behind a TLS-intercepting proxy, build with `UV_BASE_IMAGE` (backend, scan worker, DAST
worker), `NODE_BASE_IMAGE` (frontend) and `GO_BASE_IMAGE` (the scan worker's cbomkit-theia stage) set to base images
that trust the proxy CA: the system bundle (`/etc/ssl/certs/ca-certificates.crt`, which apt, apk, curl, git and
Python read) must contain it, and `SSL_CERT_FILE` / `UV_NATIVE_TLS=1` / `NODE_EXTRA_CA_CERTS` set so uv and npm do. Plain-HTTP staging (no certificates): build with
`NEXT_PUBLIC_BACKEND_URL=http://<API_HOST>` and set `CORS_ORIGINS=http://<FRONTEND_HOST>`.

## Scan node downloads

Customers have no repository access and no ZeroShield registry, so **CBOM > Sources > Scan nodes > Add scan node**
offers the scan node as downloads served by the API to members of the team (`GET /{team}/cbom/node-artifacts`, and a
short-lived link per file; `backend/routers/cbom_node_artifacts.py`):

| File | Made by |
|---|---|
| `scan-node-<version>.tar.gz` + `.sha256` | `scripts/release/scan_node_image.sh build <version>`: `docker save` of `localhost/zeroshield/cbom-scan-node:<version>`, the name the wizard's `docker run --pull never` uses |
| `cbom-scan-node-<version>.tgz` + `.sha256` | `scripts/release/node_artifacts.py`: `deploy/helm/cbom-scan-node`, version and appVersion = `<version>` |
| `cbom-scan-node-ova-kit-<version>.zip`, `cbom-scan-node-ami-kit-<version>.zip` + `.sha256` | `node_artifacts.py`: the Packer kit from `deploy/node-images` with a customer README (`deploy/node-images/kit/`), building from the image file |
| `manifest.json` | `node_artifacts.py`: version, `image_ref`, the file names; the API lists only what it names |

`<version>` is `scan_node/zs_scan_node/__init__.py` `VERSION` (or `CBOM_NODE_VERSION`). `staging.sh node-artifacts`
(the workflow's "Scan node downloads" step) builds them into `deploy/staging/images/node-artifacts/` (the chart and
the kits are about 25 KB together; the size is the image file's, which the deploy log prints); `push` counts their size in the host's disk check (`--node-artifacts-bytes`) and
copies them to `deploy/staging/node-artifacts/<tag>.part/`; `deploy` checks every file against its `.sha256` and
moves them to `deploy/staging/node-artifacts/<tag>/`, which `docker-compose.yml` mounts read-only into the backend at
`/node-artifacts` (`CBOM_NODE_ARTIFACT_DIR`). They are kept and removed with their tag's images (retention, the disk
preflight), so a rollback serves the downloads of the tag it went back to. A tag deployed without them gets an empty
directory: the wizard then says each download is "not available on this server yet. Contact your administrator."

**What the host must provide:** nothing new beyond disk space (the downloads count in the disk check) and `sha256sum`
(coreutils). `CBOM_NODE_IMAGE_REF` / `CBOM_NODE_CHART_REF` in `.env` (a registry customers can pull from) are set by
the deploy: see "Public registry".

### Terminal-only hosts: the one-paste install

"Create node and show install command" (and New registration token, Reset) also returns `install_links`: one link per
file the node's way of running needs (Docker: the image; Helm: the image and the chart; OVA/AMI: the kit and the
image), each with its SHA-256. The wizard turns them into ONE copy-paste block per method that downloads with `curl`
(or `wget`, shown below it), checks `sha256sum -c`, then `docker load` + `docker run --pull never`, or pushes the image
to `$REGISTRY` and `helm upgrade --install` the downloaded chart, or unzips the kit and runs Packer. The proxy the
wizard collected is passed to the download (`--proxy`), and its CA (`--cacert`, a file next to the command) only when
the proxy inspects TLS: curl uses it for that download from ZeroShield only, nothing is installed system-wide.

A link (`?node_ticket=<node>.<HMAC>`) is bound to the team, the node, the file kind and the node's current
registration token: it works exactly as long as that token does and stops when the node registers, when the token is
regenerated or the node reset, or after 24 h. It never contains the token (only an HMAC over its hash). Every use is an
audit event (`node_artifact.download`, actor the node). Like the registration token, the links end up in the shell
history of the host: start the command with a space (bash `HISTCONTROL=ignorespace`) or clear the history afterwards.

## Public registry (GHCR)

`publish-ghcr.yml` pushes the scan node to GitHub Container Registry on every push to dev/staging
(`ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node:<branch>-<sha12>`), and on a push to
**staging** it also releases (job `release`):

* `devsecshield-scan-node:<version>`: **written once, never overwritten** (`<version>` = `scan_node/zs_scan_node/__init__.py`
  `VERSION`; bump it to release a new node), and `:<major.minor>` and `:latest` pointing at that version;
* the Helm chart as an OCI artifact, `ghcr.io/cyberultron-consulting-private-limited/charts/cbom-scan-node:<version>`
  (written once; its default image is the GHCR image above).

The staging deploy points the Add scan node wizard at them (`staging.sh` `set_node_refs`, `.env` ->
`docker-compose.yml` -> the backend): `CBOM_NODE_IMAGE_REF=ghcr.io/.../devsecshield-scan-node:<version>` (the release,
never a moving tag) and, only once anyone can pull it without a login (checked with GHCR's anonymous token API at
deploy), `CBOM_NODE_CHART_REF=oci://ghcr.io/.../charts/cbom-scan-node:<version>`. The wizard's main command is then
`docker pull ghcr.io/...:<version> && docker run ...` (Helm: `helm upgrade --install ... oci://... --version <version>`,
or the downloaded chart with the GHCR image while the chart is not public); the downloads and the one-paste install
stay below it as the air-gapped alternative.

The switch is `CBOM_NODE_REGISTRY_PUBLIC` (a variable of the `staging` environment; deploy-staging.yml): unset or `1`
(default, the image package is public) = on for push deploys; `0` = never offer a pull (clears both refs; set it if
a package is ever made private again). A manual deploy run always clears them (it may deploy a commit with no release).

**Owner step (one click per package, GitHub UI):** a package pushed by the workflow is private at first. The image
package `devsecshield-scan-node` is public already (14 Nov). After the first push to staging with this release job,
make the chart public too: GitHub -> the organisation -> **Packages** -> `charts/cbom-scan-node` -> **Package
settings** -> **Danger Zone** -> **Change visibility** -> **Public** -> type the package name -> confirm. The next
deploy then offers `helm ... oci://` (until then the wizard installs the downloaded chart with the GHCR image).

## Disk space

The staging host is shared with other sites. A release archive is about 5.5 GB and `docker load` needs about three
times that again where Docker stores images (Deploy staging run 43572299641 ran the host out of disk part way through
the load). So, before the archive is copied (`push` runs `staging.sh disk-check <tag> --archive-bytes <size>
--need-bytes <need>` on the host) and again before it is loaded (`deploy`), `staging.sh` checks the filesystems that
receive it, identified by device (`stat -c %d`), so a bind mount of the same disk counts once and the needs add up:
* the one holding `deploy/staging/images/`: room for the part of the archive not copied yet;
* the one holding the image store: what loading the archive needs. The image store is containerd's root with the
  containerd image store (Docker 29's default; `docker info` says `driver-type io.containerd.snapshotter.v1`;
  `/var/lib/containerd` unless the containerd config says otherwise, or `STAGING_CONTAINERD_ROOT`), else Docker's
  root (`docker info` `DockerRootDir`).
  * **Measured** (`<archive>.need`, written by `save` with `scripts/deploy/archive_need.py`, copied with the archive and
    uploaded with the workflow's artifact): every layer as stored in the archive (the containerd store keeps it in its
    content store; the classic store extracts it to a temporary directory) plus every layer unpacked, + 10% for
    filesystem overhead. This holds whatever store the builder had.
  * Otherwise `STAGING_DISK_FACTOR` (default **3.3**) x the archive's size. Measured on run 43572299641's archive
    (5,484,863,244 bytes, from a containerd-store builder, as the CI runner is): its layers are stored
    gzip-compressed (1.00x the archive) and unpack to 2.04x (scan-worker alone 4.72 GB stored, 9.02 GB unpacked), so
    3.04x, and 3.3 adds about 10%. **An archive saved by a classic-store builder** holds uncompressed layer tars and
    needs about 4x: without its `.need`, set `STAGING_DISK_FACTOR=4`. Layers a release shares with one already
    loaded need no new space, so both err on the safe side;
plus `STAGING_DISK_RESERVE_MB` (default 1024) left free on each, for the other sites. An invalid
`STAGING_DISK_FACTOR` or `STAGING_DISK_RESERVE_MB` (`3,3`, `1G`) refuses the deploy before anything is changed.

When a filesystem is short, `staging.sh` removes **this deployment's** images of every tag except the running tag,
its rollback target (the tag `rollback` would go back to), the last release that passed its checks
(`releases/passed`) and the tag being deployed, and its archives except the new tag's (`rollback` uses images, never
archives), then checks again; still short, it stops before anything is copied, loaded or switched and prints what it
needs and what is free. After a deploy whose checks passed it keeps the images of the new tag, its rollback target and
the last other release that passed its checks (the rollback target, unless the deploy before failed), and the new
tag's archive only. Only `<DSS_IMAGE_PREFIX>/{devsecshield-backend,devsecshield-frontend,scan-worker,dast-worker}:<tag>`
images and `deploy/staging/images/<prefix>-<tag>.tar.gz` (with `.sha256`, `.part` and `.need`) are ever removed, and an
archive only when `<tag>` is a release this host knows (its images, `deploy-history`, `releases/`): another
deployment's `dss-staging-eu-<tag>.tar.gz` never matches. Removal is one by one: never another site's images or
files, never `docker image prune` or `docker system prune`, never by force (docker refuses an image a container was
created from; `staging.sh` says so and keeps it). The settings can also be set in `.env` (`STAGING_DISK_FACTOR`,
`STAGING_DISK_RESERVE_MB`, `STAGING_CONTAINERD_ROOT`) or passed to `push` from the build machine (the first two).
`staging.sh` runs with `LC_ALL=C`, so numbers read the same under any locale an ssh session forwards.

A `docker load` that still runs out of space (the containerd store tags the images, prints "Error unpacking image
...: no space left on device" and exits 0; the classic store exits non-zero) fails the deploy before anything is
switched, and the images of the new tag it loaded are removed (never the running tag's, its rollback target's or the
last passed release's).

Runbook, on the host (`cd /opt/devsecshield-staging`):
```sh
scripts/deploy/staging.sh disk-plan <tag>                          # archive (and its .need) already copied
scripts/deploy/staging.sh disk-plan <tag> --archive-bytes <size> [--need-bytes <need>]   # before the copy
df -h deploy/staging/images /var/lib/containerd /var/lib/docker     # where the space went
docker system df                                                    # every site's images, containers, volumes
```
`<size>` is `wc -c` of the archive and `<need>` the number in its `.need` (both on the build machine or in the
workflow's artifact). `disk-plan` prints each filesystem's need and free space, what the preflight would remove and
what retention would remove after the deploy; it removes nothing. When even then the host is short, the space is
someone else's: ask the owners of the other sites, or grow the disk; then push again (or re-run the newest Deploy
staging run).

## Checks

`staging.sh check` (run by `deploy` and `rollback`) first asks compose: every service (or each of
`STAGING_SERVICES`) has a container from `DSS_TAG`'s images that is running, and healthy when it has a health check;
the one-shots (`migrate`, `minio-init`) exited 0. A deploy with `STAGING_SERVICES` records that set for its tag
(`releases/<tag>/services`); `check` and `rollback` (so `make check-staging` and `make rollback-staging`) use the
recorded set when they are not given one, and a later deploy without `STAGING_SERVICES` starts and checks every
service again. Then it talks to nginx on this host with the real host names:
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
`DSS_EXPOSE_BUILD` (see "Build identity"),
`IS_DOCKER_CONTAINER`, `PG_HOST`, `PG_PORT`, `PG_USER`, `PG_USER_PASS`, `PG_DB`, `MONGO_HOST`, `MONGO_PORT`,
`MONGO_INITDB_ROOT_USERNAME`, `MONGO_INITDB_ROOT_PASSWORD`, `RABBITMQ_HOST`, `RABBITMQ_PORT`,
`RABBIT_ADMIN_USERNAME`, `RABBIT_ADMIN_PASSWORD`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_DEFAULT_REGION`, `AWS_ENDPOINT_URL_S3`, `GIT_ALLOWED_HOSTS`, optional `MINIO_IMAGE`; read only by
`staging.sh` (optional, see "Disk space"): `STAGING_DISK_FACTOR`, `STAGING_DISK_RESERVE_MB`, `STAGING_CONTAINERD_ROOT`;
optional for the backend: `CBOM_NODE_IMAGE_REF` (see "Scan node downloads").

`backend.env` (backend-image containers only): `JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `ENCRYPTION_KEY`,
`CERTIN_HMAC_SECRET`, `CORS_ORIGINS`, `CBOM_PUBLIC_APP_URL`, mail (`SMTP_*`, `MAIL_FROM` or `TENANT_ID`,
`CLIENT_ID`, `CLIENT_SECRET`, `EMAIL_SENDER`), `CBOM_AWS_*`, `CBOM_IDP_ALLOWED_PRIVATE`, `CBOM_EXTRA_CA_FILE`;
the full list is `backend/.env.example`.

## AWS collection on staging (lab mode)

Without `CBOM_AWS_PRINCIPAL_ARN` the AWS form says "This ZeroShield deployment is not set up for AWS collection; contact
your administrator". Staging's only AWS account is the sandbox **935951870001**, which is also the account of the
collector identity, and a customer role in the deployment's own account is refused ("This role is in ZeroShield's own
AWS account") unless **lab mode** is on. Lab mode (`CBOM_AWS_LAB_SAME_ACCOUNT=1`, `backend/utilities/cbom_sources/lab_mode.py`)
accepts such a role for a single-account source, on a deployment whose `DSS_ENV` names a test deployment
(`docker-compose.yml` sets `DSS_ENV: staging` for `backend` and `cbom-cloud-worker`); `DSS_ENV=production`, any other
value or none refuses it. Every other check still runs and must pass: AssumeRole with the external ID, refusal
without it, SecurityAudit, the data-plane deny, the denied secret read. The AWS form and every run of such a source
show "Lab mode: same-account collection — not for production"; each use is logged (`lab_mode same_account USED`) and
audited (`source.validate.lab_same_account`, `job.lab_same_account`).

### 1. Set four values (once)

GitHub > repository Settings > Environments > `staging`:

| Where | Name | Value |
|---|---|---|
| Environment secret | `CBOM_AWS_PRINCIPAL_ARN` | `arn:aws:iam::935951870001:user/devsecshield/devsecshield-developer` |
| Environment secret | `CBOM_AWS_ACCESS_KEY_ID` | that user's access key id (`<ACCESS_KEY_ID>`; never in the repo, an issue or a PR) |
| Environment secret | `CBOM_AWS_SECRET_ACCESS_KEY` | that key's secret (`<SECRET_ACCESS_KEY>`) |
| Environment variable (or secret) | `CBOM_AWS_LAB_SAME_ACCOUNT` | `1` |

The next Deploy staging run (a push to `staging`, or re-run the latest one) writes exactly these keys into the host's
`backend.env` (`staging.sh push` sends them over ssh's stdin to `staging.sh backend-env`; they are never on a command
line or in the log, and GitHub masks the secrets) and recreates the backend containers with them. An unset or empty
secret leaves the host's value as it is; to turn lab mode off set the variable to `0`. Without GitHub, the same on the
host: `cd /opt/devsecshield-staging && printf 'CBOM_AWS_LAB_SAME_ACCOUNT=1\n' | scripts/deploy/staging.sh backend-env`
(one `KEY=VALUE` line per key; type secrets into the pipe from a file you delete, not into shell history), then
`docker compose --project-directory deploy/staging -f deploy/staging/docker-compose.yml up -d backend cbom-cloud-worker`.

Check: Sources > Cloud & Identity > AWS shows the lab-mode banner and the form (no "not set up" message), and the
backend log has `cbom sources` lines naming `lab_mode` once you validate.

### 2. The customer role in the sandbox

The existing `arn:aws:iam::935951870001:role/DevSecShieldScannerReadOnlyRole` will NOT pass validation as it is
(CB-A1 run R1, `V2-validate`): its trust policy has no `sts:ExternalId` condition ("The role can be assumed without the
external ID") and it has no data-plane deny ("The deny statement is missing: kms:Decrypt, ..."). Use one of these
(an account administrator does it; the developer user cannot create IAM roles):

**A. Recommended: the product's own reader template.** In Sources > Cloud & Identity > AWS, choose "Single account",
download the CloudFormation template (it trusts account 935951870001 and carries this team's external ID) and deploy
it as a stack in the sandbox (CloudFormation console, any region, e.g. ap-south-1; acknowledge IAM resources). It
creates `arn:aws:iam::935951870001:role/ZeroShieldCBOMReader` with the `sts:ExternalId` condition, SecurityAudit and
the deny. Its trust policy names the account (`arn:aws:iam::935951870001:root`), so in the SAME account the collector
user also needs an identity policy allowing the role (AWS evaluates both in that case); unless the user already has
one, attach this inline policy to `devsecshield-developer`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::935951870001:role/ZeroShieldCBOMReader"
    }
  ]
}
```

Then add the source with role ARN `arn:aws:iam::935951870001:role/ZeroShieldCBOMReader` and **Validate connection**.

**B. Or fix the existing role** `DevSecShieldScannerReadOnlyRole` (IAM console > Roles > the role):
1. Trust relationships > Edit: replace the WHOLE trust policy with the one below, putting this team's external ID
   (shown on the AWS form, `zs-ext-XXXX-XXXX-XXXX-XXXX`) in place of `<EXTERNAL_ID>`. Any other statement that lets
   the user or the account assume the role without the condition makes "Role refused without external ID" fail.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::935951870001:user/devsecshield/devsecshield-developer" },
      "Action": "sts:AssumeRole",
      "Condition": { "StringEquals": { "sts:ExternalId": "<EXTERNAL_ID>" } }
    }
  ]
}
```

2. Permissions > Add permissions > Create inline policy (JSON), name `ZeroShieldCBOMReaderDeny`; keep the AWS managed
   `SecurityAudit` attached:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyKeyUseAndDataPlaneReads",
      "Effect": "Deny",
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyPair",
        "kms:GenerateDataKeyPairWithoutPlaintext",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:GenerateMac",
        "kms:VerifyMac",
        "kms:ReEncryptFrom",
        "kms:ReEncryptTo",
        "kms:Sign",
        "kms:Verify",
        "kms:DeriveSharedSecret",
        "kms:GenerateRandom",
        "secretsmanager:GetSecretValue",
        "secretsmanager:BatchGetSecretValue",
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:GetParameterHistory",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "acm:ExportCertificate",
        "dynamodb:GetItem",
        "dynamodb:BatchGetItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "rds-data:*",
        "lambda:GetFunction",
        "lambda:InvokeFunction",
        "ec2:GetPasswordData",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
        "codecommit:GitPull"
      ],
      "Resource": "*"
    }
  ]
}
```

Then add the source with role ARN `arn:aws:iam::935951870001:role/DevSecShieldScannerReadOnlyRole` and validate.
Every check must pass before a run collects; the run shows the lab-mode banner.

## Build identity

Every image carries the commit it was built from (`build_images.sh`; the OCI `revision` label and, in the backend,
`DSS_BUILD_SHA` / `DSS_BUILD_VERSION`). A tree with uncommitted or untracked changes claims no commit ("unknown")
and its version ends in `-dirty`, whoever chose the tag.
Signed-in users and operators always read it from `GET /version`; collection runs and CBOM exports record it.
`DSS_EXPOSE_BUILD=1` in `.env` also names it publicly: `GET /health` adds `build` / `version`, every response
carries `X-ZS-Build`, and `staging.sh build` puts it into the frontend's `<meta name="zs-build">` (which makes every
commit rebuild the frontend). For the meta, `staging.sh build` takes `DSS_EXPOSE_BUILD` from its environment first
and `.env` second: the **Deploy staging** workflow builds on a runner without `.env` and sets it from its
`expose_build` input (on by default). The API side is always the host's `.env`, so a staging host deployed by the
workflow needs `DSS_EXPOSE_BUILD=1` there too. Set it on staging and test stacks, where the gate compares the
deployed commit without an account; leave it unset (0) in production, where it would fingerprint the exact build
(ASVS V14.3.3).

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

AI analysis: SAST, IaC and the SCA + SBOM chat call Amazon Bedrock with the `AWS_*` of `.env` and need a Qdrant
vector store (`QDRANT_HOST`, `QDRANT_PORT`, `QDRANT_API_KEY`; not part of this compose file). Without them those
scans end as "failed"; CBOM and AI-BOM code scans need neither. SCA + SBOM downloads Grype's vulnerability database
(about 1 GB) into the scan-worker container on its first scan: keep that much free disk, and on an air-gapped site
that download is not possible.

Grype's vulnerability database (SCA + SBOM) lives on the `grype-db` volume that scan-worker and cicd-worker
share (`GRYPE_DB_CACHE_DIR=/var/cache/grype`): it is downloaded once, on the first scan, and survives recreated
containers. On an air-gapped site, download a database archive on a connected machine (`grype db list` shows the
URL of the current one), ship it with the images (`make airgap-bundle GRYPE_DB_ARCHIVE=/path/to/db.tar.zst` puts
it next to the images as `images/grype-db.tar.zst`, with a `.sha256`), and import it once on the site:
```sh
cd deploy/staging && sha256sum -c images/grype-db.tar.zst.sha256
docker compose run --rm --no-deps -v "$PWD/images/grype-db.tar.zst:/tmp/grype-db.tar.zst:ro" scan-worker \
  grype db import /tmp/grype-db.tar.zst
```
and set `GRYPE_DB_AUTO_UPDATE=false` and `GRYPE_DB_VALIDATE_AGE=false` in `.env` (the workers read it), so no
scan tries to reach the Internet or refuses an older database. Import a newer archive the same way to update.

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

**Deploy staging** (`.github/workflows/deploy-staging.yml`) runs on **every push to `staging`** (a promotion from
`dev` merged): it builds that commit (frontend for `https://devsec-staging-api.zeroshield.ai`, build exposed), checks
the image contexts, saves the archive as an artifact and deploys it to the host. Runs go one at a time in the order
they arrive; a running deploy is never cancelled, and of several waiting pushes the newest deploys. A push run
deploys only while its commit is still the tip of `staging` (step "Still the tip of staging"): GitHub re-runs keep
the original commit, so re-running an older run fails with "superseded" instead of putting that commit back over a
newer one; re-running the newest run is fine. A manual run
(GitHub offers it from the default branch only) builds and saves; with `deploy` ticked it also pushes to the host.
Nothing in it touches production. Configure in the repository's `staging` environment: secrets
`STAGING_SSH_KEY`, `STAGING_SSH_KNOWN_HOSTS`, `STAGING_SSH_TARGET`; variable `STAGING_DIR`. Nothing of that is in
the repository.

**What a red Deploy staging run leaves behind** (there is no automatic rollback; `staging.sh push`/`deploy` above):
* The build (or the superseded check) failed: nothing on the host changed.
* "not enough disk space to load <tag>" (`disk-check` before the copy, or `deploy` before the load; "Disk space"
  above), or "STAGING_DISK_FACTOR=... is not a number": the containers still run the previous tag; the host's deploy
  files are the new bundle's and `releases/files-tag` is cleared; this deployment's images of tags other than the
  running one, its rollback target, the last that passed and the new one, and its archives but the new one's, may
  have been removed (the log names each). Before the copy the archive was not
  copied at all. Run `staging.sh disk-plan <tag>` on the host, free space, then push again (or re-run the newest run).
* "docker load of ... failed": the load ran out of space part way. The images of the new tag it loaded were removed;
  the rest is as in the next case. Free space (`disk-plan`) and push again.
* `deploy` refused before switching tags (archive checksum, an image not loaded, or a database at a revision the
  new tag's migrations do not contain): the containers still run the previous tag, but the host's deploy files
  (compose file, nginx, `staging.sh`) are already the new bundle's and `releases/files-tag` is cleared. Fix the
  cause and push again (or re-run the newest run). Do not use `rollback` here (nor in the two cases above): `DSS_TAG`
  is still the running release, so `rollback` would go to the release before it.
* `compose up` failed: the host is on the new tag, partly started, and `deploy-history` says `FAILED`.
* The post-deploy `staging.sh check` failed: the new tag is live and the run is red.
In these two cases nothing is removed after the deploy: retention runs only after a deploy whose checks passed, so
the previous release's images are there for the rollback.
For the last two, go back with `make rollback-staging HOST=user@host` (or `scripts/deploy/staging.sh rollback` on
the host; it asks before a database downgrade), or push a fix to `staging`.
