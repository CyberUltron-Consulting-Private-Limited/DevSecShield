# DevSecShield on your machine, from GHCR

Run the whole product (UI, API, workers, databases, S3, a mail catcher) on one machine from the images CI publishes
to GitHub Container Registry, then connect scan nodes to real servers. This is a **local test stack**: plain HTTP,
no reverse proxy, one settings file. For a server, use `deploy/staging/` (nginx, TLS).

| What | Where |
|---|---|
| UI | http://localhost:3000 |
| API | http://localhost:8000 (`/health`) |
| Mail catcher (sign-in codes, invitations) | http://localhost:8025 |
| Images | `ghcr.io/cyberultron-consulting-private-limited/devsecshield-{backend,frontend,scan-worker,dast-worker,scan-node,minio}` (private), linux/amd64 and linux/arm64 (Apple silicon runs them natively) |

Services: postgres, mongo, rabbitmq, minio + minio-init (S3), mailpit, migrate (one-shot), backend, cbom-cloud-worker
(AWS / identity-provider sources, the CBOM scheduler), dast-scheduler, scan-worker, cicd-worker, dast-worker,
frontend. The scan node is not part of it: it runs on the machines that can reach your servers.

Needs: Docker Engine 24+ or Docker Desktop with Compose v2, about 8 GB of RAM for Docker, about 15 GB of disk (the
scan worker image is the largest), ports 3000, 8000 and 8025 free, and a checkout of this repository (the compose file
mounts `compose/aibom-config-overlay`). All commands below run from the repository root.

## 1. Log in to GHCR

The packages are private. Create a **classic** personal access token with only the `read:packages` scope
(GitHub > Settings > Developer settings > Personal access tokens > Tokens (classic)); if the organisation uses SAML
single sign-on, also press "Configure SSO" > "Authorize" for it. Then:

```sh
docker login ghcr.io -u <your GitHub user name>      # paste the token as the password
```

Every machine that pulls an image (this one, and each scan-node machine) logs in the same way.
`docker logout ghcr.io` removes the stored token.

## 2. Pick a tag

| Tag | What it is |
|---|---|
| `dev` | the latest commit on `dev` (moves on every merge that changes more than docs) |
| `staging` | the latest commit on `staging` |
| `pr-<n>` | pull request `<n>` while it carries the label `publish-preview` (its latest head) |
| `dev-<sha12>`, `staging-<sha12>`, `pr-<n>-<sha12>`, `manual-<sha12>[-<hash>]` | one exact commit; written once, never moves |

The moving tags (`dev`, `staging`, `pr-<n>`) move only after all six images of a new commit are published, and only
forward (a re-run of an older run never moves them back). They still move **one image after another, over about
20 seconds**, so a `pull` in that window can mix two commits. For a stack you rely on, **pin the immutable tag**: read
it from the backend index and put it in `DSS_TAG`.

```sh
docker buildx imagetools inspect ghcr.io/cyberultron-consulting-private-limited/devsecshield-backend:dev --raw
```
prints the index: its `annotations` name the commit (`org.opencontainers.image.revision`) and the immutable tag
(`org.opencontainers.image.version`, e.g. `dev-1a2b3c4d5e6f`), and `manifests` lists linux/amd64 and linux/arm64.

The tags of a package are also listed on GitHub: the organisation's **Packages** page > `devsecshield-backend`.

## 3. Configure

```sh
deploy/local/init-env.sh dev          # writes deploy/local/.env (mode 600) with random passwords and keys
```

It copies `.env.example` and replaces every `change-me` with a fresh random value (it never overwrites an existing
`.env`). Or copy the file yourself and replace each `change-me`. `.env` is git-ignored; never commit it. To change the
tag later, edit `DSS_TAG` in `.env`.

## 4. Start

```sh
docker compose -f deploy/local/docker-compose.yml pull
docker compose -f deploy/local/docker-compose.yml up -d --wait
docker compose -f deploy/local/docker-compose.yml ps
curl -s http://localhost:8000/health
```

The first start runs the database migrations (`migrate`, a one-shot that exits 0) before the API starts; `--wait`
returns when everything is healthy. Logs: `docker compose -f deploy/local/docker-compose.yml logs -f backend`.

To move to a newer build of the same tag: `pull`, then `up -d --wait` again (only changed containers restart).

## 5. First admin and team

1. Open http://localhost:3000/register, enter a name, e-mail and password, press **Send Verification Code**, open
   http://localhost:8025, copy the 6-digit code from the newest mail and finish the sign-up. Every account gets its
   own team; its id is the number in the UI's URLs (`http://localhost:3000/<team_id>/...`).
   Sign-in works the same way (e-mail, password, a new code each time). Codes are rate-limited (5 sends per 2 minutes).
2. Make that account the administrator (there is no other way to create the first one); replace the address:
   ```sh
   docker compose -f deploy/local/docker-compose.yml exec -T postgres \
     sh -c 'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <<'SQL'
   UPDATE "user" SET is_superuser = true WHERE lower(email) = lower('you@example.com');
   SQL
   ```
   It must print `UPDATE 1`. Sign out and in again.
3. New teams start with 0 credits, and scans spend credits (a CBOM code scan at least 1). As the administrator open
   http://localhost:3000/admin, find the team and **Update Credits** (for example 5000).
4. More users: invite them from the team settings (the invitation mail lands in Mailpit) or register more accounts.

## 6. Scan nodes: connect real servers

A scan node is a small container that runs where it can reach your servers and calls out to the API. In the UI:
**CBOM > Sources > Scan nodes > Add scan node**, choose **Docker container**, name it, and copy the command it shows:

```sh
docker run -d --name zs-scan-node-<name> --restart unless-stopped \
  -e ZS_API_URL='http://localhost:8000' \
  -e ZS_REGISTRATION_TOKEN='zsr_...' \
  -v zs-node-<name>:/var/lib/zs-node \
  ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node:<the same build's tag>
```

The image is the scan node of the same build. Two changes are needed because this stack speaks plain HTTP on your
machine: the node must be told to accept `http://` (`ZS_ALLOW_INSECURE_HTTP=1`), and `localhost` inside a container
is the container itself.

**Node on another machine** (a Linux VM or server with Docker that can reach the servers to scan):
1. Here: set `API_BIND=0.0.0.0` in `deploy/local/.env`, then
   `docker compose -f deploy/local/docker-compose.yml up -d backend` (the API now listens on your LAN address too;
   allow TCP 8000 in this machine's firewall, e.g. macOS asks on first use). Note this machine's LAN address
   (`ipconfig getifaddr en0` on macOS, `hostname -I` on Linux).
2. There: `docker login ghcr.io` (section 1), then run the UI's command with `ZS_API_URL` changed and one line added:
   ```sh
   docker run -d --name zs-scan-node-<name> --restart unless-stopped \
     -e ZS_API_URL='http://<this machine LAN address>:8000' \
     -e ZS_ALLOW_INSECURE_HTTP=1 \
     -e ZS_REGISTRATION_TOKEN='zsr_...' \
     -v zs-node-<name>:/var/lib/zs-node \
     ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node:<tag>
   ```
3. `curl http://<this machine LAN address>:8000/health` from the node machine must answer `{"status":"healthy",...}`.

**Node on this machine** (for a first try, or servers reachable from here): run the command with
`--network devsecshield-local-nodes` added right after `docker run`, `ZS_API_URL='http://devsecshield-api:8080'` and
`-e ZS_ALLOW_INSECURE_HTTP=1`. That network reaches only the API, not the databases.

Within a minute the node shows **Online** in Scan nodes, with its SSH public key. `docker logs zs-scan-node-<name>`
shows the enrolment. The registration token is single-use; to enrol again use **Reset** on the node.

`ZS_ALLOW_INSECURE_HTTP=1` means the node's token and the credentials of its jobs cross the network unencrypted.
Keep it to a network you trust. To use HTTPS instead, put a TLS proxy (for example Caddy or nginx with a certificate
for this machine's name) in front of port 8000, set `ZS_API_URL=https://<name>`, drop `ZS_ALLOW_INSECURE_HTTP`, and
give the node your CA with `-e ZS_CA_FILE=/ca.pem -v /path/to/ca.pem:/ca.pem:ro` if it is a private one.

### Servers, ranges and cloud accounts

All under **CBOM > Sources**; each form has an info tip with the details.
* **Servers**: Linux over SSH (and Windows over WinRM HTTPS). The default credential is the node's own key: add the
  public key shown in Scan nodes to the `authorized_keys` of a `zs-cbom` user on each server (the sudoers lines for
  Tier 2 are in the form). Pick the node that reaches the server.
* **Kubernetes & Databases**: kubeconfig (token or client certificate), PostgreSQL, MySQL, SQL Server, Oracle,
  MongoDB, Redis, with read-only accounts.
* **Network TLS**: IP addresses, CIDR ranges (up to a /16) or a-b ranges and the ports to probe, run by a node.
  Scan window, rate limits and the never-scan list are in the source settings, with **Stop all network scanning**.
* **Cloud & Identity**: AWS accounts and identity-provider metadata, collected by the cloud worker (no node).
  AWS needs the switches below.
* **Review & Run** starts a run; results appear in the CBOM views of the team.

## 7. CBOM switches

Set in `deploy/local/.env`, then `docker compose -f deploy/local/docker-compose.yml up -d` (the containers that read
`.env` are recreated). Empty means off.

| Variable | Effect |
|---|---|
| `CBOM_FLEET_INVENTORY`, `CBOM_FLEET_POLICIES`, `CBOM_FLEET_MATERIALIZE` | `1` turns on the Fleet parts (inventory; policies; policies may create managed sources and schedules). |
| `CBOM_FLEET_TRANSPORTS`, `CBOM_SSH_CA` | `1` turns on fleet transports and the SSH certificate authority. |
| (any of the five above) | The **Fleet** tab of Sources appears when at least one is on (`GET /fleet/status`). A part's screens exist only in builds that contain that part: a tag built before the part was merged shows the tab without them. |
| `CBOM_AWS_PRINCIPAL_ARN` | The AWS identity customer accounts trust (`arn:aws:iam::<account>:role/<name>` or `:user/<name>`). Unset, the AWS form says **"This ZeroShield deployment is not set up for AWS collection; contact your administrator"** and the CloudFormation template cannot be downloaded. |
| `CBOM_AWS_ACCESS_KEY_ID`, `CBOM_AWS_SECRET_ACCESS_KEY` (`CBOM_AWS_SESSION_TOKEN`) | That identity's credentials; **Validate connection** and collection assume the customer's role with them. Without them validation answers that the credentials are not configured. |
| `CBOM_IDP_ALLOWED_PRIVATE` | Identity-provider metadata URLs on private networks (CIDRs and/or host names) that may be fetched; loopback, link-local and CGNAT stay refused. |
| `CBOM_EXTRA_CA_FILE` | A PEM bundle trusted for those metadata URLs (mount the file into the backend-image services with a compose override). |
| `CBOM_LAB_ALLOW_PRIVATE_FETCH` | `1`: metadata fetches may reach any RFC 1918 address. Test labs only. |
| `CBOM_SCHEDULER` | `0` stops the CBOM schedule runner in the cloud worker (default on). |
| `CBOM_ALLOW_LLM` | `1` allows the AI chat on CBOM scans (needs Bedrock credentials in `AWS_*`, which here are MinIO's). |
| `CBOM_PUBLIC_APP_URL`, `CORS_ORIGINS` | The UI's address (`http://localhost:3000`); links in mails use it. |
| `CBOM_MTLS_HEADER_TRUSTED`, `CBOM_MTLS_REQUIRED`, `CBOM_MTLS_PIN` | **Leave unset here.** They need nginx in front (deploy/staging); without it any client could send the certificate headers. |

AWS, step by step: put the collector identity in the four `CBOM_AWS_*` variables and restart; in **Cloud & Identity >
AWS** download the CloudFormation template (it creates the read-only role `ZeroShieldCBOMReader` that trusts that
account with the team's external id), deploy it in the account to scan, enter the role ARN and press **Validate
connection**. Never commit those keys; `.env` is git-ignored. The collector calls the customer's account at AWS for
every service: it ignores `AWS_ENDPOINT_URL_S3` (here the local MinIO, for the product's own uploads). Images built
before that fix (`pr-92-de22b950885a`, `pr-92-f4f9b8a92971`) sent the account's S3 calls to MinIO, so their CBOM shows
no S3 buckets.

### AI remediation assistant (optional)

Each CBOM finding always shows the knowledge-base remediation (offline, no AI). The **AI assistant** panel under it
(Explain / Plan / Ask a question) appears only when one of the two providers below is configured; `GET
/{team}/cbom/ai/status` says which, and lists in `egress` every host the assistant will contact. It is free (no
credits). Every answer is checked before anyone sees it: a CVE or CWE id that is not in the finding's knowledge-base
entry withholds the whole answer (the KB steps are shown instead), steps without a citation are dropped, and only
commands and links that appear in the knowledge base are kept.

**AWS Bedrock (primary).** The product's only outbound call for AI: HTTPS to `bedrock-runtime.<region>.amazonaws.com`.

| Variable | Effect |
|---|---|
| `CBOM_AI_PROVIDER=bedrock` | Turns the assistant on with Bedrock (Converse API). |
| `CBOM_AI_BEDROCK_REGION` | Region (default `AWS_REGION`, then `AWS_DEFAULT_REGION`, then `ap-south-1`, as the SAST lane). |
| `CBOM_AI_MODEL` | Bedrock model id (default `openai.gpt-oss-120b-1:0`, the SAST lane's model). |
| `CBOM_AI_AWS_PROFILE` | A named profile from a mounted `~/.aws` (then the `AWS_*` keys are not used; **needed here**, where `AWS_*` are MinIO's). Unset: the standard AWS chain (environment, profile files, ECS/EKS role, instance role). |
| `CBOM_AI_BEDROCK_ENDPOINT_URL` | Optional PrivateLink endpoint: `https://vpce-….bedrock-runtime.<region>.vpce.amazonaws.com`, or an https name that resolves only to private (RFC 1918 / ULA) addresses. Anything else is refused. |
| `CBOM_AI_REDACT_HOSTS` | Default `1` for Bedrock: host names and addresses in the prompt become `HOST_n` and are restored in the answer. `0` sends them. |

Allow on the egress firewall / proxy: **TCP 443 to `bedrock-runtime.<region>.amazonaws.com`** (or the VPC endpoint),
and only if the credentials come from them: `169.254.169.254:80` (EC2 instance role), `169.254.170.2:80` (ECS / EKS
container role), `sts.<region>.amazonaws.com:443` (assume-role / IRSA web identity). Environment keys and profile files
call nothing else. IAM: `bedrock:InvokeModel` on the model ARN (Converse is authorised by `bedrock:InvokeModel`), e.g.
`arn:aws:bedrock:<region>::foundation-model/openai.gpt-oss-120b-1:0`, and model access enabled for it in the Bedrock
console. To keep the traffic off the internet, create an interface VPC endpoint for `com.amazonaws.<region>.bedrock-runtime`
(PrivateLink); with private DNS on, the regional name resolves to it and nothing needs to change, otherwise set
`CBOM_AI_BEDROCK_ENDPOINT_URL`. `HTTP(S)_PROXY` and `AWS_CA_BUNDLE` are ignored unless `CBOM_AI_HONOR_PROXY=1`;
redirects are never followed; there are no retries.

**A model on your own network (`openai_compat`).** Nothing leaves the network.

| Variable | Effect |
|---|---|
| `CBOM_AI_BASE_URL` | OpenAI-compatible `/v1` root: Ollama `http://ollama:11434/v1`, vLLM `http://vllm.internal:8000/v1`, llama.cpp server `http://llama:8080/v1`. Setting it (without `CBOM_AI_PROVIDER`) selects this provider. |
| `CBOM_AI_MODEL` | Model name as the server knows it (e.g. `qwen3:8b` in Ollama). Required. |
| `CBOM_AI_API_KEY`, `CBOM_AI_CA_FILE` | Bearer key if the server wants one; PEM bundle for a private CA (https). |
| `CBOM_AI_ALLOW_NONPRIVATE` | The host must resolve only to loopback / RFC 1918 / ULA addresses unless this is `1`; link-local (cloud metadata) is refused always. The resolved address is pinned for the request. |

Both: `CBOM_AI_TIMEOUT_S` (60), `CBOM_AI_MAX_TOKENS` (700), `CBOM_AI_CONCURRENCY` (2 requests at a time). 20 requests
per minute per user. Example, Ollama on the compose network: `docker run -d --name ollama --network <compose network>
-v ollama:/root/.ollama ollama/ollama`, `docker exec ollama ollama pull qwen3:8b`, then
`CBOM_AI_BASE_URL=http://ollama:11434/v1` and `CBOM_AI_MODEL=qwen3:8b`. Give the model at least 4 k tokens of
context (the assistant sends about 3 k; Ollama: `OLLAMA_CONTEXT_LENGTH=8192`, llama.cpp: `--ctx-size 8192`); a 0.5 B
model answers safely (the checks hold) but thinly, so prefer 4-8 B. Unset everything to remove the panel (after a
page reload). `CBOM_ALLOW_LLM` is a different, older switch (the whole-scan chat through the SAST lane's Bedrock
client) and stays off.

Other scans: SAST, IaC and the SCA + SBOM chat need Amazon Bedrock and a Qdrant store (`QDRANT_*`, `LLM_MODEL`); without
them they end as "failed". CBOM and AI-BOM code scans need neither.

## 8. Stop, reset, update

```sh
docker compose -f deploy/local/docker-compose.yml stop          # stop, keep everything
docker compose -f deploy/local/docker-compose.yml down          # remove the containers, keep the data volumes
docker compose -f deploy/local/docker-compose.yml down -v       # also delete all data (database, S3, mail)
docker rm -f zs-scan-node-<name> && docker volume rm zs-node-<name>   # a node on this machine
```

Going back to an OLDER tag after a newer one migrated the database fails in `migrate` ("Can't locate revision ...").
On a test stack, `down -v` and start again; `deploy/staging/README.md` ("Rollback") shows the downgrade path.

## The frontend's API address

The browser code calls the API at the address inlined when the frontend image was built: `http://localhost:8000`
(Next.js `NEXT_PUBLIC_BACKEND_URL`; the code has no runtime setting for it). So the UI works in a browser on this
machine.

**From another computer, no rebuild (recommended):** forward both ports over SSH, so the browser still uses
`localhost`:

```sh
ssh -L 3000:localhost:3000 -L 8000:localhost:8000 <user>@<this machine>
```

then open http://localhost:3000 on that computer. Nothing changes on the stack (`UI_BIND`/`API_BIND` stay 127.0.0.1).

**Alternative, a frontend built for this machine's address.** A plain-http origin other than `localhost` is not a
secure context in the browser: features that need one fail (for example the IaC scan page, which calls
`crypto.randomUUID()`, and copy to clipboard). Use it only behind TLS, or accept those gaps:

```sh
docker build -t devsecshield-frontend:lan -f frontend/Dockerfile frontend \
  --build-arg NEXT_PUBLIC_BACKEND_URL=http://<this machine LAN address>:8000 \
  --build-arg NEXT_PUBLIC_CBOM_NODE_IMAGE=ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node:<tag>
```

then point the `frontend` service at `devsecshield-frontend:lan` (a `docker-compose.override.yml` next to the compose
file with `services: {frontend: {image: devsecshield-frontend:lan}}`, passed with a second `-f`), set `UI_BIND` and
`API_BIND` to `0.0.0.0` and `CORS_ORIGINS` / `CBOM_PUBLIC_APP_URL` to `http://<address>:3000`. Once
`publish-ghcr.yml` is on `main`, its manual run does the same in CI (inputs `ref` and `api_url`; for an `api_url`
other than the default the tag is `manual-<sha12>-<8 hex of the URL's sha256>`, so two hosts never share a tag).

## Check where an image came from

Every image index carries a SLSA build-provenance attestation made by `.github/workflows/publish-ghcr.yml`:

```sh
gh attestation verify oci://ghcr.io/cyberultron-consulting-private-limited/devsecshield-backend:dev \
  -R CyberUltron-Consulting-Private-Limited/DevSecShield --source-ref refs/heads/dev
```

It names the workflow, the commit and the trigger. `docker buildx imagetools inspect <image>:<tag>` lists the two
platforms; the image labels `org.opencontainers.image.revision` / `.version` name the commit and tag.

## Troubleshooting

* `denied` / `unauthorized` on pull: log in (section 1); the token needs `read:packages` and SSO authorisation; your
  account needs read access to the repository.
* `manifest unknown`: that tag was not published (a docs-only merge publishes nothing; a PR needs `publish-preview`).
  A commit superseded by a newer push may never be published at all (only the newest waiting run on a branch runs),
  and a run whose commit was overtaken by newer code publishes its immutable tags but leaves the moving tag alone.
* The moving tag stays behind the branch after a re-run: re-run only the newest run of a branch. GitHub keeps one
  waiting run per branch, so re-running an older `dev` or `staging` run while a newer one waits replaces the newer
  one; the older run then leaves the moving tag alone (its commit is no longer the newest), and the newest commit is
  published only when its own run is re-run or the branch is pushed again. On a PR, re-running an older run cancels
  the newest one, with the same result.
* `pr-<n>` images from two commits: a push to the PR cancels its running publish (`dev` and `staging` runs queue
  instead), and a cancel while the six tags move (about 20 s) leaves `pr-<n>` mixed until the next run moves it.
  Pin `pr-<n>-<sha12>`.
* A publish run failed in "moving tags": it put back every tag it had moved, the failing one included, and its log
  names any moving tag that is not where it was (`::error::... is at ..., not back at ...`). Until a later run moves
  them, pin an immutable tag.
* Port already in use: stop what holds 3000, 8000 or 8025 (the frontend needs exactly 8000 for the API).
* No mail: http://localhost:8025 shows every mail; `docker compose ... logs backend | grep -i smtp`.
* A node stays offline: `docker logs zs-scan-node-<name>`; from the node machine `curl http://<address>:8000/health`;
  `ZS_ALLOW_INSECURE_HTTP=1` present; `API_BIND=0.0.0.0` here; the firewall.
