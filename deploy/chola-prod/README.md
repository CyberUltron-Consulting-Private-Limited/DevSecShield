# DevSecShield Chola production (runbook)

One command from the owner's machine deploys a commit to the Chola production instance:

```sh
scripts/deploy/chola-prod.sh deploy --sha <commit>
```

The owner runs it with his own AWS credentials. Nothing in this folder holds a secret; the kit reads them from AWS
Secrets Manager at run time and never prints a value. `scripts/deploy/chola-prod.sh --help` lists every command, flag
and environment variable.

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
| `scripts/deploy/chola-prod.sh` | the owner's command (preflight, host-setup, secrets, images, infra, backup, deploy, verify, rollback, attach, smtp-test, admin, status, logs; `--dry-run`) |
| `deploy/chola-prod/docker-compose.yml` | the stack (project `dss-chola`) |
| `deploy/chola-prod/nginx/` | site template + entrypoint script (host routing, real IP and scheme from the ALB subnets only, security headers) |
| `deploy/chola-prod/remote.sh` | the instance side, run over SSH by chola-prod.sh |
| `deploy/chola-prod/kit.py` | secret merge, env rendering (stdlib only) |
| `deploy/chola-prod/artifacts.py` | images from a CI run: streaming artifact unzip (upload-artifact's stored + data-descriptor format too), OCI layout check and naming, stream hashing, the run's manifest (stdlib only; the workflow and the instance use the same file) |
| `deploy/chola-prod/ci_images.sh` | the steps of `.github/workflows/chola-prod-images.yml` (tested here) |
| `deploy/chola-prod/host/` | the container IMDS block: script, systemd unit, Docker drop-in ([Instance metadata (IMDS)](#instance-metadata-imds)) |
| `.github/workflows/chola-prod-images.yml` | the CI run that packages one commit's images as artifacts ([Images from a CI run](#images-from-a-ci-run)) |
| `deploy/chola-prod/smtp_check.py` | SMTP login test (authenticates, sends nothing) |
| `backend/tests/test_chola_prod_kit.py` | tests of all of the above (run by CI's backend job) |

On the instance: `/opt/devsecshield-chola/deploy/chola-prod/` is the **live** kit (compose file, nginx, the four env
files), `/opt/devsecshield-chola/compose/aibom-config-overlay/` the backend's rollup config,
`/opt/devsecshield-chola/state/` the deploy history, per-release files and job logs, and
`/opt/devsecshield-chola/.kit/<run>/` each run's copy of the kit. Every command runs `remote.sh` from its run copy;
only a deploy installs that copy as the live kit, after its checks passed. The other commands (preflight, status,
logs, verify) never change the live files.

## 0. Before the first deploy: rotate what was exposed

Treat these as exposed and rotate them:

* **IAM access key** of `AnshSinghal-Cyberultron` (pasted into a chat): create a second access key, switch your AWS
  profile to it, `aws sts get-caller-identity`, then deactivate and delete the old key; check CloudTrail for calls
  made with the old key id.
* **SSH key** of `devsec-chola/prod/ssh-admin` (pasted into a chat): on a trusted machine, generate the new key in a
  private temporary directory with a passphrase, then remove the directory:
  ```sh
  d=$(mktemp -d) && chmod 700 "$d"
  ssh-keygen -t ed25519 -f "$d/chola-admin" -C chola-admin     # asks for a passphrase
  # 1. add "$d/chola-admin.pub" to ubuntu's ~/.ssh/authorized_keys on the instance (the current key still works)
  # 2. the infra team stores the private key in devsec-chola/prod/ssh-admin, field private_key_pem (the kit reads it
  #    non-interactively, so the stored copy has no passphrase: they remove it from a copy in their own private
  #    temporary directory with ssh-keygen -p, store it, and delete that copy)
  # 3. remove the old public key from authorized_keys, check chola-prod.sh status still connects
  rm -rf "$d"
  ```
* **The mailbox password** (`OUTLOOK_PASSWORD`) is committed in the `ansh` branch's `backend/.env`: everyone with read
  access to the repository has it. After the first `secrets` run has stored it in `devsec-chola/prod/app-secrets`,
  change the mailbox password, store the new one with `chola-prod.sh secrets --mail-prompt` (hidden prompt), and remove
  `backend/.env` from the `ansh` branch (it stays in the git history, which is why the password must change, not only
  the file). Never commit a password to update it.

## 1. Prerequisites (owner's machine)

* **AWS CLI v2.12+** (`aws ec2-instance-connect open-tunnel`), credentials of `AnshSinghal-Cyberultron` (profile:
  `export AWS_PROFILE=<profile>`). Region and account are fixed in the script (ap-south-1, 935951870001); the
  script refuses another account.
* **Docker** with **buildx** (Docker Desktop is fine). On Apple Silicon the frontend is built for linux/amd64 under
  emulation (10-20 min). About 15 GB free for images and the release archive. GHCR and ECR logins go into a throwaway
  Docker config in the scratch directory (deleted on exit), never into your credential store. **Not needed with
  `--from-run`** ([Images from a CI run](#images-from-a-ci-run)).
* **gh** signed in with the `read:packages` scope (`gh auth refresh -s read:packages`): the backend and worker
  images come from GHCR. With `--from-run`, gh only reads the run and its artifacts (`gh api`).
* **git**: a checkout of this repository that contains this folder. The mail login is read from
  `origin/ansh:backend/.env` (`OUTLOOK_EMAIL`, `OUTLOOK_PASSWORD`) **only** on the first setup (app-secrets has no mail
  keys yet) or with `--refresh-mail`; the kit fetches it with an explicit refspec
  (`+refs/heads/ansh:refs/remotes/origin/ansh`), so single-branch clones work, and says whether the branch, the file or
  the keys are missing. It is copied only into the 0700 scratch directory, never into the repository. A normal deploy
  does not read origin/ansh at all. `--mail-prompt` asks for the address and password instead (hidden input).
* **python3** 3.8+, **ssh**, **curl**, **bash** (macOS's bash 3.2 works).
* The commit to deploy must have green **Publish images (GHCR)** for it (every push to `dev` or `staging` does:
  `dev-<sha12>` / `staging-<sha12>`). Pass `--ghcr-tag <tag>` for another tag.

`preflight` proves what the first deploy needs and stops with the reason when something is missing:

* the instance is running with **IMDSv2 required** (IMDSv1 fails unless `--allow-imds`), and **containers cannot reach
  the metadata service**: with hop limit 1 AWS stops them; with the hop limit 2 this instance has, only when the
  host's container IMDS block is installed and works ([Instance metadata (IMDS)](#instance-metadata-imds)). Otherwise
  any container, e.g. the DAST worker's browser, could obtain the instance role's credentials, which read every
  `devsec-chola/prod/*` secret (the app does not use the role).
* the target group (HTTP, 80, `/nginx-health`), the four secrets, the four ECR repositories, `s3://devsecshield-storage`
  owned by 935951870001 (`head-bucket --expected-bucket-owner`; every S3 call of the kit pins the owner), the backup
  vault, and **iam:PassRole on the backup role plus backup:StartBackupJob** (IAM policy simulation; if your user may
  not simulate, it warns and the backup step will tell);
* the **EC2 Instance Connect tunnel** (it opens one; the AWS error is shown if `ec2-instance-connect:OpenTunnel` is
  missing);
* on the instance: Docker, **Docker Compose 2.24+**, python3, flock, setsid, the AWS CLI and the instance role (STS,
  a list of `s3://devsecshield-storage/releases/` **and a read**: preflight writes a tiny probe object,
  `releases/preflight-probe.txt` (one fixed key, overwritten by every preflight), the instance must `get-object` it
  with the bucket owner pinned, and the probe is deleted on exit (only when this run's put succeeded); if your user
  may put but not delete objects there, preflight says so in a WARNING and that one object stays (in an unversioned
  bucket; with versioning each run adds a version) until the next preflight overwrites it. Any two owner commands
  that run a preflight at the same moment (`preflight`, `deploy`, also by two owners) can delete each other's probe,
  and the instance then reports a failed S3 read that looks like a permission problem: run one at a time), `/var/lib/docker` on its own volume, **15 GB free where
  images are stored** (containerd's root with Docker 29's containerd image store, else Docker's root) **and** where
  the volumes are, IMDSv2 on the host, the container IMDS block's rule and unit (with hop limit > 1), and an IMDS
  token probe from a container that must fail;
* that the mail login will be found (app-secrets, else origin/ansh, else `--mail-prompt`).

Also ask the infra team for:
* **ALB idle timeout**: 60 s by default. CI/CD scan calls hold the request until the worker answers and the AI chat
  streams (server-sent events); raise it to 600 s (nginx allows 600 s) or such calls end with a 504 from the ALB.
* The instance security group: port 80 from the ALB subnets 10.60.1.0/24 and 10.60.2.0/24 only.

## 2. Deploy

```sh
cd <your DevSecShield checkout> && git fetch origin
export AWS_PROFILE=<profile of AnshSinghal-Cyberultron>

scripts/deploy/chola-prod.sh preflight --sha <commit>        # changes nothing that runs; writes + deletes one S3 probe object
scripts/deploy/chola-prod.sh host-setup                       # once: AWS CLI (if missing) + the container IMDS block
scripts/deploy/chola-prod.sh --dry-run deploy --sha <commit>  # every step it will take; nothing is run or read
scripts/deploy/chola-prod.sh deploy --sha <commit>            # asks you to type 'chola' (or --yes)
```

`--dry-run` runs no AWS, SSH, Docker, registry or `git fetch` command and reads no secret; its summary marks every step
"skipped (dry-run)". `deploy` runs, in order, stopping at the first failure:

1. **IMDS block** (`remote.sh imds-block`, idempotent: installed or refreshed on every deploy), then **preflight**
   (above).
2. **secrets**: `devsec-chola/prod/app-secrets` (empty at first) gets every missing value generated with the OS CSPRNG
   (`JWT_SECRET_KEY`, `JWT_REFRESH_SECRET_KEY`, `ENCRYPTION_KEY` (Fernet), `CERTIN_HMAC_SECRET`, `PG_USER_PASS`,
   `MONGO_INITDB_ROOT_PASSWORD`, `RABBIT_ADMIN_PASSWORD`, `QDRANT_API_KEY`) and, on the first setup, the mail login
   (`SMTP_USERNAME`, `SMTP_PASSWORD`, `MAIL_FROM`). **Every value already there is kept**: `put-secret-value` replaces
   the whole JSON, so the kit reads, merges and writes only when something changed (key names and "kept / generated /
   set" are printed, never values). An unusable stored value is refused, not replaced. The kit asks the instance
   whether database or queue volumes exist (yes/no; any other answer stops it): if they do, it never generates
   `PG_USER_PASS`, `MONGO_INITDB_ROOT_PASSWORD`, `RABBIT_ADMIN_PASSWORD`, `ENCRYPTION_KEY` or `CERTIN_HMAC_SECRET` (the
   data depends on them) and refuses when one is missing or empty: restore the `AWSPREVIOUS` version instead.
3. **images** (with `--from-run`: from the CI run instead, [Images from a CI run](#images-from-a-ci-run)): backend,
   scan-worker and dast-worker are pulled from GHCR for linux/amd64 (`<prefix>-<sha12>`; the OCI
   revision label must be the commit), the frontend is **built** from the commit's own tree (`git archive`) for
   linux/amd64 with `NEXT_PUBLIC_BACKEND_URL=https://chola-api.zeroshield.ai` and checked to contain that URL; all
   four are pushed to `935951870001.dkr.ecr.ap-south-1.amazonaws.com/devsec-chola/{devsecshield-backend,devsecshield-frontend,scan-worker,dast-worker}:<sha12>`.
   A tag already in ECR is not pushed again (the instance checks its frontend URL anyway).
4. **env and images on the instance**: `remote.sh render` writes the env files from Secrets Manager **with the instance
   role** (mode 600, owner ubuntu), one per reader: `.env` (Compose interpolation only, no container gets it),
   `backend.env` (backend-image services), `scan-worker.env` (scan and CI/CD workers: queue, results store, S3/Bedrock,
   Qdrant), `dast-worker.env` (queue, results store, Bedrock). ECR login with the instance role; `docker pull` of the
   four images (linux/amd64, 15 GB free required); the frontend's baked API URL is checked before anything starts.
5. **infra**: if the instance lacks postgres, mongo, rabbitmq, nginx or qdrant, they are pulled here **by digest**
   (`INFRA_IMAGES` in chola-prod.sh) for linux/amd64, `docker save`d under their tags to
   `s3://devsecshield-storage/releases/release.tar` (`put-object --expected-bucket-owner`), downloaded on the instance
   to `/var/lib/docker/releases/`, checked against their sha256, `docker load`ed and deleted. Skipped when present.
   With `--from-run`, the archive is the run's `chola-infra` artifact (the same pins, gzip-compressed) instead.
   Then **imds-check**: the container token probe runs again (the infrastructure images it needs are there now)
   and must fail, before the backup and before anything starts.
6. **backup**: `pg_dump` and `mongodump` into `/var/lib/docker/dss-backups/` (on the data volume; last 3 kept; no
   password on any command line: mongodump reads a 0600 config file inside its container), then the on-demand AWS
   Backup job of `vol-02a57fae6510bb790` (14 days, the production tags); waits for `COMPLETED`, stops on `FAILED` /
   `ABORTED` / `EXPIRED` / `PARTIAL` or after 2 h (`CHOLA_BACKUP_TIMEOUT_S`). Failed status polls are retried
   (`CHOLA_POLL_RETRIES`, 10 in a row) with the AWS error shown.
7. **deploy**: refuses a commit whose migrations do not contain the database's Alembic revision (older than the
   database: use rollback); records a **STARTED** line (target tag, previous tag, database revision) in
   `state/deploy-history` before it switches anything; installs the kit and the commit's aibom overlay as the live
   kit (each directory replaced by a rename, never file by file; the replaced generation is deleted only after the
   containers that read it were recreated, i.e. it stays as `deploy/chola-prod.old.*` / `compose/aibom-config-overlay.old.*`
   until the next successful deploy or rollback; the env files are removed from a replaced kit generation at once, so
   the only secret copies on disk are the live ones, and every changing command first removes the `.stage.*` /
   `.restore.*` directories a killed run left; the overlay directory's identity is part of the files-hash label, so
   every container that read a replaced overlay is recreated, even when the new one has the same content); switches `DSS_TAG` and records a **SWITCHED** line; `docker compose up --wait` (the `migrate` one-shot runs `alembic upgrade head` under a
   Postgres advisory lock first; everything that uses the database waits for it); checks every service runs the tag
   and is healthy, `/nginx-health`, `GET /health` and the login page through nginx; runs the idempotent CBOM estate
   backfill and agility heal; keeps the images of this tag, the rollback target and the last good one.
8. **smtp-test**: from a backend container with the deployed `backend.env`: connect to smtp.office365.com:587,
   STARTTLS, AUTH, QUIT. Sends nothing. A failure is reported (Troubleshooting) but does not undo the deploy.
9. **verify**: the ALB target is `healthy` (instance or ip target type; waits up to 5 min, retries failed polls),
   `curl http://localhost/nginx-health` on the instance is `ok`, `https://chola.zeroshield.ai/login` is 200 (with
   HSTS), `https://chola-api.zeroshield.ai/health` is 200 `healthy`. Then a summary.

**Detached on the instance**: the deploy, rollback, dump and infra-load steps run there as jobs (`setsid nohup`,
output in `state/jobs/<id>/log`, exit status in `.../rc`); your terminal only follows them, opening a fresh tunnel
before each and reconnecting when the EICE tunnel drops. **Ctrl-C or a lost connection does not stop the job**: the
kit prints `chola-prod.sh attach --job <id>` to follow it again (`status` lists recent jobs). One lock
(`state/.lock`) lets only one changing command run at a time.

**Interrupted deploy** (the instance rebooted or the job was killed half way): the follower reports the job either
as **failed with a non-zero exit** (a graceful reboot or stop, or `kill <pid>`, sends SIGTERM: the job records exit
143, never 0; any other fatal signal records 128 + its number while the job's wrapper process lives, and reads as
LOST if the wrapper was killed too) or as **lost** (a hard reset or SIGKILL: its processes
are gone and it recorded no exit status; the pid
and start time of the job's wrapper AND of its worker are checked, so a reused pid after a reboot is not mistaken for
it, and a killed wrapper alone does not make a running job look lost: the worker writes the exit status itself);
`status` lists it as `exit 143` or LOST. Both mean the same: the deploy did not finish. **`kill <worker pid>` is not
immediate**: the job ends with 143 only once its current step returns, and `docker compose up --wait` may take up to
`CHOLA_WAIT_S` (900 s by default). Wait for it rather than reaching for `kill -9`, which leaves a half-finished step
and a LOST job behind. Either `deploy --sha <the same
commit>` again or `rollback`: both see the interruption, remove the application containers (stateless; databases, queue and
volumes stay) and start them fresh, and try once more if the first start fails. When the interruption came before the
tag switch (STARTED without SWITCHED), nothing had changed: `rollback` then starts the release that was running again
instead of going one release further back. The rollback target survives a failed recovery: with no backend container
left, a deploy takes it from the history (never "none") or from the last release that passed its checks.

**Downtime**: one instance, so the containers that change are recreated in place; expect a minute or two of 502/503
from the ALB while the backend restarts. A change to `nginx/` or the aibom overlay alone also recreates nginx and the
backend-image services (a content-hash label; bind mounts are otherwise invisible to Compose; it works through sudo).

Single steps can be run on their own: `secrets`, `images --sha S [--from-run RUN]`,
`infra [--force-infra] [--from-run RUN]`, `backup`, `verify`, `smtp-test`, `status`,
`logs [--service backend] [--tail 500]`, `attach --job <id>`.

**Certificate identity re-key window** (`CBOM_IDENTITY_WINDOW_HOURS`, in the backend env; default 24, clamped to
1..720 hours, a non-number, `inf`, `NaN` or negative value is refused and logged once): after the deploy migration
moves the stored certificate keys, store writes also re-key rows an older-release process wrote, until the scheduler
closes the window per team. The deploy recreates every container after `migrate`, so no older writer is left; one
that wrote after the window would leave a duplicate `removed` asset and a Q0 item closed as `observation`. Raise the
variable before any rollout that keeps the old release running for more than a day. Migrations that build an index
`CONCURRENTLY` (`q102hist001`, `q110linkuq001`) wait for older transactions; `q110linkuq001` gives up after 3 x 60 s:
end the idle-in-transaction sessions and deploy again (deploy/staging/README.md, "Migrations that build an index
CONCURRENTLY").

### Images from a CI run

Three ways to get a commit's images onto the instance. Each one checks the images the same way (linux/amd64, revision
label = the commit, the frontend's API URL). Every way deploys only a commit that is on `origin/dev` or
`origin/staging`: the kit fetches both and checks with `git merge-base --is-ancestor`.

| | GHCR path (default; the owner's laptop) | `--from-run RUN`: S3 relay (default for `--from-run`) | `--from-run RUN --to-ecr` |
|---|---|---|---|
| backend, scan-worker, dast-worker | `docker pull` from GHCR here, then push to ECR | the run's copies of the GHCR images (same digests), streamed GitHub -> S3 -> instance | the run's copies, `crane push`ed to ECR from here |
| frontend | built here with buildx for `https://chola-api.zeroshield.ai` | built by the run the same way | built by the run |
| infrastructure archive | `docker pull` by digest + `docker save` here | the run's `release.tar.gz` (same pins), relayed | the run's archive, downloaded here |
| the instance gets them | `docker pull` from ECR | `docker load` from the relayed files; nothing is pulled from ECR | `docker pull` from ECR |
| needs here | Docker + buildx, gh with `read:packages`, ~15 GB | gh (`gh api`), aws; **almost no disk** | gh, crane (or curl to fetch the pinned one), the largest image's size free |

**1. Run the workflow on the commit.** `.github/workflows/chola-prod-images.yml` must run **on the commit it packages**
(`github.sha` is the commit), so the workflow, `ci_images.sh` and `artifacts.py` it runs are that reviewed commit's own
files. The commit needs a green **Publish images (GHCR)** run first. Two ways to start it:

```sh
# a branch named after the commit, pointing AT it (any commit that has the workflow file); delete it afterwards
git push origin <SHA40>:refs/heads/chola-prod-images/<SHA40>
# or, once the workflow is on the default branch (main), workflow_dispatch from a branch whose tip is the commit
gh api -X POST repos/CyberUltron-Consulting-Private-Limited/DevSecShield/actions/workflows/chola-prod-images.yml/dispatches \
  -f ref=dev -f 'inputs[sha]=<SHA40 = the tip of dev>'
```

What the run does (the steps are in `ci_images.sh`):
- It pulls the three GHCR images with `crane pull --format=oci --platform linux/amd64`, which copies their linux/amd64
  manifests byte for byte.
- It builds the frontend for linux/amd64 with `NEXT_PUBLIC_BACKEND_URL=https://chola-api.zeroshield.ai`, with the
  kit's build arguments and labels. The bundle must contain that URL.
- It `docker save`s the pinned `INFRA_IMAGES`, compressed. The shared runner's Docker is put back as it was: tags that
  existed before are put back on their images, and the tags and images this step created are removed.
- It checks each image with `artifacts.py oci-check`, uploads it straight away and deletes it, so only one image is on
  the runner's disk at a time.
- The artifacts are kept **3 days**: `chola-image-{backend,frontend,scan-worker,dast-worker}` (OCI layouts),
  `chola-infra` (`release.tar.gz`) and `chola-manifest` (`manifest.json`). The manifest holds the commit, this run's
  id, each image's source ref, index and linux/amd64 digests and revision, and the archive's sha256 and pins.
- The image and infra artifacts are uploaded with `compression-level: 0`. upload-artifact then writes stored zip
  entries with a data descriptor: the header has sizes 0, and the CRC and sizes come after the data.
  `artifacts.py unzip-stream` reads that format as it streams in. It finds the descriptor whose CRC-32 and size match
  every byte before it, so a "PK\x07\x08" inside the data is never taken for the end of the entry.
- Its token has `contents: read` and `packages: read` only.

**2. Deploy from it**: `chola-prod.sh deploy --sha <SHA> --from-run <RUN>`. The same flags work with `preflight`,
`images` and `infra`, and every `--from-run` command needs `--sha`. Before anything is copied, the kit checks:
- **the run**: it is that workflow, `completed`/`success`, started by `workflow_dispatch` or `push`, in this
  repository (its head repository too), and **its `head_sha` is `--sha`**;
- **the commit**: `--sha` is on `origin/dev` or `origin/staging`;
- **the files**: the blobs GitHub has for `.github/workflows/chola-prod-images.yml`, `deploy/chola-prod/artifacts.py`
  and `deploy/chola-prod/ci_images.sh` at that commit equal `git rev-parse <sha>:<path>` here. An edited workflow or
  helper on a pushed branch is refused;
- **the manifest**: its run id is `--from-run`, its commit is `--sha`, the frontend's API URL is this kit's, and the
  infrastructure pins are this kit's `INFRA_IMAGES`.

**S3 relay (default).** Nothing is stored on this machine.
1. Each artifact zip streams from `gh api .../actions/artifacts/<id>/zip` through `artifacts.py hash-pipe` (which
   computes its sha256 in the same stream) into `aws s3 cp - s3://devsecshield-storage/releases/<sha12>/<artifact>.zip
   --expected-bucket-owner 935951870001`. The streamed size must equal the size GitHub lists.
2. Then one detached instance job, `remote.sh relay-load`, takes the artifacts one at a time on the data volume
   (`/var/lib/docker/releases`):
   - it downloads the zip (bucket owner pinned) and checks its sha256;
   - it extracts the zip (only OCI layout names are accepted) and checks the layout against the manifest's digest
     (every blob's sha256, linux/amd64, the revision label, and the API URL label for the frontend);
   - it names the image `<ECR prefix>/<repo>:<sha12>` in `index.json` (read by the containerd image store) and in a
     docker-save `manifest.json` (read by the graphdriver/overlay2 store), which does not change the image's digest,
     and `docker load`s it. Docker 25+ loads it on either store (preflight reports which one the instance has); on an
     older Docker the kit uses `skopeo` only if the instance has it;
   - it checks what Docker now holds: linux/amd64, the label, and an id equal to the config or manifest digest. A
     mismatch removes the image again (`docker image rm`) before the job stops. What passed is recorded in
     `state/relay/<sha12>`, and `pull <tag> --local` accepts only an image with exactly that id and revision;
   - it deletes the zip and the files, whether the step succeeded or failed.

   The release archive gets the same treatment: sha256 of the zip, then sha256 of `release.tar.gz` against the
   manifest, then `docker load`, then the pins and architectures. It is relayed only when the instance lacks a pinned
   image, or with `--force-infra`.
3. The S3 objects under `releases/<sha12>/` are deleted after the load, and also when the relay fails (from the
   kit's exit trap). Only if the load job may still be running (Ctrl-C, a lost tunnel) are they kept, with a warning
   that names the prefix to delete once it has ended.
4. The deploy then never runs `ecr-login`. `remote.sh pull <tag> --local` only checks the images (and the frontend's
   API URL), and fails if one is missing. Compose already has `pull_policy: never`.

The relayed images are **not in ECR**. A rollback uses the images kept on the instance (the deploy keeps the
previous and the last good release). `rollback` plans first, before its backup: when the target's images are neither
on the instance nor in ECR, it stops there ("relay that commit again first"), and no backup is taken.

**`--to-ecr`.** The kit copies each image to ECR with crane, one at a time:
- it streams the artifact into a local layout and checks it (`oci-check`);
- it runs `crane push`, then reads back with `describe-images` the digest ECR stores under the tag, which must be the
  manifest's;
- it deletes the layout before the next download.

crane is used from PATH. Without it, `v0.22.1` is downloaded and used only if its sha256 matches the pin. A tag
already in ECR with another digest is kept, because tags are written once. That image was not built by the run and is
not checked again. Free space is checked before each download (`CHOLA_WORK_PARENT` moves the scratch directory).

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
writes them and `remote.sh` refuses to start if any env file contains them.

## 4. Verify (any time)

```sh
scripts/deploy/chola-prod.sh verify
scripts/deploy/chola-prod.sh status        # containers, deployed tag, history, jobs, images, disk, ALB target health
```

By hand: `aws elbv2 describe-target-health --target-group-arn arn:aws:elasticloadbalancing:ap-south-1:935951870001:targetgroup/devsec-chola-prod-tg/3c35d6b360c5c80a`,
`curl -I https://chola.zeroshield.ai`, `curl https://chola-api.zeroshield.ai/health` (`{"status":"healthy",...}`).
`/health` is the backend's own route (backend/main.py); it does not name the build (`DSS_EXPOSE_BUILD=0`); signed-in
users read the build from `GET /version`.

## 5. Rollback

```sh
scripts/deploy/chola-prod.sh rollback [--allow-downgrade] [--to <tag>]
```

Takes a backup first, then goes back to the tag that was running before the current one (`state/deploy-history`: the
deploy line, or the STARTED line of an interrupted deploy) with that release's own deploy files, and verifies. A
rollback records a **ROLLBACK-STARTED** line (target, current tag, database revision) before it changes anything.
**Retrying a rollback that failed or was interrupted retries that same rollback, never one release further back**:
after the tag switch (C -> B failed in `compose up`, or the job was killed) the retry starts B again; before it (or
when the downgrade failed) it runs C -> B again. A rollback counts as finished only once B's checks passed: when
they fail it records FAILED; when the job is killed during them it is left unfinished, usually with ROLLBACK-STARTED
last (SIGKILL, or a SIGTERM to the whole session that ends the job before it can write FAILED), sometimes with FAILED
last. Either way the retry starts B again. The plan line says which. Once B runs, a further `rollback` goes to the release before B. A deploy started after an unfinished rollback
to B records B (where you were heading) as its rollback target.

**When B can never start**, every retry starts B again. The way past it is explicit: `rollback --to <tag>` goes to
that release instead (for example A), with the same backup, downgrade plan and confirmation. It only accepts a release
that was deployed and passed its checks on this instance (`state/deploy-history` and `state/passed`) and that is **not
newer** than the running one (first deployed, i.e. first STARTED, before it; a deploy interrupted after its switch
counts as the newest): rollback only goes back. A plain `rollback` is different: it goes to the release the current
one replaced, so after redeploying an old commit A over C, a plain rollback goes "forward" to C (A's recorded
predecessor) while `--to C` is refused as newer. Forward is `deploy --sha <commit>`,
which also runs the estate backfill, agility heal and image retention. `status` lists the releases `--to` accepts,
newest first; nothing has to be edited by hand. `--to` and `--allow-downgrade` are refused on any other command. When the
older release's migrations do not contain the database's revision, the current image first runs `alembic downgrade
<older head>`, which **drops the tables and columns the newer migrations added, with their data**: `rollback` first
plans it (read-only), lists those migrations and asks you to type `downgrade` (or takes `--allow-downgrade`; without a
terminal and without the flag nothing is changed). When there is no downgrade path, or the downgrade fails (the
current release is started again), restore instead. Going forward again: `deploy --sha <newer>`. Users whose password
a newer release rehashed may need a password reset on an older image.

**Restore**: logical dumps are in `/var/lib/docker/dss-backups/` (`pg_restore -d ...` / `mongorestore --archive
--gzip`). They live on the same volume as the data, so also copy the newest ones off the instance regularly (for
example to a separate, access-restricted S3 location or your backup store); the AWS Backup recovery points are the
off-instance copy of the whole volume. The whole data volume: restore the pre-deployment recovery point from vault
`devsec-chola-prod-backup-vault` to a new volume and have the infra team swap it in at `/var/lib/docker` (stop Docker
first).

## 6. Where the secrets live, and rotation

| Secret (Secrets Manager, ap-south-1) | Holds | Read by |
|---|---|---|
| `devsec-chola/prod/ssh-admin` | `private_key_pem` | owner's machine (SSH key, temp file 0600, deleted on exit) |
| `devsec-chola/prod/app-secrets` | the generated keys above + `SMTP_USERNAME`, `SMTP_PASSWORD`, `MAIL_FROM` | written by the owner (`secrets`), read by the instance role (`render`) |
| `devsec-chola/prod/app-user` | the app IAM user's access key (S3 `devsecshield-storage` + Bedrock) | instance role -> `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in backend.env, scan-worker.env, dast-worker.env |
| `devsec-chola/prod/cbom-collector` | the CBOM collector's access key (sts:AssumeRole only) | instance role -> `backend.env` `CBOM_AWS_*` (its principal ARN from the secret, else from STS) |

On the instance the four env files (mode 600) are rendered on every deploy; never copy them anywhere.

Rotation (details: `docs/security/secret-rotation.md`): change the value in Secrets Manager, then
`chola-prod.sh deploy --sha <the running commit>` re-renders the files and recreates the containers. Order matters:
* `PG_USER_PASS`, `MONGO_INITDB_ROOT_PASSWORD`, `RABBIT_ADMIN_PASSWORD` only take effect on an empty volume: change the
  password **inside** the database / broker first (`ALTER ROLE`, `changeUserPassword`, `rabbitmqctl change_password`),
  then in the secret, then deploy.
* `ENCRYPTION_KEY`: one key at a time; rotating it makes stored credentials unreadable (teams re-enter them).
* JWT secrets: every session ends.
* Mail: change the mailbox password, then `chola-prod.sh secrets --mail-prompt` (hidden prompt) and deploy. Never put
  a password into git.
* app-user / cbom-collector keys: new key, update the secret, deploy, delete the old key.
* Never delete `app-secrets`: Secrets Manager keeps the previous version as `AWSPREVIOUS`.

## Instance metadata (IMDS)

The instance keeps **`HttpPutResponseHopLimit` 2** (the infra team's setting; it is not changed by this kit). With 2,
a container's IMDSv2 token request survives the Docker bridge hop, and the instance role reads every
`devsec-chola/prod/*` secret. The application does not need the role (it uses the app-user keys), and the host's AWS
CLI must keep it (ECR login, S3 release archive, Secrets Manager). So the **host** drops container traffic to the
metadata service:

* `/usr/local/sbin/devsec-chola-imds-block` (from `host/`) inserts, idempotently, `-d 169.254.169.254/32 -m comment
  --comment devsec-chola-imds -j DROP` at the top of the **`DOCKER-USER`** chain (and the `FORWARD -j DOCKER-USER` jump
  if missing). Container traffic is forwarded through the host, so it passes `FORWARD` and `DOCKER-USER`; the host's
  own requests go through `OUTPUT` and still reach IMDS. Docker never flushes `DOCKER-USER`. Compose networks and the
  default bridge are covered alike (the rule matches the destination, not an interface). A container with
  `network_mode: host` would not be covered; this stack has none.
* **IPv6**: when the instance's `HttpProtocolIpv6` is `enabled`, the same rule for `fd00:ec2::254` goes into
  `ip6tables` (the kit reads the option with `describe-instances` and writes `IPV6=enabled` to
  `/etc/default/devsec-chola-imds-block`). Disabled (today): no IPv6 rule is needed.
* **Persistence**: `devsec-chola-imds-block.service` (oneshot, `After=docker.service`, `PartOf=docker.service`,
  `WantedBy=docker.service multi-user.target`) runs it after every Docker start and restart, so a reboot or
  `systemctl restart docker` puts it back; the drop-in `docker.service.d/devsec-chola-imds-block.conf` also runs it as
  Docker's `ExecStartPre` (failure ignored there), so containers that come back on their own after a reboot never see
  a gap. Installing it runs `daemon-reload` and starts the unit; **Docker itself is not restarted**.
* **Installed by** `host-setup` and, idempotently, by **every deploy** before its preflight (`remote.sh imds-block`).
* **Checked**: with a hop limit above 1 (or an unreadable one) the instance preflight requires the rule (IPv4, and
  IPv6 when enabled), the enabled unit with its script and drop-in, and a raw IMDSv2 token `PUT` from a container
  (`qdrant/qdrant:v1.13.5`, 8 s timeout) on the default bridge **and** on the stack's `dss-chola_egress` network (once
  it exists) that must **fail**: only a connect that times out (what the DROP rule does) or is refused counts as
  blocked. A connection accepted but never answered, another answer than 200, no route (IPv4), no `timeout` in the
  image, or a probe that did not run is an error, never a pass. For IPv6, no route counts as blocked (a container
  without IPv6 cannot reach `fd00:ec2::254`). Before the infrastructure images are loaded the probe cannot run yet: preflight says so, and the deploy runs
  `remote.sh imds-check` after loading them, which requires the probe, before the backup and before anything starts.
  IMDSv1 (`HttpTokens` optional) is refused outright (the host itself would hand out credentials). `--allow-imds`
  turns each of these failures into a warning; not advised.
* To check by hand on the instance: `sudo iptables -S DOCKER-USER`, `systemctl status devsec-chola-imds-block`.
  To remove it: `sudo systemctl disable --now devsec-chola-imds-block`, delete the three files and the rule
  (`sudo iptables -D DOCKER-USER -d 169.254.169.254/32 -m comment --comment devsec-chola-imds -j DROP`), then
  `sudo systemctl daemon-reload`; preflight fails afterwards while the hop limit is 2.

## 7. Troubleshooting

* **EICE tunnel** (`SSH ... through EC2 Instance Connect failed`): the AWS error is printed. AccessDenied: the user lacks
  `ec2-instance-connect:OpenTunnel`; a timeout: no endpoint in the VPC, or the endpoint's security group cannot reach
  port 22 of the instance. AWS CLI older than 2.12 has no `open-tunnel`. A changed host key (instance rebuilt) is
  refused: remove the line from `~/.ssh/known_hosts_devsec_chola` (the first connection records it). EICE connections
  are time-limited; the kit opens a fresh tunnel before each long step and reconnects while following a job.
* **A job lost its terminal**: `chola-prod.sh status` lists the recent jobs; `chola-prod.sh attach --job <id>`.
  A job listed as LOST ended without an exit status (hard reboot, SIGKILL), one with `exit 143` was stopped by
  SIGTERM (graceful reboot or stop, `kill`; it ends only once its current step returns, up to `CHOLA_WAIT_S`): either
  way it did not finish. See its log (`state/jobs/<id>/log`), then
  deploy the same commit again or roll back.
* **Instance settings** go through from your shell: `CHOLA_MIN_FREE_GB`, `CHOLA_WAIT_S`, `CHOLA_DUMPS_KEEP`
  (whole numbers; `--help`).
* **"another chola-prod command is running"**: a deploy, rollback, dump, render or infra-load holds
  `/opt/devsecshield-chola/state/.lock` on the instance; follow it (`attach`) or wait. The lock is released when its
  process ends, also when it was killed.
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
  The backend's own log says the same without values, from any directory:
  `scripts/deploy/chola-prod.sh logs --service backend --tail 500 | grep -i smtp` (on the instance:
  `sudo docker compose -p dss-chola logs backend | grep -i smtp`).
* **Target unhealthy**: `status` (is nginx up?); on the instance `curl -i http://localhost/nginx-health`; the target
  group must use HTTP, port 80 (traffic port), path `/nginx-health`; the security group must allow port 80 from the
  ALB subnets. `nginx` exits at start when `DSS_REAL_IP_FROM` holds the unspecified address, a prefix shorter than
  /8 (IPv4) or /16 (IPv6), or a host name (`logs --service nginx`).
* **"built for another API URL"**: the frontend in ECR was built for another API URL; delete that tag in ECR and run
  `images --sha S` again (or `--frontend-image` with a correctly built image).
* **migrate fails** with "Can't locate revision": the database is newer than the commit; use `rollback`, or deploy a
  newer commit.
* **Disk**: `status` shows free space; preflight and every pull require 15 GB (`CHOLA_MIN_FREE_GB`) both where images
  are stored and where volumes are. Each deploy keeps three releases' images.

## 8. Decisions (why it is built this way)

* **S3 and Bedrock use the app-user keys, not the instance role.** The code builds its S3 client and every Bedrock
  client from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` explicitly and fails without them
  (`backend/utilities/db/s3_utils.py`, `backend/utilities/ai/llm.py`, `RabbitMQ/worker/helpers/context/s3_utils.py`,
  `base_utilities.py`, `base_agent.py`), so the instance role cannot be used without code changes; IMDS then only
  matters for security: containers must not reach it (hop limit 1, or the host's container IMDS block with the hop
  limit 2 this instance has). The CBOM AI assistant uses the same keys (`CBOM_AI_AWS_CREDENTIALS=env`).
  No MinIO: real S3, bucket `devsecshield-storage` (the code's default bucket).
* **Least privilege per container**: the backend-image services, the scan/CI-CD workers and the DAST worker each get
  only the variables their code reads (one env file each); the frontend and nginx get none. `BACKEND_WORKERS` is in
  `.env` (gunicorn's `--workers`) and in `backend.env` (the API sizes its CBOM dispatch from it).
* **Bedrock models**: every AI feature in the code calls `openai.gpt-oss-120b-1:0` (`LLM_MODEL`, `CBOM_AI_MODEL`
  default); `global.anthropic.claude-haiku-4-5-20251001-v1:0` is used only by the nightly AIBOM benchmark workflow.
* **Frontend built by the kit**: `NEXT_PUBLIC_BACKEND_URL` is inlined at `next build` (frontend/Dockerfile), and GHCR's
  dev/staging frontends carry `http://localhost:8000` (`.github/ci/ghcr_meta.py`). `CORS_ORIGINS` and
  `CBOM_PUBLIC_APP_URL` are runtime (backend.env). Sign-in tokens travel in headers, so there is no cookie domain.
* **Mail over SMTP**, not Graph: the instance cannot reach graph.microsoft.com; with `SMTP_HOST` set the backend never
  tries Graph (`backend/utilities/auth/auth_utils.py`).
* **Qdrant is part of this stack** (it is not in deploy/staging): SAST / IaC / SCA AI analysis needs it.
* **Infrastructure images pinned by digest** where they are pulled (the owner's machine); the instance cannot pull at
  all, and the archive it loads is checked against its sha256.
* **nginx**: X-Forwarded-For carries the client once (the ALB's header as it came; from anyone else only the TCP
  peer); X-Powered-By is dropped and the Server header says `nginx` without a version (removing it needs a module the
  stock image lacks); HSTS without `includeSubDomains`/`preload` (other zeroshield.ai hosts are not ours to pin);
  uploads 64 MB except `POST /{team}/cbom/sources/runs/{run}/signature/verify`, which accepts the API's 512 MB.
* `DSS_SBOM_REGISTRY=0` (in `backend.env` and `scan-worker.env`; unset is off too): the instance cannot reach public package registries. `DSS_ENV=production` (lab mode refused).
  The dast-worker gets `UV_NO_SYNC=1` / `UV_OFFLINE=1` (its image lacks them; the instance cannot reach PyPI).

## 9. What the instance's egress rules block (not fixed by this kit)

Outbound from the instance is limited to HTTPS to AWS services (ECR, S3, Bedrock, Secrets Manager, STS), GitHub, GitLab,
Bitbucket and the Grype DB, plus SMTP 587/465 and HTTP 80 for apt. These features therefore **do not work** until the
infra team allows the hosts they need (or the feature is not used):

* **DAST** scans customer-chosen target URLs: any target outside the allowed hosts is unreachable (nuclei templates
  come from GitHub and do work).
* **IdP metadata** (CBOM identity-provider sources) is fetched from the customer's IdP host: blocked.
* **Integrations** (Settings > Integrations: ServiceNow, Splunk HEC / syslog, signed webhooks, OSCAL push) send to the
  customer's hosts: blocked.
* **Certificate Transparency discovery** queries public CT log services (crt.sh / Cert Spotter): blocked.
* **SAST AI (RAG)**: the scan worker embeds code with `amazon.titan-embed-text-v2:0`
  (`RabbitMQ/worker/helpers/context/base_utilities.py`), which is not one of the two Bedrock models this account may
  call: expect `AccessDeniedException` in SAST/IaC scans until the model is allowed or the code changes.
* **Semgrep rules**: the SAST step runs `semgrep --config p/<language>`
  (`RabbitMQ/worker/helpers/tools/sast_agent/semgrep_util.py`), which downloads rules from semgrep.dev: that step
  fails ("SAST scan failed"). Allow semgrep.dev or vendor the rules.
* **Public package registries** (npm, PyPI, Maven ...) for SBOM enrichment: off (`DSS_SBOM_REGISTRY=0`).
* **Scan-node downloads** (Add scan node wizard) are not shipped (`CBOM_NODE_ARTIFACT_DIR` unset); the wizard says they
  are not available. deploy/staging has the machinery (`staging.sh node-artifacts`) if they are needed here.

What works within the rules: sign-in and mail (SMTP), the UI and API, repository clones from GitHub/GitLab/Bitbucket,
CBOM / AI-BOM code scans, SCA with the Grype DB, S3 uploads, CBOM AWS sources (STS), the CBOM AI assistant (Bedrock
gpt-oss).
