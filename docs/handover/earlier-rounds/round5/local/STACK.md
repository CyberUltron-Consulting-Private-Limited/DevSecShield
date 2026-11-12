# Local production stack (owner: L1)

REBUILDING Nov 11 06:07 UTC from ansh b59869f (integrator): backend, frontend, scan-worker, dast-worker.
READY b59869f Nov 11 06:22 UTC - backend, frontend, scan-worker, dast-worker from ansh b59869f (migrations rv6s2invite001, rv6p1nodename001); scan-node 288fba9.
REBUILDING Nov 10 16:24 UTC from ansh 006ac94 (integrator): backend, frontend only (G5 regression fixes).
READY 006ac94 Nov 10 16:27 UTC - backend and frontend from ansh 006ac94 (G5 fixes); scan-worker, scan-node 288fba9; dast-worker bd59f18.
REBUILDING Nov 10 14:20 UTC from ansh 288fba9: backend, frontend, scan-worker, scan-node:1.0 (dast-worker unchanged,
stays at bd59f18). Services restart as their image is replaced; wait for the READY 288fba9 line below.
READY 288fba9 Nov 10 14:30 UTC - backend 14:21, frontend 14:24, scan-worker 14:27 (code-scan variant), scan-node:1.0
  14:29, all from ansh 288fba9; dast-worker still bd59f18 (no changes). migrate exited 0. UI /login 200, API /health
  200, scan/cicd/dast queues 1 consumer each. Credits and accounts unchanged (table below).
  NOTE: the integration receivers (172.17.0.1 :9443 :8088 :5514 :6514) STOPPED at their 2-hour background limit
  (about 16:05 UTC) and are not running. Start them yourself if you need them:
  python3 $S/ui/l1/bin/receivers.py (logs to $S/ui/l1/logs/receivers.jsonl).

REBUILDING Nov 10 14:00 UTC from ansh bd59f18: backend, frontend, scan-worker, dast-worker, scan-node:1.0.
READY bd59f18 Nov 10 14:17 UTC - every image below built from ansh bd59f18 (L1's worktree at that commit):
  backend 14:01, frontend 14:05, scan-worker 14:09 (code-scan variant, no garak/torch; KB 2026.11.10.1; its
  revision label still says ea45608 because that build path does not set it), dast-worker 14:15 (nuclei uses the
  shipped Chromium), registry.zeroshield.ai/cbom/scan-node:1.0 14:16. compose up done: migrate exited 0, grype-db
  volume mounted in scan-worker and cicd-worker. Checks: UI /login 200, API /health 200, scan/cicd/dast queues
  1 consumer each. U1's u1-node container still runs the previous scan-node image until U1 recreates it.
  Integration receivers restarted (172.17.0.1 :9443 :8088 :5514 tcp/udp :6514). Juice Shop not started (disk).
  New since this build: manual DAST and profiles refuse private/Docker-internal targets unless listed in
  DAST_ALLOWED_PRIVATE (not set here); integrations refuse loopback/metadata/unlisted private destinations at save.

REBUILDING 10:35 UTC (backend + frontend from worktree HEAD 771a3ff; the running images predated L1's fixes).
READY 771a3ff 10:43 UTC
READY 771a3ff Nov 10 12:24 UTC - the stack came back by itself after the 12:18 container restart; checked by L1:
  all 12 dss-staging containers up (7 healthy), UI and API 200 on :443, /etc/hosts entries present, rabbitmq
  booted, scan/cicd/dast queues 1 consumer each, workers "ready". L1 restarted the integration receivers
  (172.17.0.1 :9443 :8088 :5514 tcp/udp :6514) and the stand-in sshd (127.0.0.1:2222). Free disk about 7 GB.
READY 771a3ff Nov 10 ~13:05 UTC - back after the ~13:00 restart: all dss-staging containers up, UI/API 200,
  scan/cicd/dast queues 1 consumer each. Integration receivers and stand-in sshd are NOT running (L1 is wrapping up).
  Not yet in the running images (rebuild when convenient): backend 060e865 (secrets not logged), frontend a3a141b,
  dast-worker 9c879c7. L1's stand-in stack (dss-standin-*, 127.0.0.1:8444) was stopped at 13:25 (L1 done).

## URLs
* UI  https://devsec.dss.test   API https://api.dss.test   (nginx on 127.0.0.1:443; :80 redirects to https)
* /etc/hosts already maps devsec.dss.test, api.dss.test (and the stand-in devsec2/api2) to 127.0.0.1 - nothing to add.
* TLS: a local test CA. Trust $S/ui/l1/ca/ca.pem (curl --cacert) or use ignoreHTTPSErrors in Playwright.
* These names are NOT in NO_PROXY: curl needs `--noproxy '*'`; Playwright: run node with
  `env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy` and launch Chromium with `--no-proxy-server`.
* Mail catcher (all mail the stack sends, incl. sign-in codes and team invitations): web UI http://127.0.0.1:8025
  (API: GET http://127.0.0.1:8025/api/v1/search?query=to:<address>). Read codes there as a customer would.
* OWASP Juice Shop was removed at 11:08 UTC to keep 3 GB of disk free (L1's DAST run is done); the dast-worker
  container was recreated then (its 580 MB of downloaded nuclei templates freed).
* Disk: about 11 GB free after the 14:17 rebuild (keep >= 3 GB). Grype's ~1 GB vulnerability database now goes once
  onto the shared grype-db volume (first SCA + SBOM scan downloads it), no longer into each worker container.

## Accounts and teams (sign-in = email + password + 6-digit code from the mail catcher)
| who | credentials file (0600, {email,password}) | default team id | credits |
|---|---|---|---|
| U1 | $S/local/accounts/u1.json | 7 | 6993 (+2000 Nov 10 14:02) |
| U2 | $S/local/accounts/u2.json | 8 | 6997 (+2000) |
| G1 | $S/local/accounts/g1.json | 9 | 7000 (+2000) |
| G2 | $S/local/accounts/g2.json | 10 | 6999 (+2000) |
| U3 (Uma) | $S/local/accounts/u3.json | 11 | 2000 (+2000) |
| R1 (regression agent) | $S/local/accounts/r1.json (r1@agents.dss.test, registered via UI + mail catcher) | 12 | 5000 |
Use only your own account and team (L1 tests logout/reset/delete on its own accounts; a logout revokes every token
of that account). You may also register more accounts at https://devsec.dss.test/register; a new team starts with
0 credits - ask L1 to top it up (there is no self-service top-up; superuser = L1's operator account).
Sign-in codes: one per send, single use, a wrong password spends it; "Resend" after 30 s.

## Images (DSS_TAG=l1, prefix dss-staging)
* backend, frontend, dast-worker, scan-node:1.0: built from ansh bd59f18 (Nov 10 14:01-14:16).
* scan-worker: ansh bd59f18 worker sources, CODE-SCAN VARIANT: garak/torch/CUDA left out
  (4.4 GB of wheels do not fit this disk) - LLM red-team scans cannot run on this stack.
* MinIO (profile minio) as S3; mail via SMTP to the mail catcher; no LLM keys, no AWS (Bedrock features say so).

## RabbitMQ and workers (10:43 UTC)
rabbitmq healthy; queues scan_worker_queue, cicd_worker_queue, dast_worker_queue each have 1 consumer, 0 messages.
scan-worker, cicd-worker, dast-worker, cbom-cloud-worker (also the integration dispatcher), dast-scheduler up.
Integration receivers (for Settings > Integrations) on 172.17.0.1: https :9443 (webhook/OSCAL/ServiceNow stand-in),
https :8088 (Splunk HEC), syslog tcp/udp :5514, tls :6514; INTEGRATION_ALLOWED_PRIVATE=172.17.0.1/32.

## Rebuilds
L1 owns every rebuild and restart of this stack. Before a restart L1 writes "REBUILDING <time>" here, and
"READY <commit> <time>" after. Do not run make up/down, compose, or docker restart on dss-staging-*.
