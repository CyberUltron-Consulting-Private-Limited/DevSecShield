# Local continuation brief (after the 10:20 UTC container restart) — read fully first

## What changed
* The container restarted at about 10:20 UTC and every background task stopped, including the agents. Files and
  git worktrees survived, including any uncommitted changes you had made (review them; they are yours).
* AWS is gone for now: the lab session credentials are rejected ("security token invalid"). Do NOT call AWS, do
  not start the SSM tunnel, do not use *.zslab.internal. The owner said: "since we dont have aws access for now please
  continue to develop and do the testing in your sandbox ... then do the complete testing there". Anything that only
  the AWS lab can prove is BLOCKED (say so in your report); do not fake it.
* The owner also said they fixed the staging environment themselves. Do not deploy to staging.

## Docker and disk (shared machine)
* dockerd is already running (started by the integrator). Never start a second dockerd, never stop it, never
  `docker system prune` / `image prune` / `builder prune`, never stop or remove containers or volumes you did not
  create. The compose project `dss-staging` (the local production stack, nginx on 127.0.0.1:80/443) plus
  `l1-mailpit` and `l1-juice-shop` belong to agent L1; only L1 rebuilds or restarts them.
* Your own containers, networks and volumes: name them with your prefix (u1-, u2-, g1-, g2-) and remove them before
  you finish.
* Disk: about 6.8 GB free on /. Keep at least 3 GB free at all times (check `df -h /` before any build). Only L1
  builds platform images. U1 may build the scan-node image once.

## The local stack
* L1 writes `$S/local/STACK.md` (S=/tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/round5):
  the UI and API URLs, how the browser reaches them, how to get a customer account (registration through the UI and
  the mail catcher, or a provided login), the team id, and which commit the images were built from. Wait for that
  file (poll every minute at most) before UI testing; meanwhile commit your pending fixes and run unit tests.
* Your fixes are not in the stack until the integrator merges them and L1 rebuilds. To try a frontend fix before
  that, run your worktree's frontend on your own port (e.g. `next dev` or `next build && next start`) pointed at the
  stack's API, as U1 did against the lab.

## Testing rules (unchanged from the lab brief)
* Act as a customer: everything through the web UI; anything a customer does on their own machines (run the
  scan-node command the UI shows, run grant SQL on their database, install an SSH key) you do on local Docker
  containers you create, using exactly the text the UI gave you.
* Playwright: `const require = createRequire("/home/claude/.npm-global/lib/node_modules/"); const { chromium } =
  require("playwright");` For local URLs run node with the proxy env removed
  (`env -u HTTPS_PROXY -u https_proxy -u HTTP_PROXY -u http_proxy node x.mjs`) and launch with
  `--no-proxy-server`, ignoreHTTPSErrors. Desktop 1440x900 and phone 390x844 on key pages.
* Every screen: every button, link, tab, menu, dialog and field (valid, invalid, empty, long, special characters,
  cancel, Escape); reload and check the result persisted; no console errors; no failed requests (record 4xx/5xx with
  the endpoint). Screenshots under `$S/local/<your-name>/`.
* A failure is a product bug unless you prove it is the sandbox. For each bug: title, severity, exact UI steps,
  expected vs actual, screenshot, failing request/response, root cause in code, the fix in your worktree with a
  regression test (unit/API test, plus the Playwright step), committed with explicit pathspecs (never `git add -A`,
  no stash, no --no-verify), every message ending with:
      Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
      Claude-Session: https://claude.ai/code/session_01SDCVQSqoacevwbyX9VGquR
* Never read `.env` files, `*.pem` or key files, never print secrets.
* Final report (<= 1200 words): table of every screen/feature with PASS / FAIL / BLOCKED and evidence path; bugs
  fixed (commit, test); bugs not fixed and why; what must be re-run after the integrator's rebuild.

## UPDATE Nov 11 (overrides the ownership lines above)
* The stack `dss-staging` (READY 006ac94 for backend/frontend; scan-worker and scan-node 288fba9; dast-worker bd59f18)
  is now owned by the integrator. No agent rebuilds or restarts platform services; ask in your report instead.
  Operator helpers (credits top-up, password reset) are in $S/ui/l1/bin and $S/ui/l1/pw (see STACK.md).
* The machine has 2 CPUs and 7 GB RAM: run at most one Playwright browser and one dev server at a time, stop them
  when done, and never run a full test suite in parallel with another one of your own.
* dockerd runs as an integrator background task limited to 2 hours; if Docker stops, wait (the integrator restarts
  it) and re-run what was interrupted, marking it as an outage.
* Reports: a subagent cannot write .md report files; keep progress in $S/local/<you>/progress.txt.
