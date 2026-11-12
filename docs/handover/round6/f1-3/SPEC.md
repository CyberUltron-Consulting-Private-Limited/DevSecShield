# F1.3 spec: agentless transports through the customer's tools, plus `zs-collect`

Binding design: `$R6/f1/CONTRACT.md` (sections 2-7, 9). Flag `CBOM_FLEET_TRANSPORTS`. Migration prefix `r6f13trn`.
Base: `dev` 3399452. Two PRs (contract order F1.3-a, then F1.3-b + F1.3-c):

| PR | Branch | Contents | Depends on |
|---|---|---|---|
| A | `feat/f1-zs-collect` | `zs-collect` (LocalSession, envelope, read-only guarantees), the `collect_target` split, JSON schema, release signing, parity harness | none (scan_node + bench + one backend test) |
| B | `feat/f1-transports` | `Transport` protocol (node canonical + byte-identical backend copy), AWX and Salt adapters on the node, SSM adapter in the cloud worker, `cbomtransport` + `cbomzscollectrelease` tables, routes, fleet kinds, claim plugin, artifacts, UI | F1.1 (`secret_refs`, `capabilities`), F1.2-a0 (aggregator `cbom_fleet.py`, `sections.tsx`); seams are optional imports until they merge |

## Explored (evidence)
* SSH path: `linux_ssh.collect` -> `_credentials` -> `_targets` (never-scan) -> per target `collect_target(ctx, target, config, creds)`
  (`linux_ssh.py:370-516`): `open_session` (TCP + paramiko + host key + auth) then ~25 Tier 1 commands (`commands.tier1_line`)
  and up to 7 Tier 2 checks (`commands.sudo_line(argv)` per variant), per-file commands for the Tier 2 `find` list.
  `Session.run(command, timeout, binary) -> (status|None, stdout, stderr, timed_out)`, 4 MB stdout cap, 64 KB stderr cap.
* `python -m zs_scan_node.collect` prints `{"status","error","result","assets","elapsed_s"}` (`collect.py:60`); assets come from
  `JobContext.emit` (scrubbed, `_clean`, 16 KB facts cap), `result` from `JobContext.result()`.
* Backend `AssetIn` (`schemas.py:376`), `jobs._asset_key` (`jobs.py:804`), `jobs.TARGET_STATUSES` (`jobs.py:50`).
* scan_node has no `jsonschema`; backend has jsonschema 4.26 (schema validated there). No new runtime dependency.
* Tools on the build machine: `unshare -rn` works (user + net namespace), strace 6.8, docker 29.9, OpenSSL 3.0.13.

## PR A design
* `linux_ssh.collect_target` = `open_session` + new `collect_on_session(ctx, sess, label, config, t_deadline=None)` (the whole
  former body, unchanged). One additive line: pids in `getattr(sess, "exclude_pids", ())` are not grouped into
  `process_library` (the collector must not report itself; the SSH path has no such pids).
* `zs_scan_node/zscollect.py` (entry `zs-collect`, also `python -m zs_scan_node.zscollect`):
  `zs-collect --nonce <16-128 [A-Za-z0-9_-]> [--tier 1|2] [--label X] [--run-as zs-cbom] [--tmp-dir D] [--timeout-s N]
  [--output json|chunks] [--chunk-bytes N<=524288] [--version]`.
  1. Root: chown `--tmp-dir` to the run-as user, pre-import every module the collection needs, `setgroups([])`, `setgid`,
     `setuid` to `--run-as` (refuse if the user is missing or the drop does not stick). Not root: run as is.
  2. `LocalSession.run` executes `["/bin/sh", "-c", line]` with `stdin=DEVNULL`, fixed env (`PATH`, `LC_ALL=C`, `HOME=tmp`),
     own process group (killed on timeout), the same 4 MB / 64 KB caps and the same tuple. Every `line` must pass
     `allowed_line()` (exact Tier 1 lines, Tier 2 `sudo_line` variants, per-file templates with one `shlex.quote`d absolute
     path without control characters); anything else raises `NotAllowed` and is never executed.
  3. `host_key` = the host's own key in paramiko's preference order (ed25519, ecdsa, rsa) through the allowed
     `ssh-keygen -l -f` line, shaped exactly like `open_session`'s `{key_type, bits, fingerprint}`.
  4. `JobContext(poster=None, never_scan=empty, state_dir=tmp)`; the node checks never-scan before dispatch.
  5. Output: the `collect.py` document plus the zs-collect/1 envelope (`format, collector_version, run_nonce, target_label,
     tier, host{hostname, os_id, machine_id_sha256}, started_at, finished_at`). `--output chunks`: gzip + base64 of the JSON,
     split into lines `ZSC1 <nonce> <i>/<n> <sha256 of gzip> <data>`, each <= `--chunk-bytes` (default 393216 so an AWX
     event stays < 512 KB). `reassemble()` checks count, order and checksum.
  6. `validate_document(doc, nonce, version)` (pure Python, used by the node and cloud worker in PR B).
  7. Exit codes: 0 success, 1 collection failure (document still printed), 2 usage/refusal.
* `zs_scan_node/schemas/zs-collect-1.schema.json` (draft 2020-12), packaged with the node.
* `scan_node/zs_collect/`: `Dockerfile.build` (pinned base, pinned PyInstaller with hash), `build.sh` (one-file binary per
  arch -> `zs-collect-<ver>-linux-<arch>`), `release.py` (`manifest`, `sign`, `verify`, `wrapper`), `zs-release-ed25519.pub`
  (PEM SPKI). Manifest `{format, version, git_commit, files[{name, arch, sha256, size}]}`, `manifest.json.sig` = base64 raw
  Ed25519. `release.py wrapper` writes the POSIX sh wrapper the transports embed: `mktemp -d` (0700) as `TMPDIR`, `trap rm -rf`,
  `sha256sum -c` before exec, `openssl pkeyutl -verify -rawin` on the manifest when OpenSSL >= 3.
* Release key: a development key is generated for this round (private half only in `$R6/secrets/`, 0600); the owner must
  replace it with an offline key before GA (stated in the PR). CI and tests use ephemeral keys.
* `bench/f1_transports/`: `normalize.py` (contract section 4 rules + pids/ports-free `process_library`, documented),
  `parity.py` (N sshd containers: SSH path vs zs-collect binary, empty normalised diff), `lab/Dockerfile.target`.

## PR B design (summary; details in the PR)
* `scan_node/zs_scan_node/transports/base.py` = contract section 3 verbatim; `backend/utilities/cbom_sources/transports/base.py`
  byte-identical; backend test compares bytes.
* Node adapters `transports/{ssh,awx,salt}.py`, glue `collectors/fleet.py` (never-scan before dispatch, replay through
  `ctx.emit` with `target = label`, status mapping to `TARGET_STATUSES`). AWX: launch job template with `limit` + extra vars
  (nonce, tier, sha256), poll, read `runner_item_on_ok` events, reassemble chunks per host. Salt: `/login` eauth, `local_async`
  / `ssh` client `cmd.run` or `state.apply`, jobs lookup, minion-not-answering -> `unreachable`.
* Cloud worker `transports/ssm.py`: assume the run-command role (team external id), `SendCommand` (explicit instance ids from
  handles, `devsecshield-*` document, S3 output), `ListCommandInvocations`, read S3 output (`GetCommandInvocation` truncates at
  24,000 chars), validate, emit.
* Backend: `transports/{models,flags,registry,claim,artifacts}.py`, `kinds_fleet.py` (`awx_hosts`, `salt_hosts`, `ssm_hosts`),
  `routers/cbom_transports.py`, migration `r6f13trn001`, cleanup order, cloud worker branch.
* UI: `TransportsSection.tsx`, `FleetHostsSourceForm.tsx`, `utils/api/cbom_transports.ts`, kind union.

## Acceptance criteria -> proof
| AC (PARALLEL-PLAN F1.3) | Proof |
|---|---|
| zs-collect signed | `test_zs_collect_release.py` (manifest/sign/verify, tampered binary and manifest refused, OpenSSL interop) + release run log |
| read-only: only allow-listed commands | `test_zs_collect.py::test_every_command_is_on_the_allow_list`, `::test_unlisted_command_is_never_executed` |
| no network listener / no outbound connection | `::test_output_identical_without_network` (`unshare -rn`), `::test_no_inet_socket_syscalls` (strace) |
| no writes outside its temp dir | `::test_writes_only_inside_tmp_dir` (strace openat/mkdir/rename/unlink), docker `--read-only --tmpfs /tmp` run (bench log) |
| emits the scan-node inventory format | backend `test_zs_collect_schema.py` (schema + every asset is `AssetIn`) |
| output identical to the SSH path on the same host | `bench/f1_transports/parity.py` on 20 sshd containers: empty normalised diff; unit `::test_parity_same_session_outputs` |
| AWX transport, 200 targets | PR B: fake-AWX tests + 200-target run (real AWX if it fits, else API-compatible fake) |
| Salt transport, 200 targets | PR B: salt-api fake tests + salt-ssh roster 200 + 20 real minions |
| SSM transport | PR B: Stubber tests + live run on 2 tagged t3.micro |
| typed credentials, credits per run as today | PR B: kinds use `RATES_C["server"]`; transport secrets write-only |

## Risks
* PyInstaller binary needs build glibc <= target glibc: built on Debian bullseye (glibc 2.31). Older hosts (RHEL 7, AL2)
  need a manylinux2014 build: follow-up issue.
* Privilege drop inside a PyInstaller process: modules are imported before the drop; `_MEIPASS` is under the tmp dir that is
  chowned to the run-as user.
* T1 edits `open_session`; this PR only edits `collect_target`'s body and adds a function, so the hunks do not overlap.
