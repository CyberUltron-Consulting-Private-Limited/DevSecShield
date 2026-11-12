# T1 spec: never-scan applies to the whole name (issue #17)

Branch `fix/never-scan-dual-stack` from `origin/dev` 3399452.

## Current behaviour (evidence)
* `scan_node/zs_scan_node/netutil.py::resolve_checked` resolves a name, drops never-scan addresses and returns the rest
  (`allowed = [ip for ip in addresses if not never.blocks_ip(ip)]`); it refuses the name only when nothing is left, or
  with `every=True` (one caller: `windows_winrm.check_name`).
* `netutil.expand_targets` (hostname lines of Linux SSH, appliance, WinRM sources) does the same per address and picks
  `allowed[0]`. So an SSH source `db.internal` -> 10.0.0.5 (excluded) + fd00::5 is collected over fd00::5.
* Linux SSH / appliance re-check only `target.ip` at connect time, so a never-scan entry added mid-job for another
  address of the name is missed.
* CI proof: PR #16 scan-node job (issue #17): `localhost` -> 127.0.0.1 + ::1 with never=["127.0.0.1"] -> the node
  connected to ::1 and reported `unreachable`, not `skipped_never_scan`. Test widened in 903d049.

## Every place that applies never-scan (audit)
scan_node (enforcement):
| Place | What it gates | Today | After |
|---|---|---|---|
| `netutil.resolve_checked` | names: registry, token service, blob/any redirect (container_images `_client`), DB driver lookups and SQL Server/Oracle redirects (`drivergate._addresses`), K8s API (`kubernetes.check_scope`), KMIP (`kmip._target`), CA / AD CS (`ca._target`, `collect_adcs`), database host (`database._one`), WinRM re-check (`every=True`) | per address | whole name |
| `netutil.expand_targets` hostname lines | Linux SSH, appliance (SSH + REST), WinRM targets | per address | whole name (via `resolve_checked`) |
| `expand_targets` IP / CIDR / `a-b` lines | same sources | per address | unchanged |
| `linux_ssh.open_session` pre-check | SSH + appliance SSH | `target.ip` only | every address the name resolved to |
| `netutil.checked_ip` / `connect` / `udp_connect` / `http_client` | the exact address at connect time | per address | unchanged |
| `network.py` `_do_address`, `test_range` | range sweeps (IP/CIDR only; hostname lines are ignored) | per address | unchanged |
| `network.py::_sni_for` | SNI names matched against the address being scanned, never connected to | no never-scan | unchanged (documented) |
| `drivergate` pinned names | name the collector already checked -> its checked address | per address | unchanged (pin came from `resolve_checked`) |

backend (no enforcement, no DNS): `targets.in_scope` / `count_in_scope` / `sample_targets` subtract intervals and
exact hostnames for estimates, credits and connection-test samples; `jobs._scope_for` sends the union list to the
node. The backend cannot resolve customer-internal names, so it does not and cannot apply an address rule to names.
No backend change; `safe_fetch` is SSRF protection (already "one refused address refuses the host"), not never-scan.

## Rule (goes into the PR and the README)
1. A **name** is skipped as `skipped_never_scan` when the name is listed, or when ANY address it resolves to is
   listed (an IPv4-mapped IPv6 address is compared as IPv4). Otherwise the node connects only to one of the
   addresses it checked (IPv4 first). Same for every name a target sends the node to (token service, redirect,
   database redirect).
2. An **IP literal** is checked as itself.
3. **CIDR and `a-b` ranges** are per address: each listed address inside the range is skipped (one outcome each),
   the others are scanned. A range has no names, so a dual-stack host whose other address lies inside a scanned
   range is scanned on that address unless that address is listed too.
4. The list can change while a job runs; a name's re-check before connecting covers every address it resolved to.
5. A name that resolves to no address is `unreachable`, not `skipped_never_scan`.

## Changes
* `netutil.Blocked(what, address=None)`: message says which address matched.
* `resolve_checked(host, never, timeout)`: refuse when any address is blocked; `every` removed (now the only rule).
* `Target.addresses`: every address a name resolved to; `netutil.blocked_address(target, never)` re-check.
* `expand_targets` hostname lines go through `resolve_checked`.
* `linux_ssh.open_session` re-checks every address; `windows_winrm.check_name` drops `every=True`.
* Collectors that build their own skip message (container_images, kmip, ca, database) use the Blocked reason.
* README network-gate paragraph states the rule.

## Acceptance criteria -> proof
| AC | Proof |
|---|---|
| Any listed address -> whole name skipped, registry + redirect | `test_wp8b_agent_registry.py::test_never_scan_applies_to_the_registry_and_to_redirect_targets` (restored, forced dual stack too); new `tests/test_never_scan_names.py` registry/redirect cases with a fake client |
| Test restored to 127.0.0.1 only; unit test excluded IPv4 + non-excluded IPv6 | diff of the test; `test_never_scan_names.py::test_name_with_excluded_ipv4_and_allowed_ipv6_is_skipped` |
| Excluded IPv6 only -> skipped | `test_name_with_excluded_ipv6_only_is_skipped` |
| No excluded address -> scanned | `test_name_without_excluded_address_is_scanned` |
| CIDR per address unchanged | `test_ranges_keep_per_address_skipping` (expand_targets) + network sweep test |
| Live update covers all addresses | `test_ssh_recheck_covers_every_address_of_a_name` |

## Risks
* Behaviour change customers can see: a round-robin / dual-stack name with one listed address is now skipped whole
  (intended: conservative reading of "never scan"); the outcome text names the address that matched.
* Other tracks calling `resolve_checked(..., every=True)` would get a TypeError; none on origin today (checked).
