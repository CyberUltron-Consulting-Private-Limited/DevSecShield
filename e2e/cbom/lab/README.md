# CBOM lab (CB-02): reproducible targets with independent oracles

The lab the CBOM end-to-end gate scans. Every target is a local container (or a set of files), generated per run
together with its **oracle**, the values the product must report. The oracle never comes from the product: it is the
output of the tool that created the target (OpenSSL, ssh-keygen, keytool, pkcs11-tool), or, for code, the public
benchmark's own labels. Before the product scans, an **independent self-check** measures every running target with
tools that share no code with the scan node and must agree with the oracle (rules O-1..O-10 in
`round6/cbom/DEVILS-ADVOCATE.md` §3). The interface with the gate (CB-01) is `round6/cbom/INTERFACES.md`.

## Use

```bash
python3 e2e/cbom/lab/gen.py up        --run-dir $RUN --wave core        # build images if missing, generate, start
python3 e2e/cbom/lab/gen.py selfcheck --run-dir $RUN                    # O-3: exit 0 all agree, 2 lab bug
python3 e2e/cbom/lab/gen.py mutate    --run-dir $RUN --step run2        # G13/G13b change set + run-2 oracle
python3 e2e/cbom/lab/gen.py down                                        # every cb02-* container; the network if ours
python3 e2e/cbom/lab/gen.py status    --run-dir $RUN
python3 e2e/cbom/lab/gen.py hash      --run-dir $RUN [--verify SHA]     # O-5: read-only, exit 2 when edited
python3 e2e/cbom/lab/gen.py hash      --run-dir $RUN --accept-change --reason TEXT   # the only way to re-record
python3 e2e/cbom/lab/gen.py negative  --run-dir-base $DIR               # failing-first proofs (below)
```
Host needs Python >= 3.11 and Docker with Compose v2. Generation runs inside the `cb02-lab/tools` image, so the host
needs neither OpenSSL 3.5 nor Java. `up` refuses to start when less than 1.5 GB of memory would stay available.
Behind a TLS-intercepting proxy, set `CB_LAB_BUILD_CA` to the proxy's CA file: `gen.py build` passes it as a BuildKit
secret, never into an image. Images carry a label with the hash of their build inputs (`images/`, `entrypoints/`,
`tlscheck/`); `up` rebuilds when it differs, and `lab/gen.json.images` records the image ids for the gate's MANIFEST.
Package pins: both images pin every Alpine package exactly and every base by digest. Alpine keeps only the newest
build of a package per branch, so a pin breaks when the branch moves (postgresql16-client 16.15-r0 -> 16.16-r0 on
2026-11-14). `images/apk-pins.sh` lists every pin as OK or MISSING (with the version the repository has now) from
inside the pinned base; update the Dockerfile to that version and rebuild.
Locks: image builds take `$CB_LAB_LOCKS/docker-build.lock`; the lab is a singleton, so the caller holds
`cbom-lab.lock` from `up` to `down` (INTERFACES v3).

**Frozen oracle (O-5).** Only generation and `mutate` record the oracle hash. `hash` is read-only; re-recording an
edited oracle needs `--accept-change --reason`, is appended to `lab/gen.json.oracle_changes` and
`lab/oracle-changes.log`, and every self-check report carries the accepted changes. `selfcheck --expect-sha` takes the
hash from outside the lab (CB-01's MANIFEST).

**Independence (O-3).** Every key that `oracle/run<k>.json` asserts is compared with an observation that shares no
code with the generator's tool or parser: rows carry `verifies` (the run-file `oracle_id`/key they prove), and each
target reports `independent_keys`, `unverified_keys` and `verified_independently` (INTERFACES v7.1). Rows that re-run
the generator's own tool on the generator's file (identity checks), and the ML-DSA fallback through OpenSSL
`s_client` (the program the node's prober wraps), are `"independent": false` with a reason and never prove a key.
The ML-DSA certificate itself is independent once its served DER is byte-identical (sha256) to the file the generator
wrote: `s_client` then only transported bytes, and labread's DER reader parses them (INTERFACES v7.3).
`labread.py` decodes the artefacts itself (stdlib only): certificates and PKCS#8 keys from DER, JKS files from the
file format (with the store password's integrity digest), the SoftHSM2 object store, SSH key blobs (size and SHA256
fingerprint). Served certificates are read by Go's crypto/x509 (tlscheck), PKCS#12 by OpenSSL (not Java), HSM private
keys by GnuTLS `p11tool`; the benchmark labels against counts pinned from two openpyxl reads, and case by case with
openpyxl when the host has it. The self-check also rebuilds `oracle/run<k>.json` from `oracle/facts/` and fails on
any difference (so an accepted edit of the judged file cannot pass), and checks that every address of a scanned range
is a target, empty (no container holds it) or never-scan (`ranges`, INTERFACES v7 #1).

**Oracle fields for the gate (INTERFACES v7/v7.1).** `ranges` (top level): per scanned cidr, its `empty_addresses`
and `never_scan` addresses, so an asset fabricated at, or a coverage row dropped from, an empty address is judged.
`quantum_vulnerable` on every `tls_endpoint` and `ssh_endpoint` row: true when no key exchange the endpoint accepts
includes a PQ KEM (NIST IR 8547 final, 2026-10-27, doi 10.6028/NIST.IR.8547: §2.1.1-2.1.2, §4.1.1 Table 2,
§4.1.2 Table 4; IANA TLS Supported Groups and SSH Key Exchange Method Names, closed tables: an unknown name is never
read as classical), so a server that also accepts a hybrid is false. `must_report` on z02/z16: the planted CBC and
static-RSA suites the product must name among the accepted ones.
`codes_include` / `codes_exclude` / `impact_min` on every asset row a spec-named weakness applies to (INTERFACES
v7.3): `PROTO_TLS10`, `STATIC_RSA_KEX`, `CERT_EXPIRED`, `RSA_LT_2048`, `CERT_SELF_SHA1`, `SSH_NO_PQ_KEX`,
`DB_MD5_ACCEPTED`, `DB_NATIVE_PW`, `KEY_EXTRACTABLE` from the lab's own facts (a rule that holds includes the code, one
that does not excludes it), `NO_PQ_KEX` excluded wherever a PQ group is accepted (DA §4.4 KF-3), and `impact_min`
"Low" on rows with a current weakness. The spec names no code for TLS 1.1 or CBC suites, so none is asserted
(`protocol_versions` and `must_report` judge them); each code's spec citation is in the run file's `codes_source`.

## Waves (compose profiles) and targets

| Wave | Target | Address | What is planted | Oracle source | Self-check tool |
|---|---|---|---|---|---|
| core | z01 | .17:443 | nginx, TLS 1.3 only, EC P-256 lab-CA cert, groups pinned x25519+secp256r1 | openssl x509; gen config | Go crypto/tls (`tlscheck`) |
| core | z02 | .18:443 | nginx, TLS 1.0-1.2, RSA-1024 SHA-1 self-signed, 4 CBC suites incl. static RSA, @SECLEVEL=0 | openssl x509; explicit IANA suite list | tlscheck, nmap ssl-enum-ciphers |
| core | z04 | .19:443 | nginx, RSA-2048 lab-CA cert expired now-400 d | openssl x509 | tlscheck, nmap |
| core | z05 | .20:443 | s_server, X25519MLKEM768 only | gen config | tlscheck (Go 1.25 offers ML-KEM hybrids) |
| core | z05b | .21:443 | s_server, ML-DSA-65 self-signed cert, groups X25519MLKEM768+x25519 | openssl x509 | tlscheck must fail (no ML-DSA in Go); openssl s_client of the tools image (fallback, recorded, not independent) for versions and groups; the certificate by labread DER when the served bytes equal the generated file (independent) |
| core | z09 | .22:443 | nginx `ssl_reject_handshake` default + vhost `sni.lab` | openssl x509; gen config | tlscheck with and without SNI, nmap with `tls.servername` |
| core | z16 | .26:443 | nginx, TLS 1.0 only, RSA-2048 lab-CA cert | openssl x509 | tlscheck, nmap |
| core | sshd-legacy | .23:22 | OpenSSH 10, classic KEX only, hmac-sha1, RSA-1024 + Ed25519 host keys | ssh-keygen | nmap ssh2-enum-algos, ssh-keyscan blobs decoded by labread (type, size, SHA256), ssh-audit |
| core | sshd-pq | .24:22 | OpenSSH 10, `mlkem768x25519-sha256` only, Ed25519 | ssh-keygen | same |
| psp | sshd-psp | .28:22 | OpenSSH 10 with the default PerSourcePenalties; only the self-check (.11) is exempt (all other lab sshd exempt the lab network) | ssh-keygen; sshd -T | same, plus `sshd -T`, a burst from the throwaway `cb02-burst` (.12) that must be penalised (banners, sshd's own "Not allowed at this time" refusals, EOFs, connect errors and other payloads counted apart: only refusals and EOFs with a penalty for .12 in the sshd log count; a refused or timed-out connect never does), and a banner from .11 right after |
| core | host | .40:22 | sshd as `zs-cbom` with a ForceCommand logger; /srv/cbom-lab: RSA-1024 key, expired cert, SHA-1 cert, PKCS#12, JKS (expired RSA-1024 trusted entry) | openssl, keytool -list -v | SSH login (known_hosts = oracle keys) + sha256sum/stat; files and served certificates by labread DER; keystores by the labread JKS reader and `openssl pkcs12 -nokeys` (OpenSSL, not Java) + labread DER; the logger must record the login |
| core | pg-tls | .41:5432 | PostgreSQL 16, TLS >= 1.2 with lab-CA cert, `md5` HBA line, pgcrypto, log_connections | openssl x509; pg_hba written by gen | tlscheck pg (SSLRequest) per version, psql (`SHOW ssl`, pg_hba_file_rules, pg_authid), server log |
| core | canary / control | .33 / .34:443 | socat listeners (generated `listen.sh`/`accept.sh`): product peers in `lab/listeners/<id>.jsonl`, the lab's own (.11, .12, loopback) in `<id>.lab.jsonl`, both created empty at `up`; canary named `cbom-e2e-canary` (never-scan); control (and idn-punycode) expect one `coverage` row, status `not_tls`, scope the port, and no TLS asset (CB-12 #110) | - | health from /proc/net/tcp (never connects to the canary); control logs the self-check's accept in its lab log, and Go crypto/tls (tlscheck matrix) gets TCP but no handshake on any version; no lab peer in a product log |
| core | idn-fass / idn-punycode | .44 / .45:443 | listeners named `fass.lab` / `xn--fa-hia.lab` (IDNA 2003 vs 2008 form of `faß.lab`) | - | name resolution, accept log |
| db | pg-notls | .46:5432 | PostgreSQL 16, ssl=off | gen config | tlscheck pg must get `N`; psql |
| db | mysql-tls / mysql-notls | .47 / .48:3306 | MySQL 8.4, TLS 1.2/1.3 lab-CA cert and one `mysql_native_password` user / TLS off | openssl x509; gen config | tlscheck mysql (CLIENT_SSL + SSLRequest) per version; the server's own `mysql` client |
| hsm | softhsm | files | SoftHSM2: token A (RSA-2048, EC P-256 non-extractable, AES-128 extractable), token B (decoy, own PIN) | pkcs11-tool --list-objects | p11tool (GnuTLS) on a copy and labread's object-store reader vs the catalogue and the oracle, both ways (every non-public object on a token is a managed_key row); B must refuse A's PIN |
| code | code-cryptoapi-bench | files | CryptoAPI-Bench @759622f tree + reproducible zip | the benchmark's `CryptoAPI-Bench_details.xlsx` | counts pinned from two openpyxl reads (171 cases, 136/35; 170 judgeable, 135/35; 18 date-typed line cells flagged `lines_unreliable`); openpyxl case by case; archive == tree |
| run2 | z08, control-tls | .25, .34 | started by `mutate`; z02 loses TLS 1.0, z04 re-issued, the RSA-1024 key file is removed | as above | as above |

Every negative observation is paired with a positive control seen by the same tool in the same capture (O-8):
TLS 1.0 refused on z01 counts only because z16 shows TLS 1.0 to the same client, the absent hybrid group only because
z05 shows it, "no PQ KEX" only because sshd-pq offers it, `ssl=off` only because pg-tls answers `S`, and so on.

## Failing-first proofs (`gen.py negative`)

| Broken lab | Caught by |
|---|---|
| z02 also asks for `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (Alpine's OpenSSL 3.5 does not build 3DES) | nmap's suite list lacks it: `cipher_suites[TLSv1.2]` disagrees |
| z01 without pinned groups (OpenSSL 3.5's default offers X25519MLKEM768) | tlscheck sees the hybrid group: `groups` disagrees |
| E2: z02's server also accepts X25519 (`prime256v1:X25519`), oracle keeps `[secp256r1]` | one TLS 1.2 handshake per group sees X25519: `groups` disagrees (equality) |
| an oracle file edited after generation | the O-5 hash: self-check exits 2 "oracle changed" |
| C: the generator's pkcs11-tool parser inverts `extractable` | p11tool: `extractable` disagrees per managed key |
| D1: the generator's pkcs11-tool parser doubles `bits` | p11tool (private keys) and the SoftHSM object store (secret keys): `key_size` disagrees |
| D2: the generator's keytool parser reports `key_bits` + 1 | labread's JKS reader and OpenSSL's PKCS#12 read: `entries` disagrees |
| hsm-parser-drop: the generator's pkcs11-tool parser drops `aes-128-wrap` (the oracle omits it) | p11tool lists every object block: the token's non-public objects differ from the run file's managed keys |
| B: z02's facts edited to x25519, accepted with `--accept-change --reason` | nmap's kex_info cross-check and the rebuild of `run1.json` from the facts |
| B (original form): `oracle/run1.json` edited to X25519 and accepted | z02 `groups` (compared on the run file itself) and the rebuild check |

## Files

`gen.py` host CLI and compose generator; `labspec.py` the catalogue (single source of addresses, profiles and
planted values; `compose.yml` is generated from it, a unit test keeps them equal); `labgen.py` the generator (runs in
the tools image); `oraclefmt.py` the CB-01 oracle/lab/canary formats, the endpoint quantum verdict, `ranges`, the
run-2 `drift` and the O-5 hash; `labcheck.py` the self-check; `labread.py` its independent readers; `labmutate.py` the run-2 change set; `labnegative.py` the failing-first proofs; `tlscheck/` the Go
observer; `images/` the two lab images; `entrypoints/` the target container scripts; `tests/` unit tests (run in
CI through `backend/tests/test_cbom_e2e_lab.py`).

## Deferred parts
`lab/lab.json` and `oracle/run<k>.json` list them under `deferred` (part, address, gate rows, reason, issue #93, draft
at `round6/cbom/cb-02/issue-deferred.md`), so the gate reports those rows NOT-RUN from the marking: the `.42` IdP (G7),
the `.43` webhook receiver (G13, W-INT), an Ubuntu `.40` with the product's Tier-2 sudoers (G4, G15) and the kind
wave (W-HOST). Realism gap until the Ubuntu host exists: sshd, its host keys and the planted files belong to the
login user, so a Tier-1 login reads more than on a real host and can write the file copy of the command log. The
authoritative command record is the container log (`docker logs cb02-host`, lines `cb02-cmd {...}`), exported to
`lab/forcecommand.authoritative.jsonl` by `selfcheck`, `status` and `down --run-dir`; the self-check fails when the
file copy lacks an entry of the container log.

## Findings the lab surfaced (for the product tracks; also in round6/cbom/FINDINGS-LOG.md)
* **OpenSSH >= 9.8 `PerSourcePenalties`** (defaults `noauth:1 min:15`): about 15 connections from one address that
  never authenticate, within ~16 s, get that address dropped (`activating ipv4 penalty of 16 seconds`, then
  `drop connection ... penalty: connections without attempting authentication`); the node's own SSH probe
  (`network.py::_ssh`) makes exactly such connections. Measured by the PR #79 reviewer with the node's code: 7 passes
  (14 connections) fine, 8 passes dropped the following paramiko login; sshd-legacy refused the probe itself from pass
  11. Gate rows that flake when it is hit: G4, G9/G10, G11 (host, sshd-legacy, sshd-pq), G13, G15, and G5 on .23/.24.
  So every lab sshd exempts the lab network (`PerSourcePenaltyExemptList 10.231.0.0/24`), and the `psp` wave's
  `sshd-psp` keeps the default to show the product's behaviour against it. CB-05: no retry loops against one sshd;
  classify `drop connection ... penalty` in G16.
