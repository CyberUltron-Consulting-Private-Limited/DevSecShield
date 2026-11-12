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
python3 e2e/cbom/lab/gen.py hash      --run-dir $RUN [--verify SHA]     # O-5 frozen oracle
python3 e2e/cbom/lab/gen.py negative  --run-dir-base $DIR               # failing-first proofs (below)
```
Host needs Python >= 3.11 and Docker with Compose v2. Generation runs inside the `cb02-lab/tools` image, so the host
needs neither OpenSSL 3.5 nor Java. `up` refuses to start when less than 1.5 GB of memory would stay available.
Behind a TLS-intercepting proxy, `gen.py build` passes the proxy CA as a BuildKit secret (`CB_LAB_BUILD_CA`); it is
never written into an image. Locks: image builds take `$CB_LAB_LOCKS/docker-build.lock` when that directory exists.

## Waves (compose profiles) and targets

| Wave | Target | Address | What is planted | Oracle source | Self-check tool |
|---|---|---|---|---|---|
| core | z01 | .17:443 | nginx, TLS 1.3 only, EC P-256 lab-CA cert, groups pinned x25519+secp256r1 | openssl x509; gen config | Go crypto/tls (`tlscheck`) |
| core | z02 | .18:443 | nginx, TLS 1.0-1.2, RSA-1024 SHA-1 self-signed, 4 CBC suites incl. static RSA, @SECLEVEL=0 | openssl x509; explicit IANA suite list | tlscheck, nmap ssl-enum-ciphers |
| core | z04 | .19:443 | nginx, RSA-2048 lab-CA cert expired now-400 d | openssl x509 | tlscheck, nmap |
| core | z05 | .20:443 | s_server, X25519MLKEM768 only | gen config | tlscheck (Go 1.25 offers ML-KEM hybrids) |
| core | z05b | .21:443 | s_server, ML-DSA-65 self-signed cert, groups X25519MLKEM768+x25519 | openssl x509 | tlscheck must fail (no ML-DSA in Go); openssl s_client of the tools image (fallback, recorded) |
| core | z09 | .22:443 | nginx `ssl_reject_handshake` default + vhost `sni.lab` | openssl x509; gen config | tlscheck with and without SNI, nmap with `tls.servername` |
| core | z16 | .26:443 | nginx, TLS 1.0 only, RSA-2048 lab-CA cert | openssl x509 | tlscheck, nmap |
| core | sshd-legacy | .23:22 | OpenSSH 10, classic KEX only, hmac-sha1, RSA-1024 + Ed25519 host keys | ssh-keygen | nmap ssh2-enum-algos, ssh-keyscan + ssh-keygen -l, ssh-audit |
| core | sshd-pq | .24:22 | OpenSSH 10, `mlkem768x25519-sha256` only, Ed25519 | ssh-keygen | same |
| core | host | .40:22 | sshd as `zs-cbom` with a ForceCommand logger; /srv/cbom-lab: RSA-1024 key, expired cert, SHA-1 cert, PKCS#12, JKS (expired RSA-1024 trusted entry) | openssl, keytool -list -v | SSH login (known_hosts = oracle keys) + sha256sum/stat, keytool, openssl x509; the logger must record the login |
| core | pg-tls | .41:5432 | PostgreSQL 16, TLS >= 1.2 with lab-CA cert, `md5` HBA line, pgcrypto, log_connections | openssl x509; pg_hba written by gen | tlscheck pg (SSLRequest) per version, psql (`SHOW ssl`, pg_hba_file_rules, pg_authid), server log |
| core | canary / control | .33 / .34:443 | socat listeners; canary named `cbom-e2e-canary` (never-scan) | - | health from /proc/net/tcp (never connects to the canary); control logs the self-check's accept |
| core | idn-fass / idn-punycode | .44 / .45:443 | listeners named `fass.lab` / `xn--fa-hia.lab` (IDNA 2003 vs 2008 form of `faß.lab`) | - | name resolution, accept log |
| db | pg-notls | .46:5432 | PostgreSQL 16, ssl=off | gen config | tlscheck pg must get `N`; psql |
| db | mysql-tls / mysql-notls | .47 / .48:3306 | MySQL 8.4, TLS 1.2/1.3 lab-CA cert and one `mysql_native_password` user / TLS off | openssl x509; gen config | tlscheck mysql (CLIENT_SSL + SSLRequest) per version; the server's own `mysql` client |
| hsm | softhsm | files | SoftHSM2: token A (RSA-2048, EC P-256 non-extractable, AES-128 extractable), token B (decoy, own PIN) | pkcs11-tool --list-objects | pkcs11-tool on a copy; B must refuse A's PIN |
| code | code-cryptoapi-bench | files | CryptoAPI-Bench @759622f tree + reproducible zip | the benchmark's `CryptoAPI-Bench_details.xlsx` | re-read labels, archive == tree, per-file sha256 |
| run2 | z08, control-tls | .25, .34 | started by `mutate`; z02 loses TLS 1.0, z04 re-issued, the RSA-1024 key file is removed | as above | as above |

Every negative observation is paired with a positive control seen by the same tool in the same capture (O-8):
TLS 1.0 refused on z01 counts only because z16 shows TLS 1.0 to the same client, the absent hybrid group only because
z05 shows it, "no PQ KEX" only because sshd-pq offers it, `ssl=off` only because pg-tls answers `S`, and so on.

## Failing-first proofs (`gen.py negative`)

| Broken lab | Caught by |
|---|---|
| z02 also asks for `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (Alpine's OpenSSL 3.5 does not build 3DES) | nmap's suite list lacks it: `cipher_suites[TLSv1.2]` disagrees |
| z01 without pinned groups (OpenSSL 3.5's default offers X25519MLKEM768) | tlscheck sees the hybrid group: `groups` disagrees |
| an oracle file edited after generation | the O-5 hash: self-check exits 2 "oracle changed" |

## Files

`gen.py` host CLI and compose generator; `labspec.py` the catalogue (single source of addresses, profiles and
planted values; `compose.yml` is generated from it, a unit test keeps them equal); `labgen.py` the generator (runs in
the tools image); `oraclefmt.py` the CB-01 oracle/lab/canary formats and the O-5 hash; `labcheck.py` the
self-check; `labmutate.py` the run-2 change set; `labnegative.py` the failing-first proofs; `tlscheck/` the Go
observer; `images/` the two lab images; `entrypoints/` the target container scripts; `tests/` unit tests (run in
CI through `backend/tests/test_cbom_e2e_lab.py`).

## Findings the lab surfaced (for the product tracks)
* OpenSSH >= 9.8 `PerSourcePenalties`: probes that never authenticate (the network collector's SSH banner/KEX read)
  get the same source's later login dropped ("penalty: connections without attempting authentication"). The lab
  exempts only the self-check's address, so the product meets the default behaviour.
