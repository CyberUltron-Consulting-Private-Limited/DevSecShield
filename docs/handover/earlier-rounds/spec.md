### Code resilience

| ID | Test | Pass when |
| --- | --- | --- |
| RES-03 | Network faults to self-hosted Git | Retries; no corrupt partial scans |

### Scan node

| ID | Test | Pass when |
| --- | --- | --- |
| NODE-01 | Registration token rules | Single use; 24 h expiry; node identity bound to its key |
| NODE-02 | Outbound-only, works through an authenticating proxy | No listening ports; jobs flow through the proxy |
| NODE-03 | TLS-inspecting proxy | Refuses unknown CA; works when the customer CA is configured |
| NODE-04 | Connectivity loss mid-job | Buffers locally; resumes; no duplicate findings |
| NODE-05 | Cloned VM | Duplicate identity detected; clone refused |
| NODE-06 | Signed updates | Update rejected |
| NODE-07 | Clock skew | Clear error, no silent failure |

### Scan node security

| ID | Test | Pass when |
| --- | --- | --- |
| NODE-SEC-01 | Image hardening | Zero critical findings |
| NODE-SEC-02 | Credentials at rest on the node | Vault-fetched secrets never on disk; stored ones encrypted |
| NODE-SEC-03 | Sealed credentials unreadable by the control plane | Ciphertext only; no key to decrypt it |
| NODE-SEC-04 | Credential bound to its targets | Node refuses; rogue log shows no password or key attempt |
| NODE-SEC-05 | Signed command set | Node refuses to run it |
| NODE-SEC-06 | Egress payload copies and command transcripts | Complete and identical |

### Linux

| ID | Test | Pass when |
| --- | --- | --- |
| HST-01 | Tier 1 accuracy: packages, configs, keys, certificates, keystores | Gates met against host ground truth |
| HST-02 | Tier 2 accuracy: process-to-library, deleted libraries, sshd -T, LUKS | Gates met; deleted libcrypto reported |
| HST-03 | Old OpenSSL inside a container | Reported with host, container and image |
| HST-04 | Static binaries (Go, Rust) | Crypto use reported via binary inspection |
| HST-05 | Crypto policy, FIPS, openssl.cnf and java.security overrides | All overrides reported |
| HST-06 | Only the public half of private keys leaves the host | Zero canary hits |

### Linux security

| ID | Test | Pass when |
| --- | --- | --- |
| HST-SEC-01 | Commands executed match the published allowlist | No command outside the allowlist |
| HST-SEC-02 | Sudoers bypass attempts | Every attempt denied |
| HST-SEC-03 | No writes on targets | Zero write events; no changed files outside log paths |
| HST-SEC-04 | Absolute paths only (PATH hijack) | No canary callback; no junk parsed |

### Linux resilience

| ID | Test | Pass when |
| --- | --- | --- |
| HST-RES-01 | FIFO named server.key | No hang; file skipped and reported |
| HST-RES-02 | 2 GB file, symlink loop, unreadable directory | Bounded time; each skipped with reason |
| HST-RES-03 | Hostile file names on host | No injection; names escaped in UI |
| HST-RES-04 | Legacy-only sshd | Connects with explicit legacy allowance or fails clearly; weak algorithms reported either way |
| HST-RES-05 | Host key change | Scan refused; alert raised |
| HST-RES-06 | Reboot or SSH drop mid-collection | Partial result marked partial; retry succeeds |
| HST-RES-07 | Hung NFS mount | Search skips network mounts; no hang |

### Windows

| ID | Test | Pass when |
| --- | --- | --- |
| WIN-01 | SCHANNEL, TLS, cipher and .NET strong-crypto settings | TLS 1.0, 3DES and SchUseStrongCrypto=0 reported |
| WIN-02 | Certificate stores with provider, key length, exportable flag | RSA-1024 SHA-1 exportable cert in legacy CSP reported |
| WIN-03 | IIS bindings and RDP security | Bindings mapped to certificates |
| WIN-04 | BitLocker and process crypto DLLs | BitLocker off reported; DLL list per process |
| WIN-05 | JEA endpoint limits | Denied |

### Active Directory

| ID | Test | Pass when |
| --- | --- | --- |
| AD-01 | RC4 and DES Kerberos encryption types | Both accounts reported |
| AD-02 | AD CS hash algorithm and templates | SHA-1 CA reported |

### Kubernetes

| ID | Test | Pass when |
| --- | --- | --- |
| K8S-01 | Tier 1 accuracy without Secret access | cert-manager certificates, ingress TLS refs and images reported |
| K8S-02 | Tier 2 accuracy with Secret access | TLS secret, PEM in Opaque secret and ConfigMap, AES_KEY env reported |
| K8S-03 | RBAC least privilege | Tier 1 cannot read secrets; neither can write or exec |
| K8S-04 | Secret values never leave the node | Zero canary hits |
| K8S-05 | Large cluster | Completes; API throttling respected |

### Databases

| ID | Test | Pass when |
| --- | --- | --- |
| DB-01 | PostgreSQL settings and md5 roles | Unencrypted storage, force_ssl off and md5 roles reported |
| DB-02 | MySQL settings and native-password users | mysql_native_password user reported; TLS enforcement recognised |
| DB-03 | Read-only enforcement | Only SELECT/SHOW statements; login has no write grants |

### Cloud

| ID | Test | Pass when |
| --- | --- | --- |
| CLD-01 | KMS inventory | Every key with correct spec, rotation, origin |
| CLD-02 | ACM and IAM certificates | All reported; expiring cert flagged |
| CLD-03 | Load balancer TLS policies | Policies and their protocol sets reported |
| CLD-04 | Storage encryption | Each resource's encryption state correct |
| CLD-05 | Secrets and parameters inventory | No-rotation secret and plain-text PEM parameter flagged |
| CLD-06 | EC2 key pair types | Both reported with type |
| CLD-07 | Organisation-wide onboarding | All member accounts discovered |

### Cloud safety

| ID | Test | Pass when |
| --- | --- | --- |
| CLD-SAF-01 | CloudTrail proof of read-only | Zero data-plane or write events by the reader role |
| CLD-SAF-02 | External ID enforced | Both fail |
| CLD-SAF-03 | Secrets returned by read APIs | Each reported as a finding; zero canary hits in ZeroShield stores |

### Certificates

| ID | Test | Pass when |
| --- | --- | --- |
| CRT-01 | Fingerprint correlation across sources | One asset with several occurrences |
| CRT-02 | Managed, unmanaged and orphaned classification | Classification matches the definitions in this doc |
| CRT-03 | CT log discovery | Certificates issued for the domain found |
| CRT-04 | Expiry tracking | Status changes; alert raised |

### Identity

| ID | Test | Pass when |
| --- | --- | --- |
| IDP-01 | OIDC JWKS and SAML metadata | Key types, sizes and rotation reported |

### Network

| ID | Test | Pass when |
| --- | --- | --- |
| NET-01 | Protocols, cipher suites, groups, signature algorithms vs reference tools | At least 98% field agreement; every disagreement adjudicated |
| NET-02 | Hybrid post-quantum key exchange | X25519MLKEM768 reported where offered |
| NET-03 | SNI handling | Both certificates reported |
| NET-04 | mTLS endpoint | Server parameters reported; client-auth flagged |
| NET-05 | STARTTLS, PostgreSQL TLS, SSH key exchange | Matches reference |
| NET-06 | Downgrade exposure | FALLBACK_SCSV and renegotiation results match reference |
| NET-07 | Hostile endpoints | Bounded time per endpoint; no crash; no XSS |
| NET-08 | Passive mode | Negotiated versions and ciphers recorded per client |

### Network safety

| ID | Test | Pass when |
| --- | --- | --- |
| NET-RATE-01 | Connection-rate limits | Max SYN/s at or under X |
| NET-RATE-02 | Scan windows | No traffic outside the window; resumes next window |
| NET-RATE-03 | Out-of-scope tripwire | Zero packets from the node to the excluded subnet |
| NET-RATE-04 | Kill switch | Traffic stops within 30 s |

### Evidence

| ID | Test | Pass when |
| --- | --- | --- |
| EVD-01 | Questionnaire and vendor token links | Expiry and single-use enforced |
| EVD-02 | Vendor silence stays Q0 | Shown as Q0 gap; never counted as safe |
| EVD-03 | Contradiction detection | Contradiction flagged |
| EVD-04 | Evidence expiry | Level reverts per policy |
| EVD-05 | Hostile evidence uploads | Same limits and escaping as HOS tests |

### Correlation

| ID | Test | Pass when |
| --- | --- | --- |
| COR-01 | Host process to network endpoint | Network finding linked to process and library |
| COR-02 | Code to image to running pod | Linked across sources |
| COR-03 | One consistent PQC readiness score | Score reproducible run to run |

### On-prem edition

| ID | Test | Pass when |
| --- | --- | --- |
| OPE-01 | Install from offline bundle | Install completes from bundle alone |
| OPE-02 | Zero egress | No traffic leaving the VPC; no external DNS lookups |
| OPE-03 | Offline update signatures | Rejected |
| OPE-04 | Backup and restore | Inventory identical |
