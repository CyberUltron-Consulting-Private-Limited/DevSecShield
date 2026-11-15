/**
 * (i) tip text of the "cbsrc-ssh-ca" area (ids: cbsrc.sshca.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources: Fleet > SSH CA (components/cbom/sources/fleet/SshCaSection.tsx)
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:1-5, frontend/components/cbom/sources/fleet/SshCaSection.tsx:179-183 — short-lived per-job certificates for the node's own key
  "cbsrc.sshca.card": {
    what: "ZeroShield signs each scan node's own key into a short-lived certificate for every job (5 minutes by default), with principals zs-<team>-<group>, bound to the node's address and with no forwarding or terminal. Servers trust this CA for the zs-cbom login only; every certificate issued is listed below.",
    why: "Servers trust one CA instead of every node key, and a stolen certificate is useless within minutes.",
    example: "prod-servers-ca, Ed25519, 300-second certificates.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:193-194 — up to 64 characters
  "cbsrc.sshca.name": {
    what: "A name for the CA, up to 64 characters.",
    why: "Linux sources pick their SSH CA by this name.",
    example: "prod-servers-ca.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:196-203 — built in or HashiCorp Vault SSH engine
  "cbsrc.sshca.provider": {
    what: "Built in: ZeroShield holds the CA key, encrypted (with AWS KMS when this deployment has a key). Vault: your HashiCorp Vault SSH secrets engine signs and the key never leaves Vault.",
    why: "With Vault, the signing key stays under your own controls and audit.",
    example: "Vault, using the ssh-client-signer mount.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:205-207 — 60 to 3,600 seconds; renewed during a job
  "cbsrc.sshca.ttl": {
    what: "How long each job certificate is valid, 60 to 3,600 seconds. A job renews its certificate before it runs out.",
    why: "Shorter lifetimes shrink the window in which a copied certificate works.",
    example: "300 seconds.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:210-216 — Ed25519 or ECDSA P-256
  "cbsrc.sshca.alg": {
    what: "The CA key's algorithm: Ed25519 (recommended) or ECDSA P-256.",
    why: "Both are widely supported by OpenSSH; neither is quantum-safe, so plan a rotation when post-quantum SSH keys are supported.",
    example: "Ed25519.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:219-227 — AWS KMS or the deployment key
  "cbsrc.sshca.wrap": {
    what: "How the built-in CA key is encrypted at rest: with AWS KMS when this deployment has a KMS key, otherwise with the deployment key (ENCRYPTION_KEY).",
    why: "KMS keeps the CA key unusable without access to your KMS key.",
    example: "AWS KMS.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:230-235 — labels of the allowed KMS keys
  "cbsrc.sshca.kms": {
    what: "Which of this deployment's allowed AWS KMS keys wraps the CA key.",
    why: "Separate keys per environment limit the reach of one KMS policy.",
    example: "cbom-sshca-prod (default).",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:240-241 — https, the active node
  "cbsrc.sshca.vault_addr": {
    what: "The HTTPS address of your Vault's active node.",
    why: "Signing requests go only to this address.",
    example: "https://vault.bank.in:8200.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:243-244 — the SSH secrets engine path
  "cbsrc.sshca.vault_mount": {
    what: "The path where the SSH secrets engine is mounted in Vault.",
    why: "The token below is limited to signing under this mount.",
    example: "ssh-client-signer.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:246-247 — allowed_critical_options must include source-address
  "cbsrc.sshca.vault_role": {
    what: "The Vault SSH role that signs. Its allowed_critical_options must include source-address and its default_extensions must be empty.",
    why: "Without source-address the certificates would work from any machine.",
    example: "zs-cbom-signer.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:220-240, scan_node/zs_scan_node/sshca_node.py — the key stays on the node (#61)
  "cbsrc.sshca.node_public_key": {
    what: "The public half of the CA key you install on the scan node (ZS_SSH_CA_KEY, default <state dir>/ssh-ca/ca_key, mode 0400). ZeroShield stores only this public key; for each job it records the certificate it allows and the node signs exactly that with your key, then reports it.",
    why: "No login-capable CA key is held by ZeroShield; the audit list and the KRL still have every certificate's serial.",
    example: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... ca@bank, from ssh-keygen -t ed25519 -N '' -f ca_key.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:249-250 — write-only; may only call <mount>/sign/<role>
  "cbsrc.sshca.vault_token": {
    what: "A Vault token that may only call <mount>/sign/<role>. Write-only: it is never shown again.",
    why: "A token limited to signing cannot read secrets or change the CA.",
    example: "A periodic token with a policy allowing update on ssh-client-signer/sign/zs-cbom-signer.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:48-53 — active, rotation, retired, revoked
  "cbsrc.sshca.col.state": {
    what: "Active (signs), Rotation (trusted, not signing yet), Retired (still trusted during the overlap) or Revoked.",
    why: "Promote a rotation only once every server trusts the new key, or scan logins fail.",
    example: "Rotation: trusted, not signing yet.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:287 — algorithm and fingerprint
  "cbsrc.sshca.col.key": {
    what: "The CA key's algorithm and SHA-256 fingerprint.",
    why: "Compare the fingerprint with TrustedUserCAKeys on a server to confirm it trusts this CA.",
    example: "ssh-ed25519 SHA256:3f9c...",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:280 — default certificate lifetime in seconds
  "cbsrc.sshca.col.lifetime": {
    what: "The default lifetime of the certificates this CA issues, in seconds.",
    why: "Shorter is safer; jobs renew as needed.",
    example: "300 s.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:289-292,280 — certificates issued by this CA
  "cbsrc.sshca.col.certs": {
    what: "How many certificates this CA has issued.",
    why: "Each one is listed in the certificate audit below.",
    example: "1,284.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:328-329 — lowercase letters, digits, . _ -
  "cbsrc.sshca.group": {
    what: "The server group for the principals file: certificates carry zs-<team>-<group>, and a server accepts only the groups in its file. Lowercase letters, digits, dots, underscores and dashes.",
    why: "Groups let production servers refuse certificates meant for test servers.",
    example: "prod.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:342-347 — read trusted keys, KRL and principals only
  "cbsrc.sshca.trust_tokens": {
    what: "A trust token lets your servers or configuration management fetch this team's trusted keys, revocation list and principals, and nothing else. It is shown once.",
    why: "Servers keep their trust files current on their own, so rotations need no manual roll-out.",
    example: "prod-servers, used by 212 servers in the last 24 hours.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:353-354 — up to 64 characters
  "cbsrc.sshca.token_name": {
    what: "A name for the trust token, up to 64 characters.",
    why: "Name it after the servers that will use it, so you know what breaks if it is revoked.",
    example: "prod-servers.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:363-366 — shown once; keep it root-only
  "cbsrc.sshca.new_token": {
    what: "The new trust token is shown only once. Store it in a file only root can read and point ZS_TRUST_TOKEN at it.",
    why: "Anyone with the token can read your trusted keys and revocation list.",
    example: "/etc/zs-cbom/trust-token, mode 0600.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:377 — the token's prefix
  "cbsrc.sshca.col.token": {
    what: "The first characters of the token, to match it with the file on your servers.",
    why: "The full value is never shown again.",
    example: "zst_4f1c...",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:376 — servers that fetched in the last 24 hours
  "cbsrc.sshca.col.servers": {
    what: "How many servers fetched their trust files with this token in the last 24 hours.",
    why: "During a rotation it shows how many servers already have the new key.",
    example: "212 of your 230 production servers.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:373 — last fetch
  "cbsrc.sshca.col.last_used": {
    what: "When a server last fetched with this token.",
    why: "A token unused for weeks may belong to retired servers; revoke it.",
    example: "14 Nov 2026, 02:05 am IST.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:380 — active or revoked
  "cbsrc.sshca.col.token_status": {
    what: "Whether the token still works: active, or revoked (servers using it get 401 and keep their current files).",
    why: "Revoke a token as soon as it may have leaked.",
    example: "Active.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:411 — when the certificate was issued
  "cbsrc.sshca.col.issued": {
    what: "When the certificate was issued.",
    why: "Match it with sshd's log on a server to trace a scan login.",
    example: "14 Nov 2026, 02:00:07 am IST.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:410 — serial and CA
  "cbsrc.sshca.col.serial": {
    what: "The certificate's serial number and the CA that issued it.",
    why: "sshd logs the serial, so you can tie each login to a job.",
    example: "88213 · CA #3.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:411 — principals in the certificate
  "cbsrc.sshca.col.principals": {
    what: "The principals written into the certificate.",
    why: "A server accepts it only if its principals file lists one of them.",
    example: "zs-12-prod.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:412 — source-address restriction
  "cbsrc.sshca.col.from": {
    what: "The source-address restriction: the only addresses the certificate works from.",
    why: "A certificate copied elsewhere is refused.",
    example: "10.20.1.15/32.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:409 — node, job, at claim or renewal
  "cbsrc.sshca.col.node_job": {
    what: "The scan node and job the certificate was issued for, and whether at the job's claim or as a renewal.",
    why: "Lets you trace every login back to a specific collection job.",
    example: "node #7 · job #4410 · at claim.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:409 — valid_before
  "cbsrc.sshca.col.valid_until": {
    what: "When the certificate stops working.",
    why: "After this time it cannot be used even if copied.",
    example: "14 Nov 2026, 02:05:07 am IST.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:54, frontend/components/cbom/sources/fleet/SshCaSection.tsx:409 — valid, expired, revoked
  "cbsrc.sshca.col.cert_status": {
    what: "valid, expired or revoked (in the revocation list; servers refuse it once they have the new list).",
    why: "Revoke a certificate if its node may be compromised before it expires.",
    example: "expired.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:446-451 — promote before the readiness check passes
  "cbsrc.sshca.promote_now": {
    what: "Promote the new key now, before the readiness check shows every server has it. Servers that do not trust it yet refuse every scan login.",
    why: "Use only when you know every server already has the new trusted keys.",
    example: "Tick after your Ansible run pushed the new trusted keys everywhere.",
  },
  // src: frontend/components/cbom/sources/fleet/SshCaSection.tsx:461-466 — recorded in the audit, up to 512 characters
  "cbsrc.sshca.reason": {
    what: "Why you are revoking, up to 512 characters. It is recorded in the audit.",
    why: "Auditors and teammates see why a CA, certificate or token was revoked.",
    example: "Node VM snapshot copied to an untrusted host.",
  },
} as const satisfies TipAreaText;

export default TEXT;
