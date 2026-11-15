/**
 * (i) tip text of the "cbsrc-servers" area (ids: cbsrc.servers.*, cbsrc.test.*, cbsrc.app.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // src: frontend/components/cbom/sources/ServersTab.tsx:991-999, frontend/components/cbom/sources/ServersTab.tsx:993 — 1,000 lines; ranges up to /16; 262,144 addresses per source
  "cbsrc.servers.targets": {
    what: "The servers to read: IP addresses, CIDR ranges or hostnames, one per line, up to 1,000 lines. A range may be at most a /16 and a source at most 262,144 addresses. Import CSV adds the first column of a file.",
    why: "Only listed targets are scanned, so a server left out is a blind spot in the CBOM.",
    example: "10.20.0.0/24, 10.20.5.17 and app-01.bank.local: 256 + 1 + 1 targets.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:121-124 — SSH 22, WinRM over HTTPS 5986, LDAPS 636 by default
  "cbsrc.servers.port": {
    what: "The port the scan node connects to: SSH for Linux (default 22), WinRM over HTTPS for Windows (5986), LDAPS for Active Directory (636).",
    why: "A port that is closed or filtered from the node fails the connection test for every server.",
    example: "2222 when your Linux servers run sshd on a non-standard port.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1092-1099, backend/utilities/cbom_sources/kinds.py:27 — up to 64 characters; DOMAIN\\user accepted for Windows and AD
  "cbsrc.servers.login": {
    what: "The account the scan node logs in as, up to 64 characters. For Linux a read-only account on each server (zs-cbom by default); for Windows and Active Directory a local or domain account, DOMAIN\\user accepted.",
    why: "A dedicated read-only account limits what a leaked credential could do and makes the scan easy to spot in audit logs.",
    example: "zs-cbom on Linux; BANK\\svc-zscbom for Active Directory.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1115-1132 — trust on first use or pinned known_hosts; a password forces pinning
  "cbsrc.servers.host_key_policy": {
    what: "How the node checks each server's SSH host key before logging in. Trust on first use remembers the key on first contact and refuses and alerts if it changes. Pin fingerprints accepts only the keys you paste. Host certificates accepts a server whose OpenSSH host certificate is signed by a host CA you list. A password credential requires pinned keys or host certificates.",
    why: "The host key check stops a machine impersonating the server from capturing the credential.",
    example: "Pin fingerprints with the output of ssh-keyscan for servers you already trust.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1185-1205, backend/utilities/cbom_sources/kinds.py check_host_ca_keys — host_ca (#59)
  "cbsrc.servers.host_ca_keys": {
    what: "The public keys of the CAs that sign your servers' OpenSSH host certificates (HostCertificate in sshd_config), one per line as in the CA's .pub file. The node offers only host-certificate key types and accepts a server only with a certificate from one of these CAs that is a host certificate, names the server's host name or address, and is inside its validity period.",
    why: "One CA key proves every server it certified, without pasting each host key; a spoofed server without such a certificate never receives the login.",
    example: "One line of the CA's .pub file, such as ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... host-ca@bank.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1136-1143 — public keys only
  "cbsrc.servers.known_hosts": {
    what: "The SSH host keys to accept, in known_hosts format: the output of ssh-keyscan or your existing known_hosts file. Public keys only; upload a file or paste the lines.",
    why: "A server whose key is not listed is refused, so a spoofed server never receives the login.",
    example: "10.20.0.11 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1177-1185, backend/utilities/cbom_sources/kinds.py:21 — PEM up to 64 KB, checked before the login is sent
  "cbsrc.servers.ca_pem": {
    what: "Optional PEM certificate of the CA that issued the WinRM (HTTPS) or LDAPS certificate of the servers. The server's certificate is checked against it before the login is sent. Needed when an internal CA issued it.",
    why: "Without the right CA the TLS check fails and the node never sends the password.",
    example: "The root certificate of BANK-ISSUING-CA, as -----BEGIN CERTIFICATE-----...",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:128-134,1226, frontend/components/cbom/sources/ServersTab.tsx:1226-1238 — node key, SSH CA, SSH certificate, vault reference or password; vault and SSH CA for admins only
  "cbsrc.servers.credential": {
    what: "How the node proves who it is. Node-generated SSH key (recommended, the private key never leaves the node), SSH CA certificate (signed per job for minutes), your own SSH certificate, a vault reference, or a password. Only team admins choose vault or SSH CA.",
    why: "The credential is the most sensitive thing a source holds; options that keep secrets off ZeroShield reduce what a breach could expose.",
    example: "Linux: Node-generated SSH key, then install the shown public key for zs-cbom.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1293-1305, backend/utilities/cbom_sources/kinds.py:20 — secrets up to 256 KB, encrypted at rest
  "cbsrc.servers.ssh_certificate": {
    what: "An OpenSSH user certificate signed by your own SSH CA, used together with the private key below. Encrypted at rest and sent only to the scan node that runs the job.",
    why: "A short-lived certificate expires on its own, so a copied credential stops working.",
    example: "ssh-ed25519-cert-v01@openssh.com AAAA... zs-cbom valid for 8 hours.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1306-1318, backend/utilities/cbom_sources/kinds.py:20 — secrets up to 256 KB, encrypted at rest
  "cbsrc.servers.private_key": {
    what: "The private key that goes with the SSH certificate, in OpenSSH or PEM format. Encrypted at rest, never shown again, sent only to the scan node that runs the job.",
    why: "Without the matching private key the certificate cannot be used to log in.",
    example: "-----BEGIN OPENSSH PRIVATE KEY----- ....",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1325-1335 — the CA's active key signs the node's key for each job
  "cbsrc.servers.ssh_ca": {
    what: "The ZeroShield SSH CA (created on Fleet > SSH CA) whose active key signs the scan node's own key for each job; the certificate lives for minutes. Rotating the CA needs no change here.",
    why: "Servers trust one CA instead of a key per node, and no long-lived credential exists to steal.",
    example: "prod-ssh-ca, trusted on the servers through TrustedUserCAKeys.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1338, frontend/components/cbom/sources/ServersTab.tsx:1338-1341 — zs-<team>-<name>, one per line
  "cbsrc.servers.principals": {
    what: "The principals written into each job's certificate, one per line, in the form zs-<team id>-<name>. A server accepts the certificate only for a login whose principals file lists one of them.",
    why: "Principals decide which servers accept the certificate, so prod and test servers can trust different ones.",
    example: "zs-12-prod, listed in /etc/ssh/zs-cbom/principals/zs-cbom on the production servers.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1343-1347 — source-address of the certificate; /16 or narrower (IPv6 /48)
  "cbsrc.servers.source_addresses": {
    what: "The source-address restriction written into each certificate: the addresses or networks (/16 or narrower, IPv6 /48) the servers see the node connect from. Blank uses the node's own addresses.",
    why: "A certificate copied off the node cannot be used from anywhere else.",
    example: "10.20.1.15, or 10.20.1.0/28 when the node sits behind a NAT pool.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:142-171,1415, frontend/components/cbom/sources/ServersTab.tsx:1415-1429 — Tier 1 read-only commands; Tier 2 adds an exact sudo allowlist
  "cbsrc.servers.tier": {
    what: "Tier 1 runs read-only commands as the login user: packages, crypto configs, readable keys, certificates and keystores. Tier 2 adds an exact sudo allowlist (no wildcards) to see which process loads which crypto library, socket owners, the effective SSH config and disk encryption.",
    why: "Tier 2 finds crypto in use at runtime that config files alone do not show, at the cost of a sudoers entry.",
    example: "Tier 2 shows that java on port 8443 loads libssl 1.1.1 with TLS 1.0 enabled.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1257-1267 — the public key for the login user
  "cbsrc.servers.node_key_install": {
    what: "Copy this public key into authorized_keys of the login user on every server of this source.",
    why: "Until the key is installed, the connection test reports Login failed for each server.",
    example: "ssh-copy-id is not needed: echo 'ssh-ed25519 AAAA...' >> ~zs-cbom/.ssh/authorized_keys.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:171 — 1 to 64, default 8
  "cbsrc.servers.parallel": {
    what: "How many servers the scan node reads at the same time, 1 to 64 (default 8).",
    why: "Higher finishes large ranges sooner but adds load on the node and the network.",
    example: "8 reads a /24 of 254 servers in about 32 rounds.",
  },
  // src: backend/utilities/cbom_sources/kinds.py:172 — 10 to 3,600 s, default 300
  "cbsrc.servers.timeout": {
    what: "How long the node may spend on one server, 10 to 3,600 seconds (default 300). A server that takes longer is reported as timed out and the job moves on.",
    why: "One hung server cannot stall the whole run.",
    example: "600 for servers with very large keystores to read.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:932-937, frontend/components/cbom/sources/ServersTab.tsx:118-125,476 — Linux, Windows or Active Directory sources
  "cbsrc.servers.form": {
    what: "A server source is one list of Linux servers, Windows servers or an Active Directory, read through one scan node with a read-only account. Pick the type, then where the servers are and how to log in.",
    why: "Servers hold most of the keys, certificates and crypto libraries an inventory has to cover.",
    example: "Linux: 10.20.0.0/24 through node-dc1, login zs-cbom with the node's SSH key.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:514-549 — each source with its target count after exclusions
  "cbsrc.servers.list": {
    what: "The server sources of this team with their type, target count after exclusions, scan node, privilege tier and last connection test.",
    why: "Sources here are what a run on the Review & Run tab collects from.",
    example: "dc-mumbai-linux · Linux · 256 targets · node-dc1 · Tier 1 · Passed.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:142-171,1629, frontend/components/cbom/sources/ServersTab.tsx:1627-1633 — the command lists; nothing is installed
  "cbsrc.servers.what_runs": {
    what: "The exact commands the node runs on each server for the chosen type and tier. Nothing is installed; output is parsed on the node.",
    why: "Your change board can review every command before approving the scan.",
    example: "Tier 1 runs openssl version -a and cat /etc/ssh/sshd_config, among others.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:323, backend/utilities/cbom_sources/jobs.py:716-726 — up to 5 sampled targets
  "cbsrc.servers.test": {
    what: "The result of the last connection test: up to 5 sampled targets, each checked for reachability, login and privilege. Passed when every sample is ready, Partly ready when some are.",
    why: "It proves the node, network path and credential work before a full run spends credits.",
    example: "4 of 5 samples ready: 10.20.0.9 refused the login.",
  },
  // src: backend/utilities/cbom_sources/jobs.py:323 — sampled target
  "cbsrc.test.server": {
    what: "One of the targets sampled for the connection test.",
    why: "Samples stand in for the whole range, so fix their failures before running.",
    example: "10.20.0.17.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1800-1802 — yes, no, or waiting
  "cbsrc.test.reachable": {
    what: "Whether the scan node could open a connection to the server on the configured port.",
    why: "No here points at routing, a firewall or the wrong port, not the credential.",
    example: "No: port 22 is filtered between node-dc1 and 10.20.0.17.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1800-1803 — yes, no, or waiting
  "cbsrc.test.login": {
    what: "Whether the login user could authenticate with the configured credential.",
    why: "No here means the key, certificate or password is not accepted on that server.",
    example: "No: the node's key is not in authorized_keys of zs-cbom.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1791, frontend/components/cbom/sources/ServersTab.tsx:1804 — sudo allowlist (Linux Tier 2) or Windows group
  "cbsrc.test.privilege": {
    what: "Linux Tier 2: whether the sudo allowlist works. Windows: whether the account may open a WinRM shell (Remote Management Users with WinRM access). Not needed for Linux Tier 1.",
    why: "Without it, runtime crypto use is not collected even though the login works.",
    example: "No: the sudoers file was not installed on 10.20.0.17.",
  },
  // src: frontend/components/cbom/sources/ServersTab.tsx:1779-1784 — the sample's status and note
  "cbsrc.test.result": {
    what: "The sample's overall status with the node's note, for example Ready, Unreachable or Login failed.",
    why: "The note names the exact cause to fix.",
    example: "Login failed · Permission denied (publickey).",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: network appliances, container images, CMDB import
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:1-3, frontend/components/cbom/sources/AppliancesSection.tsx:60-63, backend/utilities/cbom_sources/kinds.py:714-715 — Cisco IOS/ASA, FortiOS over SSH; PAN-OS, F5 over API
  "cbsrc.app.card": {
    what: "Read-only configuration pulls from routers, firewalls and load balancers through a scan node: Cisco IOS and ASA and FortiOS over SSH show commands, PAN-OS and F5 BIG-IP over API reads. TLS, SSH and IKE/IPsec settings and key sizes are inventoried.",
    why: "VPN tunnels and load balancers carry most traffic; weak IKE groups there are harvest-now-decrypt-later targets.",
    example: "fw-dc1 (FortiGate): IKE phase 1 uses DH group 14 (2048-bit MODP), quantum-vulnerable.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:29-36 — the appliance platform
  "cbsrc.app.col.vendor": {
    what: "The appliance platform and how it is read (SSH show commands or API).",
    why: "Each platform has its own read commands and credential type.",
    example: "Cisco ASA.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:218 — devices of the source
  "cbsrc.app.col.targets": {
    what: "The devices this source reads, all with the same account.",
    why: "Group devices that share an account and platform into one source.",
    example: "3 devices.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:29-36, frontend/components/cbom/sources/AppliancesSection.tsx:201-212 — what is read on each platform
  "cbsrc.app.vendor": {
    what: "The platform of the devices. The hint lists exactly what is read: show commands for Cisco IOS, ASA and FortiOS; read-only API calls for PAN-OS and F5 BIG-IP.",
    why: "Only the listed reads are sent, so your change board can approve them up front.",
    example: "F5 BIG-IP: GET client-ssl profiles and key type and size only.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:215-216 — up to 64 characters
  "cbsrc.app.name": {
    what: "A name for this appliance source, up to 64 characters, shown in lists, run results and reports.",
    why: "Each finding records it as its source.",
    example: "dc1-firewalls.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:218-220 — one address or host name per line
  "cbsrc.app.devices": {
    what: "The devices to read, one address or host name per line; all use the same account.",
    why: "Devices not listed keep their weak VPN settings unseen.",
    example: "10.20.0.1 and fw-dc1.bank.local.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:223-224 — default 22 for SSH, 443 for API
  "cbsrc.app.port": {
    what: "The management port: 22 by default for SSH platforms, 443 for API platforms.",
    why: "A management interface on a custom port fails the test until it is set here.",
    example: "8443 for a BIG-IP management port.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:227-228 — a read-only account, up to 64 characters
  "cbsrc.app.login": {
    what: "A read-only account on the devices, up to 64 characters. On Cisco ASA it must land in privileged EXEC.",
    why: "A read-only role limits what a leaked password could change.",
    example: "zs-cbom with privilege 15 view-only.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:230, backend/utilities/cbom_sources/kinds.py:258-260 — encrypted at rest; SSH passwords need a pinned host key
  "cbsrc.app.secret": {
    what: "The account's password, or the API key for PAN-OS. Encrypted at rest and sent only to the scan node. SSH platforms require the pinned host key below, so the password only goes to the real device.",
    why: "Pinning stops a spoofed device from capturing the password.",
    example: "The PAN-OS API key generated for zs-cbom.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:233-234 — the node that reaches the management interface
  "cbsrc.app.node": {
    what: "The scan node that reaches the devices' management interfaces.",
    why: "Management networks are usually isolated; the node must sit where it can reach them.",
    example: "node-mgmt in the out-of-band network.",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:237-240 — known_hosts lines, required for SSH
  "cbsrc.app.known_hosts": {
    what: "The devices' SSH host keys in known_hosts format. Required for SSH platforms.",
    why: "A device whose key does not match is refused before the password is sent.",
    example: "fw-dc1.bank.local ssh-rsa AAAAB3Nza...",
  },
  // src: frontend/components/cbom/sources/AppliancesSection.tsx:243-244 — PEM, for a privately issued management certificate
  "cbsrc.app.ca": {
    what: "Optional PEM certificate of the CA that issued the management certificate of API platforms. The certificate is always verified.",
    why: "Needed when the management interface uses an internal CA.",
    example: "bank-root-ca.pem.",
  },
} as const satisfies TipAreaText;

export default TEXT;
