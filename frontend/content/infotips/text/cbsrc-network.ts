/**
 * (i) tip text of the "cbsrc-network" area (ids: cbsrc.net.*), loaded on demand by
 * content/infotips/load.ts. The label of each tip is in content/infotips/labels.ts; the rules for the text are in
 * content/infotips/index.ts (checked by content/infotips.test.ts).
 */
import type { TipAreaText } from "../types";

const TEXT = {
  // ────────────────────────────────────────────────────────────── CBOM Sources: Network TLS (components/cbom/sources/NetworkTab.tsx)
  // src: frontend/components/cbom/sources/NetworkTab.tsx:446-454 — the team emergency stop
  "cbsrc.net.stopped": {
    what: "A team admin stopped all network scanning. Scan nodes skip network ranges and discovery sweeps until a team admin resumes it; other sources are not affected.",
    why: "The emergency stop exists so the SOC can halt probing at once if a device misbehaves.",
    example: "Stopped 12 minutes ago after a PLC on 10.50.0.0/24 raised an alarm.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:465, frontend/components/cbom/sources/NetworkTab.tsx:467-497 — allowed ranges, never scan, SNI names, ports
  "cbsrc.net.scope": {
    what: "What the network scan may touch and how: the allowed ranges and their scan nodes, the never-scan list, hostnames for SNI and the ports and protocols to probe.",
    why: "Nothing outside the allowed ranges is ever probed, and never-scan always wins.",
    example: "10.20.0.0/16 through node-dc1, except 10.20.99.0/24 (OT), on ports 443, 8443 and 22.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:467-497, frontend/components/cbom/sources/NetworkTab.tsx:1180-1187,468 — nothing is scanned until a range is allowed
  "cbsrc.net.ranges": {
    what: "The address ranges the network scan may probe, each with the scan node that reaches it. Nothing is scanned until you allow a range.",
    why: "An explicit allow list keeps scans inside the networks you approved.",
    example: "10.20.0.0/16 through node-dc1, Full mode.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1180 — a /16 or smaller, one IP, or a-b
  "cbsrc.net.col.range": {
    what: "The addresses: a CIDR range of /16 or smaller, one IP address, or a first-last range. A /24 or larger skips its network and broadcast addresses; a /25 or smaller is scanned whole.",
    why: "Each address in it may be probed on every listed port.",
    example: "10.20.5.0/24.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:540, frontend/components/cbom/sources/NetworkTab.tsx:1203-1217 — Full or Fragile (version check only)
  "cbsrc.net.col.mode": {
    what: "Full: complete TLS and SSH handshakes on every listed port. Fragile: a version check only, for OT or devices that may not cope with many handshakes.",
    why: "Old PLCs and medical devices can crash under repeated handshakes.",
    example: "Fragile for the SCADA network 10.50.0.0/24.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:590, frontend/components/cbom/sources/NetworkTab.tsx:590-692 — up to 500 entries; always wins in every job of the team
  "cbsrc.net.never_scan": {
    what: "Addresses and ranges, up to 500, that no job of this team may touch. The node refuses them even if a job asks; a server, database, registry or Kubernetes API whose name resolves to a listed address is skipped as a whole. Add each with a reason.",
    why: "It protects OT networks, core routers and partner systems from any probe, whatever a source says.",
    example: "10.20.99.0/24 · OT plant network.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:601, frontend/components/cbom/sources/NetworkTab.tsx:671-680 — up to 120 characters
  "cbsrc.net.col.reason": {
    what: "Why the range is excluded, up to 120 characters, so others know not to remove it.",
    why: "An exclusion without a reason tends to be deleted during clean-ups.",
    example: "OT plant network, no active scanning per IT-OT policy.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:701, frontend/components/cbom/sources/NetworkTab.tsx:701-710 — up to 10,000 names
  "cbsrc.net.sni": {
    what: "Hostnames, up to 10,000, sent as SNI in TLS handshakes so servers that host several sites return each site's certificate.",
    why: "Without SNI a shared server shows only its default certificate and the others go uninventoried.",
    example: "www.bank.in and api.bank.in on the same load balancer address.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:78-92,712, frontend/components/cbom/sources/NetworkTab.tsx:712, frontend/components/cbom/sources/NetworkTab.tsx:712-785 — up to 64 ports; TLS, StartTLS, SSH, RDP, IKE, OT
  "cbsrc.net.ports": {
    what: "The ports probed on each address, up to 64, each with its protocol: TLS, StartTLS for LDAP, SMTP, IMAP, PostgreSQL or MySQL, SQL Server, SSH, RDP, IKE, and OT protocols (OPC UA, Modbus). Add a port, its protocol and an optional label.",
    why: "A service on a port that is not listed is never seen.",
    example: "7443 · TLS · admin console.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:791 — window, rates, SOC contacts
  "cbsrc.net.safety": {
    what: "When network scans may run, how fast they may go, and who your SOC should call.",
    why: "Probing at the wrong hour or speed can set off alarms or disturb fragile devices.",
    example: "Weekday nights only, 50 connections per second per node.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:793-842 — weekly hours in a time zone; work pauses at the end
  "cbsrc.net.window": {
    what: "The weekly hours, in the chosen time zone, when network scans and sources set to the team window may run. Work pauses at the end of the window and resumes in the next one.",
    why: "Keeps probes out of business hours and change freezes.",
    example: "Weekday nights, 22:00 to 06:00 Asia/Kolkata: 40 hours a week.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:111 — 1 to 500
  "cbsrc.net.rate_conn": {
    what: "The most new connections per second each scan node opens, 1 to 500.",
    why: "Lower values avoid tripping IDS alerts and connection limits on firewalls.",
    example: "50 for a branch network behind a small firewall.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:112 — 1 to 32
  "cbsrc.net.rate_parallel": {
    what: "The most connections a node keeps open to one server at a time, 1 to 32.",
    why: "Protects small servers from being overloaded by parallel handshakes.",
    example: "4 for older appliances that limit concurrent TLS sessions.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:113 — 1 to 200
  "cbsrc.net.rate_handshakes": {
    what: "The most TLS or SSH handshakes made to one endpoint (address and port), 1 to 200. More handshakes test more protocol versions and cipher suites.",
    why: "A full cipher-suite enumeration needs many handshakes; fewer is gentler but less complete.",
    example: "60 enumerates TLS 1.0 to 1.3 suites on a typical web server.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:876-930 — each node's source IPs and your contacts
  "cbsrc.net.soc": {
    what: "The source IP addresses of each scan node that scans networks, to give your SOC so the scans are recognised, and the contacts they can reach. Host-agent nodes are left out: they never scan networks.",
    why: "An unannounced scan looks like an attack and may be blocked mid-run.",
    example: "node-dc1 scans from 10.20.1.15.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:894 — the node
  "cbsrc.net.col.node": {
    what: "The scan node whose source addresses are listed.",
    why: "Each node scans from its own addresses.",
    example: "node-dc1.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:895 — addresses the node reported
  "cbsrc.net.col.source_ips": {
    what: "The addresses the node reported it connects from, to whitelist or recognise in your SOC tools.",
    why: "Behind NAT the address seen by targets may differ; check with your network team.",
    example: "10.20.1.15, fd00:20::15.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:909, frontend/components/cbom/sources/NetworkTab.tsx:909-917 — up to 254 characters
  "cbsrc.net.soc_email": {
    what: "Your SOC's email address, up to 254 characters, recorded with the team's network settings as the contact for these scans.",
    why: "Gives operators one place to send questions about a scan they see.",
    example: "soc@bank.in.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:920, frontend/components/cbom/sources/NetworkTab.tsx:920-928 — a phone number, up to 64 characters
  "cbsrc.net.emergency": {
    what: "A phone number, up to 64 characters, for whoever can stop the scans at once.",
    why: "If a device misbehaves during a scan, someone must be reachable to stop it.",
    example: "+91 22 5555 0100 (NOC, 24x7).",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1198-1201 — the node that reaches the range
  "cbsrc.net.range_form_node": {
    what: "The scan node that probes this range. It must reach every address in it on the listed ports.",
    why: "A node in another segment sees every address as silent.",
    example: "node-dc1 for 10.20.0.0/16.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1419, frontend/components/cbom/sources/NetworkTab.tsx:1419-1420 — BIND export up to 8 MB; A, AAAA, CNAME names
  "cbsrc.net.sni_zone": {
    what: "Add hostnames from a BIND zone export, up to 8 MB: the names of its A, AAAA and CNAME records.",
    why: "A zone file lists names nobody remembers to type in.",
    example: "bank.in.zone exported from the DNS server.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1422-1423 — text or CSV; first column
  "cbsrc.net.sni_list": {
    what: "Add hostnames from a text or CSV file; the first column of each row is used.",
    why: "Reuse an existing asset list instead of typing names.",
    example: "hosts.csv exported from the CMDB.",
  },
  // src: frontend/components/cbom/sources/NetworkTab.tsx:1426, frontend/components/cbom/sources/NetworkTab.tsx:1426-1433 — one per line, up to 10,000; duplicates dropped
  "cbsrc.net.sni_text": {
    what: "One hostname per line, up to 10,000; duplicates are dropped.",
    why: "Each name is sent as SNI so the right certificate is returned.",
    example: "www.bank.in, api.bank.in, mail.bank.in.",
  },
  // ────────────────────────────────────────────────────────────── CBOM Sources: network sweep totals (#234) and the node image pull (#233)
  // src: frontend/components/cbom/sources/NetworkTab.tsx:935-948, frontend/components/cbom/sources/networkEstimate.ts:18-36 — unique addresses over enabled ranges
  "cbsrc.net.before_first": {
    what: "What the first sweep will cover: the unique addresses across the enabled ranges, after the never-scan list, times the ports listed. Disabled ranges are not swept and not counted. A discovery sweep on each scan node with ranges finds the open ports first.",
    why: "Check the size before you tell your SOC and start the run.",
    example: "4,096 unique addresses across 2 enabled ranges after the never-scan list, 6 ports. 1 disabled range is not counted.",
  },
} as const satisfies TipAreaText;

export default TEXT;
