// Pure helpers for the CBOM Sources pages (no React, no network) so they can be unit-tested with tsx.

export type WindowGrid = boolean[][] // 7 rows (Monday first) x 24 hours

export const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const

export function emptyGrid(): WindowGrid {
  return Array.from({ length: 7 }, () => Array.from({ length: 24 }, () => false))
}

export function normalizeGrid(grid: unknown): WindowGrid {
  if (!Array.isArray(grid) || grid.length !== 7) return emptyGrid()
  return grid.map((row) => (Array.isArray(row) && row.length === 24 ? row.map(Boolean) : Array(24).fill(false)))
}

export function countHours(grid: WindowGrid): number {
  return grid.reduce((sum, row) => sum + row.filter(Boolean).length, 0)
}

export function setCell(grid: WindowGrid, day: number, hour: number, value: boolean): WindowGrid {
  return grid.map((row, d) => (d === day ? row.map((cell, h) => (h === hour ? value : cell)) : row))
}

/** Weekdays 22:00-05:00, matching the backend default. */
export function defaultWindow(): WindowGrid {
  let grid = emptyGrid()
  for (let day = 0; day < 5; day++) {
    grid = setCell(setCell(grid, day, 22, true), day, 23, true)
    for (let hour = 0; hour < 5; hour++) grid = setCell(grid, day + 1, hour, true)
  }
  return grid
}

/** Split a textarea into clean lines (CR, BOM, blanks and # comments dropped). */
export function splitLines(text: string): string[] {
  return text
    .replace(/﻿/g, "")
    .split(/\r?\n/)
    .map((line) => line.split("#")[0].trim())
    .filter((line) => line.length > 0)
}

/** First column of a CSV (header row dropped when it is not an address). */
export function csvFirstColumn(text: string): string[] {
  const rows = splitLines(text).map((line) => line.split(/[,;\t]/)[0].trim().replace(/^"|"$/g, ""))
  if (rows.length && /^(ip|ips|host|hostname|address|target|name)$/i.test(rows[0])) rows.shift()
  return rows.filter(Boolean)
}

/** Host names from a BIND zone file export (A, AAAA and CNAME owners). */
export function zoneFileHostnames(text: string): string[] {
  let origin = ""
  let last = ""
  const names = new Set<string>()
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.split(";")[0]
    if (!line.trim()) continue
    const originMatch = line.match(/^\$ORIGIN\s+(\S+)/i)
    if (originMatch) {
      origin = originMatch[1].replace(/\.$/, "")
      continue
    }
    if (line.startsWith("$")) continue
    const parts = line.trim().split(/\s+/)
    const startsWithSpace = /^\s/.test(line)
    const owner = startsWithSpace ? last : parts[0]
    if (!startsWithSpace) last = owner
    const type = parts.find((p) => /^(A|AAAA|CNAME)$/i.test(p))
    if (!type || !owner) continue
    let name = owner === "@" ? origin : owner
    if (!name.endsWith(".") && origin && owner !== "@") name = `${name}.${origin}`
    name = name.replace(/\.$/, "").toLowerCase()
    if (/^[a-z0-9_.-]+$/.test(name) && name.includes(".") && !name.startsWith("*")) names.add(name)
  }
  return Array.from(names)
}

/** POSIX single-quote for shell commands we show to the customer. */
export function shQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`
}

export type DeployMethod = "docker" | "helm" | "ami" | "ova"

export function installCommand(
  method: DeployMethod,
  opts: { token: string; apiUrl: string; proxyUrl?: string | null; image: string; name: string },
): string {
  const proxy = opts.proxyUrl ? opts.proxyUrl : ""
  if (method === "docker") {
    return [
      "docker run -d --name zs-scan-node --restart unless-stopped \\",
      `  -e ZS_API_URL=${shQuote(opts.apiUrl)} \\`,
      `  -e ZS_REGISTRATION_TOKEN=${shQuote(opts.token)} \\`,
      ...(proxy ? [`  -e HTTPS_PROXY=${shQuote(proxy)} \\`] : []),
      "  -v zs-node:/var/lib/zs-node \\",
      `  ${opts.image}`,
    ].join("\n")
  }
  if (method === "helm") {
    const [repo, tag] = opts.image.includes(":") ? [opts.image.slice(0, opts.image.lastIndexOf(":")), opts.image.slice(opts.image.lastIndexOf(":") + 1)] : [opts.image, "latest"]
    return [
      "helm upgrade --install zs-scan-node oci://registry.zeroshield.ai/charts/cbom-scan-node \\",
      "  --namespace zs-cbom --create-namespace \\",
      `  --set image.repository=${shQuote(repo)} --set image.tag=${shQuote(tag)} \\`,
      `  --set apiUrl=${shQuote(opts.apiUrl)} \\`,
      `  --set registrationToken=${shQuote(opts.token)}${proxy ? " \\" : ""}`,
      ...(proxy ? [`  --set httpsProxy=${shQuote(proxy)}`] : []),
    ].join("\n")
  }
  if (method === "ami") {
    return [
      "#cloud-config  (paste as EC2 user data when you launch the ZeroShield scan node AMI)",
      "write_files:",
      "  - path: /etc/zs-node/env",
      "    permissions: '0600'",
      "    content: |",
      `      ZS_API_URL=${opts.apiUrl}`,
      `      ZS_REGISTRATION_TOKEN=${opts.token}`,
      ...(proxy ? [`      HTTPS_PROXY=${proxy}`] : []),
    ].join("\n")
  }
  return [
    "# OVA (VMware / Hyper-V): set these vApp properties when you deploy the appliance",
    `zs.api_url = ${opts.apiUrl}`,
    `zs.registration_token = ${opts.token}`,
    ...(proxy ? [`zs.https_proxy = ${proxy}`] : []),
  ].join("\n")
}

/** The published node image's name (scripts/release/scan_node_image.sh builds and saves it under this name). */
export const PUBLISHED_NODE_IMAGE = "registry.zeroshield.ai/cbom/scan-node"

/** For a site that cannot pull the node image: the image file from `make node-image` (or the release workflow),
 * checked with its .sha256 and loaded with `docker load` (scan_node/README.md, "Without registry access"). Helm also
 * needs the image in a registry the cluster can pull from, and the chart from the repository. Null for the AMI and
 * the OVA, which carry the image inside. */
export function offlineImageSteps(method: DeployMethod, image: string): string | null {
  if (method !== "docker" && method !== "helm") return null
  const cut = image.lastIndexOf(":")
  const version = cut > image.lastIndexOf("/") ? image.slice(cut + 1) : "latest"
  const archive = `scan-node-${version}.tar.gz`
  const lines = [
    `# 1. Get the image file: in the DevSecShield repository run  make node-image VERSION=${version}`,
    `#    (it writes dist/scan-node/${archive} and ${archive}.sha256), or ask ZeroShield for both files.`,
    "# 2. Copy both files to the host, check the file, then load it:",
    `sha256sum -c ${archive}.sha256`,
    `docker load -i ${archive}`,
  ]
  const loaded = `${PUBLISHED_NODE_IMAGE}:${version}`
  if (loaded !== image) lines.push(`docker tag ${loaded} ${image}`)
  if (method === "docker") {
    lines.push("# 3. Run the command above: Docker uses the loaded image and does not pull it.")
  } else {
    lines.push(
      "# 3. Push it to a registry your cluster can pull from, and use that name in image.repository:",
      `docker tag ${image} <your-registry>/cbom/scan-node:${version}`,
      `docker push <your-registry>/cbom/scan-node:${version}`,
      "#    The chart is in the repository too: use ./deploy/helm/cbom-scan-node instead of the oci:// address.",
    )
  }
  return lines.join("\n")
}

/** How far each way of running a node has been proven. Docker and the Helm chart (Deployment and the agent
 * DaemonSet) ran end to end on k3s; the AMI and OVA are Packer templates in deploy/node-images/ to build yourself. */
export const DEPLOY_SUPPORT: Record<DeployMethod, { proven: boolean; note: string }> = {
  docker: { proven: true, note: "Proven" },
  helm: { proven: true, note: "Proven on Kubernetes (k3s): Deployment and agent DaemonSet" },
  ami: { proven: false, note: "Build it yourself: Packer template provided (deploy/node-images/)" },
  ova: { proven: false, note: "Build it yourself: Packer template provided (deploy/node-images/)" },
}

/** The Helm command for agent mode: a DaemonSet whose pods each enroll with the agent pool token as their own node
 * (named after the Kubernetes node) and read only that node, from a read-only mount of its file system. */
export function helmAgentCommand(opts: { poolToken: string; apiUrl: string; proxyUrl?: string | null; image: string }): string {
  const proxy = opts.proxyUrl ? opts.proxyUrl : ""
  const [repo, tag] = opts.image.includes(":") ? [opts.image.slice(0, opts.image.lastIndexOf(":")), opts.image.slice(opts.image.lastIndexOf(":") + 1)] : [opts.image, "latest"]
  return [
    "helm upgrade --install zs-host-agents oci://registry.zeroshield.ai/charts/cbom-scan-node \\",
    "  --namespace zs-cbom --create-namespace \\",
    `  --set image.repository=${shQuote(repo)} --set image.tag=${shQuote(tag)} \\`,
    `  --set apiUrl=${shQuote(opts.apiUrl)} \\`,
    "  --set deployment.enabled=false --set agent.enabled=true \\",
    `  --set agent.poolToken=${shQuote(opts.poolToken)}${proxy ? " \\" : ""}`,
    ...(proxy ? [`  --set httpsProxy=${shQuote(proxy)}`] : []),
  ].join("\n")
}

export function ansibleSnippet(publicKey: string, user: string): string {
  return [
    "- name: ZeroShield CBOM read-only account",
    "  hosts: cbom_targets",
    "  become: true",
    "  tasks:",
    `    - ansible.builtin.user: { name: ${shQuote(user)}, shell: /bin/bash, create_home: true }`,
    "    - ansible.posix.authorized_key:",
    `        user: ${shQuote(user)}`,
    `        key: ${shQuote(publicKey)}`,
  ].join("\n")
}

/** "30 s ago" relative to the server clock, so a skewed laptop clock cannot make a node look offline. */
export function ago(iso: string | null | undefined, serverNowIso: string | null | undefined): string {
  if (!iso) return "Never"
  const then = Date.parse(iso)
  const now = serverNowIso ? Date.parse(serverNowIso) : Date.now()
  if (Number.isNaN(then) || Number.isNaN(now)) return "—"
  const s = Math.max(0, Math.round((now - then) / 1000))
  if (s < 60) return `${s} s ago`
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} d ago`
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return "—"
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return "—"
  return d.toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })
}

/** A YYYY-MM-DD date shown without time-zone shifting. */
export function formatDay(day: string | null | undefined): string {
  if (!day || !/^\d{4}-\d{2}-\d{2}$/.test(day)) return "—"
  const [y, m, d] = day.split("-").map(Number)
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" })
}

export function newRequestId(): string {
  const c = (globalThis as { crypto?: Crypto }).crypto
  if (c && typeof c.randomUUID === "function") return c.randomUUID().replace(/-/g, "")
  return `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 12)}`
}

export const MAX_TEXT_FILE = 256 * 1024

/** Read a small text file (PEM, kubeconfig, known_hosts, CSV); refuses binaries and oversize files. */
export async function readTextFile(file: File, maxBytes = MAX_TEXT_FILE): Promise<string> {
  if (file.size > maxBytes) throw new Error(`${file.name} is larger than ${Math.round(maxBytes / 1024)} KB`)
  const buffer = new Uint8Array(await file.arrayBuffer())
  if (buffer.includes(0)) throw new Error(`${file.name} is a binary file; choose a text (PEM or YAML) file`)
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(buffer)
  } catch {
    throw new Error(`${file.name} is not UTF-8 text`)
  }
}

export function pluralize(count: number, one: string, many = `${one}s`): string {
  return `${count.toLocaleString()} ${count === 1 ? one : many}`
}

export function credits(value: number | null | undefined): string {
  if (value == null) return "—"
  return Number(value).toLocaleString(undefined, { maximumFractionDigits: 2 })
}

// ---- source metadata: internet exposure (an override of what the collected facts say; "auto" = no override)

export type ExposureChoice = "auto" | "internet" | "internal" | "unknown"

export const EXPOSURE_CHOICES: { value: ExposureChoice; label: string }[] = [
  { value: "auto", label: "From collected facts" },
  { value: "internet", label: "Internet-facing" },
  { value: "internal", label: "Internal" },
  { value: "unknown", label: "Unknown" },
]

export function exposureFrom(config: Record<string, unknown> | null | undefined): ExposureChoice {
  const value = config?.exposure
  return value === "internet" || value === "internal" || value === "unknown" ? value : "auto"
}

/** The source config with new metadata fields and exposure (null clears; the connection settings are kept). */
export function withMetadata(
  config: Record<string, unknown> | null | undefined,
  fields: Record<string, unknown>,
  exposure: ExposureChoice,
): Record<string, unknown> {
  return { ...(config ?? {}), ...fields, exposure: exposure === "auto" ? null : exposure }
}
