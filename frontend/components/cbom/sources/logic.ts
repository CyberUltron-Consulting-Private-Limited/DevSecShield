// Pure helpers for the CBOM Sources pages (no React, no network) so they can be unit-tested with tsx.

// One request per click burst for the Create node button (see utils/single_flight.ts).
export { singleFlight } from "../../../utils/single_flight"

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

/** The sudoers file download.  Its first lines say `sudo install -m 0440 zs-cbom /etc/sudoers.d/zs-cbom`, so it must
 * save as exactly "zs-cbom": Chromium appends ".txt" to an extensionless text/plain download (zs-cbom.txt), so the
 * file goes out as a generic binary type, which keeps the name as given. */
export const SUDOERS_DOWNLOAD = { filename: "zs-cbom", type: "application/octet-stream" } as const

/** The message for a secret field left blank, or null when blank is fine.  A stored secret is kept only while the
 * targets and the way their identity is checked stay the same (the server clears it otherwise and refuses the save,
 * backend kinds.py where_fields), so then it must be entered again. */
export function blankSecretError(stored: boolean, whereChanged: boolean, missing: string): string | null {
  if (stored && !whereChanged) return null
  return stored ? "Enter it again: the targets, port, login, host key check, vault path or scan node changed" : missing
}

export type DeployMethod = "docker" | "helm" | "ami" | "ova"

/** Names of the Docker container, its state volume and the Helm release for one scan node, taken from the node's
 * name.  They must differ per node: the state volume holds the node's credential, so a second node started with the
 * first node's volume would silently run as the first node (and never register), and a second `docker run` or
 * `helm upgrade --install` under the same name fails or replaces the first node.  Lowercase letters, digits and
 * dashes only (valid for Docker names and Helm release names, at most 53 characters). */
export function nodeInstallNames(nodeName: string): { container: string; volume: string; release: string } {
  const slug = nodeName.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+/, "").slice(0, 40).replace(/-+$/, "")
  if (!slug) return { container: "zs-scan-node", volume: "zs-node", release: "zs-scan-node" }
  return { container: `zs-scan-node-${slug}`, volume: `zs-node-${slug}`, release: `zs-scan-node-${slug}` }
}

export function installCommand(
  method: DeployMethod,
  opts: { token: string; apiUrl: string; proxyUrl?: string | null; image: string; name: string },
): string {
  const proxy = opts.proxyUrl ? opts.proxyUrl : ""
  const names = nodeInstallNames(opts.name)
  if (method === "docker") {
    return [
      `docker run -d --name ${names.container} --restart unless-stopped \\`,
      `  -e ZS_API_URL=${shQuote(opts.apiUrl)} \\`,
      `  -e ZS_REGISTRATION_TOKEN=${shQuote(opts.token)} \\`,
      ...(proxy ? [`  -e HTTPS_PROXY=${shQuote(proxy)} \\`] : []),
      `  -v ${names.volume}:/var/lib/zs-node \\`,
      `  ${opts.image}`,
    ].join("\n")
  }
  if (method === "helm") {
    const [repo, tag] = opts.image.includes(":") ? [opts.image.slice(0, opts.image.lastIndexOf(":")), opts.image.slice(opts.image.lastIndexOf(":") + 1)] : [opts.image, "latest"]
    return [
      `helm upgrade --install ${names.release} oci://registry.zeroshield.ai/charts/cbom-scan-node \\`,
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

/** The server's reason for refusing a request (a 4xx with a ``detail`` sentence, e.g. 403 "User is not in team"), to
 * show instead of a bare "Could not load this section" (lab UI r1: /7/cbom/sources for a team one is not in), as the
 * toasts do since L1 (utils/error-handler.ts). Null for a network error, a 401 (the client signs in again), a 5xx or
 * a detail that is not a sentence (a validation list). */
export function refusalReason(error: unknown): string | null {
  const response = (error as { response?: { status?: unknown; data?: unknown } } | null | undefined)?.response
  const status = typeof response?.status === "number" ? response.status : 0
  if (status < 400 || status >= 500 || status === 401) return null
  const detail = (response?.data as { detail?: unknown } | null | undefined)?.detail
  return typeof detail === "string" && detail.trim() ? detail.trim().slice(0, 300) : null
}

/** "Not read in this run" (lab UI r1 F2): assets of a compared source that the later run did not read because of a
 * coverage gap (a stopped target, a denied check). They are neither removed nor resolved, so they are listed apart,
 * grouped by why they were not read (the coverage row's detail, from the server) and by source. */
export const NOT_READ_NO_REASON = "The scan node reported a coverage gap here"
export function groupNotRead<T extends { reason?: string | null; source_name?: string | null }>(
  items: T[],
): { reason: string; source: string | null; items: T[] }[] {
  const groups = new Map<string, { reason: string; source: string | null; items: T[] }>()
  for (const item of items) {
    const reason = item.reason?.trim() || NOT_READ_NO_REASON
    const source = item.source_name ?? null
    const key = `${source ?? ""}\u0000${reason}`
    const group = groups.get(key) ?? { reason, source, items: [] }
    group.items.push(item)
    groups.set(key, group)
  }
  return [...groups.values()]
}

/** What Reset says for a node of an agent pool (a DaemonSet pod): the server issues it no registration token, since
 * the pod enrolls again by itself with the pool token after its next heartbeat (every 30 s) is refused (lab UI r1 N1:
 * Reset opened "Register <node> again" with a standalone Helm command and a fresh 24-hour token). */
export const POOL_NODE_REENROLLS = "The pod enrolls again by itself within a minute."

/** After New registration token / Reset: the install wizard with the token, or (a pool node, no token) nothing to copy. */
export function registrationOutcome(data: { registration_token: string | null }): { wizard: true; token: string } | { wizard: false; note: string } {
  return data.registration_token ? { wizard: true, token: data.registration_token } : { wizard: false, note: POOL_NODE_REENROLLS }
}

/** A row menu offers "New registration token" only to a standalone node that has not registered; a pool node is
 * never given one (the server refuses), so it is offered Reset instead. */
export function offersRegistrationToken(node: { pool_id?: number | null; status: string }): boolean {
  return node.pool_id == null && (node.status === "pending_registration" || node.status === "registration_expired")
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

/** ``timeZone``: show the moment in that IANA zone (e.g. the team's scan-window zone) instead of the browser's. */
export function formatDateTime(iso: string | null | undefined, timeZone?: string): string {
  if (!iso) return "—"
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return "—"
  const opts: Intl.DateTimeFormatOptions = { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }
  try {
    return d.toLocaleString(undefined, timeZone ? { ...opts, timeZone } : opts)
  } catch {
    return d.toLocaleString(undefined, opts) // an unknown zone name: the browser's zone rather than nothing
  }
}

/** "120 of 254 addresses" for a network range while it runs; null when the scan node does not report it (an older
 * node, another kind of job) or the job is not running, so those rows show what they showed before. */
export function addressProgress(job: { status: string; progress?: { done: number; total: number } | null }): string | null {
  const p = job.progress
  if (job.status !== "claimed" || !p || !Number.isFinite(p.total) || p.total <= 0) return null
  const done = Math.min(Math.max(0, Math.floor(p.done)), p.total)
  return `${done.toLocaleString()} of ${pluralize(p.total, "address", "addresses")}`
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
  const whole = new Uint8Array(await file.arrayBuffer())
  // Trailing NUL bytes are a C string terminator, not binary content: MySQL's own auto-generated ca.pem (the CA a
  // MySQL source asks for) ends with "\n\0" (local lab, round 5).  A NUL anywhere else still means a binary file.
  let end = whole.length
  while (end > 0 && whole[end - 1] === 0) end--
  const buffer = whole.subarray(0, end)
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

/** Review & Run coverage text for the groups whose units mix kinds: a container images source counts its images (not
 * clusters) in the Kubernetes group, and HSMs / key managers count in the Databases group (backend planning.py). */
export function mixedGroupScope(group: "kubernetes" | "databases", byKind: Record<string, number> | undefined, units: number): string {
  const n = (kind: string) => byKind?.[kind] ?? 0
  const parts: string[] = []
  if (group === "kubernetes") {
    const clusters = n("kubernetes")
    if (clusters) parts.push(pluralize(clusters, "cluster"))
    if (n("container_images")) parts.push(pluralize(Math.max(0, units - clusters), "container image"))
    return parts.join(" · ") || pluralize(units, "cluster")
  }
  const keyManagers = n("key_manager")
  const databases = Math.max(0, units - keyManagers)
  if (databases || !keyManagers) parts.push(pluralize(databases, "database"))
  if (keyManagers) parts.push(pluralize(keyManagers, "HSM or key manager", "HSMs or key managers"))
  return parts.join(" · ")
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

/** A plan item's scan-window facts (estimate / overview ``plan.items``). */
export interface WindowedItem {
  status: string
  window_applies?: boolean
  window_starts_at?: string | null
}

/** Scan-node jobs (servers, Kubernetes, databases, network) wait for their scan window; cloud jobs do not. The queued
 * items that will wait, and the earliest moment one of them may start (null when every one starts now). */
export function windowWait(items: WindowedItem[]): { applies: number; waiting: number; firstStart: string | null } {
  const queued = items.filter((i) => i.status === "queued" && i.window_applies)
  const starts = queued.map((i) => i.window_starts_at).filter((s): s is string => !!s).sort()
  return { applies: queued.length, waiting: starts.length, firstStart: starts[0] ?? null }
}

/** The line under a Review & Run row whose sources wait for a scan window (null when none of them has one). */
export function windowLine(items: WindowedItem[]): string | null {
  const w = windowWait(items)
  if (!w.applies) return null
  if (!w.waiting) return "In the scan window now"
  return `Outside the scan window: starts ${formatDateTime(w.firstStart)}`
}

/** Said before Start charges a run: which sources wait for their window and when the first one starts. */
export function windowStartNotice(items: WindowedItem[]): string | null {
  const w = windowWait(items)
  if (!w.waiting) return null
  const who = w.waiting === 1 ? "1 source is" : `${w.waiting} sources are`
  return `${who} outside the scan window. The run is charged now; ${w.waiting === 1 ? "it starts" : "they start"} ` +
    `when the window opens (${formatDateTime(w.firstStart)}${w.waiting > 1 ? " at the earliest" : ""}) and stay ` +
    "queued until then."
}
