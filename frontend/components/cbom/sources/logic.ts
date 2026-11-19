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

/** Header words of a target CSV: the same set as the backend (backend/utilities/cbom_sources/targets.py _HEADER_WORDS,
 * kept equal by sourceFormChecks.test.ts), so a "hosts" or "targets" header is never imported as a target (#151). */
export const TARGET_HEADER_WORDS = ["ip", "ips", "host", "hosts", "hostname", "address", "addresses", "target", "targets", "name"] as const

/** First column of a CSV, the file's own header row dropped (before the rows are added to the box, #151). */
export function csvFirstColumn(text: string): string[] {
  const rows = splitLines(text).map((line) => line.split(/[,;\t]/)[0].trim().replace(/^"|"$/g, ""))
  if (rows.length && (TARGET_HEADER_WORDS as readonly string[]).includes(rows[0].toLowerCase())) rows.shift()
  return rows.filter(Boolean)
}

/** The target box after an import: the box's lines plus the file's, each once; with the line-limit message when the
 * result is over the per-source limit (the same message the box shows when typed, #151). */
export function mergeImportedTargets(box: string, rows: string[], maxLines: number): { text: string; error: string | null } {
  const lines = [...splitLines(box), ...rows].filter((v, i, all) => all.indexOf(v) === i)
  const error = lines.length > maxLines
    ? `${lines.length.toLocaleString("en-US")} lines; the limit is ${maxLines.toLocaleString("en-US")} per source`
    : null
  return { text: lines.join("\n"), error }
}

/** Why pasted or uploaded text is not known_hosts lines (#149: the backend's kinds.check_known_hosts, simplified), or
 * null. A private key is refused before it is ever put in the box. */
export function knownHostsProblem(text: string): string | null {
  if (/PRIVATE KEY/.test(text)) {
    return "This is a private key, not known_hosts lines. Paste the servers' public host keys (ssh-keyscan output)"
  }
  let lines = 0
  const all = text.replace(/\r\n?/g, "\n").split("\n")
  for (let i = 0; i < all.length; i++) {
    const line = all[i].trim()
    if (!line || line.startsWith("#")) continue
    let fields = line.split(/\s+/)
    if (fields[0] === "@cert-authority" || fields[0] === "@revoked") fields = fields.slice(1)
    if (fields.length < 3 || !/^[a-z0-9][a-z0-9@._-]{2,63}$/.test(fields[1]) || !/^[A-Za-z0-9+/]+={0,2}$/.test(fields[2])) {
      return `Line ${i + 1} is not a known_hosts line: expected host, key type and base64 key (ssh-keyscan output)`
    }
    lines++
  }
  return lines ? null : "Paste the known_hosts lines to pin, or choose trust on first use"
}

/** #156: a Windows or Active Directory port that would send the login to a server that is not verified, or null
 * (the backend's kinds.credential_target_problem: WINRM_HTTP_PORTS and AD_NOT_LDAPS_PORTS). */
export function windowsPortProblem(kind: string, port: number): string | null {
  if (kind === "windows_servers" && [80, 5985, 8080].includes(port)) {
    return `${port} is a plain-HTTP port: WinRM over HTTP cannot prove the server; use HTTPS (5986)`
  }
  if (kind === "active_directory" && [389, 3268, 80, 5985, 5986, 8080].includes(port)) {
    return `${port} is not LDAPS: use 636, or 3269 for the global catalog`
  }
  return null
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

/** Why a scan node could not connect with an install command built from this API URL, or null when it can.
 * It mirrors the node's own rule (scan_node/zs_scan_node/agent.py: the stripped ZS_API_URL must start with
 * "https://", exactly, lower case; claim answers carry decrypted credentials), so the wizard warns exactly when the
 * node would exit. Port 80 is the plain-HTTP port: the node accepts the URL but its TLS client cannot connect there.
 * A lower-case http:// URL is the one case the node's lab switch ZS_ALLOW_INSECURE_HTTP=1 accepts (CB-08): the
 * warning says so, and the wizard shows its commands with the switch inside a "Test lab only" block.
 * The commands the wizard shows use this deployment's own API URL, so the customer is told before running one. */
export function insecureApiWarning(apiUrl: string): string | null {
  const value = (apiUrl || "").trim()
  if (!value) return null
  if (!value.startsWith("https://")) {
    if (value.startsWith("http://")) {
      return `This ZeroShield deployment serves its API over plain HTTP (${value}). The scan node refuses http:// unless it is started with ZS_ALLOW_INSECURE_HTTP=1, a test-lab switch that sends your server credentials unencrypted (the commands below carry it inside a "Test lab only" block). Ask your ZeroShield administrator to serve the API over https:// for real use.`
    }
    return `This ZeroShield deployment's API address (${value}) does not start with https:// (lower case), so the scan node refuses it and exits. Ask your ZeroShield administrator for the https:// address of the API.`
  }
  let url: URL
  try {
    url = new URL(value)
  } catch {
    return `This ZeroShield deployment's API address (${value}) is not a valid URL, so a scan node cannot connect with the command below. Ask your ZeroShield administrator for the https:// address of the API.`
  }
  if (url.port === "80") {
    return `This ZeroShield deployment's API address uses port 80 (${value}), the plain-HTTP port: the scan node connects with TLS only and cannot connect there. Ask your ZeroShield administrator for the https:// address of the API.`
  }
  return null
}

/** True when the node's lab switch makes it accept this API URL: agent.py accepts http:// (exact, lower case, after
 * strip) only with ZS_ALLOW_INSECURE_HTTP=1. Then the wizard shows a test-lab command carrying the switch (CB-08). */
export function labSwitchHelps(apiUrl: string): boolean {
  return (apiUrl || "").trim().startsWith("http://")
}

/** zs-ovf-env maps only zs.api_url, zs.registration_token, zs.https_proxy and zs.mode (deploy/node-images). */
export const OVA_NO_INSECURE_SWITCH =
  "The OVA has no plain-HTTP switch, so it cannot reach this deployment: use Docker or Helm for a plain-HTTP test lab, or serve the API over HTTPS."

/** The outbound port a scan node uses to reach this API, or null when a node cannot use the address as it is (never
 * port 80: that is the plain-HTTP port). */
export function nodeApiPort(apiUrl: string): string | null {
  if (insecureApiWarning(apiUrl)) return null
  try {
    return new URL(apiUrl.trim()).port || "443"
  } catch {
    return null
  }
}

/** The scan node image as the wizard offers it. Customers have no access to a ZeroShield registry or to the
 * repository: the server serves the image file (GET /{team}/cbom/node-artifacts, backend/routers/cbom_node_artifacts.py)
 * and the commands load it (`docker load`) and run the name it loads as, with `docker run --pull never`. Only when the
 * server names a registry customers can pull from (CBOM_NODE_IMAGE_REF, or a build's NEXT_PUBLIC_CBOM_NODE_IMAGE) is a
 * pull variant offered too. */
export interface NodeImage {
  /** the image the command runs: the name the image file loads as, or (pull) a registry image */
  image: string
  /** true: from a registry; false (default): from the downloaded image file */
  pull?: boolean
  /** the downloaded image file and Helm chart (the server's names; default scan-node-<tag>.tar.gz, cbom-scan-node-<tag>.tgz) */
  archive?: string
  chart?: string
  /** the server's SHA-256 of the image file and of the chart: written into the command, so the check cannot be skipped
   * by a missing .sha256 file (#228) */
  archiveSha256?: string
  chartSha256?: string
  /** #197: the 40-character commit the image file was built from (manifest build): the tag the Helm commands push it
   * under to the customer's registry carries it (<version>-<sha12>), so a cluster that already holds an older image of
   * the same version (pullPolicy IfNotPresent) never keeps running it */
  build?: string
}

/** The name scripts/release/scan_node_image.sh saves the image under (SCAN_NODE_IMAGE's default) for the scan node's
 * VERSION: what the wizard runs until the server says what its image file holds. */
export const DEFAULT_NODE_IMAGE = "localhost/zeroshield/cbom-scan-node:1.0.1"

/** What the server offers (GET /{team}/cbom/node-artifacts). */
export interface NodeArtifact {
  kind: "image" | "helm-chart" | "ova-kit" | "ami-kit"
  label: string
  available: boolean
  filename: string | null
  size: number | null
  sha256: string | null
  message: string | null
}
export interface NodeArtifacts {
  version: string | null
  /** the 40-character commit the shipped node image was built from, and "<version>+<12 characters>" (staging QA B6-1) */
  build?: string | null
  node_build?: string | null
  image_ref: string | null
  pull_image_ref: string | null
  /** #197: is pull_image_ref this server's node build (backend node_release.image_freshness) */
  pull_image_freshness?: ImageFreshness | null
  /** the Helm chart in the same registry (CBOM_NODE_CHART_REF): oci://... and its version; only with pull_image_ref */
  pull_chart_ref?: string | null
  pull_chart_version?: string | null
  artifacts: NodeArtifact[]
}

/** #197: is a registry image this server's node release? The same rules as the backend's
 * node_release.image_freshness (one table of cases for both: contracts/cbom/node_image_freshness.json), from the tag
 * alone. Since #377 every node-changing promotion is a new release 1.0.N, so the same version is current; 1.0.0 (the
 * version every build claimed before release versions) never is; <prefix>-<sha12> names one commit; staging / dev /
 * stable / latest / pr-<n> / X.Y / no tag are moving tags. */
export type ImageFreshnessState = "current" | "outdated" | "different" | "unverified" | "moving" | "unknown"
export interface ImageFreshness {
  state: ImageFreshnessState
  reason: string | null
  message: string | null
  server_build?: string | null
  tag?: string | null
}
/** The states in which the wizard does not install the registry image: it says why and uses this server's file. */
export const STALE_IMAGE_STATES: readonly ImageFreshnessState[] = ["outdated", "different", "unverified"]
/** scan_node/release.json: releases start at 1.0.1; 1.0.0 named many different builds (node_release.LEGACY_VERSION). */
const LEGACY_NODE_VERSION = "1.0.0"

const SHA_TAG = /^(?:dev|staging|manual|pr-[1-9][0-9]{0,6})-([0-9a-f]{12})(?:-[0-9a-f]{8})?$/
const RELEASE_TAG = /^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$/
const MOVING_TAG = /^(?:dev|staging|stable|latest|main|pr-[1-9][0-9]{0,6}|[0-9]+\.[0-9]+|[0-9]+)$/

/** -1 / 0 / 1 for two semver-like versions (a pre-release before its release), null when either is not one. */
export function compareNodeVersions(a: string, b: string): number | null {
  if (a === b) return 0
  const parse = (v: string) => {
    const m = /^([0-9]+(?:\.[0-9]+)*)(?:-([0-9A-Za-z.-]+))?$/.exec(v)
    return m ? { core: m[1].split(".").map(Number), pre: m[2] ?? null } : null
  }
  const x = parse(a), y = parse(b)
  if (!x || !y) return null
  const width = Math.max(x.core.length, y.core.length, 3)
  for (let i = 0; i < width; i++) {
    const d = (x.core[i] ?? 0) - (y.core[i] ?? 0)
    if (d) return d < 0 ? -1 : 1
  }
  if (x.pre === y.pre) return 0
  if (x.pre === null) return 1
  if (y.pre === null) return -1
  const xp = x.pre.split("."), yp = y.pre.split(".")
  for (let i = 0; i < Math.max(xp.length, yp.length); i++) {
    if (xp[i] === undefined) return -1
    if (yp[i] === undefined) return 1
    if (xp[i] === yp[i]) continue
    const xn = /^[0-9]+$/.test(xp[i]), yn = /^[0-9]+$/.test(yp[i])
    if (xn && yn) return Number(xp[i]) < Number(yp[i]) ? -1 : 1
    if (xn !== yn) return xn ? -1 : 1
    return xp[i] < yp[i] ? -1 : 1
  }
  return 0
}

export function imageFreshness(ref: string | null | undefined, serverVersion: string | null | undefined,
  serverBuild: string | null | undefined): ImageFreshness | null {
  const image = (ref ?? "").trim()
  if (!image) return null
  const [, tag] = splitImage(image.split("@")[0])
  const build = serverBuild && /^[0-9a-f]{40}$/.test(serverBuild) ? serverBuild : null
  const server = serverVersion ? (build ? `${serverVersion}+${build.slice(0, 12)}` : serverVersion) : null
  const say = (state: ImageFreshnessState, reason: string, message: string | null): ImageFreshness =>
    ({ state, reason, message, server_build: server, tag })
  if (!serverVersion) return say("unknown", "no_server_build", null)
  if (RELEASE_TAG.test(tag)) {
    const order = compareNodeVersions(tag, serverVersion)
    if (order !== null && order < 0) return say("outdated", "older_version", `${image} is scan node ${tag}, older than this server's node release ${server}.`)
    if (order !== null && order > 0) return say("different", "newer_version", `${image} is scan node ${tag}, newer than this server's node release ${server}.`)
    if (tag === LEGACY_NODE_VERSION) {
      return say("unverified", "legacy_version", `${image} is ${tag}, the version every scan node build reported before release versions existed: it cannot be shown to be this server's node build ${server}.`)
    }
    return say("current", "same_version", null)
  }
  const sha = SHA_TAG.exec(tag)
  if (sha) {
    if (!build) return say("unknown", "no_server_build_id", null)
    if (build.startsWith(sha[1])) return say("current", "same_build", null)
    return say("unverified", "other_commit", `${image} was built from commit ${sha[1]}: it cannot be shown to be this server's node release ${server}.`)
  }
  if (MOVING_TAG.test(tag)) {
    return say("moving", "moving_tag", `${image} is a moving tag: it names whatever was published last, which may not be this server's node release ${server}.`)
  }
  return say("unknown", "unrecognised_tag", null)
}

/** The registry image the wizard would install and what it is against the server's node build. */
export interface RegistryImage { image: string; freshness: ImageFreshness | null; stale: boolean }

/** The image the commands load and run, and the registry image when one is configured. #197: a registry image that
 * is not this server's node build (STALE_IMAGE_STATES) is never offered (`pulled` null): `registry` says what it is,
 * and the commands use this server's image file, which is its node build by definition. */
export function nodeImages(data: NodeArtifacts | undefined | null, buildPullRef?: string | null):
  { loaded: NodeImage; pulled: NodeImage | null; registry: RegistryImage | null } {
  const found = (kind: NodeArtifact["kind"]) => data?.artifacts.find((a) => a.kind === kind && a.available) ?? null
  const sha = (kind: NodeArtifact["kind"]) => {
    const value = found(kind)?.sha256
    return value && /^[0-9a-f]{64}$/.test(value) ? value : undefined
  }
  const build = data?.build && /^[0-9a-f]{40}$/.test(data.build) ? data.build : undefined
  const loaded: NodeImage = {
    image: data?.image_ref || DEFAULT_NODE_IMAGE, pull: false, archive: found("image")?.filename ?? undefined,
    chart: found("helm-chart")?.filename ?? undefined, archiveSha256: sha("image"), chartSha256: sha("helm-chart"), build,
  }
  const serverRef = (data?.pull_image_ref || "").trim()
  const ref = (serverRef || buildPullRef || "").trim()
  if (!ref) return { loaded, pulled: null, registry: null }
  // the server's own verdict on its registry image; the build's image (NEXT_PUBLIC_CBOM_NODE_IMAGE) is judged here
  const freshness = serverRef && data?.pull_image_freshness !== undefined
    ? data.pull_image_freshness
    : imageFreshness(ref, data?.version, build)
  const stale = !!freshness && STALE_IMAGE_STATES.includes(freshness.state)
  return {
    loaded,
    pulled: stale ? null : { image: ref, pull: true, chart: loaded.chart, chartSha256: loaded.chartSha256 },
    registry: { image: ref, freshness, stale },
  }
}

/** The tag a downloaded image is pushed under to the customer's registry: <tag>-<sha12> when the server names the
 * commit it was built from (#197), so a new build never reuses the tag of an older one of the same version. */
export function pushTag(img: NodeImage): string {
  const [, tag] = splitImage(img.image)
  return !img.pull && img.build && /^[0-9a-f]{40}$/.test(img.build) ? `${tag}-${img.build.slice(0, 12)}` : tag
}

function splitImage(image: string): [string, string] {
  const cut = image.lastIndexOf(":")
  return cut > image.lastIndexOf("/") ? [image.slice(0, cut), image.slice(cut + 1)] : [image, "latest"]
}

/** The files a loaded-image command names. */
export function nodeFiles(img: NodeImage): { archive: string; chart: string; tag: string } {
  const [, tag] = splitImage(img.image)
  return { archive: img.archive || `scan-node-${tag}.tar.gz`, chart: img.chart || `cbom-scan-node-${tag}.tgz`, tag }
}

/** Where the Helm chart comes from and which image it runs: the downloaded chart always; the image either pushed by
 * the customer to their own registry ($REGISTRY, set in the first line) or the configured registry image. */
/** The check of a downloaded file, written to gate the next command (`check && \`): the server's SHA-256 inline when
 * known (a missing .sha256 file cannot skip it), else the file's .sha256 (missing: sha256sum fails, nothing runs). */
export function checkFile(file: string, sha256?: string): string {
  return sha256 && /^[0-9a-f]{64}$/.test(sha256) ? `echo '${sha256}  ${file}' | sha256sum -c -` : `sha256sum -c ${file}.sha256`
}

/** Where the Helm chart comes from and which image it runs: the downloaded chart always; the image either pushed by
 * the customer to their own registry ($REGISTRY, set in the first line) or the configured registry image. Every
 * step is chained with && from the checks on (#228): a file that fails its SHA-256 check is never loaded, pushed or
 * installed. */
function helmSource(img: NodeImage): { steps: string[]; chart: string; repoArg: string; tag: string } {
  const { archive, chart } = nodeFiles(img)
  const chartCheck = `${checkFile(chart, img.chartSha256)} && \\`
  if (img.pull) {
    const [repo, ptag] = splitImage(img.image)
    return {
      steps: ["# The chart you downloaded (Download Helm chart); nothing is installed if its check fails:", chartCheck],
      chart: `./${chart}`, repoArg: shQuote(repo), tag: ptag,
    }
  }
  const base = splitImage(img.image)[0].split("/").pop() || "cbom-scan-node"
  const pushed = pushTag(img)
  return {
    steps: [
      "# The image file and the chart you downloaded (Download scan node image, Download Helm chart): the image is pushed",
      "# to a registry your cluster pulls from, then the chart installed. Nothing is loaded, pushed or installed if a check fails.",
      "REGISTRY=registry.example.internal/zeroshield   # change to your registry",
      `${checkFile(archive, img.archiveSha256)} && \\`,
      chartCheck,
      `docker load -i ${archive} && \\`,
      `docker tag ${img.image} "$REGISTRY/${base}:${pushed}" && \\`,
      `docker push "$REGISTRY/${base}:${pushed}" && \\`,
    ],
    chart: `./${chart}`,
    repoArg: `"$REGISTRY/${base}"`,
    tag: pushed,
  }
}

/** How the node trusts the ZeroShield API (CB-15): a private CA bundle (ZS_CA_FILE) and/or a client certificate when
 * the API requires mTLS (ZS_CLIENT_CERT / ZS_CLIENT_KEY). Docker and Helm read the files from the paths given here
 * (absolute host paths); the AMI and OVA read them from TRUST_DIR on the VM. The files never leave the host. */
export interface NodeTrust {
  caFile?: string | null
  clientCert?: string | null
  clientKey?: string | null
}
/** Where the node reads the trust files: inside the container (Docker, VM kits), and the VM directory zs-node-run mounts. */
export const TRUST_DIR = "/etc/zs-node/trust"
export const TRUST_PATHS = { ca: `${TRUST_DIR}/ca.pem`, cert: `${TRUST_DIR}/client.crt`, key: `${TRUST_DIR}/client.key`,
  proxyAuth: `${TRUST_DIR}/proxy-auth` }
/** The Helm Secrets the wizard's command creates (chart values trust.caSecret / trust.clientSecret / proxyAuthSecret). */
export const TRUST_SECRETS = { ca: "zs-node-ca", client: "zs-node-client", proxyAuth: "zs-node-proxy-auth" }
/** #199: the file the install command writes the proxy login to (user:password, 0400 for the node's user): the
 * password is typed on the host with `read -s`, never in ZeroShield, the command, the shell history or the env. */
export const PROXY_AUTH_FILE = "zs-proxy-auth"
/** #196: the node's CA bundle when both a private API CA and the inspecting proxy's CA are given. */
export const CA_BUNDLE_FILE = "zs-node-ca.pem"
/** The node container's user (Dockerfile USER 10001): the owner of the 0400 files it reads. */
const NODE_UID = 10001

function given(v: string | null | undefined): string | null {
  const t = (v ?? "").trim()
  return t ? t : null
}

/** What is wrong with the trust options, or null: absolute paths only (a Docker bind mount needs one), and a client
 * certificate always with its key. */
export function trustProblem(t: NodeTrust | null | undefined): string | null {
  if (!t) return null
  const ca = given(t.caFile), cert = given(t.clientCert), key = given(t.clientKey)
  if (!!cert !== !!key) return "Give both the client certificate and its key, or neither."
  for (const [label, v] of [["CA bundle", ca], ["Client certificate", cert], ["Client key", key]] as const) {
    if (v && (!v.startsWith("/") || /[\s'"$`\\]/.test(v))) return `${label}: an absolute path on the host, without spaces or quotes.`
  }
  return null
}

/** The trust options in use (empty paths dropped), or null when none is set or they are invalid. */
export function activeTrust(t: NodeTrust | null | undefined): Required<NodeTrust> | null {
  if (!t || trustProblem(t)) return null
  const out = { caFile: given(t.caFile), clientCert: given(t.clientCert), clientKey: given(t.clientKey) }
  return out.caFile || out.clientCert ? out : null
}

/** KEY=value lines of the trust options for an env file (AMI cloud-config, OVA): the files sit in TRUST_DIR on the VM. */
export function trustEnvLines(t: NodeTrust | null | undefined): string[] {
  const a = activeTrust(t)
  if (!a) return []
  return [
    ...(a.caFile ? [`ZS_CA_FILE=${TRUST_PATHS.ca}`] : []),
    ...(a.clientCert ? [`ZS_CLIENT_CERT=${TRUST_PATHS.cert}`, `ZS_CLIENT_KEY=${TRUST_PATHS.key}`] : []),
  ]
}

/** `docker run` options: the env and read-only bind mounts of the files (the API CA from apiCa: #196). */
function trustDockerLines(t: NodeTrust | null | undefined, ca: string | null = null): string[] {
  const a = activeTrust(t)
  return [
    ...(ca ? [`  -e ZS_CA_FILE=${TRUST_PATHS.ca} -v ${ca}:${TRUST_PATHS.ca}:ro \\`] : []),
    ...(a?.clientCert ? [
      `  -e ZS_CLIENT_CERT=${TRUST_PATHS.cert} -v ${a.clientCert}:${TRUST_PATHS.cert}:ro \\`,
      `  -e ZS_CLIENT_KEY=${TRUST_PATHS.key} -v ${a.clientKey}:${TRUST_PATHS.key}:ro \\`,
    ] : []),
  ]
}

/** Helm: the Secrets made from the files (before the install, each step chained with &&) and the chart values. */
function trustHelm(opts: NodeCommandOpts): { pre: string[]; sets: string[] } {
  const a = activeTrust(opts.trust)
  const ca = apiCa(opts)
  const auth = !!given(opts.proxyUser)
  if (!ca.local && !a?.clientCert && !auth) return { pre: [], sets: [] }
  const apply = "--dry-run=client -o yaml | kubectl apply -f - && \\"
  return {
    pre: [
      ...ca.pre,
      "kubectl create namespace zs-cbom --dry-run=client -o yaml | kubectl apply -f - && \\",
      ...(ca.local ? [`kubectl -n zs-cbom create secret generic ${TRUST_SECRETS.ca} --from-file=ca.pem=${ca.local} ${apply}`] : []),
      ...(a?.clientCert ? [`kubectl -n zs-cbom create secret tls ${TRUST_SECRETS.client} --cert=${a.clientCert} --key=${a.clientKey} ${apply}`] : []),
      // #199: the login goes into a Secret (mounted 0440 for the node's group) and the file leaves this host
      ...(auth ? [`kubectl -n zs-cbom create secret generic ${TRUST_SECRETS.proxyAuth} --from-file=auth=${PROXY_AUTH_FILE} ${apply}`,
        `rm -f ${PROXY_AUTH_FILE} && \\`] : []),
    ],
    sets: [
      ...(ca.local ? [`  --set trust.caSecret=${TRUST_SECRETS.ca} \\`] : []),
      ...(a?.clientCert ? [`  --set trust.clientSecret=${TRUST_SECRETS.client} \\`] : []),
      ...(auth ? [`  --set proxyAuthSecret=${TRUST_SECRETS.proxyAuth} \\`] : []),
    ],
  }
}

type NodeCommandOpts = {
  token: string; apiUrl: string; proxyUrl?: string | null; image: string; name: string; insecureHttp?: boolean; trust?: NodeTrust | null
  /** #196: the TLS-inspecting proxy's CA file name in this directory (only when the proxy inspects TLS and its CA was
   * given): the node trusts it for the ZeroShield API (ZS_CA_FILE), with the private CA when there is one too */
  caFile?: string | null
  /** #199: the proxy's user name when it needs a login (the password is typed on the host: proxyAuthCreate) */
  proxyUser?: string | null
  /** #197: the commit the downloaded image file was built from (NodeImage.build): the Helm push tag carries it */
  build?: string | null
}

/** #196: where the node's API CA comes from: the private CA path (CB-15), the proxy's CA file here, or both bundled. */
function apiCa(opts: NodeCommandOpts): { pre: string[]; host: string | null; local: string | null } {
  const priv = activeTrust(opts.trust)?.caFile ?? null
  const proxyCa = given(opts.caFile)
  if (priv && proxyCa) {
    return { pre: [`cat ${priv} ./${proxyCa} > ${CA_BUNDLE_FILE} && \\`], host: `"$PWD/${CA_BUNDLE_FILE}"`, local: `./${CA_BUNDLE_FILE}` }
  }
  if (proxyCa) return { pre: [], host: `"$PWD/${proxyCa}"`, local: `./${proxyCa}` }
  return { pre: [], host: priv, local: priv }
}

/** #199: the lines that make the proxy login file on the host, first in every command (the downloads use it too). */
export function proxyAuthCreate(user: string | null | undefined): string[] {
  const u = given(user)
  if (!u) return []
  return [
    `# The proxy password stays on this host: typed here (not shown, not in the shell history), kept in ${PROXY_AUTH_FILE}`,
    `read -rsp ${shQuote(`Password of proxy user ${u}: `)} ZS_PROXY_PW && echo && \\`,
    `( umask 077 && printf '%s:%s\\n' ${shQuote(u)} "$ZS_PROXY_PW" > ${PROXY_AUTH_FILE} ) && unset ZS_PROXY_PW && \\`,
  ]
}

/** `docker run` of one node (pullNever: the image was just loaded from the file, never one from a registry). */
function dockerRunLines(opts: NodeCommandOpts, pullNever: boolean): string[] {
  const proxy = opts.proxyUrl ? opts.proxyUrl : ""
  const names = nodeInstallNames(opts.name)
  const ca = apiCa(opts)
  const auth = !!given(opts.proxyUser)
  return [
    ...ca.pre,
    // #199: the login file (made first: proxyAuthCreate) is handed to the node's user, read-only
    ...(auth ? [`chmod 0400 ${PROXY_AUTH_FILE} && sudo chown ${NODE_UID} ${PROXY_AUTH_FILE} && \\`] : []),
    `docker run -d${pullNever ? " --pull never" : ""} --name ${names.container} --restart unless-stopped \\`,
    `  -e ZS_API_URL=${shQuote(opts.apiUrl)} \\`,
    `  -e ZS_REGISTRATION_TOKEN=${shQuote(opts.token)} \\`,
    ...(opts.insecureHttp ? ["  -e ZS_ALLOW_INSECURE_HTTP=1 \\"] : []),
    ...(proxy ? [`  -e HTTPS_PROXY=${shQuote(proxy)} \\`] : []),
    ...(auth ? [`  -e ZS_PROXY_AUTH_FILE=${TRUST_PATHS.proxyAuth} -v "$PWD/${PROXY_AUTH_FILE}":${TRUST_PATHS.proxyAuth}:ro \\`] : []),
    ...trustDockerLines(opts.trust, ca.host),
    `  -v ${names.volume}:/var/lib/zs-node \\`,
    `  ${opts.image}`,
  ]
}

/** `helm upgrade --install` of one node from <chart> (a downloaded .tgz or an oci:// reference with its --version). */
function helmInstallLines(release: string, chart: string, repoArg: string, tag: string, opts: NodeCommandOpts): string[] {
  const proxy = opts.proxyUrl ? opts.proxyUrl : ""
  const trust = trustHelm(opts)
  return [
    ...trust.pre,
    `helm upgrade --install ${release} ${chart} \\`,
    "  --namespace zs-cbom --create-namespace \\",
    `  --set image.repository=${repoArg} --set image.tag=${shQuote(tag)} \\`,
    `  --set apiUrl=${shQuote(opts.apiUrl)} \\`,
    ...(opts.insecureHttp ? ["  --set allowInsecureHttp=true \\"] : []),
    ...trust.sets,
    `  --set registrationToken=${shQuote(opts.token)}${proxy ? " \\" : ""}`,
    ...(proxy ? [`  --set httpsProxy=${shQuote(proxy)}`] : []),
  ]
}

export function installCommand(
  method: DeployMethod,
  opts: NodeCommandOpts & { pull?: boolean; archive?: string; chart?: string; archiveSha256?: string; chartSha256?: string },
): string {
  const proxy = opts.proxyUrl ? opts.proxyUrl : ""
  const names = nodeInstallNames(opts.name)
  const img: NodeImage = { image: opts.image, pull: opts.pull, archive: opts.archive, chart: opts.chart,
    archiveSha256: opts.archiveSha256, chartSha256: opts.chartSha256, build: opts.build ?? undefined }
  if (method === "docker") {
    const { archive } = nodeFiles(img)
    return [
      ...proxyAuthCreate(opts.proxyUser),
      ...(opts.pull ? [] : [
        "# Check, load and run the image file you downloaded (Download scan node image); nothing is loaded or run if",
        "# the check fails. --pull never: the image just loaded, never one from a registry.",
        `${checkFile(archive, img.archiveSha256)} && \\`,
        `docker load -i ${archive} && \\`,
      ]),
      ...dockerRunLines(opts, !opts.pull),
    ].join("\n")
  }
  if (method === "helm") {
    const src = helmSource(img)
    return [...proxyAuthCreate(opts.proxyUser), ...src.steps, ...helmInstallLines(names.release, src.chart, src.repoArg, src.tag, opts)].join("\n")
  }
  if (method === "ami") {
    return [
      "#cloud-config  (paste as EC2 user data when you launch the scan node AMI you built with the AMI build kit)",
      "write_files:",
      "  - path: /etc/zs-node/env",
      "    permissions: '0600'",
      "    content: |",
      `      ZS_API_URL=${opts.apiUrl}`,
      `      ZS_REGISTRATION_TOKEN=${opts.token}`,
      ...(opts.insecureHttp ? ["      ZS_ALLOW_INSECURE_HTTP=1"] : []),
      ...(proxy ? [`      HTTPS_PROXY=${proxy}`] : []),
      ...vmEnvLines(opts).map((l) => `      ${l}`),
      ...(vmFiles(opts).length ? [
        `# Put the trust files in ${TRUST_DIR}/ on the instance before the node starts (the key and the proxy password never in user data):`,
        ...vmFiles(opts).map((l) => `#   ${l}`),
      ] : []),
    ].join("\n")
  }
  return [
    "# OVA (VMware): set these vApp properties when you deploy the OVA you built with the OVA build kit",
    `zs.api_url = ${opts.apiUrl}`,
    `zs.registration_token = ${opts.token}`,
    ...(proxy ? [`zs.https_proxy = ${proxy}`] : []),
    ...(vmFiles(opts).length ? [
      `# Then on the VM: put the trust files in ${TRUST_DIR}/, add these lines to /etc/zs-node/env and restart the node:`,
      ...vmFiles(opts).map((l) => `#   ${l}`),
      ...vmEnvLines(opts).map((l) => `#   ${l}`),
      "#   sudo systemctl restart zs-scan-node",
    ] : []),
  ].join("\n")
}

/** AMI / OVA env lines: the CB-15 trust options, the proxy's CA (#196) and the proxy login file (#199). */
export function vmEnvLines(opts: NodeCommandOpts): string[] {
  const lines = trustEnvLines(opts.trust)
  const withCa = given(opts.caFile) && !lines.some((l) => l.startsWith("ZS_CA_FILE=")) ? [`ZS_CA_FILE=${TRUST_PATHS.ca}`] : []
  return [...withCa, ...lines, ...(given(opts.proxyUser) ? [`ZS_PROXY_AUTH_FILE=${TRUST_PATHS.proxyAuth}`] : [])]
}

/** AMI / OVA: which file goes where on the VM, the proxy's CA and login included. */
export function vmFiles(opts: NodeCommandOpts): string[] {
  const proxyCa = given(opts.caFile)
  const priv = activeTrust(opts.trust)?.caFile
  const files = vmTrustFiles(opts.trust).filter((l) => !(proxyCa && l.startsWith(TRUST_PATHS.ca)))
  const user = given(opts.proxyUser)
  return [
    ...(proxyCa ? [`${TRUST_PATHS.ca}: ${priv ? `your CA bundle followed by your proxy's CA (${proxyCa}): cat them into one file` : `your proxy's CA (${proxyCa})`}`] : []),
    ...files,
    ...(user ? [`${TRUST_PATHS.proxyAuth}: one line ${user}:<proxy password>, made on the VM (sudo install -m 0400 -o ${NODE_UID} /dev/null ${TRUST_PATHS.proxyAuth}, then write it with read -s and printf, never in user data)`] : []),
  ]
}

/** Which file goes where on an AMI / OVA VM (TRUST_DIR, read by the node's user, uid 10001). */
export function vmTrustFiles(t: NodeTrust | null | undefined): string[] {
  const a = activeTrust(t)
  if (!a) return []
  return [
    ...(a.caFile ? [`${TRUST_PATHS.ca} (your CA bundle)`] : []),
    ...(a.clientCert ? [`${TRUST_PATHS.cert} and ${TRUST_PATHS.key} (chown 10001 and chmod 0400 the key)`] : []),
  ]
}

/** One file of a node's install links (POST /nodes, /registration-token, /reset: install_links; backend
 * routers/cbom_node_artifacts.py install_links): a link that works only while the node's registration token does. */
export interface InstallFile {
  kind: NodeArtifact["kind"]
  filename: string
  size: number
  sha256: string
  /** a path on the API: /<team>/cbom/node-artifacts/<kind>?node_ticket=... */
  url: string
}
export interface InstallLinks {
  version: string | null
  expires_at: string | null
  files: InstallFile[]
}

export type Fetcher = "curl" | "wget"

/** The proxy CA a TLS-inspecting proxy needs, as a file next to the command; curl/wget use it for these downloads
 * from ZeroShield only (--cacert / --ca-certificate apply to that one command, nothing is installed system-wide). */
export const DEFAULT_PROXY_CA_FILE = "zs-proxy-ca.pem"

export interface FetchOpts {
  apiUrl: string
  proxyUrl?: string | null
  /** set only when the proxy inspects TLS and its CA was given (the wizard's "trust its CA only for ZeroShield
   * hostnames"): the CA file's name on the host */
  caFile?: string | null
  fetcher?: Fetcher
  /** a plain-HTTP test-lab API (CB-08): curl may not be held to https */
  insecureHttp?: boolean
  /** #199: the proxy needs a login: read from PROXY_AUTH_FILE (made by proxyAuthCreate) through a config on stdin
   * (curl -K -) or a process substitution (wget --config), never on the command line */
  proxyUser?: string | null
}

/** Download one install file from ZeroShield and check it: `curl ... -o <file> && echo '<sha256>  <file>' | sha256sum -c -`
 * (or wget). The proxy and CA settings of the wizard apply; the link goes to the ZeroShield API only. */
export function fetchCommand(file: InstallFile, o: FetchOpts): string {
  const url = shQuote(`${o.apiUrl.trim().replace(/\/+$/, "")}${file.url}`)
  const proxy = o.proxyUrl?.trim() || ""
  const login = !!proxy && !!given(o.proxyUser)
  const parts = (o.fetcher ?? "curl") === "wget"
    ? ["wget -q", ...(login ? [`--config=<(awk -F: '{print "proxy_user = " $1; sub(/^[^:]*:/, ""); print "proxy_password = " $0}' ${PROXY_AUTH_FILE})`] : []),
      ...(proxy ? ["-e use_proxy=yes", `-e https_proxy=${shQuote(proxy)}`] : []),
      ...(o.caFile ? [`--ca-certificate=${shQuote(o.caFile)}`] : []), `-O ${file.filename}`, url]
    : ["curl -fsSL", ...(login ? ["-K -"] : []), o.insecureHttp ? "--proto '=http,https'" : "--proto '=https'", ...(proxy ? [`--proxy ${shQuote(proxy)}`] : []),
      ...(o.caFile ? [`--cacert ${shQuote(o.caFile)}`] : []), url, `-o ${file.filename}`]
  // curl -K - reads proxy-user "user:password" from stdin (quotes and backslashes escaped), never from argv
  const feed = login && (o.fetcher ?? "curl") !== "wget"
    ? `sed 's/[\\\\"]/\\\\&/g; s/^/proxy-user = "/; s/$/"/' ${PROXY_AUTH_FILE} | ` : ""
  return `${feed}${parts.join(" ")} && echo '${file.sha256}  ${file.filename}' | sha256sum -c -`
}

/** The one-paste install of a node on a terminal-only host: fetch its files from ZeroShield with its install links,
 * check their SHA-256, then load and run (Docker), push and install (Helm), or unzip and build (OVA/AMI kits). Null
 * when the server sent no links or not every file the method needs. */
export function onePasteInstall(
  method: DeployMethod,
  links: InstallLinks | null | undefined,
  opts: NodeCommandOpts & FetchOpts,
): string | null {
  const file = (kind: NodeArtifact["kind"]) => links?.files.find((f) => f.kind === kind) ?? null
  const image = file("image")
  if (!image) return null
  const fetch = (f: InstallFile) => `${fetchCommand(f, opts)} && \\`
  const tool = (opts.fetcher ?? "curl") === "wget" ? "wget" : "curl"
  const ca = opts.caFile
    ? [`# ${opts.caFile}: your proxy's CA certificate (the file you uploaded), in this directory; ${tool} trusts it for these downloads only`]
    : []
  const auth = proxyAuthCreate(opts.proxyUser)
  if (method === "docker") {
    return [
      ...auth,
      ...ca,
      fetch(image),
      `docker load -i ${image.filename} && \\`,
      ...dockerRunLines(opts, true),
    ].join("\n")
  }
  if (method === "helm") {
    const chart = file("helm-chart")
    if (!chart) return null
    const [repo] = splitImage(opts.image)
    const base = repo.split("/").pop() || "cbom-scan-node"
    const tag = pushTag({ image: opts.image, build: opts.build ?? undefined })
    return [
      "REGISTRY=registry.example.internal/zeroshield   # change to the registry your cluster pulls from",
      ...auth,
      ...ca,
      fetch(image),
      fetch(chart),
      `docker load -i ${image.filename} && \\`,
      `docker tag ${opts.image} "$REGISTRY/${base}:${tag}" && \\`,
      `docker push "$REGISTRY/${base}:${tag}" && \\`,
      ...helmInstallLines(nodeInstallNames(opts.name).release, `./${chart.filename}`, `"$REGISTRY/${base}"`, tag, opts),
    ].join("\n")
  }
  const kit = file(method === "ova" ? "ova-kit" : "ami-kit")
  if (!kit) return null
  const dir = kit.filename.replace(/\.zip$/, "")
  const template = method === "ova" ? "ova.pkr.hcl" : "ami.pkr.hcl"
  const build = method === "ova"
    ? `packer build -var build_password="$(openssl rand -hex 16)" ${template}`
    : `packer build -var region="\${AWS_REGION:-ap-south-1}" ${template}   # your region; AWS credentials from the environment`
  return [
    `# Build the ${method === "ova" ? "OVA" : "AMI"} once (needs ${tool}, unzip and Packer; the kit's README.md has the details):`,
    ...auth,
    ...ca,
    fetch(kit),
    fetch(image),
    `unzip -q ${kit.filename} && mv ${image.filename} ${dir}/ && cd ${dir} && \\`,
    `packer init ${template} && ${build}`,
  ].join("\n")
}

/** The node from a registry customers can pull from (only when the server names one: CBOM_NODE_IMAGE_REF, set by the
 * staging deploy only while the GHCR packages are public): `docker pull` + `docker run`, or Helm straight from the
 * chart's oci:// reference. Null when the server names no such image (or, for Helm, no chart). */
export function registryInstall(
  method: DeployMethod,
  data: NodeArtifacts | null | undefined,
  opts: Omit<NodeCommandOpts, "image">,
): string | null {
  const image = data?.pull_image_ref?.trim()
  if (!image) return null
  if (method === "docker") {
    return [...proxyAuthCreate(opts.proxyUser), `docker pull ${image} && \\`, ...dockerRunLines({ ...opts, image }, false)].join("\n")
  }
  if (method === "helm") {
    const chart = data?.pull_chart_ref?.trim()
    const version = data?.pull_chart_version?.trim()
    if (!chart || !version) return null
    const [repo, tag] = splitImage(image)
    return [...proxyAuthCreate(opts.proxyUser), ...helmInstallLines(nodeInstallNames(opts.name).release,
      `${chart} --version ${shQuote(version)}`, shQuote(repo), tag, { ...opts, image })].join("\n")
  }
  return null
}

/** How far each way of running a node has been proven. Docker and the Helm chart (Deployment and the agent
 * DaemonSet) ran end to end on k3s; the AMI and OVA are Packer build kits the customer downloads and builds. */
export const DEPLOY_SUPPORT: Record<DeployMethod, { proven: boolean; note: string }> = {
  docker: { proven: true, note: "Proven" },
  helm: { proven: true, note: "Proven on Kubernetes (k3s): Deployment and agent DaemonSet" },
  ami: { proven: false, note: "Packer build kit: download it below and build the AMI in your AWS account" },
  ova: { proven: false, note: "Packer build kit: download it below and build the OVA on your build machine" },
}

/** The three steps under a build kit's download button (Add scan node, OVA and AMI). */
export const KIT_STEPS: Record<"ova" | "ami", string[]> = {
  ova: [
    "Download the OVA build kit and the scan node image file, unzip the kit, put the image file and its .sha256 in its folder and check it: sha256sum -c must print OK (never build from a file that fails).",
    "On a Linux machine with KVM, qemu-img and Packer: packer init ova.pkr.hcl, then packer build -var build_password=<random> ova.pkr.hcl (the kit's README.md has the details).",
    "Deploy the OVA in vSphere and set the vApp properties shown after you create the node.",
  ],
  ami: [
    "Download the AMI build kit and the scan node image file, unzip the kit, put the image file and its .sha256 in its folder and check it: sha256sum -c must print OK (never build from a file that fails).",
    "With Packer and AWS credentials: packer init ami.pkr.hcl, then packer build -var region=<your region> ami.pkr.hcl (the kit's README.md has the details).",
    "Launch the AMI in the VPC that reaches your targets, with the cloud-config shown after you create the node as user data.",
  ],
}

/** The OVA/AMI build needs internet access (#230): the wizard says so next to the kit, with the offline ways. */
export const KIT_NEEDS_INTERNET: Record<"ova" | "ami", string> = {
  ova: "Building the OVA needs internet access on the build machine: it downloads the Ubuntu 24.04 cloud image (cloud-images.ubuntu.com), Packer's plugin (packer init, from GitHub) and Ubuntu packages (apt-get: Docker and updates). No internet there? Use the Docker image file (docker load on any Linux host with Docker), or the Helm chart with the image pushed to your own registry: neither needs internet at install time.",
  ami: "Building the AMI needs internet access: Packer's plugin (packer init, from GitHub), AWS APIs, Canonical's Ubuntu 24.04 AMI, and Ubuntu packages (apt-get: Docker and updates) on the build instance. No internet there? Use the Docker image file (docker load on any Linux host with Docker), or the Helm chart with the image pushed to your own registry: neither needs internet at install time.",
}

/** What needs network access, for restricted networks (#230): shown on the Scan nodes tab. */
export const NETWORK_REQUIREMENTS: string[] = [
  "A scan node always needs outbound HTTPS to the ZeroShield API (nothing calls in) and DNS (port 53) to your resolver; it reaches your targets directly.",
  "Installing it from the image file or the Helm chart (both downloaded from ZeroShield) needs nothing else; pulling the image from a public registry, when the page offers it, needs access to that registry.",
  "Building the OVA or AMI from the build kits needs internet access (Ubuntu image, Packer plugin, Ubuntu packages).",
  "Cloud and identity sources (AWS, Azure, GCP, Oracle Cloud, IdPs) are read from ZeroShield's servers, so those providers' APIs must be reachable from ZeroShield.",
]

/** The downloads Add scan node offers for each way of running a node, main one first. */
export function downloadKinds(method: DeployMethod): NodeArtifact["kind"][] {
  if (method === "helm") return ["helm-chart", "image"]
  if (method === "ova") return ["ova-kit", "image"]
  if (method === "ami") return ["ami-kit", "image"]
  return ["image"]
}

const DOWNLOAD_LABEL: Record<NodeArtifact["kind"], string> = {
  image: "Download scan node image",
  "helm-chart": "Download Helm chart",
  "ova-kit": "Download OVA build kit",
  "ami-kit": "Download AMI build kit",
}

/** "79.6 MB"; a file under 1 MB in KB ("10 KB"), so a small build kit is never labelled "0.0 MB". */
export function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${bytes > 0 ? Math.max(1, Math.round(bytes / 1024)) : 0} KB`
}

/** "Download scan node image (63.2 MB, sha256 3f9a1c2b7d4e…)"; without its size and hash while the server does
 * not hold the file. */
export function downloadLabel(kind: NodeArtifact["kind"], artifact?: NodeArtifact | null): string {
  const base = DOWNLOAD_LABEL[kind]
  if (!artifact?.available || artifact.size == null) return base
  return artifact.sha256 ? `${base} (${formatSize(artifact.size)}, sha256 ${artifact.sha256.slice(0, 12)}…)` : `${base} (${formatSize(artifact.size)})`
}

/** What the wizard says for a file the server does not hold (the server's own sentence when it sent one). */
export function notAvailable(kind: NodeArtifact["kind"], artifact?: NodeArtifact | null): string {
  if (artifact?.message) return artifact.message
  const label = { image: "Scan node image", "helm-chart": "Helm chart", "ova-kit": "OVA build kit", "ami-kit": "AMI build kit" }[kind]
  return `${label} is not available on this server yet. Contact your administrator.`
}

/** The Helm command for agent mode: a DaemonSet whose pods each enroll with the agent pool token as their own node
 * (named after the Kubernetes node) and read only that node, from a read-only mount of its file system. */
export function helmAgentCommand(opts: { poolToken: string; apiUrl: string; proxyUrl?: string | null; image: string; insecureHttp?: boolean; pull?: boolean; archive?: string; chart?: string; archiveSha256?: string; chartSha256?: string; build?: string }): string {
  const proxy = opts.proxyUrl ? opts.proxyUrl : ""
  const src = helmSource({ image: opts.image, pull: opts.pull, archive: opts.archive, chart: opts.chart,
    archiveSha256: opts.archiveSha256, chartSha256: opts.chartSha256, build: opts.build })
  return [
    ...src.steps,
    `helm upgrade --install zs-host-agents ${src.chart} \\`,
    "  --namespace zs-cbom --create-namespace \\",
    `  --set image.repository=${src.repoArg} --set image.tag=${shQuote(src.tag)} \\`,
    `  --set apiUrl=${shQuote(opts.apiUrl)} \\`,
    ...(opts.insecureHttp ? ["  --set allowInsecureHttp=true \\"] : []),
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
  let data = response?.data
  if (typeof data === "string") {
    // a file fetched as text (responseType "text"): a refusal's body is still the server's JSON {"detail": ...}
    try { data = JSON.parse(data) } catch { data = null }
  }
  const detail = (data as { detail?: unknown } | null | undefined)?.detail
  return typeof detail === "string" && detail.trim() ? detail.trim().slice(0, 300) : null
}

/** "Not read in this run" (lab UI r1 F2): assets of a compared source that the later run did not read because of a
 * coverage gap (a stopped target, a denied check). They are neither removed nor resolved, so they are listed apart,
 * grouped by why they were not read (the coverage row's detail, from the server) and by source. */
/** What to do about a target the node could not reach. An IPv6 target with no route: the wizard's `docker run` puts the
 * node on Docker's default bridge, which has no IPv6 (scan_node tlsprobe.connect_error: "IPv6 is not available on this
 * scan node"). */
export const IPV6_NO_ROUTE_GUIDANCE =
  "Give the scan node an IPv6 route: run its container on a Docker network created with --ipv6 (or with --network host on a host that has IPv6), or run it in a dual-stack Kubernetes cluster, then run the scan again."

export function targetGuidance(status: string, error: string | null | undefined, target: string): string | null {
  if (status !== "no_route") return null
  const host = target.replace(/^\[([^\]]+)\](:\d+)?$/, "$1")
  const ipv6 = /IPv6/.test(error ?? "") || (host.includes(":") && /^[0-9a-fA-F:.]+(:\d+)?$/.test(host) && (host.match(/:/g) ?? []).length >= 2)
  return ipv6 ? IPV6_NO_ROUTE_GUIDANCE : null
}

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

/** "120 of 254 addresses" for a network range while it runs, "377 of 1,200 account-regions" for an AWS source the
 * cloud pool collects one account x region at a time (``unit`` from the API); null when the job does not report it (an
 * older node, another kind of job) or is not running, so those rows show what they showed before. */
export function addressProgress(job: { status: string; progress?: { done: number; total: number; unit?: string } | null }): string | null {
  const p = job.progress
  if (job.status !== "claimed" || !p || !Number.isFinite(p.total) || p.total <= 0) return null
  const done = Math.min(Math.max(0, Math.floor(p.done)), p.total)
  if (p.unit === "account-regions") return `${done.toLocaleString()} of ${pluralize(p.total, "account-region", "account-regions")}`
  return `${done.toLocaleString()} of ${pluralize(p.total, "address", "addresses")}`
}

/** An AWS organisation's charge per run, as recorded at its last validation: "Estimated per run: 1,000 accounts × 4
 * credits = 4,000 credits", and, when the count changed, "changed from 200 accounts (800 credits) on 14 Nov 2026", so
 * a new charge is visible before the next scheduled run takes it. */
export function orgEstimateLines(est: { accounts: number; credits_per_account: number; credits_per_run: number;
  changed_from?: { accounts: number; credits_per_run: number }; changed_at?: string | null } | null | undefined,
  timeZone?: string): { estimate: string; change: string | null } | null {
  if (!est || !Number.isFinite(est.accounts) || !Number.isFinite(est.credits_per_run)) return null
  const estimate = `Estimated per run: ${pluralize(est.accounts, "account")} × ${credits(est.credits_per_account)} credits = ${credits(est.credits_per_run)} credits`
  let change: string | null = null
  if (est.changed_from && Number.isFinite(est.changed_from.accounts)) {
    const when = est.changed_at ? new Date(est.changed_at) : null
    const day = when && !Number.isNaN(when.getTime())
      ? when.toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric", timeZone: timeZone ?? "UTC" })
      : null
    change = `Changed from ${pluralize(est.changed_from.accounts, "account")} (${credits(est.changed_from.credits_per_run)} credits)${day ? ` on ${day}` : ""}`
  }
  return { estimate, change }
}

/** An AWS organisation source validated before F1: its stored count stopped at 200 accounts and it has no recorded
 * estimate, so its charge per run is not yet what F1 reads and charges. Its row asks for a re-validation. */
export function orgEstimateStale(source: { kind: string; config?: Record<string, unknown> | null;
  last_test_result?: { member_accounts?: number; estimate?: unknown } | null }): boolean {
  if (source.kind !== "aws_account" || source.config?.scope !== "organization") return false
  const r = source.last_test_result
  return !!r && typeof r.member_accounts === "number" && r.member_accounts <= 200 && !r.estimate
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

// ---------------------------------------------------------------------------- certificate transparency
const CT_PROVIDER_LABEL: Record<string, string> = { certspotter: "Cert Spotter", crtsh: "crt.sh" }

/** The providers the server asks, in order, as the CT card names them ("Cert Spotter (then crt.sh when it cannot answer)"). */
export function ctProviderSentence(providers: string[] | undefined): string {
  const names = (providers ?? []).map((p) => CT_PROVIDER_LABEL[p] ?? p)
  if (names.length === 0) return "a public CT search service"
  return names.length === 1 ? names[0] : `${names[0]} (then ${names.slice(1).join(", ")} when it cannot answer)`
}

/** Credits one run charges for the CT source: the server's per-domain rate times the domains it searches (the
 *  planner's units), rounded to cents as the server rounds; null while the rate is unknown. */
export function ctRunCredits(rate: number | undefined, domainsSearched: number): number | null {
  if (rate === undefined || !Number.isFinite(rate)) return null
  return Math.round(rate * 100 * domainsSearched) / 100
}
