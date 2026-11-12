// Pure helpers of the Repositories pages (F3): labels, filter forms, credit and schedule wording, form checks.
// Kept free of React so `npx --yes tsx components/repositories/logic.test.ts` covers them.

import type {
  ScmAuthKind,
  ScmConnection,
  ScmEstimate,
  ScmFilters,
  ScmProduct,
  ScmProvider,
  ScmSchedule,
  ScmScopeKind,
} from "@/utils/api/scm"

export const PRODUCTS: ScmProduct[] = ["sast", "iac", "sbom_sca", "cbom", "ai_bom"]

export const PRODUCT_LABEL: Record<ScmProduct, string> = {
  sast: "SAST",
  iac: "IaC",
  sbom_sca: "SCA + SBOM",
  cbom: "CBOM",
  ai_bom: "AI BOM",
}

export const PROVIDER_LABEL: Record<ScmProvider, string> = { github: "GitHub", gitlab: "GitLab", bitbucket: "Bitbucket" }

/** Why a repository is in or out of scope (backend/utilities/scm/filters.py REASONS). */
export const REASON_LABEL: Record<string, string> = {
  matched: "Matches the filters",
  manual_include: "Included by hand",
  manual_exclude: "Excluded by hand",
  archived: "Archived",
  fork: "Fork",
  visibility: "Visibility not selected",
  too_large: "Larger than the size limit",
  excluded_name: "Name excluded",
  not_included_name: "Name not in the include list",
  excluded_topic: "Has an excluded topic",
  missing_topic: "Has none of the required topics",
  language: "Language not selected",
  removed: "No longer visible to the connection",
}

export function reasonLabel(reason: string | null | undefined): string {
  return REASON_LABEL[reason ?? ""] ?? (reason ? reason.replace(/_/g, " ") : "Unknown")
}

/** Why a scan was not queued (queue.plan). */
export const SKIP_LABEL: Record<string, string> = {
  already_queued: "already queued or running",
  sast_language: "SAST cannot read the repository's language",
  no_policy: "no policy covers the repository",
}

export function emptyFilters(): ScmFilters {
  return {
    include_names: [],
    exclude_names: [],
    topics_any: [],
    exclude_topics: [],
    languages: [],
    include_archived: false,
    include_forks: false,
    visibility: [],
    max_size_mb: null,
  }
}

export function filtersFrom(partial: Partial<ScmFilters> | null | undefined): ScmFilters {
  return { ...emptyFilters(), ...(partial ?? {}) }
}

/** "a, b\nc" -> ["a", "b", "c"]: commas or new lines, trimmed, empty entries and repeats dropped. */
export function parseList(text: string): string[] {
  const out: string[] = []
  for (const part of text.split(/[\n,]/)) {
    const v = part.trim()
    if (v && !out.includes(v)) out.push(v)
  }
  return out
}

export function joinList(list: string[] | null | undefined): string {
  return (list ?? []).join(", ")
}

export const MAX_RULES = 100
export const MAX_PATTERN = 200

/** The server's rule (filters.RepoFilters), checked before sending: at most 100 entries of at most 200 characters. */
export function listError(list: string[]): string | null {
  if (list.length > MAX_RULES) return `At most ${MAX_RULES} entries`
  const long = list.find((v) => v.length > MAX_PATTERN)
  return long ? `Each entry is at most ${MAX_PATTERN} characters` : null
}

export function filtersError(f: ScmFilters): string | null {
  for (const key of ["include_names", "exclude_names", "topics_any", "exclude_topics", "languages"] as const) {
    const err = listError(f[key])
    if (err) return err
  }
  if (f.max_size_mb !== null && (!Number.isFinite(f.max_size_mb) || f.max_size_mb < 0)) return "The size limit must be 0 or more"
  return null
}

export function formatCredits(value: number | null | undefined): string {
  const n = Math.round(Number(value ?? 0) * 100) / 100
  return `${n.toLocaleString("en-US", { maximumFractionDigits: 2 })} credit${n === 1 ? "" : "s"}`
}

export function skippedSentence(counts: Record<string, number> | null | undefined): string {
  const parts = Object.entries(counts ?? {})
    .filter(([, n]) => n > 0)
    .map(([why, n]) => `${n} ${SKIP_LABEL[why] ?? why.replace(/_/g, " ")}`)
  return parts.length ? `Not queued: ${parts.join("; ")}.` : ""
}

/** The sentence shown before a run starts: what will be scanned, what it costs, and whether the team can pay. */
export function estimateSentence(est: Pick<ScmEstimate, "scans" | "repos" | "credits" | "balance" | "affordable">): string {
  if (!est.scans) return "Nothing to scan: every chosen scan is already queued or cannot run."
  const head = `${est.scans.toLocaleString("en-US")} scan${est.scans === 1 ? "" : "s"} of ${est.repos.toLocaleString("en-US")} ` +
    `repositor${est.repos === 1 ? "y" : "ies"} for ${formatCredits(est.credits)}.`
  return est.affordable
    ? `${head} The team has ${formatCredits(est.balance)}; the run is charged once, when it starts.`
    : `${head} The team has only ${formatCredits(est.balance)}, so the run cannot start.`
}

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

export function scheduleText(s: Partial<ScmSchedule> | null | undefined): string {
  if (!s || !s.frequency || s.frequency === "off") return "No schedule"
  const at = `at ${s.time_of_day ?? "02:00"} (${s.timezone ?? "UTC"})`
  if (s.frequency === "daily") return `Daily ${at}`
  if (s.frequency === "weekly") return `Weekly on ${WEEKDAYS[s.weekday ?? 6] ?? "Sunday"} ${at}`
  return `Monthly on day ${s.monthday ?? 1} ${at}`
}

export const SCOPES: Record<ScmProvider, { auth: ScmAuthKind; scope: ScmScopeKind; label: string; hint: string }[]> = {
  github: [
    { auth: "github_app", scope: "installation", label: "GitHub App installation",
      hint: "A private GitHub App installed on the organisation, with Metadata and Contents read access. Recommended: tokens last 1 hour and are minted per use." },
    { auth: "token", scope: "org", label: "Organisation, with a token",
      hint: "A fine-grained token (or a classic token with repo read) that can read the organisation's repositories." },
    { auth: "token", scope: "user", label: "My repositories, with a token",
      hint: "Every repository the token's user can read." },
  ],
  gitlab: [
    { auth: "token", scope: "group", label: "Group, with a group access token",
      hint: "A group access token with read_api and read_repository. Subgroups are included." },
  ],
  bitbucket: [
    { auth: "token", scope: "workspace", label: "Workspace, with an access token",
      hint: "A workspace access token with repository read." },
  ],
}

export interface ConnectionForm {
  name: string
  provider: ScmProvider
  auth_kind: ScmAuthKind
  scope_kind: ScmScopeKind
  scope_name: string
  api_base: string
  app_id: string
  installation_id: string
  token: string
  private_key: string
}

export function emptyConnectionForm(provider: ScmProvider = "github"): ConnectionForm {
  const first = SCOPES[provider][0]
  return { name: "", provider, auth_kind: first.auth, scope_kind: first.scope, scope_name: "", api_base: "", app_id: "",
    installation_id: "", token: "", private_key: "" }
}

/** Connection and policy names (routers/scm.py ConnectionCreate.name, PolicyBody.name). */
export const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/
export const NAME_RULE = "1 to 64 letters, digits, spaces, dots, dashes or underscores, starting with a letter or digit"

export function nameError(name: string): string | null {
  return NAME_RE.test(name.trim()) ? null : NAME_RULE
}

/** Field -> message for what the server would refuse (routers/scm.py ConnectionCreate and _check_shape). */
export function connectionErrors(f: ConnectionForm): Partial<Record<keyof ConnectionForm, string>> {
  const e: Partial<Record<keyof ConnectionForm, string>> = {}
  if (!NAME_RE.test(f.name.trim())) e.name = NAME_RULE
  if (f.scope_kind !== "user" && f.scope_kind !== "installation" && !f.scope_name.trim()) {
    e.scope_name = f.provider === "gitlab" ? "The group path is required" : f.provider === "bitbucket" ? "The workspace is required" : "The organisation is required"
  }
  if (f.auth_kind === "github_app") {
    if (!/^\d+$/.test(f.app_id.trim())) e.app_id = "The App id is a number (App settings, About)"
    if (!/^\d+$/.test(f.installation_id.trim())) e.installation_id = "The installation id is a number (the end of the installation's URL)"
    if (!f.private_key.includes("PRIVATE KEY")) e.private_key = "Paste the App's private key (.pem)"
  } else if (!f.token.trim()) {
    e.token = "The access token is required"
  }
  if (f.api_base.trim() && !/^https?:\/\//i.test(f.api_base.trim())) e.api_base = "Start with https://"
  return e
}

export function connectionBody(f: ConnectionForm, filters: ScmFilters) {
  return {
    name: f.name.trim(),
    provider: f.provider,
    auth_kind: f.auth_kind,
    api_base: f.api_base.trim() || null,
    scope_kind: f.scope_kind,
    scope_name: f.scope_name.trim(),
    config: f.auth_kind === "github_app" ? { app_id: f.app_id.trim(), installation_id: f.installation_id.trim() } : {},
    secrets: f.auth_kind === "github_app" ? { private_key: f.private_key } : { token: f.token.trim() },
    filters,
  }
}

// ---------------------------------------------------------------------------- editing a connection
/** The edit form of an existing connection: the credential is write-only, so it starts blank ("keep the saved one"). */
export interface ConnectionEditForm {
  name: string
  scope_name: string
  api_base: string
  app_id: string
  installation_id: string
  secret: string
  sync_interval_min: string
}

export function editFormFrom(c: ScmConnection, defaultApi: string): ConnectionEditForm {
  return {
    name: c.name,
    scope_name: c.scope_name ?? "",
    api_base: c.api_base === defaultApi ? "" : c.api_base,
    app_id: c.config?.app_id ?? "",
    installation_id: c.config?.installation_id ?? "",
    secret: "",
    sync_interval_min: String(c.sync_interval_min),
  }
}

/** True when the edit points the credential somewhere else (API URL, scope or App): the server then refuses the change
 * unless the credential is entered again (routers/scm.py _update_connection), so nobody who cannot see a token can aim
 * it at another host or organisation. */
export function editMovesCredential(c: ScmConnection, f: ConnectionEditForm, defaultApi: string): boolean {
  const api = f.api_base.trim().replace(/\/+$/, "") || defaultApi
  if (api !== c.api_base) return true
  if (f.scope_name.trim() !== (c.scope_name ?? "")) return true
  if (c.auth_kind === "github_app") {
    return f.app_id.trim() !== (c.config?.app_id ?? "") || f.installation_id.trim() !== (c.config?.installation_id ?? "")
  }
  return false
}

export function editErrors(c: ScmConnection, f: ConnectionEditForm, defaultApi: string): Partial<Record<keyof ConnectionEditForm, string>> {
  const e: Partial<Record<keyof ConnectionEditForm, string>> = {}
  if (!NAME_RE.test(f.name.trim())) e.name = NAME_RULE
  if (c.scope_kind !== "user" && c.scope_kind !== "installation" && !f.scope_name.trim()) {
    e.scope_name = c.provider === "gitlab" ? "The group path is required" : c.provider === "bitbucket" ? "The workspace is required" : "The organisation is required"
  }
  if (c.auth_kind === "github_app") {
    if (!/^\d+$/.test(f.app_id.trim())) e.app_id = "The App id is a number (App settings, About)"
    if (!/^\d+$/.test(f.installation_id.trim())) e.installation_id = "The installation id is a number (the end of the installation's URL)"
    if (f.secret && !f.secret.includes("PRIVATE KEY")) e.secret = "Paste the App's private key (.pem)"
  }
  if (f.api_base.trim() && !/^https?:\/\//i.test(f.api_base.trim())) e.api_base = "Start with https://"
  const minutes = Number(f.sync_interval_min)
  if (!Number.isInteger(minutes) || minutes < 15 || minutes > 10080) e.sync_interval_min = "15 to 10,080 minutes (one week)"
  if (!e.secret && !f.secret.trim() && editMovesCredential(c, f, defaultApi)) {
    e.secret = c.auth_kind === "github_app"
      ? "Paste the App's private key again: the API URL, organisation or App changed"
      : "Enter the access token again: the API URL or the scope changed"
  }
  return e
}

/** The PATCH body: only what changed, plus the row version the form was opened at (a stale form gets 409). */
export function editPatch(c: ScmConnection, f: ConnectionEditForm, defaultApi: string): Record<string, unknown> {
  const body: Record<string, unknown> = { expected_version: c.row_version }
  if (f.name.trim() !== c.name) body.name = f.name.trim()
  if (f.scope_name.trim() !== (c.scope_name ?? "")) body.scope_name = f.scope_name.trim()
  const api = f.api_base.trim().replace(/\/+$/, "") || defaultApi
  // "" (not null: null means "unchanged" to the server) puts the connection back on the provider's cloud API
  if (api !== c.api_base) body.api_base = f.api_base.trim().replace(/\/+$/, "")
  if (c.auth_kind === "github_app" &&
      (f.app_id.trim() !== (c.config?.app_id ?? "") || f.installation_id.trim() !== (c.config?.installation_id ?? ""))) {
    body.config = { ...c.config, app_id: f.app_id.trim(), installation_id: f.installation_id.trim() }
  }
  if (Number(f.sync_interval_min) !== c.sync_interval_min) body.sync_interval_min = Number(f.sync_interval_min)
  if (f.secret.trim()) body.secrets = c.auth_kind === "github_app" ? { private_key: f.secret } : { token: f.secret.trim() }
  return body
}

// ---------------------------------------------------------------------------- the queue and runs
/** How many scans run at once: the global cap always, a per-team limit only when the operator set one (0 = none; each
 * free slot goes to the team with the fewest scans in flight, backend/utilities/scm/queue.py). */
export function capsText(maxInflight: number, teamMaxInflight: number): string {
  return teamMaxInflight > 0
    ? `At most ${maxInflight} at once, ${teamMaxInflight} per team`
    : `At most ${maxInflight} at once, shared fairly between teams`
}

/** POST /runs answers 409 {code: "estimate_changed", estimate} when the price moved since the estimate: nothing was
 * charged, and the new estimate is shown before the customer starts again. */
export function runEstimateChangedOf(error: unknown): ScmEstimate | null {
  const response = (error as { response?: { status?: number; data?: unknown } } | null)?.response
  if (!response || response.status !== 409) return null
  const data = response.data as { code?: unknown; estimate?: unknown } | null | undefined
  if (!data || data.code !== "estimate_changed" || !data.estimate || typeof data.estimate !== "object") return null
  const est = data.estimate as ScmEstimate
  return typeof est.credits === "number" ? est : null
}

/** The public URL a provider posts webhooks to. */
export function webhookUrl(apiBase: string, path: string): string {
  return `${apiBase.replace(/\/+$/, "")}${path}`
}

export function webhookHelp(provider: ScmProvider): string {
  if (provider === "github") {
    return "In the organisation's (or the App's) webhook settings: Payload URL = this URL, content type application/json, " +
      "Secret = this secret, events Push and Repository. GitHub signs each delivery with X-Hub-Signature-256."
  }
  if (provider === "gitlab") {
    return "In the group's Settings, Webhooks: URL = this URL, Secret token = this secret, trigger Push events."
  }
  return "In the workspace's Settings, Webhooks: URL = this URL, Secret = this secret, trigger Repository push."
}

export function sizeLabel(kb: number): string {
  if (kb < 1024) return `${kb} KB`
  const mb = kb / 1024
  return mb < 1024 ? `${mb.toFixed(mb < 10 ? 1 : 0)} MB` : `${(mb / 1024).toFixed(1)} GB`
}

export function newClientRequestId(): string {
  const rand = Math.random().toString(36).slice(2, 10)
  return `ui-${Date.now().toString(36)}-${rand}`
}

/** Selection across pages: toggling one id, or every id of the visible page. */
export function toggleIds(selected: number[], ids: number[], on: boolean): number[] {
  const set = new Set(selected)
  for (const id of ids) {
    if (on) set.add(id)
    else set.delete(id)
  }
  return [...set]
}
