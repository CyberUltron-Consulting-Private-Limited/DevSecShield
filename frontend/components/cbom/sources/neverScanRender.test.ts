/**
 * PR #32 re-review 5879769432: the team never-scan list and a server source's Never scan field, RENDERED (not read from
 * the source text). The real NetworkTab and ServersTab are mounted in jsdom (react-dom/client); the API is a fake axios
 * adapter on the app's own client (utils/interceptors), so every request the tab makes goes through the real code.
 *
 * NetworkTab, a team list saved before the API refused host names (printer.corp.invalid, localhost):
 * - each stored host name gets a note in its own full-width row below the entry, and the loopback name's note says
 *   what the node does with it (only 127.0.0.0/8 and ::1, nothing held); addresses, ranges and zone ids get none;
 * - nothing on the page is role="alert" until the customer does something (the notes are static, not live errors);
 * - the Remove button of a marked entry is described by its note (aria-describedby);
 * - a typed host name is refused inline with the API's words; a save the API refuses puts the API's detail inline,
 *   with role="alert"; removing an entry clears that error.
 * ServersTab: the hint under the source's Never scan field says what a loopback name does there.
 * jsdom comes with isomorphic-dompurify (a dependency of the app), react-dom with the app itself.
 * Run: npx --yes tsx components/cbom/sources/neverScanRender.test.ts
 */
import assert from "node:assert/strict"
import { createRequire } from "node:module"

type Dom = { window: Window & typeof globalThis }
const load = createRequire(__filename)
const { JSDOM } = load("jsdom") as { JSDOM: new (html: string, options: Record<string, unknown>) => Dom }

const LEGACY = [
  { cidr: "10.20.99.0/24", reason: "OT plant" },
  { cidr: "printer.corp.invalid", reason: "printer" },
  { cidr: "localhost", reason: "the node itself" },
  { cidr: "fe80::1%br-ab12", reason: "bridge" },
]

async function main() {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://devsec.example/1/cbom/sources", pretendToBeVisual: true })
  const g = globalThis as Record<string, unknown>
  for (const name of ["window", "document", "navigator", "HTMLElement", "Element", "Node", "MutationObserver", "getComputedStyle",
    "requestAnimationFrame", "cancelAnimationFrame", "localStorage", "sessionStorage", "Event", "KeyboardEvent", "MouseEvent",
    "PointerEvent", "FocusEvent", "CustomEvent", "InputEvent", "DocumentFragment", "HTMLInputElement", "HTMLTextAreaElement",
    "HTMLButtonElement"]) {
    const value = (dom.window as unknown as Record<string, unknown>)[name]
    if (value !== undefined) Object.defineProperty(g, name, { value, configurable: true, writable: true })
  }
  g.IS_REACT_ACT_ENVIRONMENT = true
  const consoleError = console.error // Radix's portalled items update outside act(): noise, not a failure
  console.error = (...args: unknown[]) => { if (!String(args[0]).includes("not wrapped in act")) consoleError(...args) }
  const consoleLog = console.log // utils/interceptors prints the API base URL on import; the error toast logs each refusal
  console.log = (...args: unknown[]) => {
    if (String(args[0]).startsWith("api base url")) return
    if (args[0] instanceof Error && args[0].message.endsWith("status code 422")) return // the refusals this test asks for
    consoleLog(...args)
  }
  g.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} }
  ;(dom.window as unknown as Record<string, unknown>).scrollTo = () => {}
  ;(dom.window.HTMLElement.prototype as unknown as Record<string, unknown>).scrollIntoView = () => {}
  process.env.NEXT_PUBLIC_BACKEND_URL = "https://api.devsec.example"

  // one module system for the test and the components (tsx compiles them to CommonJS)
  const React = load("react") as typeof import("react")
  const { act } = React
  const { createRoot } = load("react-dom/client") as typeof import("react-dom/client")
  const { QueryClient, QueryClientProvider } = load("@tanstack/react-query") as typeof import("@tanstack/react-query")
  const { AxiosError } = load("axios") as typeof import("axios")
  const { default: api } = load("../../../utils/interceptors") as { default: import("axios").AxiosInstance }
  const words = load("./teamNeverScan") as typeof import("./teamNeverScan")

  // ------------------------------------------------------------------ the fake API (the app's own axios client)
  let stored = LEGACY.map((e) => ({ ...e }))
  const settings = () => ({
    aws_external_id: "zs-ext", aws_collection_configured: false, cert_domains: [], network_exclusions: stored, sni_hostnames: [],
    ports: [{ port: 443, protocol: "tls", label: "" }], zeek_span: false, scan_window: Array.from({ length: 7 }, () => Array(24).fill(true)),
    window_timezone: "UTC", rate_conn_per_s: 20, rate_parallel_per_server: 2, rate_handshakes_per_endpoint: 20,
    soc_email: "soc@bank.example", emergency_contact: null, risk_model: { data_shelf_life_years: null, migration_years: null, threat_years: null },
    stop_all_network: false, require_signed_nodes: false, stop_all_changed_by: null, stop_all_changed_at: null, next_window_start: null,
    in_window_now: true, row_version: 2, last_updated: null,
  })
  const node = {
    id: 5, team_id: 1, owner_user_id: 1, name: "dc-mumbai-01", segment: "Data centre", timezone: "UTC", deployment: "docker",
    proxy_url: null, has_proxy_ca: false, proxy_tls_inspect: false, status: "online", registration_issued_at: null,
    registration_expires_at: null, enrolled_at: new Date().toISOString(), hostname: "n1", node_version: "1.0", source_ips: ["10.20.1.15"],
    ssh_public_key: null, capabilities: {}, clock_skew_s: 0, clock_in_sync: true, last_heartbeat_at: new Date().toISOString(),
    last_claim_at: null, last_seen_ip: "10.20.1.15", last_node_error: null, signing: "required", client_cert_sha256: null,
    mode: "agentless", pool_id: null, assigned_targets: 0, sources: 0, row_version: 1, created_at: null, last_updated: null,
  }
  const patches: Record<string, unknown>[] = []
  api.defaults.adapter = async (config) => {
    const url = String(config.url)
    const method = String(config.method).toUpperCase()
    const reply = (status: number, data: unknown) => {
      const response = { data, status, statusText: String(status), headers: {}, config, request: {} }
      if (status >= 400) throw new AxiosError(`Request failed with status code ${status}`, "ERR_BAD_REQUEST", config, {}, response as never)
      return response
    }
    const now = new Date().toISOString()
    if (method === "GET" && url.endsWith("/settings")) return reply(200, { settings: settings() })
    if (method === "GET" && url.endsWith("/items")) return reply(200, { sources: [], server_time: now })
    if (method === "GET" && url.endsWith("/nodes")) return reply(200, { nodes: [node], server_time: now })
    if (method === "GET" && url.endsWith("/overview")) return reply(200, { viewer: { is_admin: true } })
    if (method === "PATCH" && url.endsWith("/settings")) {
      const body = JSON.parse(String(config.data)) as { network_exclusions?: { cidr: string }[] }
      patches.push(body)
      // the API's rule (routers/cbom_sources.py): the first entry that reads as a host name is refused, as typed
      const name = (body.network_exclusions ?? []).find((e) => words.readsAsHostName(e.cidr))
      if (name) return reply(422, { detail: `network_exclusions: ${words.HOST_NAME_NOT_ALLOWED.replace("{entry}", () => name.cidr.trim())}` })
      stored = (body.network_exclusions ?? stored) as typeof stored
      return reply(200, { settings: settings() })
    }
    if (method === "GET") return reply(200, {})
    return reply(404, { detail: `no fake for ${method} ${url}` })
  }

  const { default: NetworkTab } = load("./NetworkTab") as typeof import("./NetworkTab")
  const { default: ServersTab } = load("./ServersTab") as typeof import("./ServersTab")

  const mount = async (el: React.ReactElement) => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } })
    const host = document.createElement("div")
    document.body.appendChild(host)
    const root = createRoot(host)
    await act(async () => { root.render(React.createElement(QueryClientProvider, { client: qc }, el)) })
    for (let i = 0; i < 50 && host.querySelector('[data-testid="network-exclusions-table"], #servers-exclusions') === null; i++) {
      await act(async () => { await new Promise((r) => setTimeout(r, 10)) }) // the first fetches answer
    }
    return { host, root }
  }
  const settle = async () => { for (let i = 0; i < 5; i++) await act(async () => { await new Promise((r) => setTimeout(r, 10)) }) }
  const click = async (el: Element | null | undefined, what: string) => {
    assert.ok(el, `${what} is on the page`)
    await act(async () => { el!.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true })) })
    await settle()
  }
  const type = async (input: HTMLInputElement, value: string) => {
    const setter = Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, "value")!.set!
    await act(async () => {
      setter.call(input, value)
      input.dispatchEvent(new dom.window.Event("input", { bubbles: true }))
    })
  }
  const button = (host: Element, text: RegExp) => [...host.querySelectorAll("button")].find((b) => text.test(b.textContent || ""))

  // ------------------------------------------------------------------ 1. a legacy team list, as the customer opens it
  const tab = await mount(React.createElement(NetworkTab, { teamId: 1, onNavigate: () => {} }))
  const table = tab.host.querySelector('[data-testid="network-exclusions-table"]')
  assert.ok(table, "the never-scan table is rendered")
  const rows = () => [...table!.querySelectorAll("tbody tr")]
  const notes = () => [...tab.host.querySelectorAll('[data-testid="network-exclusion-hostname"]')]
  // each marked entry is followed by its note, in a row of its own that spans the table
  const layout = rows().map((r) => (r.getAttribute("data-testid") === "network-exclusion-hostname" ? "note" : r.querySelector("td")?.textContent))
  assert.deepEqual(layout, ["10.20.99.0/24", "printer.corp.invalid", "note", "localhost", "note", "fe80::1%br-ab12"])
  for (const note of notes()) {
    assert.equal(note.tagName, "TR")
    assert.equal(note.querySelectorAll("td").length, 1)
    assert.equal(note.querySelector("td")!.getAttribute("colspan"), "3")
    assert.ok(note.textContent!.includes("Host name: not allowed here"))
  }
  const [printerNote, loopbackNote] = notes().map((n) => n.textContent!.replace("Host name: not allowed here", ""))
  assert.equal(printerNote, words.storedExclusionIssue("printer.corp.invalid"))
  assert.ok(printerNote.includes("holds every job of this team"), printerNote)
  assert.equal(loopbackNote, words.storedExclusionIssue("localhost"))
  assert.ok(loopbackNote.includes("only keeps the loopback addresses (127.0.0.0/8 and ::1) out; nothing is held"), loopbackNote)
  assert.ok(!loopbackNote.includes("holds every job"), "localhost does not hold the team's jobs on the node")
  // static notes are not live errors: nothing announces itself as an alert when the tab opens
  assert.equal(tab.host.querySelectorAll('[role="alert"]').length, 0, "no role=alert before the customer acts")
  // the Remove button of a marked entry points to its note; the others point nowhere
  for (const entry of LEGACY) {
    const remove = tab.host.querySelector(`button[aria-label="Remove ${entry.cidr} from never scan"]`)
    assert.ok(remove, `Remove ${entry.cidr}`)
    const describedBy = remove!.getAttribute("aria-describedby")
    const issue = words.storedExclusionIssue(entry.cidr)
    assert.equal(!!describedBy, !!issue, entry.cidr)
    if (describedBy) assert.ok(tab.host.querySelector(`#${describedBy}`)!.textContent!.includes(issue!), entry.cidr)
  }

  // ------------------------------------------------------------------ 2. a typed host name: refused inline, in the API's words
  const cidr = tab.host.querySelector('[data-testid="network-exclusion-cidr"]') as HTMLInputElement
  await type(cidr, "Printer.Corp.")
  await click(tab.host.querySelector('[data-testid="network-exclusion-add"]'), "Add")
  const alerts = () => [...tab.host.querySelectorAll('[role="alert"]')].map((a) => a.textContent)
  assert.deepEqual(alerts(), [words.hostNameNotAllowed("Printer.Corp.")])
  assert.equal(alerts()[0], "Printer.Corp. is not an address or range (it reads as a host name); the team never-scan list takes addresses and ranges only. List host names in a server source's own Never scan field")
  assert.equal(rows().length, 6, "nothing was added")

  // ------------------------------------------------------------------ 3. a save the API refuses: its detail goes inline
  await type(cidr, "10.20.98.0/24")
  await click(tab.host.querySelector('[data-testid="network-exclusion-add"]'), "Add")
  assert.deepEqual(alerts(), [], "a valid entry clears the error")
  await click(button(tab.host, /Save network scope/), "Save network scope")
  assert.equal(patches.length, 1, "the save was sent")
  assert.deepEqual(alerts(), [words.hostNameNotAllowed("printer.corp.invalid")], "the API's 422, inline")

  // ------------------------------------------------------------------ 4. removing the entry clears it; the next refusal is the next name
  await click(tab.host.querySelector('button[aria-label="Remove printer.corp.invalid from never scan"]'), "Remove printer")
  assert.deepEqual(alerts(), [], "Remove clears the inline error")
  assert.equal(notes().length, 1, "only the localhost note is left")
  await click(button(tab.host, /Save network scope/), "Save network scope")
  assert.deepEqual(alerts(), [words.hostNameNotAllowed("localhost")])
  await click(tab.host.querySelector('button[aria-label="Remove localhost from never scan"]'), "Remove localhost")
  await click(button(tab.host, /Save network scope/), "Save network scope")
  assert.deepEqual(alerts(), [])
  assert.deepEqual(stored.map((e) => e.cidr), ["10.20.99.0/24", "fe80::1%br-ab12", "10.20.98.0/24"])
  await settle()
  assert.equal(notes().length, 0, "after the save: no marked entry")
  tab.root.unmount()

  // ------------------------------------------------------------------ 5. a server source's Never scan field explains loopback names
  const servers = await mount(React.createElement(ServersTab, { teamId: 1, onNavigate: () => {} }))
  const field = servers.host.querySelector("#servers-exclusions")
  assert.ok(field, "the source form's Never scan field is rendered")
  const hint = [...servers.host.querySelectorAll("p, span, div")].find((el) => el.textContent === words.SOURCE_NEVER_SCAN_HINT)
  assert.ok(hint, "the hint under Never scan is the shared text")
  assert.ok(words.SOURCE_NEVER_SCAN_HINT.includes("localhost, names under .localhost and the other standard loopback names"))
  assert.ok(words.SOURCE_NEVER_SCAN_HINT.includes("cover only 127.0.0.0/8 and ::1"))
  servers.root.unmount()

  console.log("never-scan render tests passed")
  process.exit(0)
}

main().catch((e) => { console.error(e); process.exit(1) })
