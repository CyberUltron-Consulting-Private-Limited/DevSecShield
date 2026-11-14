/**
 * N7 / N9 (owner bug list 14 Nov 2026), RENDERED: the real NetworkTab mounted in jsdom on the app's own axios client
 * with a fake adapter (same harness as neverScanRender.test.ts).
 * - the reported ranges: a disabled /24, two /25s, two /30s inside them. "Before the first run" says the API's 252
 *   unique addresses (it said 510: every range's own count, the disabled /24 and the overlaps included);
 * - the disabled range's row is muted (opacity-60, struck-through range) with a "Disabled" badge; enabled rows are not;
 * - a range whose last test probed 25 addresses shows "Partly ready · 18 of 25 sampled";
 * - N5: no Zeek ssl.log option is rendered, even with the stored setting on.
 * Run: npx --yes tsx components/cbom/sources/networkTabRender.test.ts
 */
import assert from "node:assert/strict"
import { createRequire } from "node:module"

type Dom = { window: Window & typeof globalThis }
const load = createRequire(__filename)
const { JSDOM } = load("jsdom") as { JSDOM: new (html: string, options: Record<string, unknown>) => Dom }

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

  const now = new Date().toISOString()
  const settings = {
    aws_external_id: "zs-ext", aws_collection_configured: false, cert_domains: [], network_exclusions: [], sni_hostnames: [],
    ports: [{ port: 443, protocol: "tls", label: "" }, { port: 8443, protocol: "tls", label: "" }, { port: 22, protocol: "ssh", label: "" }],
    zeek_span: true, scan_window: Array.from({ length: 7 }, () => Array(24).fill(true)),
    window_timezone: "UTC", rate_conn_per_s: 20, rate_parallel_per_server: 2, rate_handshakes_per_endpoint: 20,
    soc_email: "soc@bank.example", emergency_contact: null, risk_model: { data_shelf_life_years: null, migration_years: null, threat_years: null },
    stop_all_network: false, require_signed_nodes: false, stop_all_changed_by: null, stop_all_changed_at: null, next_window_start: null,
    in_window_now: true, row_version: 2, last_updated: null,
  }
  const samples = Array.from({ length: 25 }, (_, i) => ({ target: `10.232.0.${1 + i * 5}`, status: i < 18 ? "ready" : "unreachable" }))
  const range = (id: number, cidr: string, target_count: number, enabled = true, test: Record<string, unknown> = {}) => ({
    id, team_id: 1, owner_user_id: 1, kind: "network_range", kind_label: "Network range", group: "network", name: cidr,
    node_id: 5, node_name: "dc-mumbai-01", node_status: "online", enabled, config: { cidr, mode: "full" }, secrets_set: [],
    target_count, target_unit: "addresses", last_test_status: "never", last_test_at: null, last_test_summary: null,
    last_test_job_id: null, last_test_result: {}, row_version: 1, created_at: now, last_updated: now, ...test,
  })
  const ranges = [
    range(1, "10.232.0.0/24", 254, false),
    range(2, "10.232.0.0/25", 126, true, { last_test_status: "partial", last_test_at: now,
      last_test_summary: "18 of 25 samples ready: no answer on the listed ports", last_test_result: { samples } }),
    range(3, "10.232.0.128/25", 126),
    range(4, "10.232.0.0/30", 2),
    range(5, "10.232.0.128/30", 2),
  ]
  const node = {
    id: 5, team_id: 1, owner_user_id: 1, name: "dc-mumbai-01", segment: "Data centre", timezone: "UTC", deployment: "docker",
    proxy_url: null, has_proxy_ca: false, proxy_tls_inspect: false, status: "online", registration_issued_at: null,
    registration_expires_at: null, enrolled_at: now, hostname: "n1", node_version: "1.0", source_ips: ["10.20.1.15"],
    ssh_public_key: null, capabilities: {}, clock_skew_s: 0, clock_in_sync: true, last_heartbeat_at: now,
    last_claim_at: null, last_seen_ip: "10.20.1.15", last_node_error: null, signing: "required", client_cert_sha256: null,
    mode: "agentless", pool_id: null, assigned_targets: 0, sources: 5, row_version: 1, created_at: null, last_updated: null,
  }
  api.defaults.adapter = async (config) => {
    const url = String(config.url)
    const method = String(config.method).toUpperCase()
    const reply = (status: number, data: unknown) => {
      const response = { data, status, statusText: String(status), headers: {}, config, request: {} }
      if (status >= 400) throw new AxiosError(`Request failed with status code ${status}`, "ERR_BAD_REQUEST", config, {}, response as never)
      return response
    }
    if (method === "GET" && url.endsWith("/settings")) return reply(200, { settings })
    if (method === "GET" && url.endsWith("/items")) {
      return reply(200, { sources: ranges, server_time: now, network_totals: { addresses: 252, ranges_enabled: 4, ranges_disabled: 1 } })
    }
    if (method === "GET" && url.endsWith("/nodes")) return reply(200, { nodes: [node], server_time: now })
    if (method === "GET" && url.endsWith("/overview")) return reply(200, { viewer: { is_admin: true } })
    if (method === "GET") return reply(200, {})
    return reply(404, { detail: `no fake for ${method} ${url}` })
  }

  const { default: NetworkTab } = load("./NetworkTab") as typeof import("./NetworkTab")
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } })
  const host = document.createElement("div")
  document.body.appendChild(host)
  const root = createRoot(host)
  await act(async () => { root.render(React.createElement(QueryClientProvider, { client: qc }, React.createElement(NetworkTab, { teamId: 1, onNavigate: () => {} }))) })
  for (let i = 0; i < 50 && host.querySelector('[data-testid="network-ranges-table"]') === null; i++) {
    await act(async () => { await new Promise((r) => setTimeout(r, 10)) })
  }

  // N7: the estimate
  const totals = host.querySelector('[data-testid="network-totals"]')?.textContent ?? ""
  assert.equal(totals, "252 unique addresses across 4 enabled ranges after the never-scan list, 3 ports. 1 disabled range is not counted.")
  assert.ok(!/510/.test(totals), "the old sum is gone")

  // N7: the disabled row looks disabled, the others do not
  const rows = [...host.querySelectorAll('[data-testid="network-ranges-table"] tbody tr')] as HTMLElement[]
  assert.equal(rows.length, 5)
  const [disabled, ...active] = rows
  assert.ok(disabled.textContent!.includes("10.232.0.0/24") && disabled.textContent!.includes("Disabled"), disabled.textContent!)
  assert.ok(disabled.className.includes("opacity-60") && disabled.dataset.disabled === "true")
  assert.ok(disabled.textContent!.includes("not swept"))
  for (const row of active) {
    assert.ok(!row.textContent!.includes("Disabled") && !row.className.includes("opacity-60"), row.textContent!)
  }

  // N5: no Zeek ssl.log option is offered (PR #96 removed it; no scan node reads ssl.log), even for a team whose stored
  // setting is on; the API ignores the stored value (backend test_cbom_cb08_promises, test_cbom_review5_jobs_schedules)
  assert.ok(!/zeek|ssl\.log/i.test(host.textContent ?? ""), "the rendered tab offers no Zeek ssl.log option")
  assert.equal(host.querySelectorAll('input[type="checkbox"], [role="checkbox"]').length, 0, "no checkbox on the tab")

  // N9: the readiness label carries the sample size
  assert.ok(active[0].textContent!.includes("Partly ready · 18 of 25 sampled"), active[0].textContent!)

  await act(async () => { root.unmount() })
  console.log("networkTabRender.test.ts: ok")
}

main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1) })
