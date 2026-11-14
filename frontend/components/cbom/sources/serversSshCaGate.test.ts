/**
 * CB36-BUG-03 (= F-QA-B-1): the Servers tab asked GET /fleet/ssh-ca on every visit and read its 404 as "the SSH CA is
 * off", so a default deployment (CBOM_SSH_CA unset) logged "Failed to load resource: ... 404" in the browser console
 * two or three times per visit (CB-36 C3/C6 browser logs). The tab now asks GET /fleet/status, the unflagged probe
 * the backend has for this (backend/routers/cbom_fleet.py, "Which fleet features are turned on"), and lists the SSH
 * CAs only when it reports ssh_ca on.
 * The real ServersTab is mounted in jsdom (react-dom/client) with the app's axios instance answered by a recording
 * adapter that behaves like the backend: /fleet/ssh-ca is 404 while the flag is off. Every request is recorded.
 * Run: npx --yes tsx components/cbom/sources/serversSshCaGate.test.ts
 */
import assert from "node:assert/strict"
import { createRequire } from "node:module"

type Dom = { window: Window & typeof globalThis }
const load = createRequire(__filename)
const { JSDOM } = load("jsdom") as { JSDOM: new (html: string, options: Record<string, unknown>) => Dom }

const TEAM = 7
const NODE = { id: 3, name: "cb36-node", status: "online", mode: "standalone", capabilities: [], public_key: "ssh-ed25519 AAAA node" }

async function main() {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://devsec.example/7/cbom/sources", pretendToBeVisual: true })
  const g = globalThis as Record<string, unknown>
  for (const name of ["window", "document", "navigator", "HTMLElement", "Element", "Node", "MutationObserver", "getComputedStyle",
    "requestAnimationFrame", "cancelAnimationFrame", "localStorage", "sessionStorage", "Event", "KeyboardEvent", "MouseEvent",
    "PointerEvent", "FocusEvent", "CustomEvent", "DocumentFragment", "HTMLInputElement", "HTMLButtonElement"]) {
    const value = (dom.window as unknown as Record<string, unknown>)[name]
    if (value !== undefined) Object.defineProperty(g, name, { value, configurable: true, writable: true })
  }
  g.IS_REACT_ACT_ENVIRONMENT = true
  const consoleError = console.error
  console.error = (...args: unknown[]) => { if (!String(args[0]).includes("not wrapped in act")) consoleError(...args) }
  g.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} }
  ;(dom.window as unknown as Record<string, unknown>).scrollTo = () => {}
  ;(dom.window.HTMLElement.prototype as unknown as Record<string, unknown>).scrollIntoView = () => {}
  process.env.NEXT_PUBLIC_BACKEND_URL = "https://devsec-api.example"
  const realLog = console.log
  console.log = (...args: unknown[]) => { if (!String(args[0]).startsWith("api base url")) realLog(...args) }

  const React = load("react") as typeof import("react")
  const { act } = React
  const { createRoot } = load("react-dom/client") as typeof import("react-dom/client")
  const { QueryClient, QueryClientProvider } = load("@tanstack/react-query") as typeof import("@tanstack/react-query")
  const { AxiosError } = load("axios") as typeof import("axios")
  const api = (load("@/utils/interceptors") as { default: import("axios").AxiosInstance }).default
  const { default: ServersTab } = load("./ServersTab") as typeof import("./ServersTab")

  /** Visit the Servers tab once on a deployment whose SSH CA flag is ``sshCa``; returns every request made. */
  const visit = async (sshCa: boolean | "no-fleet-routes") => {
    const requests: string[] = []
    const failed: string[] = []
    api.defaults.adapter = async (config) => {
      const url = String(config.url)
      requests.push(`${(config.method ?? "get").toUpperCase()} ${url}`)
      const ok = (data: unknown) => ({ data, status: 200, statusText: "OK", headers: {}, config, request: {} })
      const notFound = () => {
        failed.push(`404 ${url}`)
        const response = { data: { detail: "Not Found" }, status: 404, statusText: "Not Found", headers: {}, config, request: {} }
        throw new AxiosError("Request failed with status code 404", "ERR_BAD_REQUEST", config, {}, response)
      }
      if (url.endsWith("/cbom/sources/fleet/status")) {
        if (sshCa === "no-fleet-routes") return notFound()
        return ok({ inventory: false, policies: false, transports: false, ssh_ca: sshCa })
      }
      if (url.endsWith("/cbom/sources/fleet/ssh-ca")) return sshCa === true ? ok({ cas: [] }) : notFound()
      if (url.includes("/cbom/sources/nodes")) return ok({ nodes: [NODE], server_time: new Date().toISOString() })
      if (url.includes("/cbom/sources/settings")) return ok({ settings: { network_exclusions: [] } })
      if (url.includes("/cbom/sources/overview")) return ok({ viewer: { is_admin: true } })
      if (url.includes("/cbom/sources")) return ok({ sources: [], server_time: new Date().toISOString() })
      return ok({})
    }
    const client = new QueryClient({ defaultOptions: { queries: { retry: false, refetchInterval: false } } })
    const host = document.createElement("div")
    document.body.appendChild(host)
    const root = createRoot(host)
    await act(async () => { root.render(React.createElement(QueryClientProvider, { client }, React.createElement(ServersTab, { teamId: TEAM, onNavigate: () => {} }))) })
    for (let i = 0; i < 10; i++) await act(async () => { await new Promise((r) => setTimeout(r, 20)) })
    const formShown = !!host.querySelector('[data-testid="servers-name"]')
    root.unmount()
    host.remove()
    client.clear()
    return { requests, failed, formShown }
  }

  // 1. default deployment (CBOM_SSH_CA unset): the status is asked, the SSH CA list is not, nothing fails
  const off = await visit(false)
  assert.ok(off.formShown, "the Linux server form is on the page")
  assert.ok(off.requests.includes(`GET /${TEAM}/cbom/sources/fleet/status`), `fleet status asked: ${off.requests.join(", ")}`)
  assert.deepEqual(off.requests.filter((r) => r.endsWith("/fleet/ssh-ca")), [], "no SSH CA request while the flag is off")
  assert.deepEqual(off.failed, [], "no failed (404) request on the Servers tab")

  // 2. an older server without the fleet routes: its status 404 hides the option, and still no SSH CA request
  const old = await visit("no-fleet-routes")
  assert.deepEqual(old.requests.filter((r) => r.endsWith("/fleet/ssh-ca")), [], "no SSH CA request without fleet routes")

  // 3. CBOM_SSH_CA on: the list is asked once and answers 200
  const on = await visit(true)
  assert.equal(on.requests.filter((r) => r.endsWith("/fleet/ssh-ca")).length, 1, `SSH CA list asked once: ${on.requests.join(", ")}`)
  assert.deepEqual(on.failed, [])

  console.log = realLog
  console.log("servers SSH CA gate tests passed")
  process.exit(0)
}

main().catch((e) => { console.error(e); process.exit(1) })
