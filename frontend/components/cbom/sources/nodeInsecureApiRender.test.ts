/**
 * CB-03 review (PR #72, AC8): the warning is RENDERED, not just present in the source. The real ScanNodesTab and
 * AgentPoolsCard are mounted in jsdom (react-dom/client) with this deployment's API URL set to plain HTTP, the way
 * a customer opens them: "Add your first scan node" opens the wizard, "Create agent pool token" opens the pool form.
 * With an https:// URL the pool card shows nothing. No network: the node list and pool list are seeded in the cache.
 * jsdom comes with isomorphic-dompurify (a dependency of the app), react-dom with the app itself.
 * Run: npx --yes tsx components/cbom/sources/nodeInsecureApiRender.test.ts
 */
import assert from "node:assert/strict"
import { createRequire } from "node:module"

const HTTP_API = "http://devsec-staging-api.example"

// jsdom ships no type declarations in this install; the test needs only its constructor and window
type Dom = { window: Window & typeof globalThis }
const load = createRequire(__filename)
const { JSDOM } = load("jsdom") as { JSDOM: new (html: string, options: Record<string, unknown>) => Dom }

async function main() {
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://devsec.example/1/cbom/sources", pretendToBeVisual: true })
  const g = globalThis as Record<string, unknown>
  for (const name of ["window", "document", "navigator", "HTMLElement", "Element", "Node", "MutationObserver", "getComputedStyle",
    "requestAnimationFrame", "cancelAnimationFrame", "localStorage", "sessionStorage", "Event", "KeyboardEvent", "MouseEvent",
    "PointerEvent", "FocusEvent", "CustomEvent", "DocumentFragment", "HTMLInputElement", "HTMLButtonElement"]) {
    const value = (dom.window as unknown as Record<string, unknown>)[name]
    if (value !== undefined) Object.defineProperty(g, name, { value, configurable: true, writable: true })
  }
  g.IS_REACT_ACT_ENVIRONMENT = true
  const consoleError = console.error // Radix's portalled Select items update outside act(): noise, not a failure
  console.error = (...args: unknown[]) => { if (!String(args[0]).includes("not wrapped in act")) consoleError(...args) }
  g.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} }
  ;(dom.window as unknown as Record<string, unknown>).scrollTo = () => {}
  ;(dom.window.HTMLElement.prototype as unknown as Record<string, unknown>).scrollIntoView = () => {}
  process.env.NEXT_PUBLIC_BACKEND_URL = HTTP_API // read by utils/interceptors when ScanNodesTab is imported below

  // one module system for the test and the components (tsx compiles the components to CommonJS): a dynamic import()
  // would load the ESM builds of react / react-query, a second copy the components never see
  const React = load("react") as typeof import("react")
  const { act } = React
  const { createRoot } = load("react-dom/client") as typeof import("react-dom/client")
  const { QueryClient, QueryClientProvider } = load("@tanstack/react-query") as typeof import("@tanstack/react-query")
  const { default: ScanNodesTab } = load("./ScanNodesTab") as typeof import("./ScanNodesTab")
  const { AgentPoolsCard } = load("./AgentPoolsCard") as typeof import("./AgentPoolsCard")
  const { cbomSourcesKeys } = load("./keys") as typeof import("./keys")

  const client = () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, refetchInterval: false } } })
    qc.setQueryData(cbomSourcesKeys.nodes(1), { nodes: [], server_time: new Date().toISOString() })
    qc.setQueryData([...cbomSourcesKeys.all(1), "node-pools"], { pools: [] })
    return qc
  }
  const mount = async (el: React.ReactElement) => {
    const host = document.createElement("div")
    document.body.appendChild(host)
    const root = createRoot(host)
    await act(async () => { root.render(React.createElement(QueryClientProvider, { client: client() }, el)) })
    return { host, root }
  }
  const click = async (host: HTMLElement, text: RegExp) => {
    const button = [...host.querySelectorAll("button")].find((b) => text.test(b.textContent || ""))
    assert.ok(button, `button ${text} on the page`)
    await act(async () => { button!.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true })) })
  }

  // 1. the scan-node wizard, as a customer opens it
  const tab = await mount(React.createElement(ScanNodesTab, { teamId: 1, onNavigate: () => {} }))
  assert.equal(tab.host.querySelector('[data-testid="node-api-insecure"]'), null, "nothing before the wizard opens")
  await click(tab.host, /Add your first scan node/)
  const warning = tab.host.querySelector('[data-testid="node-api-insecure"]')
  assert.ok(warning, "the wizard shows the warning")
  assert.ok(warning!.textContent!.includes(HTTP_API) && /refuses http:\/\//.test(warning!.textContent!), warning!.textContent!)
  assert.equal(warning!.getAttribute("role"), "alert")
  tab.root.unmount()

  // 2. the agent-pool card: plain HTTP warns once the form is open, https:// never does
  for (const [url, shown] of [[HTTP_API, true], ["https://api.example", false]] as const) {
    const card = await mount(React.createElement(AgentPoolsCard, { teamId: 1, image: "img:1", apiUrl: url }))
    await click(card.host, /Create agent pool token/)
    assert.ok(card.host.querySelector('[data-testid="agent-pool-form"]'), "the pool form is open")
    const pool = card.host.querySelector('[data-testid="pool-api-insecure"]')
    assert.equal(!!pool, shown, `${url}: pool warning shown=${!!pool}`)
    if (pool) assert.ok(pool.textContent!.includes(url))
    card.root.unmount()
  }
  console.log("insecure API URL render tests passed")
  process.exit(0)
}

main().catch((e) => { console.error(e); process.exit(1) })
