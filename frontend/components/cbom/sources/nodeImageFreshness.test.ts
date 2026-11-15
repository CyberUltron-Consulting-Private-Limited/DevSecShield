/**
 * Issue #197 (staging 6a6ef42, 14 Nov): the Add scan node wizard installed a stale scan node image. Its registry image
 * was the release tag devsecshield-scan-node:1.0.0, written once on 2 Nov and never again while the node VERSION
 * stayed 1.0.0, so dc-mumbai-01 (Docker) did not sign requests and k8s-lab-01 (Helm) never became Ready (no alive
 * file for the chart's readiness probe); old and new images both reported 1.0.0.
 *
 * 1. logic.imageFreshness agrees with the backend on every case of contracts/cbom/node_image_freshness.json.
 * 2. The real ScanNodesTab, mounted in jsdom the way a customer opens it: a stale registry image (the frozen release
 *    tag, another commit, an older version) is never in the commands, the wizard says why, and the commands install
 *    this server's image file; the server's own build (<version>-<sha12>) is the one-command docker pull with no
 *    warning; a moving tag (:staging) is offered with a note.
 * 3. The air-gapped Helm commands push the downloaded image as <version>-<sha12>, so a cluster holding an older image
 *    of the same version (pullPolicy IfNotPresent) cannot keep running it.
 * Run: npx --yes tsx components/cbom/sources/nodeImageFreshness.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import { createRequire } from "node:module"
import path from "node:path"

const API = "https://devsec-api.example"
const SHA = "3f9a1c2b7d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcd"
const BUILD = "5d41b4cc9a1f2e3d4c5b6a79881726354a5b6c7d"
const GHCR = "ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node"

type Dom = { window: Window & typeof globalThis }
const load = createRequire(__filename)
const { JSDOM } = load("jsdom") as { JSDOM: new (html: string, options: Record<string, unknown>) => Dom }

type Case = { ref: string; server_version: string | null; server_build: string | null; state: string; reason: string }

async function main() {
  // ---------------------------------------------------------------------------------------------- 1. the contract
  const logic = load("./logic") as typeof import("./logic")
  const contract = JSON.parse(fs.readFileSync(path.join(__dirname, "../../../../contracts/cbom/node_image_freshness.json"), "utf8")) as
    { server_build: string; stale_states: string[]; cases: Case[] }
  assert.deepEqual([...logic.STALE_IMAGE_STATES], contract.stale_states)
  for (const c of contract.cases) {
    const got = logic.imageFreshness(c.ref, c.server_version, c.server_build === "SERVER" ? contract.server_build : c.server_build)
    assert.ok(got, c.ref)
    assert.deepEqual([got!.state, got!.reason], [c.state, c.reason], `${c.ref} @ ${c.server_version}: ${JSON.stringify(got)}`)
    assert.equal(got!.message !== null, contract.stale_states.includes(c.state) || c.state === "moving", c.ref)
  }
  assert.equal(logic.imageFreshness("", "1.1.0", BUILD), null)

  // nodeImages: the server's verdict wins for its own image; a stale image is never offered for pulling
  const base = {
    version: "1.1.0", build: BUILD, node_build: `1.1.0+${BUILD.slice(0, 12)}`,
    image_ref: "localhost/zeroshield/cbom-scan-node:1.1.0", pull_image_ref: null as string | null,
    artifacts: [
      { kind: "image", label: "Scan node image", available: true, filename: "scan-node-1.1.0.tar.gz", size: 66_270_412, sha256: SHA, message: null },
      { kind: "helm-chart", label: "Helm chart", available: true, filename: "cbom-scan-node-1.1.0.tgz", size: 9_216, sha256: SHA.replace(/3/g, "4"), message: null },
      { kind: "ova-kit", label: "OVA build kit", available: true, filename: "cbom-scan-node-ova-kit-1.1.0.zip", size: 14_000, sha256: SHA.replace(/a/g, "b"), message: null },
      { kind: "ami-kit", label: "AMI build kit", available: true, filename: "cbom-scan-node-ami-kit-1.1.0.zip", size: 9_000, sha256: SHA.replace(/c/g, "d"), message: null },
    ] as import("./logic").NodeArtifact[],
  }
  const verdict = (ref: string) => logic.imageFreshness(ref, "1.1.0", BUILD)
  {
    const frozen = `${GHCR}:1.1.0`
    const imgs = logic.nodeImages({ ...base, pull_image_ref: frozen, pull_image_freshness: verdict(frozen) })
    assert.equal(imgs.pulled, null, "the release tag written once is not offered")
    assert.ok(imgs.registry?.stale && imgs.registry.freshness?.state === "unverified")
    const own = `${GHCR}:1.1.0-${BUILD.slice(0, 12)}`
    const ok = logic.nodeImages({ ...base, pull_image_ref: own, pull_image_freshness: verdict(own) })
    assert.equal(ok.pulled?.image, own)
    assert.equal(ok.registry?.stale, false)
    // the build's image (NEXT_PUBLIC_CBOM_NODE_IMAGE) when the server names none: judged against the server's build
    const old = logic.nodeImages(base, `${GHCR}:dev-0123456789ab`)
    assert.equal(old.pulled, null)
    assert.equal(old.registry?.freshness?.state, "different")
    assert.equal(logic.nodeImages(base, `${GHCR}:dev-${BUILD.slice(0, 12)}`).pulled?.image, `${GHCR}:dev-${BUILD.slice(0, 12)}`)
    // the downloaded image carries the build; the push tag names it, a pulled image keeps its own tag
    assert.equal(ok.loaded.build, BUILD)
    assert.equal(logic.pushTag(ok.loaded), `1.1.0-${BUILD.slice(0, 12)}`)
    assert.equal(logic.pushTag({ image: own, pull: true, build: BUILD }), `1.1.0-${BUILD.slice(0, 12)}`)
    assert.equal(logic.pushTag({ image: "localhost/zeroshield/cbom-scan-node:1.1.0" }), "1.1.0", "no build known: the version")
    // the pool (host agents) command pushes the same tag
    const pool = logic.helmAgentCommand({ poolToken: "zsp_TESTONLY", apiUrl: API, ...ok.loaded })
    assert.ok(pool.includes(`docker push "$REGISTRY/cbom-scan-node:1.1.0-${BUILD.slice(0, 12)}"`), pool)
    assert.ok(pool.includes(`--set image.tag='1.1.0-${BUILD.slice(0, 12)}'`), pool)
  }

  // ---------------------------------------------------------------------------------------------- 2. the wizard
  const dom = new JSDOM("<!doctype html><html><body></body></html>", { url: "https://devsec.example/1/cbom/sources", pretendToBeVisual: true })
  const g = globalThis as Record<string, unknown>
  for (const name of ["window", "document", "navigator", "HTMLElement", "HTMLAnchorElement", "Element", "Node", "MutationObserver",
    "getComputedStyle", "requestAnimationFrame", "cancelAnimationFrame", "localStorage", "sessionStorage", "Event", "KeyboardEvent",
    "MouseEvent", "PointerEvent", "FocusEvent", "CustomEvent", "DocumentFragment", "HTMLInputElement", "HTMLButtonElement"]) {
    const value = (dom.window as unknown as Record<string, unknown>)[name]
    if (value !== undefined) Object.defineProperty(g, name, { value, configurable: true, writable: true })
  }
  g.IS_REACT_ACT_ENVIRONMENT = true
  const consoleError = console.error
  console.error = (...args: unknown[]) => { if (!String(args[0]).includes("not wrapped in act")) consoleError(...args) }
  g.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} }
  ;(dom.window as unknown as Record<string, unknown>).scrollTo = () => {}
  ;(dom.window.HTMLElement.prototype as unknown as Record<string, unknown>).scrollIntoView = () => {}
  process.env.NEXT_PUBLIC_BACKEND_URL = API

  const React = load("react") as typeof import("react")
  const { act } = React
  const { createRoot } = load("react-dom/client") as typeof import("react-dom/client")
  const { QueryClient, QueryClientProvider } = load("@tanstack/react-query") as typeof import("@tanstack/react-query")
  const { default: api } = load("../../../utils/interceptors") as { default: { defaults: { adapter: unknown } } }
  const { default: ScanNodesTab } = load("./ScanNodesTab") as typeof import("./ScanNodesTab")
  const { cbomSourcesKeys } = load("./keys") as typeof import("./keys")

  const NODE = {
    id: 41, name: "dc-1", segment: "Data centre", timezone: "Asia/Kolkata", deployment: "docker", proxy_url: null, status: "pending",
    mode: "agentless", pool_id: null, node_version: null, enrolled_at: null, last_heartbeat_at: null, assigned_targets: 0,
    registration_expires_at: null, clock_in_sync: null, clock_skew_s: null, signing: "required", source_ips: [], row_version: 1,
  }
  let createdNode: Record<string, unknown> = NODE
  let installLinks: unknown = undefined
  api.defaults.adapter = async (config: { url?: string; method?: string }) => {
    const ok = (data: unknown) => ({ data, status: 200, statusText: "OK", headers: {}, config })
    if (config.method === "post" && config.url === "/1/cbom/sources/nodes") {
      return ok({ node: createdNode, registration_token: "zsr_TESTONLY", ...(installLinks === undefined ? {} : { install_links: installLinks }) })
    }
    if (config.method === "get" && config.url === "/1/cbom/sources/nodes") return ok({ nodes: [createdNode], server_time: new Date().toISOString() })
    throw Object.assign(new Error("unexpected request"), { config, response: { status: 404, data: {}, headers: {}, config } })
  }
  const mount = async (artifacts: unknown) => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity, refetchInterval: false } } })
    qc.setQueryData(cbomSourcesKeys.nodes(1), { nodes: [], server_time: new Date().toISOString() })
    qc.setQueryData([...cbomSourcesKeys.all(1), "node-pools"], { pools: [] })
    qc.setQueryData(cbomSourcesKeys.nodeArtifacts(1), artifacts)
    const host = document.createElement("div")
    document.body.appendChild(host)
    const root = createRoot(host)
    await act(async () => {
      root.render(React.createElement(QueryClientProvider, { client: qc }, React.createElement(ScanNodesTab, { teamId: 1, onNavigate: () => {}, apiUrl: API })))
    })
    return { host, root }
  }
  const click = async (el: Element) => {
    await act(async () => { el.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true })) })
  }
  const button = (host: HTMLElement, text: RegExp) => {
    const found = [...host.querySelectorAll("button")].find((b) => text.test(b.textContent || ""))
    assert.ok(found, `button ${text}`)
    return found!
  }
  const choose = async (host: HTMLElement, title: string) => {
    const label = [...host.querySelectorAll("label")].find((l) => l.textContent?.includes(title))
    assert.ok(label, `deployment card ${title}`)
    await click(label!.querySelector("input")!)
  }
  const wizard = (host: HTMLElement) => host.querySelector("#scan-node-wizard")!.textContent!.replace(/\s+/g, " ")
  const create = async (artifacts: unknown, card = "Docker container", method = "docker") => {
    createdNode = { ...NODE, deployment: method }
    const t = await mount(artifacts)
    await click(button(t.host, /Add your first scan node/))
    if (card !== "Docker container") await choose(t.host, card)
    const before = wizard(t.host)
    const name = t.host.querySelector("#node-name") as HTMLInputElement
    await act(async () => {
      Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, "value")!.set!.call(name, "dc-1")
      name.dispatchEvent(new dom.window.Event("input", { bubbles: true }))
    })
    await click(button(t.host, /Create node and show install command/))
    return { ...t, before, after: wizard(t.host) }
  }
  const OWN = `${GHCR}:1.1.0-${BUILD.slice(0, 12)}`

  // the stale registry images of #197: the frozen release tag (the server's own version, written once), an older
  // version, another commit. Each: a warning before the node is created, and no command names the image.
  for (const ref of [`${GHCR}:1.1.0`, `${GHCR}:1.0.0`, `${GHCR}:staging-0123456789ab`]) {
    const artifacts = { ...base, pull_image_ref: ref, pull_image_freshness: verdict(ref),
      pull_chart_ref: "oci://ghcr.io/cyberultron-consulting-private-limited/charts/cbom-scan-node", pull_chart_version: "1.1.0" }
    for (const [card, method] of [["Docker container", "docker"], ["Helm chart", "helm"]] as const) {
      const w = await create(artifacts, card, method)
      const warn = w.host.querySelector('[data-testid="node-image-stale"]')
      assert.ok(warn, `${ref} ${method}: a warning\n${w.after}`)
      assert.ok(warn!.textContent!.includes(ref) && warn!.textContent!.includes(`1.1.0+${BUILD.slice(0, 12)}`), warn!.textContent!)
      assert.ok(w.before.includes("not this server's scan node build"), "said before the node is created")
      assert.equal(w.host.querySelector('[data-testid="node-command-pull"]'), null, `${ref} ${method}: no pull command`)
      // the command installs this server's image file (Docker: loaded and run; Helm: pushed under <version>-<sha12>)
      const commands = [...w.host.querySelectorAll("pre, code")].map((e) => e.textContent).join("\n")
      assert.ok(!commands.includes(ref), `${ref} ${method}: never in a command\n${commands}`)
      if (method === "docker") {
        assert.ok(commands.includes("docker load -i scan-node-1.1.0.tar.gz") && commands.includes("--pull never"), commands)
      } else {
        assert.ok(commands.includes(`docker push "$REGISTRY/cbom-scan-node:1.1.0-${BUILD.slice(0, 12)}"`), commands)
        assert.ok(!commands.includes("oci://"), "no chart from the registry either: it would run the stale image's tag")
      }
      w.root.unmount()
    }
  }

  // the server's own build in the registry: one command, docker pull of exactly that image, no warning
  {
    const w = await create({ ...base, pull_image_ref: OWN, pull_image_freshness: verdict(OWN) })
    assert.equal(w.host.querySelector('[data-testid="node-image-stale"]'), null)
    assert.equal(w.host.querySelector('[data-testid="node-image-moving"]'), null)
    const pull = w.host.querySelector('[data-testid="node-command-pull"]')!.textContent!
    assert.ok(pull.includes(`docker pull ${OWN}`) && pull.includes(`  ${OWN}`), pull)
    w.root.unmount()
  }
  // a moving channel tag (the deploy found no published image of its build yet): offered, with a note
  {
    const moving = `${GHCR}:staging`
    const w = await create({ ...base, pull_image_ref: moving, pull_image_freshness: verdict(moving) })
    assert.equal(w.host.querySelector('[data-testid="node-image-stale"]'), null)
    assert.ok(w.host.querySelector('[data-testid="node-image-moving"]')!.textContent!.includes("moving tag"))
    assert.ok(w.host.querySelector('[data-testid="node-command-pull"]')!.textContent!.includes(`docker pull ${moving}`))
    w.root.unmount()
  }
  // 3. the one-paste Helm install (terminal-only hosts) pushes the image under its build too
  {
    const link = (kind: string, filename: string) => ({ kind, filename, size: 10, sha256: SHA, url: `/1/cbom/node-artifacts/${kind}?node_ticket=41.SIG` })
    installLinks = { version: "1.1.0", expires_at: "2026-11-16T10:00:00Z",
      files: [link("image", "scan-node-1.1.0.tar.gz"), link("helm-chart", "cbom-scan-node-1.1.0.tgz")] }
    const w = await create(base, "Helm chart", "helm")
    const block = w.host.querySelector('[data-testid="node-one-paste"]')!.textContent!.replace(/\s+/g, " ")
    assert.ok(block.includes(`docker tag localhost/zeroshield/cbom-scan-node:1.1.0 "$REGISTRY/cbom-scan-node:1.1.0-${BUILD.slice(0, 12)}"`), block)
    assert.ok(block.includes(`--set image.tag='1.1.0-${BUILD.slice(0, 12)}'`), block)
    w.root.unmount()
    installLinks = undefined
  }
  console.log("nodeImageFreshness: ok")
}

main().then(() => process.exit(0), (err) => { console.error(err); process.exit(1) })
