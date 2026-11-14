/**
 * Owner, staging 14 Nov (Sources > Scan nodes > Add node): the docker command named an image that does not exist
 * (registry.zeroshield.ai), the air-gap text told customers to run `make node-image` in a repository they never get,
 * the OVA and AMI rows said "Build it yourself (template provided)" with nothing to download, and the Helm row needed
 * the repository. Now the server serves the scan node (image file, Helm chart, OVA/AMI build kits) and the wizard
 * offers them as buttons.
 *
 * The real ScanNodesTab is mounted in jsdom (react-dom/client) the way a customer opens it, with the server's list of
 * downloads seeded in the query cache and the API answered by a stub adapter on the app's axios instance: each way
 * of running a node shows its download buttons, a download asks for a link and hands it to the browser, a server
 * without the files says so, and no customer-facing text names registry.zeroshield.ai or `make node-image`.
 * Run: npx --yes tsx components/cbom/sources/nodeDownloads.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import { createRequire } from "node:module"
import path from "node:path"

const API = "https://devsec-api.example"
const SHA = "3f9a1c2b7d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcd"

type Dom = { window: Window & typeof globalThis }
const load = createRequire(__filename)
const { JSDOM } = load("jsdom") as { JSDOM: new (html: string, options: Record<string, unknown>) => Dom }

// Customer-facing text: never a registry we do not run, never a step in a repository customers do not have.
const BANNED = [/registry\.zeroshield\.ai/, /make node-image/, /Build it yourself/i, /in the DevSecShield repository/i,
  /deploy\/node-images\//, /oci:\/\//]

const AVAILABLE = {
  version: "1.0.0",
  image_ref: "localhost/zeroshield/cbom-scan-node:1.0.0",
  pull_image_ref: null,
  artifacts: [
    { kind: "image", label: "Scan node image", available: true, filename: "scan-node-1.0.0.tar.gz", size: 66_270_412, sha256: SHA, message: null },
    { kind: "helm-chart", label: "Helm chart", available: true, filename: "cbom-scan-node-1.0.0.tgz", size: 9_216, sha256: SHA.replace(/3/g, "4"), message: null },
    { kind: "ova-kit", label: "OVA build kit", available: true, filename: "cbom-scan-node-ova-kit-1.0.0.zip", size: 14_000, sha256: SHA.replace(/a/g, "b"), message: null },
    { kind: "ami-kit", label: "AMI build kit", available: true, filename: "cbom-scan-node-ami-kit-1.0.0.zip", size: 9_000, sha256: SHA.replace(/c/g, "d"), message: null },
  ],
}
const NOT_HERE = (label: string) => `${label} is not available on this server yet. Contact your administrator.`
const MISSING = {
  version: null, image_ref: null, pull_image_ref: null,
  artifacts: AVAILABLE.artifacts.map((a) => ({ ...a, available: false, filename: null, size: null, sha256: null, message: NOT_HERE(a.label) })),
}

const NODE = {
  id: 41, name: "dc-1", segment: "Data centre", timezone: "Asia/Kolkata", deployment: "docker", proxy_url: null, status: "pending",
  mode: "agentless", pool_id: null, node_version: null, enrolled_at: null, last_heartbeat_at: null, assigned_targets: 0,
  registration_expires_at: null, clock_in_sync: null, clock_skew_s: null, signing: "required", source_ips: [], row_version: 1,
}

async function main() {
  // 0. the source of every customer-facing piece (components and the page), tests excluded
  const here = __dirname
  const sources = fs.readdirSync(here).filter((f) => /\.(ts|tsx)$/.test(f) && !f.endsWith(".test.ts")).map((f) => path.join(here, f))
  sources.push(path.join(here, "../../../app/[team_id]/cbom/sources/page.tsx"))
  for (const file of sources) {
    const text = fs.readFileSync(file, "utf8")
    for (const banned of BANNED.slice(0, 2)) assert.ok(!banned.test(text), `${path.basename(file)} says ${banned}`)
  }

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

  // the browser download: record the link the page hands to the browser instead of navigating
  const followed: string[] = []
  ;(dom.window.HTMLAnchorElement.prototype as unknown as { click: () => void }).click = function (this: HTMLAnchorElement) {
    followed.push(this.href)
  }

  const React = load("react") as typeof import("react")
  const { act } = React
  const { createRoot } = load("react-dom/client") as typeof import("react-dom/client")
  const { QueryClient, QueryClientProvider } = load("@tanstack/react-query") as typeof import("@tanstack/react-query")
  const { default: api } = load("../../../utils/interceptors") as { default: { defaults: { adapter: unknown } } }
  const { default: ScanNodesTab } = load("./ScanNodesTab") as typeof import("./ScanNodesTab")
  const { cbomSourcesKeys } = load("./keys") as typeof import("./keys")

  // the API: a link for a file the server holds, the server's 404 sentence for one it does not
  const requests: string[] = []
  let serverHasFiles = true
  // what "Create node" answers and the node list then holds (1c: install links, the node's method and proxy)
  let createdNode: Record<string, unknown> = NODE
  let installLinks: unknown = undefined
  api.defaults.adapter = async (config: { url?: string; method?: string }) => {
    requests.push(`${config.method?.toUpperCase()} ${config.url}`)
    const ok = (data: unknown) => ({ data, status: 200, statusText: "OK", headers: {}, config })
    if (config.method === "post" && config.url === "/1/cbom/sources/nodes") {
      return ok({ node: createdNode, registration_token: "zsr_TESTONLY", ...(installLinks === undefined ? {} : { install_links: installLinks }) })
    }
    if (config.method === "get" && config.url === "/1/cbom/sources/nodes") return ok({ nodes: [createdNode], server_time: new Date().toISOString() })
    const m = /^\/1\/cbom\/node-artifacts\/([a-z0-9-]+)\/link$/.exec(config.url ?? "")
    if (m && serverHasFiles) {
      return { data: { url: `/1/cbom/node-artifacts/${m[1]}?ticket=1.2.sig`, expires_in: 300 }, status: 200, statusText: "OK", headers: {}, config }
    }
    const error = Object.assign(new Error("Request failed with status code 404"), {
      config, response: { status: 404, data: { detail: NOT_HERE("OVA build kit") }, headers: {}, config },
    })
    throw error
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
  const buttons = (host: HTMLElement) => [...host.querySelectorAll("button")]
  const button = (host: HTMLElement, text: RegExp) => {
    const found = buttons(host).find((b) => text.test(b.textContent || ""))
    assert.ok(found, `button ${text} on the page: ${buttons(host).map((b) => b.textContent).join(" | ")}`)
    return found!
  }
  const click = async (el: Element) => {
    await act(async () => { el.dispatchEvent(new dom.window.MouseEvent("click", { bubbles: true })) })
  }
  const choose = async (host: HTMLElement, title: string) => {
    const label = [...host.querySelectorAll("label")].find((l) => l.textContent?.includes(title))
    assert.ok(label, `deployment card ${title}`)
    await click(label!.querySelector("input")!)
  }
  const wizardText = (host: HTMLElement) => host.querySelector("#scan-node-wizard")!.textContent!

  // 1. a server with every download: each way of running a node offers its files
  const tab = await mount(AVAILABLE)
  await click(button(tab.host, /Add your first scan node/))
  let text = wizardText(tab.host)
  assert.ok(text.includes("Downloads (scan node 1.0.0)"), text)
  const image = button(tab.host, /^Download scan node image/)
  assert.equal(image.textContent, "Download scan node image (63.2 MB, sha256 3f9a1c2b7d4e…)")
  assert.equal(image.disabled, false)
  assert.ok(text.includes(`scan-node-1.0.0.tar.gz · SHA-256 ${SHA}`), "the full hash to check against")
  assert.ok(button(tab.host, /^\.sha256$/))
  for (const banned of BANNED) assert.ok(!banned.test(text), `Docker: ${banned}`)

  await choose(tab.host, "OVA appliance")
  text = wizardText(tab.host)
  assert.ok(text.includes("Packer build kit (download below)"))
  assert.equal(button(tab.host, /^Download OVA build kit/).disabled, false)
  assert.ok(button(tab.host, /^Download scan node image/), "the kit builds from the image file: offered next to it")
  const ovaSteps = tab.host.querySelector('[data-testid="node-kit-steps-ova"]')!
  assert.equal(ovaSteps.querySelectorAll("li").length, 3, "three lines of instructions")
  assert.ok(ovaSteps.textContent!.includes("packer build"))
  for (const banned of BANNED) assert.ok(!banned.test(text), `OVA: ${banned}`)

  await choose(tab.host, "AWS AMI")
  text = wizardText(tab.host)
  assert.equal(button(tab.host, /^Download AMI build kit/).disabled, false)
  assert.equal(tab.host.querySelector('[data-testid="node-kit-steps-ami"]')!.querySelectorAll("li").length, 3)
  for (const banned of BANNED) assert.ok(!banned.test(text), `AMI: ${banned}`)

  await choose(tab.host, "Helm chart")
  text = wizardText(tab.host)
  assert.ok(button(tab.host, /^Download Helm chart/) && button(tab.host, /^Download scan node image/))
  for (const banned of BANNED) assert.ok(!banned.test(text), `Helm: ${banned}`)

  // a download: a link from the server, followed by the browser (straight to disk), on the API's origin
  await click(button(tab.host, /^Download Helm chart/))
  assert.deepEqual(requests.filter((r) => r.includes("node-artifacts")), ["POST /1/cbom/node-artifacts/helm-chart/link"])
  assert.deepEqual(followed, [`${API}/1/cbom/node-artifacts/helm-chart?ticket=1.2.sig`])
  await click(button(tab.host, /^Download scan node image/))
  await click(button(tab.host, /^\.sha256$/))
  assert.deepEqual(followed.slice(1), [`${API}/1/cbom/node-artifacts/image?ticket=1.2.sig`, `${API}/1/cbom/node-artifacts/image-sha256?ticket=1.2.sig`])

  // the files went away between the list and the click: the server's sentence is shown
  serverHasFiles = false
  await choose(tab.host, "OVA appliance")
  await click(button(tab.host, /^Download OVA build kit/))
  assert.ok(wizardText(tab.host).includes(NOT_HERE("OVA build kit")), wizardText(tab.host))
  assert.equal(followed.length, 3, "nothing handed to the browser")
  tab.root.unmount()

  // 1b. the command after "Create node": check and load the downloaded file, then run the name it loads as, never
  // pulling it; with a registry the server names (CBOM_NODE_IMAGE_REF), a pull variant as well
  for (const pullRef of [null, "reg.bank.example/zs/cbom-scan-node:1.0.0"]) {
    const t = await mount({ ...AVAILABLE, pull_image_ref: pullRef })
    await click(button(t.host, /Add your first scan node/))
    const name = t.host.querySelector("#node-name") as HTMLInputElement
    await act(async () => {
      Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, "value")!.set!.call(name, "dc-1")
      name.dispatchEvent(new dom.window.Event("input", { bubbles: true }))
    })
    await click(button(t.host, /Create node and show install command/))
    const shown = wizardText(t.host).replace(/\s+/g, " ")
    const check = shown.indexOf("sha256sum -c scan-node-1.0.0.tar.gz.sha256")
    const loadAt = shown.indexOf("docker load -i scan-node-1.0.0.tar.gz")
    const run = shown.indexOf("docker run -d --pull never --name zs-scan-node-dc-1")
    assert.ok(check >= 0 && loadAt > check && run > loadAt, shown)
    assert.ok(shown.includes("localhost/zeroshield/cbom-scan-node:1.0.0") && shown.includes("zsr_TESTONLY"), shown)
    const pull = t.host.querySelector('[data-testid="node-command-pull"]')
    if (pullRef) {
      assert.ok(pull && pull.textContent!.includes(`docker run -d --name zs-scan-node-dc-1`) && pull.textContent!.includes(pullRef), pull?.textContent ?? "")
    } else {
      assert.equal(pull, null, "no registry configured: no pull command")
    }
    for (const banned of BANNED) assert.ok(!banned.test(shown), `created node: ${banned}`)
    t.root.unmount()
  }

  // 1c. terminal-only hosts: after "Create node" ONE paste per method that fetches the node's files with its install
  // links (curl; wget below it), checks them and installs; the proxy and (TLS-inspecting proxy) CA apply to the
  // download. No pull command unless the server names a public registry image; with one, docker pull / helm oci://.
  const link = (kind: string, filename: string, sha256: string) => ({ kind, filename, size: 10, sha256, url: `/1/cbom/node-artifacts/${kind}?node_ticket=41.SIG` })
  const FILES = {
    image: link("image", "scan-node-1.0.0.tar.gz", SHA),
    "helm-chart": link("helm-chart", "cbom-scan-node-1.0.0.tgz", SHA.replace(/3/g, "4")),
    "ova-kit": link("ova-kit", "cbom-scan-node-ova-kit-1.0.0.zip", SHA.replace(/a/g, "b")),
    "ami-kit": link("ami-kit", "cbom-scan-node-ami-kit-1.0.0.zip", SHA.replace(/c/g, "d")),
  }
  const GHCR = "ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node:1.0.0"  // pinned to the release
  const CHART = "oci://ghcr.io/cyberultron-consulting-private-limited/charts/cbom-scan-node"
  const PUBLIC = { ...AVAILABLE, pull_image_ref: GHCR, pull_chart_ref: CHART, pull_chart_version: "1.0.0" }
  const createWith = async (artifacts: unknown, card: string, method: string, kinds: (keyof typeof FILES)[], node: Record<string, unknown> = {}) => {
    createdNode = { ...NODE, deployment: method, ...node }
    installLinks = { version: "1.0.0", expires_at: "2026-11-15T10:00:00Z", files: kinds.map((k) => FILES[k]) }
    const t = await mount(artifacts)
    await click(button(t.host, /Add your first scan node/))
    await choose(t.host, card)
    const name = t.host.querySelector("#node-name") as HTMLInputElement
    await act(async () => {
      Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, "value")!.set!.call(name, "dc-1")
      name.dispatchEvent(new dom.window.Event("input", { bubbles: true }))
    })
    await click(button(t.host, /Create node and show install command/))
    const block = t.host.querySelector('[data-testid="node-one-paste"]')
    assert.ok(block, `${card}: a one-paste block\n${wizardText(t.host)}`)
    return { t, block: block!.textContent!.replace(/\s+/g, " "), wget: t.host.querySelector('[data-testid="node-one-paste-wget"]')!.textContent!.replace(/\s+/g, " "),
      pull: t.host.querySelector('[data-testid="node-command-pull"]')?.textContent?.replace(/\s+/g, " ") ?? null }
  }
  const fetchOf = (kind: keyof typeof FILES) =>
    `curl -fsSL --proto '=https' '${API}${FILES[kind].url}' -o ${FILES[kind].filename} && echo '${FILES[kind].sha256} ${FILES[kind].filename}' | sha256sum -c -`
  {
    const d = await createWith(AVAILABLE, "Docker container", "docker", ["image"])
    assert.ok(d.block.includes(`${fetchOf("image")} && \\ docker load -i scan-node-1.0.0.tar.gz && \\ docker run -d --pull never --name zs-scan-node-dc-1`), d.block)
    assert.ok(d.block.includes("-e ZS_REGISTRATION_TOKEN='zsr_TESTONLY'") && d.block.includes("localhost/zeroshield/cbom-scan-node:1.0.0"), d.block)
    assert.ok(d.block.includes("stay in your shell history"), "the shell-history note")
    assert.ok(d.wget.includes(`wget -q -O scan-node-1.0.0.tar.gz '${API}${FILES.image.url}'`), d.wget)
    assert.equal(d.pull, null, "no public registry: no pull command")
    assert.ok(!/docker pull|oci:\/\//.test(wizardText(d.t.host)), "no pull anywhere")
    d.t.root.unmount()
  }
  {
    // the node's proxy, and its proxy inspects TLS with a CA given: --proxy and --cacert on the download
    const d = await createWith(AVAILABLE, "Docker container", "docker", ["image"],
      { proxy_url: "http://proxy.bank.local:8080", proxy_tls_inspect: true, has_proxy_ca: true })
    assert.ok(d.block.includes(`curl -fsSL --proto '=https' --proxy 'http://proxy.bank.local:8080' --cacert 'zs-proxy-ca.pem' '${API}/1/cbom/node-artifacts/image`), d.block)
    assert.ok(d.block.includes("zs-proxy-ca.pem: your proxy's CA certificate"), d.block)
    assert.ok(d.wget.includes("-e https_proxy='http://proxy.bank.local:8080' --ca-certificate='zs-proxy-ca.pem'"), d.wget)
    d.t.root.unmount()
    const noInspect = await createWith(AVAILABLE, "Docker container", "docker", ["image"],
      { proxy_url: "http://proxy.bank.local:8080", proxy_tls_inspect: false, has_proxy_ca: true })
    assert.ok(noInspect.block.includes("--proxy 'http://proxy.bank.local:8080'") && !noInspect.block.includes("--cacert"), noInspect.block)
    noInspect.t.root.unmount()
  }
  {
    const h = await createWith(AVAILABLE, "Helm chart", "helm", ["image", "helm-chart"])
    for (const part of ["REGISTRY=registry.example.internal/zeroshield", fetchOf("image"), fetchOf("helm-chart"),
      `docker tag localhost/zeroshield/cbom-scan-node:1.0.0 "$REGISTRY/cbom-scan-node:1.0.0"`, `docker push "$REGISTRY/cbom-scan-node:1.0.0"`,
      "helm upgrade --install zs-scan-node-dc-1 ./cbom-scan-node-1.0.0.tgz"]) {
      assert.ok(h.block.includes(part), `${part}\n---\n${h.block}`)
    }
    assert.equal(h.pull, null)
    h.t.root.unmount()
  }
  for (const [card, method, kit] of [["OVA appliance", "ova", "ova-kit"], ["AWS AMI", "ami", "ami-kit"]] as const) {
    const k = await createWith(AVAILABLE, card, method, [kit, "image"])
    assert.ok(k.block.includes(fetchOf(kit)) && k.block.includes(fetchOf("image")), k.block)
    assert.ok(k.block.includes(`unzip -q cbom-scan-node-${method}-kit-1.0.0.zip && mv scan-node-1.0.0.tar.gz cbom-scan-node-${method}-kit-1.0.0/`), k.block)
    assert.ok(k.block.includes(`packer init ${method}.pkr.hcl && packer build`), k.block)
    assert.ok(wizardText(k.t.host).includes(method === "ova" ? "zs.registration_token = zsr_TESTONLY" : "ZS_REGISTRATION_TOKEN=zsr_TESTONLY"),
      "the vApp properties / user data are still shown")
    k.t.root.unmount()
  }
  {
    // a public registry (staging with CBOM_NODE_REGISTRY_PUBLIC=1): the one-paste download AND docker pull / helm oci://
    const d = await createWith(PUBLIC, "Docker container", "docker", ["image"])
    assert.ok(d.pull && d.pull.includes(`docker pull ${GHCR} && \\ docker run -d --name zs-scan-node-dc-1`), d.pull ?? "")
    assert.ok(d.block.includes(fetchOf("image")), "the product download stays alongside")
    // the registry command is the MAIN one (first); the files are the air-gapped alternative below it
    const html = d.t.host.innerHTML
    assert.ok(html.indexOf('data-testid="node-command-pull"') < html.indexOf('data-testid="node-air-gapped"'), "registry first")
    const gapped = d.t.host.querySelector('[data-testid="node-air-gapped"]')!
    assert.ok(gapped.querySelector('[data-testid="node-one-paste"]'), "the one-paste download is in the air-gapped section")
    assert.ok(/Air-gapped host, or no access to ghcr\.io\?/.test(gapped.textContent!), gapped.textContent!)
    assert.ok(d.t.host.querySelector('[data-testid="node-command-pull"]')!.textContent!.includes("public, no login needed"))
    d.t.root.unmount()
    const h = await createWith(PUBLIC, "Helm chart", "helm", ["image", "helm-chart"])
    assert.ok(h.pull && h.pull.includes(`helm upgrade --install zs-scan-node-dc-1 ${CHART} --version '1.0.0'`), h.pull ?? "")
    assert.ok(h.pull!.includes("--set image.repository='ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node' --set image.tag='1.0.0'"), h.pull!)
    // the air-gapped alternative installs the downloaded chart with the image from the file, never the registry's
    const gappedHelm = h.t.host.querySelector('[data-testid="node-air-gapped"]')!.textContent!.replace(/\s+/g, " ")
    assert.ok(gappedHelm.includes("helm upgrade --install zs-scan-node-dc-1 ./cbom-scan-node-1.0.0.tgz") && !gappedHelm.includes("ghcr.io/"), gappedHelm)
    h.t.root.unmount()
  }
  {
    // an older server (no install_links in its answer): no one-paste block, the browser-download command as before
    createdNode = NODE
    installLinks = undefined
    const t = await mount(AVAILABLE)
    await click(button(t.host, /Add your first scan node/))
    const name = t.host.querySelector("#node-name") as HTMLInputElement
    await act(async () => {
      Object.getOwnPropertyDescriptor(dom.window.HTMLInputElement.prototype, "value")!.set!.call(name, "dc-1")
      name.dispatchEvent(new dom.window.Event("input", { bubbles: true }))
    })
    await click(button(t.host, /Create node and show install command/))
    assert.equal(t.host.querySelector('[data-testid="node-one-paste"]'), null)
    assert.ok(wizardText(t.host).includes("sha256sum -c scan-node-1.0.0.tar.gz.sha256"))
    t.root.unmount()
  }

  // 2. a server without the files: every button disabled, with "not available on this server yet, contact your
  // administrator", and nothing that sends the customer to a registry or a repository
  const bare = await mount(MISSING)
  await click(button(bare.host, /Add your first scan node/))
  for (const [card, kinds] of [["Docker container", ["image"]], ["OVA appliance", ["ova-kit", "image"]],
    ["AWS AMI", ["ami-kit", "image"]], ["Helm chart", ["helm-chart", "image"]]] as const) {
    await choose(bare.host, card)
    const t = wizardText(bare.host)
    for (const kind of kinds) {
      const item = bare.host.querySelector(`[data-testid="node-download-${kind}"]`)!
      assert.ok(item, `${card}: ${kind}`)
      assert.equal(item.querySelector("button")!.disabled, true, `${card}: ${kind} disabled`)
      assert.ok(/is not available on this server yet\. Contact your administrator\./.test(item.textContent!), item.textContent!)
    }
    for (const banned of BANNED) assert.ok(!banned.test(t), `${card} without files: ${banned}`)
  }
  bare.root.unmount()

  console.log("node downloads tests passed")
}

main().then(() => process.exit(0), (err) => {
  console.error(err)
  process.exit(1)
})
