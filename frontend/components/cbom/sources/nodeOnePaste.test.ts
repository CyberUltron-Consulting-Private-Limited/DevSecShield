// Run: npx --yes tsx components/cbom/sources/nodeOnePaste.test.ts
//
// Owner, 14 Nov: a terminal-only Linux server must be able to install the scan node. After "Create node and show
// install command" the wizard shows ONE copy-paste block per way of running a node: it fetches the node's files from
// ZeroShield with the node's install links (curl, or wget), checks their SHA-256, then loads and runs the image
// (Docker), pushes it and installs the chart (Helm), or unzips the build kit and runs Packer (OVA/AMI). The proxy and
// CA the wizard collects apply to the download (--proxy, --cacert only for this download from ZeroShield). A registry
// pull is offered only when the server names a registry image (staging: only while the GHCR packages are public).
//
// The blocks are also RUN here with bash against stub curl/wget/docker/helm/packer/unzip (real sha256sum), so a
// syntax slip, a wrong file name or a checksum that does not match fails this test.
import assert from "node:assert/strict"
import { execFileSync, spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import {
  fetchCommand,
  onePasteInstall,
  registryInstall,
  type InstallLinks,
  type NodeArtifacts,
} from "./logic"

const API = "https://devsec-api.example"
const IMAGE = "localhost/zeroshield/cbom-scan-node:1.0.0"
const BODY: Record<string, string> = {
  image: "docker-save-archive-bytes",
  "helm-chart": "helm-chart-bytes",
  "ova-kit": "ova-kit-bytes",
  "ami-kit": "ami-kit-bytes",
}
const NAME: Record<string, string> = {
  image: "scan-node-1.0.0.tar.gz",
  "helm-chart": "cbom-scan-node-1.0.0.tgz",
  "ova-kit": "cbom-scan-node-ova-kit-1.0.0.zip",
  "ami-kit": "cbom-scan-node-ami-kit-1.0.0.zip",
}
const sha = (text: string) => createHash("sha256").update(text).digest("hex")
const file = (kind: keyof typeof BODY) => ({
  kind: kind as "image" | "helm-chart" | "ova-kit" | "ami-kit", filename: NAME[kind], size: BODY[kind].length,
  sha256: sha(BODY[kind]), url: `/1/cbom/node-artifacts/${kind}?node_ticket=41.SIG-${kind}`,
})
const links = (...kinds: (keyof typeof BODY)[]): InstallLinks => ({ version: "1.0.0", expires_at: "2026-11-15T10:00:00Z", files: kinds.map(file) })
const base = { token: "zsr_TESTONLY", apiUrl: API, name: "dc-1", image: IMAGE }

// ---------------------------------------------------------------------------------------------------- the text
// Docker: one block, fetch + check + load + run, the run never pulls
{
  const cmd = onePasteInstall("docker", links("image"), base)!
  const lines = cmd.split("\n")
  assert.equal(lines[0], `curl -fsSL --proto '=https' '${API}/1/cbom/node-artifacts/image?node_ticket=41.SIG-image' -o scan-node-1.0.0.tar.gz && echo '${sha(BODY.image)}  scan-node-1.0.0.tar.gz' | sha256sum -c - && \\`)
  assert.equal(lines[1], "docker load -i scan-node-1.0.0.tar.gz && \\")
  assert.equal(lines[2], "docker run -d --pull never --name zs-scan-node-dc-1 --restart unless-stopped \\")
  assert.ok(cmd.includes("-e ZS_REGISTRATION_TOKEN='zsr_TESTONLY'") && cmd.trimEnd().endsWith(`  ${IMAGE}`), cmd)
  assert.ok(!cmd.includes("--proxy") && !cmd.includes("--cacert") && !cmd.includes("docker pull"), cmd)
}

// proxy and CA from the wizard: on the download only (the CA only when the proxy inspects TLS: the caller passes it)
{
  const cmd = onePasteInstall("docker", links("image"), { ...base, proxyUrl: "http://proxy.bank.local:8080", caFile: "bank-proxy.pem" })!
  assert.ok(cmd.startsWith("# bank-proxy.pem: your proxy's CA certificate"), cmd)
  assert.ok(cmd.includes(`curl -fsSL --proto '=https' --proxy 'http://proxy.bank.local:8080' --cacert 'bank-proxy.pem' '${API}/`), cmd)
  assert.ok(cmd.includes("-e HTTPS_PROXY='http://proxy.bank.local:8080'"), "the node itself still uses the proxy")
  assert.equal(cmd.match(/--cacert/g)!.length, 1, "the CA is used for the ZeroShield download only")
  const proxyOnly = onePasteInstall("docker", links("image"), { ...base, proxyUrl: "http://p:3128" })!
  assert.ok(proxyOnly.includes("--proxy 'http://p:3128'") && !proxyOnly.includes("--cacert"), proxyOnly)
}

// wget for hosts without curl: the same block with wget
{
  const cmd = onePasteInstall("docker", links("image"), { ...base, fetcher: "wget", proxyUrl: "http://p:3128", caFile: "ca.pem" })!
  assert.ok(cmd.includes(`wget -q -e use_proxy=yes -e https_proxy='http://p:3128' --ca-certificate='ca.pem' -O scan-node-1.0.0.tar.gz '${API}/1/cbom/node-artifacts/image?node_ticket=41.SIG-image' && echo '${sha(BODY.image)}  scan-node-1.0.0.tar.gz' | sha256sum -c - && \\`), cmd)
  assert.ok(!cmd.includes("curl"), cmd)
  assert.ok(cmd.includes("wget trusts it for these downloads only"), cmd)
}

// a plain-HTTP test lab: curl may follow http (with the lab switch on the node), never otherwise
{
  const lab = onePasteInstall("docker", links("image"), { ...base, apiUrl: "http://10.0.0.5:8000", insecureHttp: true })!
  assert.ok(lab.includes("--proto '=http,https' 'http://10.0.0.5:8000/1/") && lab.includes("ZS_ALLOW_INSECURE_HTTP=1"), lab)
}

// Helm: image + chart fetched and checked, image pushed to the customer's registry, chart installed from the file
{
  const cmd = onePasteInstall("helm", links("image", "helm-chart"), base)!
  const at = (s: string) => { const i = cmd.indexOf(s); assert.ok(i >= 0, `${s}\n---\n${cmd}`); return i }
  const order = [at("REGISTRY=registry.example.internal/zeroshield"), at("-o scan-node-1.0.0.tar.gz &&"),
    at("-o cbom-scan-node-1.0.0.tgz &&"), at("docker load -i scan-node-1.0.0.tar.gz && \\"),
    at(`docker tag ${IMAGE} "$REGISTRY/cbom-scan-node:1.0.0" && \\`), at('docker push "$REGISTRY/cbom-scan-node:1.0.0" && \\'),
    at("helm upgrade --install zs-scan-node-dc-1 ./cbom-scan-node-1.0.0.tgz \\")]
  assert.deepEqual(order, [...order].sort((a, b) => a - b), cmd)
  assert.ok(cmd.includes(`--set image.repository="$REGISTRY/cbom-scan-node" --set image.tag='1.0.0'`), cmd)
  assert.equal(onePasteInstall("helm", links("image"), base), null, "no chart link: no one-paste block")
}

// OVA and AMI: kit + image fetched and checked, unzipped together, Packer builds
{
  const ova = onePasteInstall("ova", links("ova-kit", "image"), base)!
  assert.ok(ova.includes("unzip -q cbom-scan-node-ova-kit-1.0.0.zip && mv scan-node-1.0.0.tar.gz cbom-scan-node-ova-kit-1.0.0/ && cd cbom-scan-node-ova-kit-1.0.0 && \\"), ova)
  assert.ok(ova.includes('packer init ova.pkr.hcl && packer build -var build_password="$(openssl rand -hex 16)" ova.pkr.hcl'), ova)
  const ami = onePasteInstall("ami", links("ami-kit", "image"), base)!
  assert.ok(ami.includes('packer init ami.pkr.hcl && packer build -var region="${AWS_REGION:-ap-south-1}" ami.pkr.hcl'), ami)
  assert.equal(onePasteInstall("ova", links("image"), base), null)
}

// no links (a server without the files, or an older server): no block at all
assert.equal(onePasteInstall("docker", null, base), null)
assert.equal(onePasteInstall("docker", { version: null, expires_at: null, files: [] }, base), null)

// fetchCommand quotes the URL and the proxy (a hostile value stays one word)
assert.ok(fetchCommand(file("image"), { apiUrl: API, proxyUrl: "http://p'; rm -rf / #" }).includes(`--proxy 'http://p'"'"'; rm -rf / #'`))

// ---------------------------------------------------------------------------------------------------- registry
{
  const none: NodeArtifacts = { version: "1.0.0", image_ref: IMAGE, pull_image_ref: null, artifacts: [] }
  for (const m of ["docker", "helm", "ova", "ami"] as const) assert.equal(registryInstall(m, none, base), null, `${m}: no public registry, no pull`)
  const ghcr = "ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node:staging-0123456789ab"
  const pub: NodeArtifacts = { ...none, pull_image_ref: ghcr, pull_chart_ref: "oci://ghcr.io/cyberultron-consulting-private-limited/charts/cbom-scan-node", pull_chart_version: "1.0.0" }
  const docker = registryInstall("docker", pub, base)!
  assert.ok(docker.startsWith(`docker pull ${ghcr} && \\\ndocker run -d --name zs-scan-node-dc-1 `), docker)
  assert.ok(docker.trimEnd().endsWith(ghcr) && !docker.includes("--pull never"), docker)
  const helm = registryInstall("helm", pub, base)!
  assert.ok(helm.startsWith("helm upgrade --install zs-scan-node-dc-1 oci://ghcr.io/cyberultron-consulting-private-limited/charts/cbom-scan-node --version '1.0.0' \\"), helm)
  assert.ok(helm.includes("--set image.repository='ghcr.io/cyberultron-consulting-private-limited/devsecshield-scan-node' --set image.tag='staging-0123456789ab'"), helm)
  assert.equal(registryInstall("helm", { ...pub, pull_chart_ref: null }, base), null, "an image without a chart: no Helm pull")
  assert.equal(registryInstall("ova", pub, base), null)
}

// ---------------------------------------------------------------------------------------------------- run them
const STUBS: Record<string, string> = {
  // curl/wget: write the body of the kind named in the URL to the -o/-O file; record the arguments
  curl: `#!/usr/bin/env bash
echo "curl $*" >> "$LOG"; out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2;; --proto|--proxy|--cacert) shift 2;; -*) shift;; *) url=$1; shift;; esac; done
kind=\${url#*/node-artifacts/}; kind=\${kind%%\\?*}; cat "$BODIES/$kind" > "$out"`,
  wget: `#!/usr/bin/env bash
echo "wget $*" >> "$LOG"; out=""; url=""
while [ $# -gt 0 ]; do case "$1" in -O) out=$2; shift 2;; -e) shift 2;; -*) shift;; *) url=$1; shift;; esac; done
kind=\${url#*/node-artifacts/}; kind=\${kind%%\\?*}; cat "$BODIES/$kind" > "$out"`,
  docker: `#!/usr/bin/env bash
echo "docker $*" >> "$LOG"; if [ "$1" = load ]; then test -f "$3" || { echo "no $3" >&2; exit 1; }; fi`,
  helm: `#!/usr/bin/env bash
echo "helm $*" >> "$LOG"`,
  packer: `#!/usr/bin/env bash
echo "packer $* in $(basename "$PWD") with $(ls | tr '\\n' ' ')" >> "$LOG"`,
  unzip: `#!/usr/bin/env bash
echo "unzip $*" >> "$LOG"; z=\${@: -1}; mkdir -p "\${z%.zip}"; touch "\${z%.zip}/kit-files"`,
  openssl: `#!/usr/bin/env bash
echo 0123456789abcdef`,
}

function runBlock(cmd: string, bodies: Record<string, string> = BODY): { status: number; log: string[]; dir: string; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "zs-onepaste-"))
  const bin = join(dir, ".bin")
  const bodyDir = join(dir, ".bodies")
  execFileSync("mkdir", ["-p", bin, bodyDir])
  for (const [name, text] of Object.entries(STUBS)) {
    writeFileSync(join(bin, name), text + "\n")
    chmodSync(join(bin, name), 0o755)
  }
  for (const [kind, text] of Object.entries(bodies)) writeFileSync(join(bodyDir, kind), text)
  const log = join(dir, ".log")
  const work = join(dir, "host")
  execFileSync("mkdir", ["-p", work])
  assert.equal(spawnSync("bash", ["-n", "-c", cmd]).status, 0, `bash -n: ${cmd}`)
  const p = spawnSync("bash", ["-e", "-o", "pipefail", "-c", cmd], {
    cwd: work, encoding: "utf8" as const, env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, LOG: log, BODIES: bodyDir, HOME: dir },
  })
  const lines = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n") : []
  return { status: p.status ?? -1, log: lines, dir, stderr: p.stderr }
}

{
  // Docker with curl: downloads, checks, loads, runs
  const r = runBlock(onePasteInstall("docker", links("image"), { ...base, proxyUrl: "http://p:3128", caFile: "ca.pem" })!)
  assert.equal(r.status, 0, r.stderr)
  assert.deepEqual(r.log.map((l) => l.split(" ").slice(0, 2).join(" ")), ["curl -fsSL", "docker load", "docker run"], r.log.join("\n"))
  assert.ok(r.log[2].includes("--pull never") && r.log[2].endsWith(IMAGE), r.log[2])
  rmSync(r.dir, { recursive: true, force: true })

  // a corrupted download stops before docker load
  const bad = runBlock(onePasteInstall("docker", links("image"), base)!, { ...BODY, image: "tampered" })
  assert.notEqual(bad.status, 0)
  assert.ok(!bad.log.some((l) => l.startsWith("docker")), bad.log.join("\n"))
  rmSync(bad.dir, { recursive: true, force: true })

  // wget variant
  const w = runBlock(onePasteInstall("docker", links("image"), { ...base, fetcher: "wget" })!)
  assert.equal(w.status, 0, w.stderr)
  assert.deepEqual(w.log.map((l) => l.split(" ")[0]), ["wget", "docker", "docker"])
  rmSync(w.dir, { recursive: true, force: true })

  // Helm: both files, push to $REGISTRY, install the downloaded chart
  const h = runBlock(onePasteInstall("helm", links("image", "helm-chart"), base)!)
  assert.equal(h.status, 0, h.stderr)
  assert.deepEqual(h.log.map((l) => l.split(" ").slice(0, 2).join(" ")),
    ["curl -fsSL", "curl -fsSL", "docker load", "docker tag", "docker push", "helm upgrade"], h.log.join("\n"))
  assert.ok(h.log[4].includes("registry.example.internal/zeroshield/cbom-scan-node:1.0.0"), h.log[4])
  assert.ok(h.log[5].includes("./cbom-scan-node-1.0.0.tgz"), h.log[5])
  rmSync(h.dir, { recursive: true, force: true })

  // OVA and AMI: Packer runs inside the kit directory with the image file next to it
  for (const m of ["ova", "ami"] as const) {
    const k = runBlock(onePasteInstall(m, links(`${m}-kit` as "ova-kit" | "ami-kit", "image"), base)!)
    assert.equal(k.status, 0, k.stderr)
    const build = k.log.find((l) => l.startsWith("packer build"))!
    assert.ok(build && build.includes(`in cbom-scan-node-${m}-kit-1.0.0 with`) && build.includes("scan-node-1.0.0.tar.gz"), k.log.join("\n"))
    rmSync(k.dir, { recursive: true, force: true })
  }
}

console.log("one-paste node install tests passed")
