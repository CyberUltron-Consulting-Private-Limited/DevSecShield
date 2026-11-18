// Run: npx --yes tsx components/cbom/sources/nodeInstallIntegrity.test.ts
//
// #228 (customer QA, staging): the wizard's commands put `sha256sum -c` and `docker load` on separate lines, so a
// tampered image file printed FAILED and was loaded anyway (Helm: tagged and pushed to the customer's registry), and a
// missing .sha256 file skipped the check. Every install block now gates the next step on the check (&&), and writes
// the server's digest into the command when it knows it.
//
// Each block the wizard can show is RUN here in bash (stub docker/helm/packer/unzip/curl/wget, the real sha256sum)
// three ways: with the genuine files (everything runs), with a tampered file (nothing is loaded, pushed, installed or
// built), and with the .sha256 file missing (the same).
import assert from "node:assert/strict"
import { execFileSync, spawnSync } from "node:child_process"
import { createHash } from "node:crypto"
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import { checkFile, helmAgentCommand, installCommand, onePasteInstall, type InstallLinks } from "./logic"

const IMAGE = "localhost/zeroshield/cbom-scan-node:1.0.0"
const FILES: Record<string, string> = {
  "scan-node-1.0.0.tar.gz": "docker-save-archive-bytes",
  "cbom-scan-node-1.0.0.tgz": "helm-chart-bytes",
  "cbom-scan-node-ova-kit-1.0.0.zip": "ova-kit-bytes",
  "cbom-scan-node-ami-kit-1.0.0.zip": "ami-kit-bytes",
}
const KIND_FILE: Record<string, string> = {
  image: "scan-node-1.0.0.tar.gz", "helm-chart": "cbom-scan-node-1.0.0.tgz",
  "ova-kit": "cbom-scan-node-ova-kit-1.0.0.zip", "ami-kit": "cbom-scan-node-ami-kit-1.0.0.zip",
}
const sha = (text: string) => createHash("sha256").update(text).digest("hex")
const base = { token: "zsr_TESTONLY", apiUrl: "https://devsec-api.example", name: "dc-1" }

// stubs: every "dangerous" step logs itself; curl/wget write the (possibly tampered) body of the file they fetch
const STUBS: Record<string, string> = {
  docker: `#!/usr/bin/env bash\necho "docker $1" >> "$LOG"`,
  helm: `#!/usr/bin/env bash\necho "helm $1" >> "$LOG"`,
  packer: `#!/usr/bin/env bash\necho "packer $1" >> "$LOG"`,
  unzip: `#!/usr/bin/env bash\necho "unzip" >> "$LOG"; z=\${@: -1}; mkdir -p "\${z%.zip}"`,
  openssl: `#!/usr/bin/env bash\necho 0123456789abcdef`,
  curl: `#!/usr/bin/env bash
out=""; url=""; while [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift 2;; --proto|--proxy|--cacert) shift 2;; -*) shift;; *) url=$1; shift;; esac; done
kind=\${url#*/node-artifacts/}; kind=\${kind%%\\?*}; cat "$SERVED/$kind" > "$out"`,
  wget: `#!/usr/bin/env bash
out=""; url=""; while [ $# -gt 0 ]; do case "$1" in -O) out=$2; shift 2;; -e) shift 2;; -*) shift;; *) url=$1; shift;; esac; done
kind=\${url#*/node-artifacts/}; kind=\${kind%%\\?*}; cat "$SERVED/$kind" > "$out"`,
}

type Mode = "genuine" | "tampered" | "no-sha-file"

/** Run a block in a fresh host directory holding the downloaded files (and their .sha256 unless no-sha-file); with
 * "tampered", every file (local and served) has one byte more than its digest. Returns the logged steps. */
function run(cmd: string, mode: Mode): { status: number; steps: string[]; stderr: string } {
  const dir = mkdtempSync(join(tmpdir(), "zs-integrity-"))
  const bin = join(dir, ".bin")
  const served = join(dir, ".served")
  const host = join(dir, "host")
  execFileSync("mkdir", ["-p", bin, served, host])
  for (const [name, text] of Object.entries(STUBS)) {
    writeFileSync(join(bin, name), text + "\n")
    chmodSync(join(bin, name), 0o755)
  }
  for (const [name, text] of Object.entries(FILES)) {
    const body = mode === "tampered" ? text + "x" : text
    writeFileSync(join(host, name), body)
    if (mode !== "no-sha-file") writeFileSync(join(host, `${name}.sha256`), `${sha(text)}  ${name}\n`)
  }
  for (const [kind, name] of Object.entries(KIND_FILE)) writeFileSync(join(served, kind), mode === "tampered" ? FILES[name] + "x" : FILES[name])
  const log = join(dir, ".log")
  assert.equal(spawnSync("bash", ["-n", "-c", cmd]).status, 0, `bash -n:\n${cmd}`)
  // plain bash, as a customer pastes it: no -e, no pipefail (the block itself must stop)
  const p = spawnSync("bash", ["-c", cmd], {
    cwd: host, encoding: "utf8", env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, LOG: log, SERVED: served, HOME: dir },
  })
  const steps = existsSync(log) ? readFileSync(log, "utf8").trim().split("\n").filter(Boolean) : []
  rmSync(dir, { recursive: true, force: true })
  return { status: p.status ?? -1, steps, stderr: p.stderr }
}

function check(label: string, cmd: string, expected: string[], modes: Mode[] = ["tampered", "no-sha-file"]) {
  const good = run(cmd, "genuine")
  assert.deepEqual(good.steps, expected, `${label}: genuine files\n${good.stderr}\n${cmd}`)
  for (const mode of modes) {
    const bad = run(cmd, mode)
    assert.deepEqual(bad.steps, [], `${label}, ${mode}: nothing may run after a failed check, ran ${JSON.stringify(bad.steps)}\n${cmd}`)
    assert.notEqual(bad.status, 0, `${label}, ${mode}: the block must fail`)
  }
}

const imageSha = sha(FILES["scan-node-1.0.0.tar.gz"])
const chartSha = sha(FILES["cbom-scan-node-1.0.0.tgz"])

// ---------------------------------------------------------------------------------------- the wizard's file commands
// with the server's digests in the command (the usual case): a missing .sha256 file changes nothing
check("docker, digest inline", installCommand("docker", { ...base, image: IMAGE, archiveSha256: imageSha }), ["docker load", "docker run"], ["tampered"])
check("helm, digests inline", installCommand("helm", { ...base, image: IMAGE, archiveSha256: imageSha, chartSha256: chartSha }),
  ["docker load", "docker tag", "docker push", "helm upgrade"], ["tampered"])
check("host agents, digests inline", helmAgentCommand({ poolToken: "zsp_T", apiUrl: base.apiUrl, image: IMAGE, archiveSha256: imageSha, chartSha256: chartSha }),
  ["docker load", "docker tag", "docker push", "helm upgrade"], ["tampered"])
// a missing .sha256 never skips the check when the digest is inline
assert.deepEqual(run(installCommand("docker", { ...base, image: IMAGE, archiveSha256: imageSha }), "no-sha-file").steps,
  ["docker load", "docker run"], "the inline digest needs no .sha256 file")
// without the server's digests (an older server): the .sha256 file, and a missing one stops everything
check("docker, .sha256 file", installCommand("docker", { ...base, image: IMAGE }), ["docker load", "docker run"])
check("helm, .sha256 files", installCommand("helm", { ...base, image: IMAGE }), ["docker load", "docker tag", "docker push", "helm upgrade"])
check("host agents, .sha256 files", helmAgentCommand({ poolToken: "zsp_T", apiUrl: base.apiUrl, image: IMAGE }),
  ["docker load", "docker tag", "docker push", "helm upgrade"])
// Helm with a registry image: the downloaded chart is still checked before it is installed
check("helm, registry image + downloaded chart", installCommand("helm", { ...base, image: "ghcr.io/o/devsecshield-scan-node:1.0.0", pull: true, chartSha256: chartSha }),
  ["helm upgrade"], ["tampered"])

// ---------------------------------------------------------------------------------------- one-paste (curl and wget)
const link = (kind: string) => ({ kind: kind as "image", filename: KIND_FILE[kind], size: 1, sha256: sha(FILES[KIND_FILE[kind]]),
  url: `/1/cbom/node-artifacts/${kind}?node_ticket=41.SIG` })
const links = (...kinds: string[]): InstallLinks => ({ version: "1.0.0", expires_at: null, files: kinds.map(link) })
for (const fetcher of ["curl", "wget"] as const) {
  const o = { ...base, image: IMAGE, fetcher }
  check(`one-paste docker (${fetcher})`, onePasteInstall("docker", links("image"), o)!, ["docker load", "docker run"], ["tampered"])
  check(`one-paste helm (${fetcher})`, onePasteInstall("helm", links("image", "helm-chart"), o)!,
    ["docker load", "docker tag", "docker push", "helm upgrade"], ["tampered"])
  check(`one-paste ova (${fetcher})`, onePasteInstall("ova", links("ova-kit", "image"), o)!, ["unzip", "packer init", "packer build"], ["tampered"])
  check(`one-paste ami (${fetcher})`, onePasteInstall("ami", links("ami-kit", "image"), o)!, ["unzip", "packer init", "packer build"], ["tampered"])
}

// ---------------------------------------------------------------------------------------- the check itself
assert.equal(checkFile("f.tgz", "a".repeat(64)), `echo '${"a".repeat(64)}  f.tgz' | sha256sum -c -`)
assert.equal(checkFile("f.tgz", "not-a-digest"), "sha256sum -c f.tgz.sha256", "a malformed digest is never written into a command")
assert.equal(checkFile("f.tgz"), "sha256sum -c f.tgz.sha256")

console.log("install integrity tests passed")
