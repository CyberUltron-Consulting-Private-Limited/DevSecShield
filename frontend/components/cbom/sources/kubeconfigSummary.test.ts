/**
 * #207 / #208 / #209 in the Kubernetes form. Run: npx --yes tsx components/cbom/sources/kubeconfigSummary.test.ts
 */
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import { join } from "node:path"

import { contextProblem, kubeconfigSettingProblem, kubeconfigSummary } from "./kubeconfigSummary"

// as `kubectl config view --raw` writes it
const KUBECTL = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTg==
    server: https://k8s-prod.bank.local:6443
  name: c-prod
- cluster:
    server: "https://10.30.0.10:6443"
  name: c-dev
contexts:
- context:
    cluster: c-prod
    user: zs-cbom
  name: prod
- context:
    cluster: c-dev
    namespace: default
    user: zs-cbom
  name: dev
current-context: dev
kind: Config
preferences: {}
users:
- name: zs-cbom
  user:
    token: not-a-real-token
`
const s = kubeconfigSummary(KUBECTL)
assert.deepEqual(s.contexts, ["prod", "dev"])
assert.equal(s.current, "dev")
assert.deepEqual(s.servers, { prod: "https://k8s-prod.bank.local:6443", dev: "https://10.30.0.10:6443" })
// indented lists (yaml.safe_dump / hand-written) read the same
const INDENTED = KUBECTL.replace(/^- /gm, "  - ").replace(/^(  )(cluster|context|user|name):/gm, "    $2:").replace(/^(    )(certificate-authority-data|server|cluster|user|namespace|token):/gm, "      $2:")
assert.deepEqual(kubeconfigSummary(INDENTED).contexts, ["prod", "dev"])
assert.deepEqual(kubeconfigSummary("not: [a, kubeconfig]").contexts, [])

assert.equal(contextProblem("", s), null)
assert.equal(contextProblem("prod", s), null)
assert.equal(contextProblem("no-such-context", s), '"no-such-context" is not in this kubeconfig; its contexts are prod, dev')
assert.equal(contextProblem("anything", kubeconfigSummary("")), null) // nothing read: the server decides

assert.match(kubeconfigSettingProblem(KUBECTL.replace("    server: https://k8s-prod", "    insecure-skip-tls-verify: true\n    server: https://k8s-prod")) ?? "", /insecure-skip-tls-verify/)
assert.match(kubeconfigSettingProblem(KUBECTL.replace("    server: https://k8s-prod", "    proxy-url: http://10.232.0.69:3128\n    server: https://k8s-prod")) ?? "", /proxy-url/)
assert.equal(kubeconfigSettingProblem(KUBECTL), null)
assert.equal(kubeconfigSettingProblem(KUBECTL.replace("    server: https://k8s-prod", "    insecure-skip-tls-verify: false\n    server: https://k8s-prod")), null)

// the form: checks the settings and the context, offers the contexts, fills the URL, shows the kubeconfig steps
const tab = readFileSync(join(__dirname, "ClustersDatabasesTab.tsx"), "utf8")
assert.match(tab, /kubeconfigSettingProblem\(text\)/)
assert.match(tab, /contextProblem\(form\.context, kubeSummary\)/)
assert.match(tab, /<datalist id="k8s-contexts"/)
assert.match(tab, /apiUrl: form\.apiUrl\.trim\(\) \? form\.apiUrl : summary\.servers\[/)
assert.match(tab, /getCbomTemplate\(teamId, "k8s-kubeconfig"\)/)
assert.match(tab, /data-testid="k8s-kubeconfig-steps"/)

console.log("kubeconfig form rules: tests passed")
