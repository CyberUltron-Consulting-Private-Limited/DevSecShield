/**
 * CB-08: sentences on the CBOM Sources pages that promised more than the code does (owner staging snapshot, Nov 12),
 * each pinned to the code that now makes it true. The code side of each one is pinned by
 * backend/tests/test_cbom_cb08_promises.py and scan_node/tests/test_cb08_postgres_reads.py.
 * Run: npx --yes tsx components/cbom/sources/promisesMatchCode.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const read = (name: string) => fs.readFileSync(path.join(__dirname, name), "utf8")
const network = read("NetworkTab.tsx")
const cloud = read("CloudIdentityTab.tsx")
const review = read("ReviewRunTab.tsx")
const clusters = read("ClustersDatabasesTab.tsx")
const page = fs.readFileSync(path.join(__dirname, "../../../app/[team_id]/cbom/sources/page.tsx"), "utf8")
const repo = path.join(__dirname, "../../../..")
const jobs = fs.readFileSync(path.join(repo, "backend/utilities/cbom_sources/jobs.py"), "utf8")
const k8s = fs.readFileSync(path.join(repo, "scan_node/zs_scan_node/collectors/kubernetes.py"), "utf8")

// 1. Zeek: no scan node reads a SPAN port, so the option is gone and the setting is no longer sent (KF-13)
assert.ok(!/zeek/i.test(network), "the Network TLS tab must not offer Zeek ssl.log: no node reads it")
assert.ok(!jobs.includes("read_zeek_span"), "jobs.py must not send read_zeek_span to scan nodes")

// 2. Header: host agents are installed on the hosts they read (AgentPoolsCard, Helm DaemonSet)
assert.ok(!page.includes("nothing is installed on your servers."), "host agents run on the servers they read")
assert.ok(page.includes("Collection is read-only, and nothing is installed on the servers it reads unless you deploy host agents."))

// 3. Certificate domains: nothing reads them (no Certificate Transparency client)
assert.ok(!cloud.includes("Saved for the certificate collector"), "there is no certificate collector")
assert.ok(cloud.includes('hint="Saved, but not read yet: ZeroShield does not query Certificate Transparency logs yet."'))
assert.ok(review.includes('pluralize(overview.settings.cert_domains, "certificate domain")} (not read yet)'),
  "Review & Run lists the domains, but not as coverage")

// 4. CLM connectors without a collector, and AWS Private CA (read by the AWS account source, aws_collect "acm-pca")
assert.ok(!cloud.includes("for the certificate collector."), "Venafi, Keyfactor, DigiCert and Sectigo have no collector")
assert.ok(cloud.includes('"Not collected yet: ZeroShield only stores the API address and key. Nothing is read from it and it is never charged."'))
assert.ok(cloud.includes('const AWS_PCA_READ = "Read when that AWS account is scanned; nothing separate to collect.";'))
assert.ok(cloud.includes("{AWS_PCA_READ}") && !/through \{awsSources[^\n]*\n[^\n]*\{NOT_AVAILABLE\}/.test(cloud),
  "the AWS Private CA row does not say 'collection is not available yet'")

// 5. Identity providers: idp_collect reads public metadata only and sends no credential
assert.ok(!cloud.includes("Application.Read.All"), "no Graph permission is used, so none is asked for")
assert.ok(!cloud.includes("A read-only API token from your Okta admin console."))
assert.ok(!cloud.includes("read-only access to clients and keys"))
assert.ok(cloud.includes('detail: "public metadata; no permission needed"'))
assert.ok(cloud.includes('const IDP_HOW = "ZeroShield reads the signing keys from your identity provider\'s public metadata only; a secret is not used yet.";'))
// ADFS: the Windows collector reads machine certificate stores, nothing ADFS-specific
assert.ok(!cloud.includes("read from the Windows servers you add on the Servers tab"))
assert.ok(cloud.includes("/FederationMetadata/2007-06/FederationMetadata.xml"), "ADFS is read through its metadata URL")

// 6. Kubernetes tiers: no pods are read (no images), and a TLS Secret's tls.key is dropped unread
assert.ok(k8s.includes('data.pop("tls.key", None)  # never parsed, never kept'), "the behaviour Tier 2 now describes")
assert.ok(!clusters.includes("images in use") && !clusters.includes("private keys left in Secrets"))
assert.ok(clusters.includes("const K8S_TIER_READS: Record<1 | 2, string[]> = {"))
assert.ok(clusters.includes('description: K8S_TIER_READS[1].join(", ")') && clusters.includes('description: K8S_TIER_READS[2].join(", ")'))

// 7. Databases: PostgreSQL lists extensions and versions, never their use
assert.ok(!clusters.includes('"pgcrypto use"'))
assert.ok(clusters.includes('"Installed extensions and their versions (for example pgcrypto); not where they are used"'))
console.log("promises match code tests passed")
