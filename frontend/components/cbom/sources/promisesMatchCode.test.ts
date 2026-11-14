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

// 2. Header: host agents are installed on the hosts they read (AgentPoolsCard, Helm DaemonSet). Every page of the
//    CBOM area (review 5876424957: the sidebar still said it).
const tsxUnder = (dir: string): string[] =>
  fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? tsxUnder(path.join(dir, e.name)) : e.name.endsWith(".tsx") ? [path.join(dir, e.name)] : [])
const cbomTsx = [...tsxUnder(__dirname), ...tsxUnder(path.join(__dirname, "../../../app/[team_id]/cbom"))]
assert.ok(cbomTsx.length > 20, "the CBOM pages were found")
const installedClaim = cbomTsx.filter((f) => /nothing is installed on your servers/i.test(fs.readFileSync(f, "utf8")))
assert.deepEqual(installedClaim, [], "host agents run on the servers they read")
assert.ok(page.includes("Collection is read-only, and nothing is installed on the servers it reads unless you deploy host agents."))
assert.ok(read("SidebarSources.tsx").includes("nothing is installed on the servers it reads unless you deploy host agents"))

// 3. Certificate domains: nothing reads them (no Certificate Transparency client)
assert.ok(!cloud.includes("Saved for the certificate collector"), "there is no certificate collector")
assert.ok(cloud.includes('hint="Saved, but not read yet: ZeroShield does not query Certificate Transparency logs yet."'))
assert.ok(review.includes('pluralize(overview.settings.cert_domains, "certificate domain")} (not read yet)'),
  "Review & Run lists the domains, but not as coverage")

// 4. CLM connectors without a collector, and AWS Private CA (read by the AWS account source, aws_collect "acm-pca")
assert.ok(!cloud.includes("for the certificate collector."), "Venafi, Keyfactor, DigiCert and Sectigo have no collector")
assert.ok(cloud.includes('"Not collected yet: ZeroShield only stores the API address and key. Nothing is read from it and it is never charged."'))
// the row shows the planner's own sentence (read by the account / account skipped / account removed; backend tests)
assert.ok(cloud.includes('{planReason(s.id) ? ` · ${planReason(s.id)}` : ""}'), "the AWS Private CA row shows the plan's reason")
assert.ok(!/through \{awsSources[^\n]*\n[^\n]*\{NOT_AVAILABLE\}/.test(cloud), "never 'collection is not available yet' for AWS Private CA")

// 5. Identity providers: idp_collect reads public metadata only and sends no credential (and admin access adds nothing)
assert.ok(!cloud.includes("No admin access?"), "a credential reads nothing more")
assert.ok(cloud.includes("Public metadata is all ZeroShield reads"))
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
// dev's CB36-BUG-04 wording (exact grants: backend test_cbom_node_core_classify.py; collector code: test_cbom_cb08_promises.py)
assert.ok(clusters.includes('title: "Tier 1 · no Secrets"') && clusters.includes('title: "Tier 2 · reads Secrets"'))
assert.ok(clusters.includes("which are dropped unparsed and never stored or sent"), "Tier 2 says tls.key is dropped")

// Review & Run: the collectors exist; their assets are in each run's results and exports and on the CBOM dashboard
assert.ok(!review.includes("once the collector for each source type ships"))
assert.ok(review.includes("Each run&apos;s assets appear in its results and exports, and on the CBOM dashboard."))

// 7. Databases: PostgreSQL lists extensions and versions, never their use
assert.ok(!clusters.includes('"pgcrypto use"'))
assert.ok(clusters.includes('"Installed extensions and their versions (for example pgcrypto); not where they are used"'))
console.log("promises match code tests passed")
