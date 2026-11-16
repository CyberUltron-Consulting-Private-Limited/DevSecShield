/**
 * C3 (owner bug list, 14 Nov): an ADFS identity-provider source was collected every run but listed nowhere on the
 * Cloud & Identity tab (the tab listed Entra ID / Okta / Keycloak rows and the SAML / OIDC metadata URLs only).
 * Every provider the backend accepts (kinds.py IdpConfig.provider) must have a row or be listed with the metadata
 * URLs, and ADFS is connected with its server address, read at the same two paths the collector reads.
 * Run: npx --yes tsx components/cbom/sources/idpProviders.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

const cloud = fs.readFileSync(path.join(__dirname, "CloudIdentityTab.tsx"), "utf8")
const repo = path.join(__dirname, "../../../..")
const kinds = fs.readFileSync(path.join(repo, "backend/utilities/cbom_sources/kinds.py"), "utf8")
const collector = fs.readFileSync(path.join(repo, "backend/utilities/cbom_sources/idp_collect.py"), "utf8")

const literal = /class IdpConfig\(_Source\):\s*\n\s*provider: Literal\[([^\]]+)\]/.exec(kinds)
assert.ok(literal, "kinds.py IdpConfig.provider is a Literal")
const backendProviders = [...literal[1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1])
assert.ok(backendProviders.includes("adfs"))

const rowsBlock = /const IDP_ROWS: IdpRow\[\] = \[([\s\S]*?)\n\];/.exec(cloud)
assert.ok(rowsBlock, "IDP_ROWS")
const rowProviders = [...rowsBlock[1].matchAll(/provider: "([a-z_]+)"/g)].map((m) => m[1])
const metadataBlock = /const METADATA_LABEL: Record<MetadataProvider, string> = \{([^}]*)\}/.exec(cloud)
assert.ok(metadataBlock, "METADATA_LABEL")
const metadataProviders = [...metadataBlock[1].matchAll(/([a-z_]+):/g)].map((m) => m[1])

// 1. every backend provider has a row or a metadata entry (ADFS has its own row now)
for (const p of backendProviders) {
  assert.ok(rowProviders.includes(p) || metadataProviders.includes(p), `IdP provider ${p} is listed on the Cloud & Identity tab`)
}
assert.ok(rowProviders.includes("adfs"), "ADFS has its own Identity providers row")
assert.ok(cloud.includes('{ provider: "adfs", label: "ADFS", detail: "public metadata; no permission needed", defaultName: "ADFS" }'))

// 2. no IdP source can fall between the lists: the metadata list holds every provider without a row
assert.ok(cloud.includes('const metadataSources = idpSources.filter((s) => !IDP_ROW_PROVIDERS.has(String(s.config?.provider ?? "")));'))
assert.ok(!cloud.includes('s.config?.provider === "saml_metadata" || s.config?.provider === "oidc_discovery"'), "the old two-provider filter hid ADFS")
// the static row that pointed ADFS users at the metadata URL box (their saved ADFS source was hidden) is gone
assert.ok(!cloud.includes("add its SAML metadata URL below"))

// 3. the ADFS dialog asks for the server address (kinds.py now requires base_url for adfs) and no secret
assert.ok(/elif p == "adfs":\s*\n\s*if not self\.base_url:/.test(kinds), "the backend requires the ADFS server address")
assert.ok(cloud.includes('if (provider === "okta" || provider === "adfs") Object.assign(config, { base_url: baseUrl.trim() });'))
assert.ok(cloud.includes('next.baseUrl = httpsUrlError(baseUrl, "ADFS server address");'))
assert.ok(cloud.includes('const asksSecret = provider !== "adfs";'))
assert.ok(/def _idp_secrets[\s\S]*?return set\(\)/.test(kinds) && !/def _idp_secrets[^\n]*\n(?:[^\n]*\n){0,5}[^\n]*adfs/.test(kinds), "ADFS stores no secret")

// 4. the paths the dialog names are the ones the collector reads
const adfsOidc = /const ADFS_OIDC_PATH = "([^"]+)"/.exec(cloud)?.[1]
const adfsMeta = /const ADFS_METADATA_PATH = "([^"]+)"/.exec(cloud)?.[1]
assert.ok(adfsOidc && collector.includes(`f"{base}${adfsOidc}"`), "ADFS OpenID path matches idp_collect.discovery_urls")
assert.ok(adfsMeta && collector.includes(`f"{base}${adfsMeta}"`), "ADFS federation metadata path matches idp_collect.discovery_urls")

console.log("idpProviders.test.ts: ok")
