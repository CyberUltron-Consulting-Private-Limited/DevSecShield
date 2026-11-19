/**
 * Oracle Cloud tenancy sources: the field rules and secrets of the three ways to connect (ociTenancy.ts), and the
 * Cloud & Identity tab lists OCI in every provider map, says "not available" in the planner's words, and shows the
 * exact read-only policy, the stack download and the Resource Manager link.
 * Run: npx --yes tsx components/cbom/sources/ociTenancy.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import {
  OCI_GROUP,
  OCI_NEVER_GRANTED,
  OCI_POLICY_GRANTS,
  OCI_PUBLIC_KEY_PLACEHOLDER,
  OCI_COMPARTMENT_RE,
  OCI_REGION_RE,
  OCI_TENANCY_PLACEHOLDER,
  OCI_TENANCY_RE,
  OCI_USER_NAME,
  OCI_USER_RE,
  checkOciForm,
  fillOciPublicKey,
  fillOciTenancy,
  ociKeyReady,
  ociMethodOf,
  ociPolicyStatement,
  ociPrivateKeyError,
  ociResourceManagerUrl,
  ociSecretsOf,
  type OciFormValues,
  type OciSaved,
} from "./ociTenancy"

const TENANCY = "ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqstifsfdsq"
const USER = "ocid1.user.oc1..aaaaaaaaxzpxbcag7zgamh2erlggqro3y63tvm2rbkkjz4z2zskvagupiz7a"
const COMPARTMENT = "ocid1.compartment.oc1..aaaaaaaa5bhgr2bxwkvvpzvqtcmqjfw3kqp5e6pnzbgzm7ql7o4d4xjrinkq"
const KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
const PUBLIC = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----"

const values = (over: Partial<OciFormValues> = {}): OciFormValues => ({
  method: "stack",
  tenancy: TENANCY,
  homeRegion: "us-ashburn-1",
  regions: "",
  compartments: "",
  userOcid: "",
  privateKey: "",
  ...over,
})
const noErrors = (e: Record<string, string | null>) => Object.values(e).every((v) => v === null)

// 1. region identifiers of every geography, nothing else
for (const r of ["us-ashburn-1", "eu-frankfurt-1", "ap-mumbai-1", "me-dubai-1", "sa-saopaulo-1", "uk-london-1", "us-chicago-1"]) {
  assert.ok(OCI_REGION_RE.test(r), `${r} is a region`)
}
for (const r of ["us-ashburn", "US-ASHBURN-1", "ashburn-1", "us_ashburn_1", "us-ashburn-1 "]) assert.ok(!OCI_REGION_RE.test(r), `${r} is not`)

// 2. generated key, first save: tenancy and home region only; the user OCID is not needed yet
{
  const { errors, config } = checkOciForm(values({ tenancy: `  ${TENANCY} `, homeRegion: " US-Ashburn-1 " }), null, false)
  assert.ok(noErrors(errors), JSON.stringify(errors))
  assert.deepEqual(config, {
    tenancy_ocid: TENANCY,
    user_ocid: null,
    home_region: "us-ashburn-1",
    regions: [],
    compartment_ocids: [],
    key_origin: "generated",
  })
  // never sends the server-owned fields
  assert.ok(!("fingerprint" in config) && !("public_key_pem" in config))
  assert.deepEqual(ociSecretsOf(values(), null), { secrets: {}, clear: [] }, "the server creates the key: nothing to send")
}
{
  const { errors } = checkOciForm(values({ tenancy: "ocid1.compartment.oc1..aaaa", homeRegion: "Ashburn" }), null, false)
  assert.match(errors.tenancy ?? "", /tenancy OCID/)
  assert.match(errors.homeRegion ?? "", /home region/)
  assert.match(checkOciForm(values({ tenancy: "ocid1.tenancy.oc2..aaaa" }), null, false).errors.tenancy ?? "", /tenancy OCID/, "oc1 only")
}

// 3. Save and validate needs the user OCID, worded for the way the user connects
assert.match(checkOciForm(values(), null, true).errors.userOcid ?? "", /user_ocid output/)
assert.equal(checkOciForm(values({ method: "console" }), null, true).errors.userOcid, "Enter the user OCID")
assert.match(checkOciForm(values({ userOcid: "ocid1.group.oc1..aaaa" }), null, false).errors.userOcid ?? "", /user OCID/, "a typed one is checked")
assert.equal(checkOciForm(values({ userOcid: USER }), null, true).config.user_ocid, USER)

// 4. regions and compartments: one per line, deduplicated, comments and blank lines dropped
{
  const { errors, config } = checkOciForm(
    values({ regions: "eu-frankfurt-1\n\nEU-FRANKFURT-1 # dup\r\nap-mumbai-1", compartments: `${COMPARTMENT}\n${TENANCY}\n${COMPARTMENT}` }),
    null,
    false,
  )
  assert.ok(noErrors(errors), JSON.stringify(errors))
  assert.deepEqual(config.regions, ["eu-frankfurt-1", "ap-mumbai-1"])
  assert.deepEqual(config.compartment_ocids, [COMPARTMENT, TENANCY], "the tenancy OCID stands for the root compartment")
  assert.match(checkOciForm(values({ regions: "frankfurt" }), null, false).errors.regions ?? "", /frankfurt is not a region/)
  assert.match(checkOciForm(values({ compartments: USER }), null, false).errors.compartments ?? "", /not a compartment OCID/)
  const many = Array.from({ length: 61 }, (_, i) => `us-region${String.fromCharCode(97 + (i % 26))}${"x".repeat(Math.floor(i / 26))}-1`).join("\n")
  assert.equal(checkOciForm(values({ regions: many }), null, false).errors.regions, "At most 60 regions")
}

// 5. own API key: required on create, kept on edit unless the tenancy changes (the server clears it then)
{
  const own = values({ method: "own", userOcid: USER })
  assert.equal(checkOciForm(own, null, true).errors.privateKey, "Upload or paste the private key")
  const withKey = { ...own, privateKey: KEY }
  const ok = checkOciForm(withKey, null, true)
  assert.ok(noErrors(ok.errors), JSON.stringify(ok.errors))
  assert.equal(ok.config.key_origin, "uploaded")
  assert.deepEqual(ociSecretsOf(withKey, null), { secrets: { api_signing_key: KEY + "\n" }, clear: [] })

  const uploaded: OciSaved = { tenancy: TENANCY, keyOrigin: "uploaded", keySet: true }
  assert.equal(checkOciForm(own, uploaded, true).errors.privateKey, null, "blank keeps the stored key")
  assert.deepEqual(ociSecretsOf(own, uploaded), { secrets: {}, clear: [] }, "and sends no secret")
  const moved = { ...own, tenancy: TENANCY.replace("aaaa", "bbbb") }
  assert.match(checkOciForm(moved, uploaded, true).errors.privateKey ?? "", /cleared when the tenancy OCID changes/)
  // a generated key is not the customer's: switching to "own" asks for one
  const generated: OciSaved = { tenancy: TENANCY, keyOrigin: "generated", keySet: true }
  assert.equal(checkOciForm(own, generated, true).errors.privateKey, "Upload or paste the private key")
}

// 6. switching an uploaded key to a generated one drops it so the server creates the pair; "Generate a new key" too
{
  const uploaded: OciSaved = { tenancy: TENANCY, keyOrigin: "uploaded", keySet: true }
  const generated: OciSaved = { tenancy: TENANCY, keyOrigin: "generated", keySet: true }
  assert.deepEqual(ociSecretsOf(values(), uploaded), { secrets: {}, clear: ["api_signing_key"] })
  assert.deepEqual(ociSecretsOf(values({ method: "console" }), generated), { secrets: {}, clear: [] }, "keeps the generated key")
  assert.deepEqual(ociSecretsOf(values(), generated, true), { secrets: {}, clear: ["api_signing_key"] }, "replace it")
  assert.deepEqual(ociSecretsOf(values(), { ...generated, keySet: false }, true), { secrets: {}, clear: ["api_signing_key"] },
    "replace it even if the list does not name the stored key")
  assert.deepEqual(ociSecretsOf(values(), { ...uploaded, keySet: false }), { secrets: {}, clear: [] }, "nothing stored, nothing to drop")
  assert.equal(checkOciForm(values({ privateKey: KEY }), generated, false).errors.privateKey, null, "no key asked for a generated pair")
}

// 7. private key shapes
assert.equal(ociPrivateKeyError(KEY), null)
assert.equal(ociPrivateKeyError(KEY.replace(/PRIVATE KEY/g, "RSA PRIVATE KEY")), null)
assert.match(ociPrivateKeyError("-----BEGIN ENCRYPTED PRIVATE KEY-----\nx\n-----END ENCRYPTED PRIVATE KEY-----") ?? "", /encrypted/)
assert.match(ociPrivateKeyError("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nx\n-----END RSA PRIVATE KEY-----") ?? "", /encrypted/)
assert.match(ociPrivateKeyError(PUBLIC) ?? "", /public key/)
assert.match(ociPrivateKeyError("ssh-rsa AAAA") ?? "", /PEM private key/)
assert.match(ociPrivateKeyError("-----BEGIN PRIVATE KEY-----" + "A".repeat(70 * 1024)) ?? "", /64 KB/)

// 8. method of a saved source, Resource Manager link, the script's public key and the policy text
assert.equal(ociMethodOf("uploaded"), "own")
assert.equal(ociMethodOf("generated"), "stack")
assert.equal(ociMethodOf(undefined), "stack")
// steps 2 and 3 show the generated key only while it belongs to the tenancy in the form (R-oci2 R1): an edited
// tenancy brings Save and create key back instead of a validate that can only fail
{
  const T = "ocid1.tenancy.oc1..aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  const T2 = "ocid1.tenancy.oc1..bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  const gen = { tenancy: T, keyOrigin: "generated" as const }
  assert.equal(ociKeyReady("stack", gen, "aa:bb", T), true)
  assert.equal(ociKeyReady("console", gen, "aa:bb", ` ${T} `), true, "whitespace is not a change")
  assert.equal(ociKeyReady("stack", gen, "aa:bb", T2), false, "a changed tenancy needs a new key first")
  assert.equal(ociKeyReady("stack", gen, "aa:bb", ""), false)
  assert.equal(ociKeyReady("stack", gen, null, T), false, "no fingerprint, no key yet")
  assert.equal(ociKeyReady("stack", null, null, T), false, "a new source")
  assert.equal(ociKeyReady("own", gen, "aa:bb", T), false, "own key has no generated-key steps")
  assert.equal(ociKeyReady("stack", { tenancy: T, keyOrigin: "uploaded" }, "aa:bb", T), false, "switching from an uploaded key")
}
assert.equal(ociResourceManagerUrl(" eu-frankfurt-1 "), "https://cloud.oracle.com/resourcemanager/stacks/create?region=eu-frankfurt-1")
assert.equal(ociResourceManagerUrl("x&y=1"), "https://cloud.oracle.com/resourcemanager/stacks/create", "never a crafted query string")
const script = `KEY='${OCI_PUBLIC_KEY_PLACEHOLDER}'\necho ok`
assert.equal(fillOciPublicKey(script, PUBLIC), `KEY='${PUBLIC}'\necho ok`)
assert.equal(fillOciPublicKey(script, ""), script, "unchanged without a key")
assert.equal(fillOciPublicKey(script, "not a key"), script)
assert.equal(ociPolicyStatement("read keys"), `Allow group ${OCI_GROUP} to read keys in tenancy`)
assert.deepEqual(OCI_POLICY_GRANTS, [
  "inspect tenancies",
  "inspect compartments",
  "read vaults",
  "read keys",
  "inspect secrets",
  "inspect certificate-authority-family",
  "read load-balancers",
  "read objectstorage-namespaces",
  "read buckets",
])
assert.ok(OCI_POLICY_GRANTS.every((g) => /^(inspect|read) /.test(g)), "inspect and read verbs only")
for (const never of ["use keys", "read secret-bundles", "read leaf-certificate-bundles"]) {
  assert.ok(OCI_NEVER_GRANTED.includes(never) && !OCI_POLICY_GRANTS.includes(never), `${never} is never granted`)
}

// 9. the tab: every provider map, the planner's sentence, the three ways and their wiring
const dir = __dirname
const read = (f: string) => fs.readFileSync(path.join(dir, f), "utf8")
const tab = read("CloudIdentityTab.tsx")
assert.ok(tab.includes('type Provider = "aws" | "azure" | "gcp" | "oci";'))
assert.ok(tab.includes('oci: "Oracle Cloud" }') && tab.includes('oci_tenancy: "oci" }'), "PROVIDER_LABEL and PROVIDER_OF_KIND")
assert.ok(tab.includes('value: "oci",'), "the provider picker offers it")
assert.ok(tab.includes('"Not available until the Oracle Cloud tenancy is connected: Save and validate must pass first"'))
assert.ok(tab.includes("{notConnected(s.kind)}"), "each unconnected row uses its own provider's sentence")
assert.ok(tab.includes('<PermissionsHelp provider="oci" />') && tab.includes("OCI_POLICY_GRANTS.map"), "the policy is shown")
for (const id of ["cloud-oci-method", "cloud-oci-create-key", "cloud-oci-download-stack", "cloud-oci-resource-manager", "cloud-oci-validate", "cloud-oci-save", "cloud-oci-key-file", "cloud-oci-new-key"]) {
  assert.ok(tab.includes(`"${id}"`), `${id} is rendered`)
}
assert.ok(tab.includes('createCbomSource(teamId, { kind: "oci_tenancy"'), "creates oci_tenancy sources")
assert.ok(tab.includes("href={ociResourceManagerUrl(savedRegion)} target=\"_blank\" rel=\"noopener noreferrer\""), "Resource Manager opens safely in a new tab")
assert.ok(tab.includes('accept=".pem,'), "the key file input takes .pem")
assert.ok(tab.includes('const [privateKey, setPrivateKey] = useState("");') && !/cfgString\(source, "api_signing_key"\)/.test(tab),
  "the key field always starts blank: a stored key is never shown back")
assert.ok(tab.includes('provider="oci"\n                  fill={(script) => fillOciTenancy(fillOciPublicKey(script, publicKey), savedTenancy)}'),
  "the script gets the public key and the tenancy")

// every other place that lists the cloud kinds
assert.ok(read("ReviewRunTab.tsx").includes('oci_tenancy: "Oracle Cloud",'))
assert.ok(read("SourceTableControls.tsx").includes('{ value: "oci_tenancy", label: "Oracle Cloud" }'))
assert.ok(read("ClustersDatabasesTab.tsx").includes('"gcp_project", "oci_tenancy"]'))
const api = fs.readFileSync(path.join(dir, "../../../utils/backend_api.ts"), "utf8")
assert.ok(api.includes('| "gcp_project" | "oci_tenancy" |'), "CbomSourceKind")
assert.ok(api.includes("/items/${source_id}/oci/stack`, { responseType: \"blob\" }") && api.includes("    downloadCbomOciStack,"), "the stack download")
console.log("oci tenancy tests passed")

// ---- parity with the backend sources (R-oci2 m1): read them, never restate them
const backend = (rel: string): string => fs.readFileSync(path.join(__dirname, "../../../../backend/utilities/cbom_sources", rel), "utf8")
const kinds = backend("kinds.py")
const collect = backend("oci_collect.py")
const templates = backend("templates.py")
const pyRegex = (name: string): string => {
  const m = new RegExp(`${name} = re\\.compile\\(r"([^"]+)"\\)`).exec(kinds)
  assert.ok(m, `${name} is in kinds.py`)
  return m![1]
}
assert.equal(OCI_TENANCY_RE.source, pyRegex("_OCI_TENANCY_RE").replace(/\\\./g, "\\."), "tenancy pattern = server")
assert.equal(OCI_USER_RE.source, pyRegex("_OCI_USER_RE"), "user pattern = server")
assert.equal(OCI_COMPARTMENT_RE.source, pyRegex("_OCI_COMPARTMENT_RE").replace("(?:", "("), "compartment pattern = server")
assert.equal(OCI_REGION_RE.source, pyRegex("OCI_REGION_RE"), "region pattern = server")
const statements = /POLICY_STATEMENTS = \(([\s\S]*?)\n\)/.exec(collect)
assert.ok(statements, "oci_collect.POLICY_STATEMENTS")
const serverGrants = [...statements![1].matchAll(/"([a-z -]+) in tenancy"/g)].map((m) => m[1])
assert.deepEqual(OCI_POLICY_GRANTS, serverGrants, "the grants shown are the ones the stack and script make")
assert.ok(templates.includes(`OCI_GROUP = "${OCI_GROUP}"`) && templates.includes(`OCI_USER = "${OCI_USER_NAME}"`), "group and user names")
assert.ok(templates.includes(OCI_PUBLIC_KEY_PLACEHOLDER) && templates.includes(OCI_TENANCY_PLACEHOLDER), "script placeholders")
const tenancyScript = `TENANCY_OCID="\${OCI_TENANCY:-${OCI_TENANCY_PLACEHOLDER}}"`
assert.equal(fillOciTenancy(tenancyScript, TENANCY), `TENANCY_OCID="\${OCI_TENANCY:-${TENANCY}}"`)
assert.equal(fillOciTenancy(tenancyScript, "not an ocid"), tenancyScript)

console.log("oci tenancy parity tests passed")
