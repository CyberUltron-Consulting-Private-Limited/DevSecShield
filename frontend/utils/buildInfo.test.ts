/**
 * CB-03: the page names the commit the frontend was built from in <meta name="zs-build">, from NEXT_PUBLIC_BUILD_SHA
 * (frontend/Dockerfile build argument; scripts/deploy/build_images.sh passes the commit). Anything that is not a
 * full commit is reported as "unknown", never echoed into the page.
 * Run: npx --yes tsx utils/buildInfo.test.ts
 */
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { buildMeta, buildSha } from "./buildInfo"

const SHA = "83b570bed86212e3afed395be942df57b8dc3df5"

assert.equal(buildSha(SHA), SHA)
assert.equal(buildSha(SHA.toUpperCase()), SHA)
assert.equal(buildSha(` ${SHA}\n`), SHA)
for (const bad of [undefined, "", "unknown", SHA.slice(0, 12), SHA + "0", "g".repeat(40), `${SHA}"><script>`]) {
  assert.equal(buildSha(bad), "unknown", String(bad))
}
assert.deepEqual(buildMeta(SHA), { other: { "zs-build": SHA } })
// no commit (a production build: scripts/deploy/build_images.sh passes it only when DSS_EXPOSE_BUILD=1): no meta tag
for (const none of [undefined, "", "unknown", "not-a-sha"]) assert.deepEqual(buildMeta(none), {}, String(none))

// the root layout puts it into every page's <head>
const layout = fs.readFileSync(path.join(__dirname, "../app/layout.tsx"), "utf8")
assert.ok(layout.includes("...buildMeta(process.env.NEXT_PUBLIC_BUILD_SHA)"), "layout metadata carries the build")

console.log("build info tests passed")
