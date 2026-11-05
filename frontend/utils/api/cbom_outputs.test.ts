/**
 * The CBOM scan page's CycloneDX downloads are the server's document, byte for byte (rev4 H2): the JSON button used to
 * rebuild a copy in the browser (merged crypto assets, no library purl, extra stamps) that never verified against the
 * BOM signature. A local HTTP server stands in for the API.
 * Run: npx --yes tsx utils/api/cbom_outputs.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";

// what GET /{team}/cbom/scan/{id}/bom?format=json serves: bom_dict_from_scan_data (the signed document)
const SERVER_DOC = JSON.stringify({
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  version: 1,
  components: [
    { type: "cryptographic-asset", "bom-ref": "crypto-algo-md5-src-a-py", name: "MD5" },
    { type: "cryptographic-asset", "bom-ref": "crypto-algo-md5-src-b-py", name: "MD5" },
    { type: "library", "bom-ref": "crypto-lib-pyca-cryptography", name: "pyca/cryptography", purl: "pkg:pypi/cryptography" },
  ],
});
async function main() {
const seen: string[] = [];
const server = http.createServer((req, res) => {
  seen.push(req.url ?? "");
  const xml = (req.url ?? "").includes("format=xml");
  res.writeHead(200, { "content-type": xml ? "application/vnd.cyclonedx+xml; version=1.6" : "application/json" });
  res.end(xml ? "<bom/>" : SERVER_DOC);
});
await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address() as { port: number };
process.env.NEXT_PUBLIC_BACKEND_URL = `http://127.0.0.1:${port}`;

const store = new Map<string, string>([["access_token", "t"]]);
const saved: { name: string; blob: Blob | string }[] = [];
const g = globalThis as Record<string, unknown>;
const origin = "http://localhost:3000";
g.window = { location: { href: `${origin}/7/cbom/12`, origin, protocol: "http:", host: "localhost:3000" } };
g.localStorage = {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => store.set(k, String(v)),
  removeItem: (k: string) => store.delete(k),
};
// in a browser axios hands the raw response over as a Blob; under Node it is the raw body text. Either way it must be
// saved as served, never parsed and re-serialised.
const blobs = new Map<string, Blob | string>();
URL.createObjectURL = ((blob: Blob | string) => {
  const url = `blob:test/${blobs.size}`;
  blobs.set(url, blob);
  return url;
}) as typeof URL.createObjectURL;
URL.revokeObjectURL = () => undefined;
const element = (tag: string) => {
  const node: Record<string, unknown> = {
    tagName: tag,
    href: "",
    download: "",
    style: {},
    appendChild: () => undefined,
    setAttribute: () => undefined,
    remove: () => undefined,
    click: () => saved.push({ name: String(node.download), blob: blobs.get(String(node.href))! }),
  };
  return node;
};
const head = element("head");
g.document = {
  head,
  body: element("body"),
  getElementsByTagName: (tag: string) => (tag === "head" ? [head] : []),
  createElement: element,
  createTextNode: (text: string) => ({ text }),
};

const { downloadCbomScanBom } = await import("./cbom_outputs");
try {
  await downloadCbomScanBom(7, 12, "json");
  assert.equal(seen.length, 1);
  assert.equal(new URL(seen[0], "http://x").pathname, "/7/cbom/scan/12/bom");
  assert.equal(new URL(seen[0], "http://x").searchParams.get("format"), "json");
  assert.equal(saved[0].name, "cbom-cyclonedx-12.cdx.json");
  const file = saved[0].blob;
  const bytes = typeof file === "string" ? file : Buffer.from(await file.arrayBuffer()).toString("utf8");
  assert.equal(bytes, SERVER_DOC, "the saved file is the server's document, unchanged");

  // the scan page's JSON button goes through this download, never a client-side rebuild of cbom_json
  const page = readFileSync(path.join(process.cwd(), "components", "CbomResults.tsx"), "utf8");
  assert.ok(!page.includes("overlayBomCompliance"), "CbomResults must not rebuild the CycloneDX JSON in the browser");
  const handler = page.slice(page.indexOf("const handleDownloadCBOMJson"), page.indexOf("const downloadBlob"));
  assert.match(handler, /downloadCbomScanBom\([^)]*"json"\)/);
} finally {
  server.close();
}
console.log("cbom_outputs.test.ts: ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
