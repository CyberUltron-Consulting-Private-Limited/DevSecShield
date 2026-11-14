/**
 * CB-38 PR-8: a Sources run's VEX, signature, PDF report and evidence pack downloads hit the run routes and save the
 * server's bytes unchanged (the signature covers the exact bytes of the run CBOM JSON, so nothing may be re-serialised
 * on the way). A local HTTP server stands in for the API.
 * Run: npx --yes tsx utils/api/cbom_run_deliverables.test.ts
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";

const BODIES: Record<string, string> = {
  vex: '{"bomFormat":"CycloneDX","specVersion":"1.6","vulnerabilities":[]}',
  signature: '{\n  "alg": "HMAC-SHA256",\n  "digest": "ab"\n}',
  "report.pdf": "%PDF-1.4 run report",
  "evidence-pack": "PK\u0003\u0004 zip",
};

async function main() {
  const seen: string[] = [];
  const posted: { url: string; sig: string | undefined; body: string }[] = [];
  const server = http.createServer((req, res) => {
    seen.push(req.url ?? "");
    if (req.method === "POST") {
      const parts: Buffer[] = [];
      req.on("data", (c: Buffer) => parts.push(c));
      req.on("end", () => {
        posted.push({ url: req.url ?? "", sig: req.headers["x-zs-signature-b64"] as string | undefined,
                      body: Buffer.concat(parts).toString("utf8") });
        res.writeHead(200, { "content-type": "application/json" });
        res.end('{"valid":true,"signature_match":true,"digest_match":true}');
      });
      return;
    }
    const kind = (req.url ?? "").split("/").pop() ?? "";
    if (!(kind in BODIES)) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"detail":"Run not found"}');
      return;
    }
    res.writeHead(200, { "content-type": "application/octet-stream" });
    res.end(BODIES[kind]);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  process.env.NEXT_PUBLIC_BACKEND_URL = `http://127.0.0.1:${port}`;

  const store = new Map<string, string>([["access_token", "t"]]);
  const saved: { name: string; blob: Blob | string }[] = [];
  const g = globalThis as Record<string, unknown>;
  const origin = "http://localhost:3000";
  g.window = { location: { href: `${origin}/7/cbom/runs/12/results`, origin, protocol: "http:", host: "localhost:3000" } };
  g.localStorage = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => store.set(k, String(v)),
    removeItem: (k: string) => store.delete(k),
  };
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

  const { downloadCbomRunDeliverable, cbomRunDeliverablePath, cbomRunDeliverableFilename, getCbomRunSignature,
          verifyCbomRunSignature } = await import("../backend_api");
  try {
    assert.equal(cbomRunDeliverablePath(7, 12, "vex"), "/7/cbom/sources/runs/12/vex");
    const expected = {
      vex: "cbom-sources-run-12.vex.json",
      signature: "cbom-sources-run-12-signature.json",
      "report.pdf": "cbom-sources-run-12-report.pdf",
      "evidence-pack": "cbom-sources-run-12-evidence-pack.zip",
    } as const;
    for (const kind of Object.keys(expected) as (keyof typeof expected)[]) {
      assert.equal(cbomRunDeliverableFilename(12, kind), expected[kind]);
      await downloadCbomRunDeliverable(7, 12, kind);
      assert.equal(new URL(seen.at(-1)!, "http://x").pathname, `/7/cbom/sources/runs/12/${kind}`);
      const file = saved.at(-1)!;
      assert.equal(file.name, expected[kind]);
      const bytes = typeof file.blob === "string" ? file.blob : Buffer.from(await file.blob.arrayBuffer()).toString("utf8");
      assert.equal(bytes, BODIES[kind], `${kind}: saved as served`);
    }
    const sig = await getCbomRunSignature(7, 12);
    assert.equal(sig.alg, "HMAC-SHA256");

    // verification sends the downloaded file as is, with the signature it came with
    const file = '{"bomFormat":"CycloneDX","components":[]}';
    const verdict = await verifyCbomRunSignature(7, 12, new Blob([file]), "c2lnbmF0dXJl");
    assert.equal(verdict.valid, true);
    assert.equal(posted[0].url, "/7/cbom/sources/runs/12/signature/verify");
    assert.equal(posted[0].sig, "c2lnbmF0dXJl");
    assert.equal(posted[0].body, file, "the file is sent byte for byte");

    // the menu offers the code page's four buttons, in its order, through this client
    const menu = readFileSync(path.join(process.cwd(), "components", "cbom", "results", "RunDeliverablesMenu.tsx"), "utf8");
    const labels = [...menu.matchAll(/label: "([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(labels, ["VEX", "Signature", "Evidence pack", "PDF Report"]);
    const codePage = readFileSync(path.join(process.cwd(), "components", "CbomResults.tsx"), "utf8");
    for (const label of labels) assert.ok(codePage.includes(label), `code page has a ${label} button`);
    assert.match(menu, /downloadCbomRunDeliverable\(teamId, runId, kind\)/);
  } finally {
    server.close();
  }
  console.log("cbom_run_deliverables.test.ts: ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
