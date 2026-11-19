/**
 * CB-38 PR-8: a Sources run's VEX, signature, PDF report and evidence pack downloads hit the run routes and save the
 * server's bytes unchanged (the signature covers the exact bytes of the run CBOM JSON, so nothing may be re-serialised
 * on the way). A local HTTP server stands in for the API.
 * Plan §7: VEX, Signature and Evidence pack stay one click; PDF Report opens the export dialog (family run), which builds
 * it through downloadRunReport with the options that differ from the default and reads the report headers.
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
    const kind = new URL(req.url ?? "", "http://x").pathname.split("/").pop() ?? "";
    if (!(kind in BODIES)) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"detail":"Run not found"}');
      return;
    }
    if (kind === "report.pdf" && (req.url ?? "").includes("?")) {
      const q = new URL(req.url ?? "", "http://x").searchParams;
      if (q.get("label") === "restricted") {
        res.writeHead(429, { "content-type": "application/json", "retry-after": "17" });
        res.end(JSON.stringify({ detail: "Too many large reports are being built; try again shortly" }));
        return;
      }
      if (q.has("statuses") || q.has("hide_evidence")) {
        res.writeHead(422, { "content-type": "application/json" });
        res.end(JSON.stringify({ detail: `${q.has("statuses") ? "statuses" : "hide_evidence"}: is not available for this report` }));
        return;
      }
      res.writeHead(200, { "content-type": "application/pdf", "x-report-findings": "12/40", "x-report-logo": "skipped" });
      res.end(BODIES[kind]);
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
  g.window = { location: { href: `${origin}/7/cbom/run-12/results`, origin, protocol: "http:", host: "localhost:3000" } };
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
          verifyCbomRunSignature, downloadRunReport, ReportDownloadError } = await import("../backend_api");
  const { DEFAULT_OPTIONS } = await import("../reportOptions");
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

    // the run's PDF report with options: the run route's keys only, the server's bytes and its report headers
    const report = await downloadRunReport(7, 12, { ...DEFAULT_OPTIONS, preset: "executive", sections: ["summary", "posture"], severities: ["critical", "high"], label: "internal" });
    const reportUrl = new URL(seen.at(-1)!, "http://x");
    assert.equal(reportUrl.pathname, "/7/cbom/sources/runs/12/report.pdf");
    assert.deepEqual(Object.fromEntries(reportUrl.searchParams), { preset: "executive", severities: "critical,high", label: "internal" });
    assert.equal(Buffer.from(await report.blob.arrayBuffer()).toString("utf8"), BODIES["report.pdf"]);
    assert.deepEqual(report.meta, { shown: 12, total: 40, logo: "skipped" });
    // defaults send no parameter: today's report
    await downloadRunReport(7, 12, { ...DEFAULT_OPTIONS });
    assert.equal(new URL(seen.at(-1)!, "http://x").search, "");
    // a run never sends a key its route refuses (statuses, hide_evidence)
    const kept = await downloadRunReport(7, 12, { ...DEFAULT_OPTIONS, statuses: ["fixed"], hide_evidence: true }).then(() => null, (e: unknown) => e);
    assert.equal(kept, null);
    assert.equal(new URL(seen.at(-1)!, "http://x").search, "", "no statuses or hide_evidence on a run");
    // a refusal arrives with the server's words (read back from the blob body), its status and Retry-After
    const refused = await downloadRunReport(7, 12, { ...DEFAULT_OPTIONS, label: "restricted" }).then(() => null, (e: unknown) => e);
    assert.ok(refused instanceof ReportDownloadError, "a ReportDownloadError");
    assert.equal(refused.status, 429);
    assert.equal(refused.detail, "Too many large reports are being built; try again shortly");
    assert.equal(refused.message, refused.detail);
    assert.equal(refused.retryAfter, 17);
    assert.ok(refused.retryAt! > Date.now() + 15_000, "Download waits until then");

    // the menu offers the code page's four buttons, in its order, through this client
    const menu = readFileSync(path.join(process.cwd(), "components", "cbom", "results", "RunDeliverablesMenu.tsx"), "utf8");
    const labels = [...menu.matchAll(/label: "([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(labels, ["VEX", "Signature", "Evidence pack", "PDF Report"]);
    const codePage = readFileSync(path.join(process.cwd(), "components", "CbomResults.tsx"), "utf8");
    for (const label of labels) assert.ok(codePage.includes(label), `code page has a ${label} button`);
    // VEX, Signature and Evidence pack: one click through this client; PDF Report: the export dialog (family run)
    assert.match(menu, /downloadCbomRunDeliverable\(teamId, runId, kind\)/);
    assert.match(menu, /onClick=\{\(\) => \(report \? pdf\.open\(\) : void download\(kind, done\)\)\}/);
    assert.match(menu, /target: \{ family: "run", runId \},\n\s*fileName: cbomRunDeliverableFilename\(runId, "report\.pdf"\),/);
    assert.ok(menu.includes("{pdf.dialog}"));
  } finally {
    server.close();
  }
  console.log("cbom_run_deliverables.test.ts: ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
