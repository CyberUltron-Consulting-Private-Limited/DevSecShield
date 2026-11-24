/**
 * The SBOM, AI BOM and CBOM results pages save the server's signed CycloneDX documents byte for byte, under the
 * server's file name (follow-up to PR #489): the SBOM and AI BOM "Download CycloneDX" used to rebuild a copy in the
 * browser from scan_metadata (overlayBomCompliance + JSON.stringify), and every VEX button re-serialised the JSON, so
 * the file was unsigned and differed from GET /bom. A local HTTP server stands in for the API. Review 6036875286: the
 * AI BOM SPDX 3.0 / SARIF files come from the API too; three signature states; a 200 that is not the file and bytes
 * that do not match X-Cbom-Sha256 are refused; a failed download shows the server's reason (503, 409) and a closed
 * session (403 "Session not active") logs out.
 * Run: npx --yes tsx utils/api/bomDownload.test.ts
 */
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import http from "node:http";
import path from "node:path";

// what the routes serve: compact JSON with an embedded JSF signature, never what JSON.stringify(x, null, 2) writes
const DOCS: Record<string, string> = {
  "/7/sbom_sca/scan/12/bom": '{"bomFormat":"CycloneDX","specVersion":"1.6","serialNumber":"urn:uuid:1","signature":{"algorithm":"ES256","value":"c2ln"}}',
  "/7/ai_bom/scan/13/bom": '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"machine-learning-model","name":"m"}]}',
  "/7/cbom/scan/14/bom": '{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}',
  "/7/sbom_sca/scan/12/vex": '{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"GHSA-3f63-hfp8-52jq"}]}',
  "/7/ai_bom/scan/13/spdx": '{\n  "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",\n  "@graph": []\n}\n',
  "/7/ai_bom/scan/13/sarif": '{\n  "version": "2.1.0",\n  "runs": []\n}\n',
  "/7/sbom_sca/scan/20/bom": '{"bomFormat":"CycloneDX"}',  // served with no X-ZS-Signature header (an older server)
  "/7/sbom_sca/scan/21/bom": '{"bomFormat":"CycloneDX"}',  // its X-Cbom-Sha256 names other bytes
};
// failures, as the API sends them (JSON detail; the browser hands a blob request's body over as a Blob)
const ERRORS: Record<string, [number, string]> = {
  "/7/ai_bom/scan/30/vex": [503, "aibom vex unavailable: No module named 'aibom'"],
  "/7/sbom_sca/scan/31/bom": [409, "No CycloneDX document is stored for this scan"],
  "/7/sbom_sca/scan/32/bom": [403, "Session not active"],
};
const DISPOSITION: Record<string, string> = {
  "/7/sbom_sca/scan/12/bom": 'attachment; filename="sbom_sca-cyclonedx-12.cdx.json"',
  "/7/ai_bom/scan/13/bom": 'attachment; filename="ai_bom-cyclonedx-13.cdx.json"',
  "/7/sbom_sca/scan/12/vex": 'inline; filename="sbom_sca-vex-12.cdx.json"',
  "/7/ai_bom/scan/13/spdx": 'attachment; filename="ai_bom-13.spdx.json"',
  "/7/ai_bom/scan/13/sarif": 'attachment; filename="ai_bom-13.sarif"',
  // no Content-Disposition for the CBOM: the helper falls back to the same name the server uses
};

async function main() {
  const seen: string[] = [];
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    seen.push(url.pathname + url.search);
    if (url.pathname === "/logout") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end('{"detail":"ok"}');
      return;
    }
    if (ERRORS[url.pathname]) {
      const [code, detail] = ERRORS[url.pathname];
      res.writeHead(code, { "content-type": "application/json" });
      res.end(JSON.stringify({ detail }));
      return;
    }
    if (url.pathname === "/7/sbom_sca/scan/22/bom") {  // a proxy's sign-in page, served with 200
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end("<html><body>Sign in to continue</body></html>");
      return;
    }
    const body = DOCS[url.pathname];
    if (!body) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end('{"detail":"No CycloneDX document is stored for this scan"}');
      return;
    }
    const digest = createHash("sha256").update(body).digest();
    const signed = !url.pathname.includes("/ai_bom/scan/13/bom");
    const stated = !url.pathname.includes("/scan/20/");
    const type = url.pathname.endsWith("/spdx") ? "application/ld+json"
      : url.pathname.endsWith("/sarif") ? "application/sarif+json" : "application/json";
    res.writeHead(200, {
      "content-type": type,
      "x-cbom-sha256": url.pathname.includes("/scan/21/") ? "0".repeat(64) : digest.toString("hex"),
      ...(stated ? { "x-zs-signature": signed ? "MEUCIQDsig==" : "unsigned" } : {}),
      ...(signed ? { "x-zs-signature-alg": "ES256", "x-zs-signature-key-id": "kid-1" } : {}),
      ...(DISPOSITION[url.pathname] ? { "content-disposition": DISPOSITION[url.pathname] } : {}),
    });
    res.end(body);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  process.env.NEXT_PUBLIC_BACKEND_URL = `http://127.0.0.1:${port}`;

  const store = new Map<string, string>([["access_token", "t"]]);
  const saved: { name: string; blob: Blob | string }[] = [];
  const g = globalThis as Record<string, unknown>;
  const origin = "http://localhost:3000";
  g.window = { location: { href: `${origin}/7/sbom_sca/12/results`, origin, protocol: "http:", host: "localhost:3000" } };
  g.localStorage = {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => store.set(k, String(v)),
    removeItem: (k: string) => store.delete(k),
    clear: () => store.clear(),
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
      tagName: tag, href: "", download: "", style: {},
      appendChild: () => undefined, setAttribute: () => undefined, remove: () => undefined,
      click: () => saved.push({ name: String(node.download), blob: blobs.get(String(node.href))! }),
    };
    return node;
  };
  const head = element("head");
  g.document = {
    head, body: element("body"),
    getElementsByTagName: (tag: string) => (tag === "head" ? [head] : []),
    createElement: element, createTextNode: (text: string) => ({ text }),
  };
  const bytes = async (file: Blob | string) =>
    typeof file === "string" ? file : Buffer.from(await file.arrayBuffer()).toString("utf8");

  const { downloadOutcome, downloadServedAiBomArtifact, downloadServedBom, downloadServedVex, fileNameFromDisposition,
    signatureNote } = await import("./bomDownload");
  const { handleApiError } = await import("../error-handler");
  try {
    // SBOM: the served bytes, the served name, the signature headers
    const sbom = await downloadServedBom(7, "sbom_sca", 12);
    assert.equal(seen[0], "/7/sbom_sca/scan/12/bom?format=json");
    assert.equal(saved[0].name, "sbom_sca-cyclonedx-12.cdx.json");
    assert.equal(await bytes(saved[0].blob), DOCS["/7/sbom_sca/scan/12/bom"], "the saved file is GET /bom, unchanged");
    assert.equal(sbom.signature, "MEUCIQDsig==");
    assert.equal(sbom.keyId, "kid-1");
    assert.equal(sbom.sha256, createHash("sha256").update(DOCS["/7/sbom_sca/scan/12/bom"]).digest("hex"));
    assert.equal(sbom.state, "signed");
    assert.equal(signatureNote(sbom), "signed ES256, key kid-1");
    assert.deepEqual(downloadOutcome("CycloneDX SBOM", sbom),
                     { level: "success", text: "CycloneDX SBOM downloaded (signed ES256, key kid-1)" });

    // AI BOM on a deployment without a key: still the server's bytes, and the toast says unsigned
    const ai = await downloadServedBom(7, "ai_bom", 13);
    assert.equal(saved[1].name, "ai_bom-cyclonedx-13.cdx.json");
    assert.equal(await bytes(saved[1].blob), DOCS["/7/ai_bom/scan/13/bom"]);
    assert.equal(ai.signature, null);
    assert.equal(ai.state, "unsigned");
    assert.deepEqual(downloadOutcome("AI BOM CycloneDX", ai), {
      level: "warning", text: "AI BOM CycloneDX downloaded (unsigned: this deployment has no usable signing key)" });

    // CBOM without a readable Content-Disposition: the server's own name pattern
    await downloadServedBom(7, "cbom", 14);
    assert.equal(saved[2].name, "cbom-cyclonedx-14.cdx.json");

    // VEX: saved as served, not re-serialised
    await downloadServedVex(7, "sbom_sca", 12);
    assert.equal(seen[3], "/7/sbom_sca/scan/12/vex");
    assert.equal(saved[3].name, "sbom_sca-vex-12.cdx.json");
    assert.equal(await bytes(saved[3].blob), DOCS["/7/sbom_sca/scan/12/vex"]);

    // a refused download saves nothing
    await assert.rejects(downloadServedBom(7, "sbom_sca", 99));
    assert.equal(saved.length, 4);

    // AI BOM SPDX 3.0 / SARIF: the server's files and names
    const spdx = await downloadServedAiBomArtifact(7, 13, "spdx");
    assert.equal(seen.at(-1), "/7/ai_bom/scan/13/spdx");
    assert.equal(saved[4].name, "ai_bom-13.spdx.json");
    assert.equal(await bytes(saved[4].blob), DOCS["/7/ai_bom/scan/13/spdx"]);
    assert.equal(spdx.state, "signed");
    await downloadServedAiBomArtifact(7, 13, "sarif");
    assert.equal(saved[5].name, "ai_bom-13.sarif");
    assert.equal(await bytes(saved[5].blob), DOCS["/7/ai_bom/scan/13/sarif"]);

    // no X-ZS-Signature at all: "not stated", a warning, never "no signing key"
    const quiet = await downloadServedBom(7, "sbom_sca", 20);
    assert.equal(quiet.state, "not_stated");
    assert.deepEqual(downloadOutcome("CycloneDX SBOM", quiet), {
      level: "warning", text: "CycloneDX SBOM downloaded (the server did not say whether this file is signed)" });
    assert.equal(saved.length, 7);

    // m1: a 200 that is not the file (a proxy's HTML page), or bytes that do not match X-Cbom-Sha256: nothing saved
    await assert.rejects(downloadServedBom(7, "sbom_sca", 22),
                         /not downloaded: the server sent a text\/html page, not the file/);
    await assert.rejects(downloadServedBom(7, "sbom_sca", 21), /do not match the SHA-256 the server stated/);
    assert.equal(saved.length, 7);

    // M2: the server's reason reaches the message; a closed session logs out like any other request
    const failure = async (promise: Promise<unknown>) => {
      try {
        await promise;
      } catch (err) {
        return err;
      }
      throw new Error("expected a failure");
    };
    const e503 = await failure(downloadServedVex(7, "ai_bom", 30));
    assert.deepEqual(handleApiError(e503), { message: "aibom vex unavailable: No module named 'aibom'", status: 503 });
    const e409 = await failure(downloadServedBom(7, "sbom_sca", 31));
    assert.deepEqual(handleApiError(e409), { message: "No CycloneDX document is stored for this scan", status: 409 });
    const e403 = await failure(downloadServedBom(7, "sbom_sca", 32));
    assert.equal(handleApiError(e403).message, "Session not active");
    for (let i = 0; i < 50 && store.size; i += 1) await new Promise((r) => setTimeout(r, 20));
    assert.ok(seen.includes("/logout"), "the closed session is logged out (GET /logout)");
    assert.equal(store.size, 0, "and the local session is cleared");
    assert.equal((g.window as { location: { href: string } }).location.href, "/login");
    assert.equal(saved.length, 7);

    // file names: RFC 5987, quotes, and never a directory part
    assert.equal(fileNameFromDisposition("attachment; filename*=UTF-8''sbom%20a.cdx.json", "f"), "sbom a.cdx.json");
    assert.equal(fileNameFromDisposition('attachment; filename="../../etc/x.json"', "f"), "x.json");
    assert.equal(fileNameFromDisposition("attachment", "fallback.json"), "fallback.json");
    assert.equal(fileNameFromDisposition(null, "fallback.json"), "fallback.json");

    // the pages' download handlers go through these helpers and build no file of their own
    const handler = (file: string, name: string) => {
      const page = readFileSync(path.join(process.cwd(), "components", file), "utf8");
      const start = page.indexOf(`const ${name}`);
      assert.ok(start > 0, `${file} has ${name}`);
      const end = page.indexOf("\n  };\n", start);
      assert.ok(end > start && end - start < 1000, `${name}'s body is found`);
      return page.slice(start, end);
    };
    for (const [file, name, call] of [
      ["SbomResults.tsx", "handleDownloadSbomJson", /downloadServedBom\(tid, "sbom_sca", conversationId, "json"\)/],
      ["SbomResults.tsx", "handleDownloadVex", /downloadServedVex\(tid, "sbom_sca", conversationId\)/],
      ["AiBomResults.tsx", "handleDownloadAiBomJson", /downloadServedBom\(tid, "ai_bom", sid, "json"\)/],
      ["AiBomResults.tsx", "handleDownloadVex", /downloadServedVex\(tid, "ai_bom", sid\)/],
      ["CbomResults.tsx", "handleDownloadVex", /downloadServedVex\(tid, "cbom", sid\)/],
      ["AiBomResults.tsx", "handleDownloadArtifact", /downloadServedAiBomArtifact\(tid, sid, artifact\)/],
    ] as const) {
      const body = handler(file, name);
      assert.match(body, call, `${file} ${name} downloads the server's file`);
      assert.ok(!/JSON\.stringify|new Blob|overlayBomCompliance/.test(body), `${file} ${name} builds no file`);
    }
    const aiPage = readFileSync(path.join(process.cwd(), "components", "AiBomResults.tsx"), "utf8");
    assert.ok(!aiPage.includes("overlayBomCompliance"), "the AI BOM page no longer rebuilds its CycloneDX");
    assert.ok(!/JSON\.stringify\(artifact/.test(aiPage), "nor its SPDX / SARIF files");
    // m2: every saved file's message says how it is signed, on all three pages (no bare "... downloaded")
    for (const file of ["SbomResults.tsx", "AiBomResults.tsx", "CbomResults.tsx"]) {
      const page = readFileSync(path.join(process.cwd(), "components", file), "utf8");
      assert.ok(!/toast\.success\("(CycloneDX[^"]*|VEX|AI BOM[^"]*) downloaded"\)/.test(page), `${file}: a bare download toast`);
    }
  } finally {
    server.close();
  }
  console.log("bomDownload.test.ts: ok");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
