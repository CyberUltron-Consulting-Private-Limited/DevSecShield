/**
 * "Run again" on a failed code scan (round 5 customer testing: a failed scan offered only "Try Again", which reloaded
 * the same failed scan, and the message said to create a new scan by hand). It creates a new scan prefilled from the
 * failed scan's stored settings; an uploaded file and an access token are never stored, so the customer gives them
 * again (G3). Run: npx --yes tsx utils/scanRerun.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { readRerun, rerunNotes, rerunPrefill, rerunTitle, saveRerun } from "./scanRerun";

// what GET /{team}/{type}/scan/{id} returns for a failed scan (scan_metadata from backend utilities/db/metadata.py)
const sast = {
  title: "payments-api", scan_status: "failure", info: { error: "git clone failed" },
  scan_metadata: { zip_file_used: false, repo_url: "https://github.com/acme/payments", repo_type: "github", branch: "release",
    app_lang: "python", exclude_path_arrays: [["vendor"], ["tests", "fixtures"]] },
};
assert.deepEqual(rerunPrefill("sast", sast), {
  repo_url: "https://github.com/acme/payments", mode: "github", branch: "release", upload: null,
  options: { app_lang: "python", exclude_path_arrays: [["vendor"], ["tests", "fixtures"]] },
});
assert.match(rerunNotes(rerunPrefill("sast", sast)!)[0], /enter its access token again: tokens are not stored/);

const iac = { scan_metadata: JSON.stringify({ zip_file_used: false, repo_url: "https://gitlab.com/acme/infra", repo_type: "gitlab",
  branch: "main", environment: "production", iac_contexts: [{ mode: "terraform", include_path_arrays: [["envs", "prod"]] }] }) };
const iacPrefill = rerunPrefill("iac", iac)!;
assert.equal(iacPrefill.mode, "gitlab");
assert.deepEqual(iacPrefill.options, { environment: "production", iac_contexts: [{ mode: "terraform", include_path_arrays: [["envs", "prod"]] }] });

// an uploaded archive: no repository fields, the options are kept, the file must be chosen again
const cbomZip = { scan_metadata: { zip_file_used: true, repo_url: null, repo_type: null, branch: null, cbom_file_used: false,
  scan_binaries: true, include_vendored: true, scan_history: false } };
const cz = rerunPrefill("cbom", cbomZip)!;
assert.deepEqual(cz, { repo_url: null, mode: null, branch: null, upload: "archive",
  options: { scan_binaries: true, include_vendored: true, scan_history: false } });
assert.match(rerunNotes(cz)[0], /Choose the archive again: uploaded files are deleted after every scan/);
assert.equal(rerunPrefill("sbom_sca", { scan_metadata: { zip_file_used: false, sbom_file_used: true } })!.upload, "sbom_file");
assert.equal(rerunPrefill("ai_bom", { scan_metadata: { ai_bom_file_used: true } })!.upload, "ai_bom_file");
// nothing stored (or junk): no prefill; an unknown platform is not copied
assert.equal(rerunPrefill("sast", { scan_metadata: null }), null);
assert.equal(rerunPrefill("sast", { scan_metadata: "{" }), null);
assert.equal(rerunPrefill("sast", { scan_metadata: { repo_url: "x", repo_type: "svn" } })!.mode, null);
// a token is never part of it, even if a server sent one
assert.ok(!JSON.stringify(rerunPrefill("sast", { scan_metadata: { ...sast.scan_metadata, PAT: "ghp_secret" } })).includes("ghp_secret"));

assert.equal(rerunTitle("payments-api"), "payments-api (run again)");
assert.equal(rerunTitle("payments-api (run again)"), "payments-api (run again)");
assert.equal(rerunTitle(undefined), "Scan (run again)");

// it travels to the new scan in sessionStorage (blocked storage: the new scan opens empty)
const store = new Map<string, string>();
(globalThis as unknown as { sessionStorage: unknown }).sessionStorage = { getItem: (k: string) => store.get(k) ?? null, setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k) };
saveRerun("sast", 42, rerunPrefill("sast", sast)!);
assert.deepEqual(readRerun("sast", 42), rerunPrefill("sast", sast));
assert.equal(readRerun("sast", 43), null);
assert.equal(readRerun("iac", 42), null);
(globalThis as unknown as { sessionStorage: unknown }).sessionStorage = { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); } };
assert.equal(readRerun("sast", 42), null);
saveRerun("sast", 42, cz);

// all five code-scan sidebars offer it on a failed scan and apply it on the new scan
const types: Record<string, string> = { sast: "sast", iac: "iac", "sca-sbom": "sbom_sca", cbom: "cbom", "ai-bom": "ai_bom" };
for (const [file, type] of Object.entries(types)) {
  const src = fs.readFileSync(path.join(__dirname, "..", "components", `${file}-options-sidebar.tsx`), "utf8");
  assert.ok(src.includes(`<RunAgainButton type="${type}" teamId={team_id} scan={query.data} />`), `${file}: Run again on a failed scan`);
  assert.ok(src.includes(`useRerunPrefill("${type}", scan_id,`), `${file}: the new scan is prefilled`);
  assert.ok(/RerunNotice prefill=\{rerun\}/.test(src), `${file}: says what to give again`);
}
console.log("scanRerun tests passed");
