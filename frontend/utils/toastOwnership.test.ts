/**
 * #12, #27: one refused action showed two identical error toasts. The API helper (utils/backend_api.ts) called
 * showErrorToast and rethrew, and the caller's useMutation onError toasted again: Team settings (save, invite or remove
 * members, delete the team), Create team (the /home dialog and page), CI/CD integrations (create, delete, rename,
 * edit) and the report download of the SAST, IaC, SCA + SBOM, AI BOM, LLM, MCP and DAST results pages. Some successes
 * were said twice as well (CI/CD delete, rename and edit; the AI BOM and DAST report downloads).
 * Now each outcome is said in one place (utils/toastPolicy.ts): a helper whose callers all show the error only throws.
 * PDF reports (plan §7): the export dialog (components/reports/ExportPdfDialog.tsx, useExportPdf) is the one owner of
 * an export's toasts; the report helpers never toast, and every opener (options sidebars, results pages, the run
 * menu) only opens the dialog. Every caller of these helpers is listed below, so a new one is checked too.
 * Failing-first on origin/dev 1884f564: 17 of the 26 caller sites below showed two toasts for one outcome.
 * Browser check: Team settings > Integrations > change the Jira URL without re-entering the token > Save: one error
 * toast; CI/CD > delete an integration: one "CI/CD integration deleted"; a results page > Download report: one toast.
 * Run: npx --yes tsx@4.23.15 utils/toastOwnership.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { toast as sonner } from "sonner";

import { mutationOptions, usersOf } from "./sourceChecks";
import { DEFAULT_OPTIONS } from "./reportOptions";

// every toast of the app goes through sonner (utils/toast.ts): count them
const toasts: string[] = [];
for (const kind of ["success", "error", "warning", "info", "message"] as const) {
  (sonner as unknown as Record<string, unknown>)[kind] = () => {
    toasts.push(kind);
    return 1;
  };
}
// what the API client and the error handler touch in a browser
(globalThis as Record<string, unknown>).window = { location: { href: "/13/settings" } };
(globalThis as Record<string, unknown>).localStorage = {
  getItem: () => "token", setItem: () => undefined, removeItem: () => undefined, clear: () => undefined,
};
console.warn = () => undefined; // utils/safeRequestLog.ts writes one line per refused request

const root = path.join(__dirname, "..");
const read = (rel: string) => fs.readFileSync(path.join(root, rel), "utf8");
const count = (text: string | undefined, re: RegExp) => (text ?? "").match(re)?.length ?? 0;
const SUCCESS = /\btoast\.success\(/g;
const ERROR = /\b(?:showErrorToast|toast\.error)\(/g;

type Api = typeof import("./backend_api");
type Opts = { toast?: boolean } | undefined;

/** How each caller site calls its helper; `opts` is what the site passes as the helper's toast option. */
const CALL: Record<string, (api: Api, opts: Opts) => Promise<unknown>> = {
  createTeam: (a) => a.createTeam({ name: "Team" }),
  updateTeam: (a) => a.updateTeam(13, { name: "Team" }),
  removeMembers: (a) => a.removeOrAddTeamMembers(13, { intent: "remove", email_ids: ["a@acme.test"] }),
  inviteMembers: (a) => a.removeOrAddTeamMembers(13, { intent: "add", email_ids: ["b@acme.test"] }),
  deleteTeam: (a) => a.deleteTeam(13),
  resendTeamInvitation: (a) => a.resendTeamInvitation(13, 4),
  revokeTeamInvitation: (a) => a.revokeTeamInvitation(13, 4),
  createCicdIntegration: (a) => a.createCicdIntegration(13, { title: "ci", scan_type: "sast" }),
  deleteCicdIntegration: (a) => a.deleteCicdIntegration(13, 5),
  renameCicdIntegration: (a) => a.renameCicdIntegration({ team_id: 13, integration_id: 5, title: "ci" }),
  updateCicdIntegration: (a) => a.updateCicdIntegration({ team_id: 13, integration_id: 5, data: { title: "ci" } }),
};
/** The PDF report helpers: none of them may toast (the export dialog, or the deliverables menu, says the outcome). */
const REPORT_CALL: Record<string, (api: Api) => Promise<unknown>> = {
  downloadScanReport: (a) => a.downloadScanReport(13, "sast", 7, { ...DEFAULT_OPTIONS }),
  downloadRunReport: (a) => a.downloadRunReport(13, 7, { ...DEFAULT_OPTIONS }),
  downloadDeliverable: (a) => a.downloadDeliverable(13, "board-executive-report", { ...DEFAULT_OPTIONS }),
  downloadCbomDeliverable: (a) => a.downloadCbomDeliverable(13, "board-executive-report", { ...DEFAULT_OPTIONS }),
};
/** Who builds PDF reports: the dialog's hook alone; the deliverables menu's one-click items say their own outcome. */
const REPORT_USERS: Record<string, string[]> = {
  downloadScanReport: ["components/reports/ExportPdfDialog.tsx"],
  downloadRunReport: ["components/reports/ExportPdfDialog.tsx"],
  downloadDeliverable: [],
  downloadCbomDeliverable: ["app/[team_id]/cbom/page.tsx"],
};
/** Every opener of the export dialog: each "Download Scan Report" / "PDF Report" button only opens it. */
const OPENERS = [
  "app/[team_id]/cbom/page.tsx", // "Cover options…" of the deliverables menu
  "app/[team_id]/dast/[scan_id]/results/page.tsx",
  "app/[team_id]/llm/[conversation_id]/results/page.tsx",
  "app/[team_id]/mcp/[conversation_id]/results/page.tsx",
  "components/AiBomResults.tsx",
  "components/CbomResults.tsx",
  "components/IACResults.tsx",
  "components/SASTResults.tsx",
  "components/SbomResults.tsx",
  "components/ai-bom-options-sidebar.tsx",
  "components/cbom-options-sidebar.tsx",
  "components/cbom/results/RunDeliverablesMenu.tsx",
  "components/dast-options-sidebar.tsx",
  "components/iac-options-sidebar.tsx",
  "components/llm-options-sidebar.tsx",
  "components/mcp-options-sidebar.tsx",
  "components/sast-options-sidebar.tsx",
  "components/sca-sbom-options-sidebar.tsx",
];
const HELPER: Record<string, string> = { removeMembers: "removeOrAddTeamMembers", inviteMembers: "removeOrAddTeamMembers" };

/** Every caller of the helpers above: [file, its useMutation, the call (CALL key), whether it opts out of the helper's
 * toasts]. Sidebars show a refused export in their own error view and leave the toasts to the helper. */
const SITES: [string, string, string, boolean][] = [
  ["app/[team_id]/settings/page.tsx", "updateTeamMutation", "updateTeam", false],
  ["app/[team_id]/settings/page.tsx", "membersMutation", "removeMembers", false],
  ["app/[team_id]/settings/page.tsx", "membersMutation", "inviteMembers", false],
  ["app/[team_id]/settings/page.tsx", "deleteTeamMutation", "deleteTeam", false],
  ["app/[team_id]/settings/page.tsx", "invitationMutation", "resendTeamInvitation", false],
  ["app/[team_id]/settings/page.tsx", "invitationMutation", "revokeTeamInvitation", false],
  ["app/home/layout.tsx", "createTeamMutation", "createTeam", false],
  ["app/home/create_team/page.tsx", "createTeamMutation", "createTeam", false],
  ["app/[team_id]/ci_cd/page.tsx", "createCicdIntegrationMutation", "createCicdIntegration", false],
  ["app/[team_id]/ci_cd/page.tsx", "deleteCicdIntegrationMutation", "deleteCicdIntegration", false],
  ["app/[team_id]/ci_cd/page.tsx", "renameCicdIntegrationMutation", "renameCicdIntegration", false],
  ["app/[team_id]/ci_cd/[integration_id]/page.tsx", "updateCicdMutation", "updateCicdIntegration", false],
];

async function main() {
  const api = (await import("./interceptors")).default;
  const backend: Api = await import("./backend_api");

  let refuse = false;
  api.defaults.adapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
    if (refuse) {
      throw new AxiosError("Request failed with status code 400", "ERR_BAD_REQUEST", config, null, {
        status: 400, statusText: "Bad Request", headers: {}, config, data: { detail: "Refused by the server" },
      });
    }
    return { status: 200, statusText: "OK", headers: {}, config, data: { team_id: 13, integration_id: 5, api_key: "k" } };
  };
  /** The toasts the helper itself shows for one call: [on success, on refusal]. */
  const helperToasts = async (call: string, opts: Opts): Promise<[number, number]> => {
    const out: number[] = [];
    for (const refused of [false, true]) {
      refuse = refused;
      toasts.length = 0;
      const error = await CALL[call](backend, opts).then(() => null, (e: unknown) => e);
      assert.equal(error === null, !refused, `${call}: ${refused ? "the refusal reaches the caller" : "succeeds"}`);
      out.push(toasts.filter((k) => k === (refused ? "error" : "success")).length);
    }
    return [out[0], out[1]];
  };

  const problems: string[] = [];
  for (const [file, mutation, call, optOut] of SITES) {
    const options = mutationOptions(read(file), mutation);
    if (!options) {
      problems.push(`${file}: no ${mutation}`);
      continue;
    }
    const helper = HELPER[call] ?? call;
    const fn = options.get("mutationFn") ?? "";
    if (!new RegExp(String.raw`\b${helper}\(`).test(fn)) problems.push(`${file} ${mutation}: does not call ${helper}`);
    if (fn.includes("{ toast: false }") !== optOut) {
      problems.push(`${file} ${mutation}: ${optOut ? "shows its own toasts but does not pass { toast: false }" : "passes { toast: false } but shows no toast of its own"}`);
    }
    const [helperSuccess, helperError] = await helperToasts(call, optOut ? { toast: false } : undefined);
    const success = helperSuccess + count(options.get("onSuccess"), SUCCESS);
    const error = helperError + count(options.get("onError"), ERROR);
    if (success !== 1) problems.push(`${file} ${mutation} (${call}): ${success} toasts on success (helper ${helperSuccess})`);
    if (error !== 1) problems.push(`${file} ${mutation} (${call}): ${error} toasts on a refusal (helper ${helperError})`);
  }
  assert.deepEqual(problems, [], `one action, one toast:\n  ${problems.join("\n  ")}`);

  // every caller of these helpers is a site above (a new caller is checked once it is listed)
  for (const helper of new Set(SITES.map(([, , call]) => HELPER[call] ?? call))) {
    const listed = [...new Set(SITES.filter(([, , call]) => (HELPER[call] ?? call) === helper).map(([file]) => file))].sort();
    assert.deepEqual(usersOf(root, helper), listed, `${helper}: a caller that is not listed in SITES`);
  }

  // PDF reports: the helpers never toast, on success or on a refusal ...
  for (const [name, call] of Object.entries(REPORT_CALL)) {
    for (const refused of [false, true]) {
      refuse = refused;
      toasts.length = 0;
      const error = await call(backend).then(() => null, (e: unknown) => e);
      assert.equal(error === null, !refused, `${name}: ${refused ? "the refusal reaches the caller" : "succeeds"}`);
      assert.deepEqual(toasts, [], `${name}: no toast of its own (${refused ? "refused" : "success"})`);
    }
    assert.deepEqual(usersOf(root, name), REPORT_USERS[name], `${name}: a caller other than the export dialog`);
  }
  // ... the dialog's hook says an export's outcome once: one success toast, and one error toast for a build that ends
  // after its dialog was closed (an open dialog shows the error inline; components/reports/exportPdfDialog.dom.test.ts)
  const dialog = read("components/reports/ExportPdfDialog.tsx");
  const hook = dialog.slice(dialog.indexOf("export function useExportPdf("), dialog.indexOf("// ---", dialog.indexOf("export function useExportPdf(")));
  assert.equal(count(hook, SUCCESS), 1, "useExportPdf: one success toast");
  assert.equal(count(hook, ERROR), 1, "useExportPdf: one error toast (dialog closed)");
  assert.equal(count(dialog, SUCCESS) + count(dialog, ERROR), 2, "no other toast in the dialog");
  // ... the deliverables menu's one-click items say theirs once (they keep their mutation)
  const menu = mutationOptions(read("app/[team_id]/cbom/page.tsx"), "downloadDeliverableMutation");
  assert.ok(menu && /\bdownloadCbomDeliverable\(/.test(menu.get("mutationFn") ?? ""), "the deliverables menu downloads through downloadCbomDeliverable");
  assert.equal(count(menu?.get("onSuccess"), SUCCESS), 1, "a deliverable: one success toast");
  assert.equal(count(menu?.get("onError"), ERROR), 1, "a deliverable: one error toast");
  // ... and every opener only opens the dialog: no export mutation, no download helper, no export toast of its own
  assert.deepEqual(usersOf(root, "useExportPdf").filter((f) => f !== "components/reports/ExportPdfDialog.tsx"), OPENERS, "useExportPdf: an opener that is not listed in OPENERS");
  for (const file of OPENERS) {
    const src = read(file);
    assert.ok(!mutationOptions(src, "exportMutation"), `${file}: still has its own export mutation`);
    assert.ok(!/\b(?:getExportResults|get[A-Z]+ExportResults|downloadScanReport|downloadRunReport)\b/.test(src), `${file}: builds a report itself`);
    assert.ok(!/toast\.(?:success|error)\([^)]*report downloaded/i.test(src), `${file}: says a report download itself`);
  }

  // the rule's home: the root layout's numbers and the helpers' option
  const policy = read("utils/toastPolicy.ts");
  assert.match(policy, /export interface HelperToastOptions \{/);
  assert.ok(!policy.includes('from "sonner"'), "the root layout (a server component) imports this file");

  console.log("one action, one toast: tests passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
