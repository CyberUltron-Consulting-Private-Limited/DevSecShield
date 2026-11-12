/**
 * #12 (R2 regression): one refused save on Team settings showed two identical error toasts. updateTeam
 * (utils/backend_api.ts) toasted and rethrew, and the settings page's onError toasted again; removing a member,
 * inviting one and deleting the team did the same. The three API helpers now only throw, and the page's onError
 * shows the one toast, with the helper's old fallback text.
 * Browser check: Team settings > Integrations > change the Jira URL without re-entering the token > Save: one toast.
 * Run: npx --yes tsx utils/teamSettingsToasts.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { AxiosError, type InternalAxiosRequestConfig } from "axios";
import { toast as sonner } from "sonner";

import { backendApiImports } from "./backendApiImports";

// every toast the app shows goes through sonner (utils/toast.ts); count them
const toasts: [string, unknown][] = [];
for (const kind of ["success", "error", "warning", "info", "message"] as const) {
  (sonner as unknown as Record<string, unknown>)[kind] = (m: unknown) => {
    toasts.push([kind, m]);
    return 1;
  };
}
const errorToasts = () => toasts.filter(([kind]) => kind === "error");

// what the error handler touches in a browser
(globalThis as Record<string, unknown>).window = { location: { href: "/13/settings" } };
(globalThis as Record<string, unknown>).localStorage = {
  getItem: () => "token", setItem: () => undefined, removeItem: () => undefined, clear: () => undefined,
};

const root = path.join(__dirname, "..");
const DETAIL = "Re-enter the Jira API token to change the Jira URL";

async function main() {
  const api = (await import("./interceptors")).default;
  const { updateTeam, removeOrAddTeamMembers, deleteTeam } = await import("./backend_api");
  const { showErrorToast } = await import("./error-handler");

  // the server refuses every team write: 400 for PUT, 403 for PATCH, 409 for DELETE
  const sent: string[] = [];
  api.defaults.adapter = async (config: InternalAxiosRequestConfig) => {
    const method = (config.method ?? "get").toUpperCase();
    sent.push(`${method} ${config.url}`);
    const status = method === "PUT" ? 400 : method === "PATCH" ? 403 : 409;
    throw new AxiosError(`Request failed with status code ${status}`, "ERR_BAD_REQUEST", config, null, {
      status, statusText: "Refused", headers: {}, config, data: { detail: DETAIL },
    });
  };

  // 1. the helpers report a refusal by throwing it, and show nothing themselves
  const failures: [string, () => Promise<unknown>, string][] = [
    ["update", () => updateTeam(13, { name: "Team", integration_settings: { jira: null } }), "PUT /team/13"],
    ["remove", () => removeOrAddTeamMembers(13, { intent: "remove", email_ids: ["a@acme.test"] }), "PATCH /team/13"],
    ["add", () => removeOrAddTeamMembers(13, { intent: "add", email_ids: ["b@acme.test"] }), "PATCH /team/13"],
    ["delete", () => deleteTeam(13), "DELETE /team/13"],
  ];
  for (const [name, call, request] of failures) {
    toasts.length = 0;
    sent.length = 0;
    const error = await call().then(() => null, (e: unknown) => e);
    assert.ok(error instanceof AxiosError, `${name}: the refusal reaches the caller`);
    assert.deepEqual(sent, [request], `${name}: one request`);
    assert.equal(errorToasts().length, 0, `${name}: the API helper toasted (${JSON.stringify(toasts)})`);
    assert.equal(toasts.length, 0, `${name}: no success toast for a refusal`);
    // ... and the page's onError (below) shows exactly one, with the server's reason
    showErrorToast(error, "fallback");
    assert.deepEqual(errorToasts(), [["error", DETAIL]], `${name}: one toast with the server's reason`);
  }

  // 2. the settings page shows the one toast for each of the three actions, keeping the old context text
  const page = fs.readFileSync(path.join(root, "app", "[team_id]", "settings", "page.tsx"), "utf8");
  const mutation = (name: string) => {
    const start = page.indexOf(`const ${name} = useMutation({`);
    assert.ok(start >= 0, `${name} not found`);
    return page.slice(start, page.indexOf("\n  });", start));
  };
  const onError = (block: string) => block.slice(block.indexOf("onError"), block.indexOf("\n", block.indexOf("onError")));
  const expected: Record<string, string[]> = {
    updateTeamMutation: ["updateTeam(", '"Error updating team"'],
    membersMutation: ["removeOrAddTeamMembers(", '"Error sending the invitation"', '"Error removing members"'],
    deleteTeamMutation: ["deleteTeam(", '"Error deleting team"'],
  };
  for (const [name, [call, ...fallbacks]] of Object.entries(expected)) {
    const block = mutation(name);
    assert.ok(block.includes(call), `${name} calls ${call}`);
    const handler = onError(block);
    assert.equal(handler.match(/showErrorToast\(/g)?.length, 1, `${name}: onError shows one toast: ${handler}`);
    for (const text of fallbacks) assert.ok(handler.includes(text), `${name}: onError keeps ${text}`);
    assert.ok(!block.includes("toast.error("), `${name}: a second error toast`);
  }

  // 3. every other user of these helpers must show the error itself (today the settings page is the only one). Found
  // by import, not by call text: a helper passed by reference (mutationFn: deleteTeam) or used from hooks/, lib/ or
  // utils/ counts too (code/QA review of PR #30).
  const helpers = ["updateTeam", "removeOrAddTeamMembers", "deleteTeam"];
  const users = sourceFiles().filter((rel) => backendApiImports(read(rel), rel).some((name) => helpers.includes(name)));
  assert.deepEqual(users, [path.join("app", "[team_id]", "settings", "page.tsx")],
    "a new user of updateTeam / removeOrAddTeamMembers / deleteTeam must show the error in its onError, then be listed here");
  // the detector itself: named, renamed, multi-line, type-mixed and namespace imports, and nothing else
  assert.deepEqual(backendApiImports('import { a, deleteTeam as remove,\n  type T } from "@/utils/backend_api";'), ["a", "deleteTeam"]);
  assert.deepEqual(backendApiImports("import { updateTeam } from '../utils/backend_api'"), ["updateTeam"]);
  assert.deepEqual(backendApiImports('import * as api from "@/utils/backend_api"; api.removeOrAddTeamMembers(1, x)'),
    ["removeOrAddTeamMembers"]);
  assert.deepEqual(backendApiImports('const m = await import("@/utils/backend_api"); m.deleteTeam(1)'), ["deleteTeam"]);
  assert.deepEqual(backendApiImports('import { deleteTeam } from "@/utils/other"; // deleteTeam(1)'), []);
  // ... and the two dynamic forms the PR #67 review found it missed (utils/backendApiImports.test.ts has every form)
  assert.deepEqual(backendApiImports('const { deleteTeam } = await import("@/utils/backend_api"); return deleteTeam(id);'),
    ["deleteTeam"]);
  assert.deepEqual(backendApiImports('import("@/utils/backend_api").then((m) => m.updateTeam(id, x))'), ["updateTeam"]);

  // 4. the helpers still say what succeeded (one success toast, from the API layer)
  const apiSrc = fs.readFileSync(path.join(root, "utils", "backend_api.ts"), "utf8");
  for (const fn of ["updateTeam", "removeOrAddTeamMembers", "deleteTeam"]) {
    const start = apiSrc.indexOf(`const ${fn} = async`);
    const body = apiSrc.slice(start, apiSrc.indexOf("\n}\n", start));
    assert.ok(body.includes("toast.success("), `${fn}: success toast`);
    assert.ok(!body.includes("showErrorToast("), `${fn}: error toast in the API helper`);
  }

  console.log("team settings: one toast per refused action: tests passed");
}

const read = (rel: string) => fs.readFileSync(path.join(root, rel), "utf8");

/** Every source file of the app (tests and the API module itself excluded), relative to frontend/. */
function sourceFiles(): string[] {
  const walk = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(dir, e.name))
      : /\.(tsx?|jsx?|mjs)$/.test(e.name) && !/\.test\.[a-z]+$/.test(e.name) ? [path.join(dir, e.name)] : []);
  return ["app", "components", "hooks", "lib", "utils"].flatMap((d) => walk(path.join(root, d)))
    .map((f) => path.relative(root, f)).filter((rel) => rel !== path.join("utils", "backend_api.ts")).sort();
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
