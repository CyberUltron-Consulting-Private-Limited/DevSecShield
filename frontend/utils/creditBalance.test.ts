/**
 * #13 (R2 regression): the credit balance in the app sidebar (the team switcher, GET /teams, query ["teams"]) stayed
 * stale after starting a SAST, AI BOM or IaC scan, until a reload; only CBOM refreshed it. Starting a scan charges
 * credits and cancelling one refunds them, so every start and cancel of the eight products now calls
 * refreshCreditBalance (utils/creditBalance.ts) when it settles.
 * PR #67 review: a re-run (/reinitialize) refreshes too, so the balance follows the server whether or not the re-run
 * charges (it does once PR #57 merges); the guard's import detector is shared (utils/backendApiImports.ts) and follows
 * dynamic imports; the watcher merges what it has seen and sends no second GET /teams while one is on its way.
 * Browser check: note the balance, start a SAST scan: it drops without a reload; cancel the scan: it comes back.
 * Run: npx --yes tsx utils/creditBalance.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { MutationObserver, QueryClient, QueryObserver } from "@tanstack/react-query";

import { backendApiImportRanges, backendApiImports } from "./backendApiImports";
import { CREDIT_BALANCE_QUERY_KEY, isCreditBalanceQuery, refreshCreditBalance } from "./creditBalance";

const settle = () => new Promise((r) => setTimeout(r, 20));
type Teams = { team_id: number; team_credit_balance: number }[];

async function main() {
  // 1. the sidebar's balance is refetched once, and the scan's own queries are left alone
  const client = new QueryClient();
  let balance = 10;
  let fetches = 0;
  const sidebar = new QueryObserver<Teams>(client, {
    queryKey: [...CREDIT_BALANCE_QUERY_KEY],
    queryFn: async () => {
      fetches += 1;
      return [{ team_id: 13, team_credit_balance: balance }];
    },
  });
  const shown: number[] = [];
  const stop = sidebar.subscribe((r) => {
    if (r.data) shown.push(r.data[0].team_credit_balance);
  });
  await settle();
  assert.deepEqual(shown, [10]);
  const scanKey = ["sast-conversation-data", 13, 7];
  client.setQueryData(scanKey, { scan_status: "pending" });

  fetches = 0;
  balance = 7; // the start charged 3 credits
  await refreshCreditBalance(client);
  assert.equal(fetches, 1, "one GET /teams");
  assert.equal(shown.at(-1), 7, "the sidebar shows the charged balance without a reload");
  assert.equal(client.getQueryState(scanKey)?.isInvalidated, false, "only the balance is refetched");

  // 2. a cancel also refreshes every other query of the page; the balance is still fetched once, not twice
  fetches = 0;
  balance = 10; // refunded
  void refreshCreditBalance(client);
  void client.invalidateQueries({ predicate: (query) => !isCreditBalanceQuery(query) });
  await settle();
  assert.equal(fetches, 1, "one GET /teams after a cancel");
  assert.equal(shown.at(-1), 10);
  assert.equal(client.getQueryState(scanKey)?.isInvalidated, true, "the scan's status is read again");
  assert.equal(isCreditBalanceQuery({ queryKey: ["teams"] }), true);
  assert.equal(isCreditBalanceQuery({ queryKey: ["team-details", "13"] }), false);
  assert.equal(isCreditBalanceQuery({ queryKey: ["user-profile"] }), false);
  stop();

  // 3. it is the query the sidebar reads
  const layout = read("app/[team_id]/layout.tsx");
  const switcher = layout.slice(layout.indexOf("function TeamSwitcher()"), layout.indexOf("const homeItem"));
  assert.ok(switcher.includes('queryKey: ["teams"],') && switcher.includes("team_credit_balance"),
    "the team switcher shows the balance from the [\"teams\"] query");
  assert.deepEqual([...CREDIT_BALANCE_QUERY_KEY], ["teams"]);

  // 4. wiring: every API helper whose endpoint charges or refunds credits, found by import (not by call text), and every
  // use of one refreshes the balance when it settles, through the helper (code/QA review of PR #30).
  const movers: Record<string, string> = {
    startScan: "POST .../scan/{id}/start charges (backend routers/scans.py), refunds when dispatch fails",
    startSastScan: "the same start endpoint (no caller today)",
    startLLMScan: "the same start endpoint (no caller today)",
    startMCPScan: "the same start endpoint (no caller today)",
    startDASTScan: "DAST dispatch charges, refunds a failed dispatch (utilities/dast/dispatch.py)",
    runDASTProfile: "a saved DAST profile run goes through the same dispatch",
    cancelScan: "a cancel refunds the charge (utilities/scan/cancel_scan.py)",
    sendMessageToScan: "0.006 credits per scan chat message (deduct_credits_from_team_for_message)",
    generateFindingRemediation: "a completed AI remediation is charged (routers/scans.py)",
    startCbomRun: "a CBOM sources run charges per target (routers/cbom_sources.py POST /runs)",
    cancelCbomRun: "cancelling a run refunds its open jobs",
    deleteCbomSource: "deleting a source cancels and refunds its pending collect jobs (cancel_open_jobs)",
    updateCbomSource: "changing a source's connection cancels and refunds its pending collect jobs",
    deleteCbomScanNode: "deleting a scan node refunds its open collect jobs",
    createGuardrailsIntegration: "0.5 credits (routers/guardrails.py); only the unrouted components/deprecated pages use it",
    // re-running a scan: POST /{team_id}/{type}/scan/{id}/reinitialize (routers/scans.py). Whether it moves credits
    // (nothing before PR #57, the price difference after it) does not matter here: the balance follows what the server
    // answers (part 6)
    reinitializeSastScan: "re-run a scan: the reinitialize endpoint",
    reinitializeLLMScan: "the same reinitialize endpoint",
    reinitializeMCPScan: "the same reinitialize endpoint",
    reinitializeIACScanWithPayload: "the same reinitialize endpoint",
    reinitializeSBOMScanWithPayload: "the same reinitialize endpoint",
    reinitializeCBOMScanWithPayload: "the same reinitialize endpoint",
    reinitializeAIBOMScanWithPayload: "the same reinitialize endpoint",
    reinitializeDASTScan: "the same reinitialize endpoint",
  };
  const apiSrc = read("utils/backend_api.ts");
  for (const name of Object.keys(movers)) {
    assert.match(apiSrc, new RegExp(String.raw`\bconst ${name} = async\b`), `utils/backend_api.ts has no ${name}`);
  }
  // every reinitialize helper is a mover, or calls a route the backend does not have (no credit can move there)
  const noRoute: Record<string, string> = {
    reinitializeIACScan: "/iac/conversation/{id}/reinitialize (the IaC sidebar uses reinitializeIACScanWithPayload)",
    reinitializeSCASBOMScan: "/sbom_sca/conversation/{id}/reinitialize (the SCA + SBOM sidebar uses ...WithPayload)",
    reinitializeDiscoveryScan: "/agent_discovery/conversation/{id}/reinitialize (agent discovery has no page)",
    reinitializeLeakageScan: "/leakage/conversation/{id}/reinitialize (data leakage shows ProductUnavailableNotice)",
  };
  assert.deepEqual([...apiSrc.matchAll(/\bconst (reinitialize\w+) = async\b/g)].map((m) => m[1]).sort(),
    [...Object.keys(movers).filter((n) => n.startsWith("reinitialize")), ...Object.keys(noRoute)].sort(),
    "a new reinitialize helper refreshes the balance (a mover) or is listed in noRoute");
  const routers = path.join(root, "..", "backend", "routers");
  const routes = fs.readdirSync(routers).filter((f) => f.endsWith(".py")).map((f) => fs.readFileSync(path.join(routers, f), "utf8"));
  assert.ok(routes.some((src) => src.includes('"/{team_id}/{type}/scan/{scan_id}/reinitialize"')), "the reinitialize route");
  assert.ok(!routes.some((src) => /conversation\/\{[^}]*\}\/reinitialize/.test(src)), "a noRoute helper's route exists now");
  // per file: how many useMutation blocks move credits, and the uses that are not a mutation (pinned below)
  const expected: Record<string, number> = {
    "components/RemediationPanel.tsx": 1, // AI remediation (the CBOM knowledge-base one is free: not counted)
    "components/ai-bom-options-sidebar.tsx": 2, // start, re-run
    "components/ai/ChatWindow.tsx": 0, // a chat message is a direct await: refreshed in its finally (below)
    "components/cbom-options-sidebar.tsx": 3, // the code scan, its linked sources run, re-run
    "components/cbom/sources/AppliancesSection.tsx": 1, // delete
    "components/cbom/sources/ClustersDatabasesTab.tsx": 4, // delete; save a cluster, a database, a key manager
    "components/cbom/sources/CloudIdentityTab.tsx": 6, // delete; save cloud, CA, IdP, two credential forms
    "components/cbom/sources/ContainerImagesSection.tsx": 1, // delete
    "components/cbom/sources/NetworkTab.tsx": 1, // delete a range
    "components/cbom/sources/ReviewRunTab.tsx": 2, // start and cancel a sources run
    "components/cbom/sources/RunPosture.tsx": 2, // business criticality, exposure (metadata: never refunds, refreshes too)
    "components/cbom/sources/ScanNodesTab.tsx": 1, // delete a node
    "components/cbom/sources/ServersTab.tsx": 3, // turn on/off, delete, save
    "components/cbom/sources/SourceMetadata.tsx": 2, // ownership and data, one source or many (metadata, as above)
    "components/dast-options-sidebar.tsx": 2, // start and re-run, through handleStartScan / handleReinitializeScan (below)
    "components/dast/DastProfilesTab.tsx": 1, // run a saved DAST profile
    "components/iac-options-sidebar.tsx": 2, // start, re-run
    "components/llm-options-sidebar.tsx": 2,
    "components/mcp-options-sidebar.tsx": 2,
    "components/sast-options-sidebar.tsx": 2, // start; re-run through handleReinitializeScan (below)
    "components/sca-sbom-options-sidebar.tsx": 2,
    "components/scan-cancel.tsx": 1, // cancel a SAST, IaC, SCA + SBOM, CBOM or AI BOM scan
  };
  // a local function that calls a mover, run by a mutation: the call must be in the function, and every mutation that
  // runs it refreshes the balance when it settles
  const wrappers: Record<string, Record<string, string>> = {
    [path.join("components", "dast-options-sidebar.tsx")]: {
      handleStartScan: "startDASTScan", // builds the DAST request
      handleReinitializeScan: "reinitializeDASTScan",
    },
    [path.join("components", "sast-options-sidebar.tsx")]: { handleReinitializeScan: "reinitializeSastScan" },
  };
  // a mover used outside a useMutation block and outside a wrapper, each with the reason it still refreshes
  const outside: Record<string, (code: string) => void> = {
    "components/ai/ChatWindow.tsx": (code) => {
      const call = code.indexOf("await sendMessageToScan(");
      const rest = code.slice(call);
      const fin = rest.search(/\}\s*finally\s*\{/);
      assert.ok(fin > 0 && rest.slice(fin, rest.indexOf("}", fin + 1) + 1).includes("refreshCreditBalance(queryClient)") &&
        !rest.slice(0, fin).includes("try {"), "a chat message refreshes the balance in the finally of its own try");
    },
  };
  const found: Record<string, number> = {};
  for (const rel of sourceFiles()) {
    if (rel.startsWith(path.join("components", "deprecated"))) continue; // unrouted: app/[team_id]/guardrails shows a notice
    const code = stripComments(read(rel));
    const used = backendApiImports(code, rel).filter((name) => name in movers);
    if (!used.length) continue;
    const pattern = new RegExp(String.raw`\b(?:${used.join("|")})\b`, "g");
    // a local function that calls a mover counts as one where a mutation runs it (pinned in `wrappers`)
    const own = wrappers[rel] ?? {};
    const uses = new RegExp(String.raw`\b(?:${[...used, ...Object.keys(own)].join("|")})\b`);
    const blocks = mutations(code);
    found[rel] = 0;
    // CBOM's remediation comes from the offline knowledge base: the backend answers it before any charge
    const free = (text: string) => rel === path.join("components", "RemediationPanel.tsx") && /\btype: "cbom"/.test(text);
    for (const block of blocks.filter((b) => uses.test(b.text) && !free(b.text))) {
      found[rel] += 1;
      assert.ok(refreshesOnSettled(block.text),
        `${rel}: a mutation that moves credits does not refresh the balance in its onSettled:\n${block.text}`);
    }
    // every other use (outside the import line) is one of the pinned exceptions
    const imports = backendApiImportRanges(code, rel);
    const wrapped = Object.entries(own).map(([fn, mover]) => {
      const start = code.indexOf(`const ${fn} = `);
      const end = code.indexOf("\n  };", start);
      const call = code.indexOf(`${mover}(`, start);
      assert.ok(start >= 0 && call > start && call < end, `${rel}: ${mover} is called in ${fn}`);
      const runs = blocks.filter((b) => new RegExp(String.raw`mutationFn: ${fn}\b`).test(b.text));
      assert.ok(runs.length > 0 && runs.every((b) => refreshesOnSettled(b.text)),
        `${rel}: the mutation that runs ${fn} refreshes the balance when it settles`);
      return [start, end] as const;
    });
    const stray = [...code.matchAll(pattern)].filter((m) =>
      !imports.some(([a, b]) => m.index! >= a && m.index! < b) && !blocks.some((b) => m.index! >= b.start && m.index! < b.end) &&
      !wrapped.some(([a, b]) => m.index! >= a && m.index! < b));
    if (stray.length) {
      assert.ok(outside[rel], `${rel}: ${stray.map((m) => m[0]).join(", ")} used outside a useMutation block`);
      outside[rel](code);
    }
    assert.ok(!/invalidateQueries\(\{ queryKey: \["teams"\] \}\)/.test(code), `${rel}: refresh the balance through refreshCreditBalance`);
    assert.ok(!/invalidateQueries\(\)/.test(code), `${rel}: invalidating everything also refetches the balance a second time`);
  }
  assert.deepEqual(found, expected, "every file that imports a credit-moving API helper, and its mutations");
  // the detector finds a mover however the module is imported, also the two dynamic forms the PR #67 review found it
  // missed (one detector for both guards: utils/backendApiImports.test.ts has every form)
  assert.deepEqual(backendApiImports('const { startScan } = await import("@/utils/backend_api"); return startScan(1);'),
    ["startScan"]);
  assert.deepEqual(backendApiImports('import("@/utils/backend_api").then((m) => m.cancelScan(1, 2));'), ["cancelScan"]);

  // 5. credits the server moves without a user action (#28): a failed scan is refunded by the status poll that sees it
  // fail (backend utilities/celery/celery_connection.py), and a CBOM sources run is refunded job by job as its jobs
  // fail, expire or are cancelled (utilities/cbom_sources/jobs.py refund_job). The app's query client watches every
  // response: a scan seen failing, or a run whose refunded total changed, refreshes the balance once.
  const { makeQueryClient } = await import("./query_client");
  const app = makeQueryClient();
  let teamsFetches = 0;
  let gate: Promise<void> | null = null; // while set, GET /teams has not answered yet
  const balanceView = new QueryObserver<Teams>(app, {
    queryKey: [...CREDIT_BALANCE_QUERY_KEY],
    queryFn: async () => {
      teamsFetches += 1;
      if (gate) await gate;
      return [{ team_id: 13, team_credit_balance: 10 }];
    },
  });
  const stopBalance = balanceView.subscribe(() => undefined);
  await settle();
  const poll = async (queryKey: unknown[], data: unknown) => {
    teamsFetches = 0;
    await app.fetchQuery({ queryKey, queryFn: async () => data, staleTime: 0 });
    await settle();
    return teamsFetches;
  };
  const mcp = ["mcp-conversation-data", 13, 105];
  assert.equal(await poll(mcp, { scan_status: "pending" }), 0, "a pending scan moves nothing");
  assert.equal(await poll(mcp, { scan_status: "started", info: { current: 10 } }), 0);
  assert.equal(await poll(mcp, { scan_status: "failure", info: { error: "boom" } }), 1, "the poll that sees it fail: refunded");
  assert.equal(await poll(mcp, { scan_status: "failure", info: { error: "boom" } }), 0, "once, not on every poll");
  assert.equal(await poll(["llm-conversation-data", 13, 108], { scan_status: "failure" }), 1,
    "first seen already failed (a lazy status poll refunds it in the same request)");
  const sast = ["sast-conversation-data", 13, 97];
  assert.equal(await poll(sast, { scan_status: "started" }), 0);
  assert.equal(await poll(sast, { scan_status: "success", scan_data: { results: [{ scan_status: "x" }] } }), 0,
    "a successful scan moves no credit");
  // a scan list (the status poll behind it refunds in a background task: the next list shows the failure)
  const list = ["dast-conversations", 13];
  assert.equal(await poll(list, [{ id: 104, scan_status: "started" }, { id: 98, scan_status: "success" }]), 0);
  assert.equal(await poll(list, [{ id: 104, scan_status: "failure" }, { id: 98, scan_status: "success" }]), 1);
  assert.equal(await poll(list, [{ id: 104, scan_status: "failure" }, { id: 98, scan_status: "success" }]), 0);
  assert.equal(await poll(list, { scans: [{ id: 104, scan_status: "failure" }, { id: 111, scan_status: "failure" }] }), 1,
    "another scan failed");
  // a CBOM sources run, alone or in a list
  const runs = ["cbom-sources", 13, "runs", "all"];
  const run = (refunded: number, status = "running") =>
    ({ id: 10, status, credits: { charged: 0.6, refunded, net: round2(0.6 - refunded) } });
  assert.equal(await poll(runs, { runs: [run(0)], server_time: "2026-11-12T00:00:00Z" }), 0);
  assert.equal(await poll(runs, { runs: [run(0.2)], server_time: "2026-11-12T00:00:06Z" }), 1, "a job failed: refunded");
  assert.equal(await poll(runs, { runs: [run(0.2)], server_time: "2026-11-12T00:00:12Z" }), 0);
  assert.equal(await poll(runs, { runs: [run(0.6, "partial")] }), 1);
  assert.equal(await poll(["cbom-sources", 13, "run", 10], { run: run(0.6, "partial") }), 1, "first seen with a refund");
  assert.equal(await poll(["cbom-sources", 13, "run", 11], { run: { ...run(0, "done"), id: 11 } }), 0);
  // the balance itself and other data move nothing
  assert.equal(await poll(["team-dashboard", 13], { scans: 3, failed: 1, status: "failure" }), 0);
  teamsFetches = 0;
  await app.refetchQueries({ queryKey: [...CREDIT_BALANCE_QUERY_KEY] });
  await settle();
  assert.equal(teamsFetches, 1, "refreshing the balance does not trigger itself");
  // a record that leaves a response and comes back is not new: a paged or filtered list moving between windows sends no
  // GET /teams for refunds it has already seen (PR #67 review: 20 in 20 polls of two alternating windows)
  const paged = ["sast-conversations", 13, "page"];
  const windowA = [1, 2, 3].map((id) => ({ id, scan_status: "failure" }));
  const windowB = [4, 5, 6].map((id) => ({ id, scan_status: "failure" }));
  assert.equal(await poll(paged, windowA), 1);
  assert.equal(await poll(paged, windowB), 1, "other scans failed");
  let alternating = 0;
  for (let i = 0; i < 20; i++) alternating += await poll(paged, i % 2 ? windowB : windowA);
  assert.equal(alternating, 0, "refunds seen before, seen again: no GET /teams");
  // ... a record that changes still counts: a re-run scan that fails again was refunded again
  assert.equal(await poll(paged, [{ id: 1, scan_status: "pending" }, ...windowB]), 0);
  assert.equal(await poll(paged, [{ id: 1, scan_status: "failure" }]), 1, "re-run, failed again: refunded again");
  // one GET /teams per change: a mutation's onSettled refreshes the balance and refetches the page, whose response then
  // shows the refund the mutation made (one CBOM "Cancel run" sent GET /teams twice: browser QA of PR #67). While the
  // balance is being fetched the watcher sends nothing, and still records what it saw.
  const cancelled = ["cbom-sources", 13, "runs", "cancel"];
  assert.equal(await poll(cancelled, { runs: [{ ...run(0), id: 20 }] }), 0);
  let release!: () => void;
  gate = new Promise<void>((resolve) => (release = resolve));
  teamsFetches = 0;
  const onSettled = refreshCreditBalance(app); // the Cancel run mutation settled: GET /teams is on its way
  await app.fetchQuery({
    queryKey: cancelled, queryFn: async () => ({ runs: [{ ...run(0.6, "cancelled"), id: 20 }] }), staleTime: 0,
  });
  await settle();
  assert.equal(teamsFetches, 1, "the refund in the refetched runs list waits for the GET /teams already sent");
  release();
  gate = null;
  await onSettled;
  await settle();
  assert.equal(teamsFetches, 1, "one GET /teams for one Cancel run");
  assert.equal(await poll(cancelled, { runs: [{ ...run(0.6, "cancelled"), id: 20 }] }), 0, "recorded while it waited");
  assert.equal(await poll(cancelled, { runs: [{ ...run(0.6, "cancelled"), id: 20 }, { ...run(0.4), id: 21 }] }), 1,
    "the next refund refreshes again");
  stopBalance();
  // the scan pages use this client: the team layout makes it
  assert.match(read("app/[team_id]/layout.tsx"), /makeQueryClient\(\)/);
  // CBOM's own refresh when a scan finished is replaced by the watcher (it would send GET /teams twice)
  assert.ok(!/scan_status === "failure"\) \{\s*refreshCreditBalance/.test(read("components/cbom-options-sidebar.tsx")),
    "cbom-options-sidebar.tsx: the query client already refreshes the balance when a scan fails");

  // 6. re-running a scan (/reinitialize) charges nothing before PR #57 and the price difference after it; a refused re-run
  // moves nothing, and one given back refunds the difference. Whatever the server did, the sidebar shows its answer: each
  // re-run mutation refreshes the balance when it settles (part 4 checks every one), as this one does.
  const rerun = makeQueryClient();
  let server = 10;
  const header: number[] = [];
  const teamsView = new QueryObserver<Teams>(rerun, {
    queryKey: [...CREDIT_BALANCE_QUERY_KEY],
    queryFn: async () => [{ team_id: 13, team_credit_balance: server }],
  });
  const stopHeader = teamsView.subscribe((r) => {
    if (r.data) header.push(r.data[0].team_credit_balance);
  });
  await settle();
  for (const [what, after, refused] of [
    ["charges nothing (before PR #57)", 10, false],
    ["charges the price difference (PR #57)", 7.5, false],
    ["is refused for too few credits (402, nothing charged)", 7.5, true],
    ["is sent, then given back (409, the difference refunded)", 10, true],
  ] as const) {
    const reinitialize = new MutationObserver(rerun, {
      mutationFn: async () => {
        server = after;
        if (refused) throw new Error(what);
        return { message: "Scan reinitialized" };
      },
      onSettled: () => {
        refreshCreditBalance(rerun);
      },
    });
    await reinitialize.mutate().catch(() => undefined);
    await settle();
    assert.equal(header.at(-1), after, `a re-run that ${what}: the sidebar shows the server's balance`);
  }
  stopHeader();

  console.log("credit balance refresh: tests passed");
}

const root = path.join(__dirname, "..");
const read = (rel: string) => fs.readFileSync(path.join(root, rel), "utf8");
const round2 = (n: number) => Math.round(n * 100) / 100;

/** onSettled of a useMutation options literal calls refreshCreditBalance(queryClient). */
function refreshesOnSettled(block: string): boolean {
  const at = block.search(/\bonSettled\b/);
  if (at < 0) return false;
  let depth = 0;
  let end = at;
  for (; end < block.length; end++) {
    const c = block[end];
    if ("([{".includes(c)) depth += 1;
    else if (")]}".includes(c)) {
      if (depth === 0) break;
      depth -= 1;
    } else if (c === "," && depth === 0) break;
  }
  return block.slice(at, end).includes("refreshCreditBalance(queryClient)");
}

/** The source with its comments removed (strings and template literals kept), so commented-out code does not count. */
function stripComments(src: string): string {
  let out = "";
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      out += src.slice(i, end < 0 ? src.length : end + 2).replace(/[^\n]/g, " ");
      i = end < 0 ? src.length : end + 1;
    } else if (c === '"' || c === "'" || c === "`") {
      let j = i + 1;
      while (j < src.length && src[j] !== c && !(c !== "`" && src[j] === "\n")) j += src[j] === "\\" ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j;
    } else out += c;
  }
  return out;
}

/** Every source file of the app (tests and the API module itself excluded), relative to frontend/. */
function sourceFiles(): string[] {
  const walk = (dir: string): string[] => fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(dir, e.name))
      : /\.(tsx?|jsx?|mjs)$/.test(e.name) && !/\.test\.[a-z]+$/.test(e.name) ? [path.join(dir, e.name)] : []);
  return ["app", "components", "hooks", "lib", "utils"].flatMap((d) => walk(path.join(root, d)))
    .map((f) => path.relative(root, f)).filter((rel) => rel !== path.join("utils", "backend_api.ts")).sort();
}

/** The options literal of every useMutation({ ... }) in a source file, with where it is. */
function mutations(src: string): { text: string; start: number; end: number }[] {
  const blocks: { text: string; start: number; end: number }[] = [];
  for (let i = src.indexOf("useMutation({"); i >= 0; i = src.indexOf("useMutation({", i + 1)) {
    const open = i + "useMutation(".length;
    let depth = 0;
    for (let j = open; j < src.length; j++) {
      if (src[j] === "{") depth += 1;
      else if (src[j] === "}" && --depth === 0) {
        blocks.push({ text: src.slice(open, j + 1), start: open, end: j + 1 });
        break;
      }
    }
  }
  return blocks;
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
