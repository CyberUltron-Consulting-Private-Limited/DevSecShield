/**
 * #13 (R2 regression): the credit balance in the app sidebar (the team switcher, GET /teams, query ["teams"]) stayed
 * stale after starting a SAST, AI BOM or IaC scan, until a reload; only CBOM refreshed it. Starting a scan charges
 * credits and cancelling one refunds them, so every start and cancel of the eight products now calls
 * refreshCreditBalance (utils/creditBalance.ts) when it settles.
 * Browser check: note the balance, start a SAST scan: it drops without a reload; cancel the scan: it comes back.
 * Run: npx --yes tsx utils/creditBalance.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { QueryClient, QueryObserver } from "@tanstack/react-query";

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
  };
  // (re-running a scan, /reinitialize, charges nothing today: #33)
  const apiSrc = read("utils/backend_api.ts");
  for (const name of Object.keys(movers)) {
    assert.match(apiSrc, new RegExp(String.raw`\bconst ${name} = async\b`), `utils/backend_api.ts has no ${name}`);
  }
  // per file: how many useMutation blocks move credits, and the uses that are not a mutation (pinned below)
  const expected: Record<string, number> = {
    "components/RemediationPanel.tsx": 1, // AI remediation (the CBOM knowledge-base one is free: not counted)
    "components/ai-bom-options-sidebar.tsx": 1,
    "components/ai/ChatWindow.tsx": 0, // a chat message is a direct await: refreshed in its finally (below)
    "components/cbom-options-sidebar.tsx": 2, // the code scan and its linked sources run
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
    "components/dast-options-sidebar.tsx": 1, // through handleStartScan (below)
    "components/dast/DastProfilesTab.tsx": 1, // run a saved DAST profile
    "components/iac-options-sidebar.tsx": 1,
    "components/llm-options-sidebar.tsx": 1,
    "components/mcp-options-sidebar.tsx": 1,
    "components/sast-options-sidebar.tsx": 1,
    "components/sca-sbom-options-sidebar.tsx": 1,
    "components/scan-cancel.tsx": 1, // cancel a SAST, IaC, SCA + SBOM, CBOM or AI BOM scan
  };
  // a mover used outside a useMutation block, each with the reason it still refreshes
  const outside: Record<string, (code: string) => void> = {
    "components/dast-options-sidebar.tsx": (code) => {
      // handleStartScan builds the DAST request; the start mutation runs it and refreshes when it settles
      const wrapper = code.slice(code.indexOf("const handleStartScan = "));
      assert.ok(wrapper.indexOf("startDASTScan(") < wrapper.indexOf("\n  };"), "startDASTScan is called in handleStartScan");
      assert.ok(mutations(code).some((b) => /mutationFn: handleStartScan\b/.test(b.text) && refreshesOnSettled(b.text)),
        "the DAST start mutation (handleStartScan) refreshes the balance when it settles");
    },
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
    const used = backendApiImports(code).filter((name) => name in movers);
    if (!used.length) continue;
    const pattern = new RegExp(String.raw`\b(?:${used.join("|")})\b`, "g");
    // a local function that calls a mover counts as one where a mutation runs it (pinned in `outside`)
    const wrappers: Record<string, string[]> = { [path.join("components", "dast-options-sidebar.tsx")]: ["handleStartScan"] };
    const uses = new RegExp(String.raw`\b(?:${[...used, ...(wrappers[rel] ?? [])].join("|")})\b`);
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
    const imports = importRanges(code);
    const stray = [...code.matchAll(pattern)].filter((m) =>
      !imports.some(([a, b]) => m.index! >= a && m.index! < b) && !blocks.some((b) => m.index! >= b.start && m.index! < b.end));
    if (stray.length) {
      assert.ok(outside[rel], `${rel}: ${stray.map((m) => m[0]).join(", ")} used outside a useMutation block`);
      outside[rel](code);
    }
    assert.ok(!/invalidateQueries\(\{ queryKey: \["teams"\] \}\)/.test(code), `${rel}: refresh the balance through refreshCreditBalance`);
    assert.ok(!/invalidateQueries\(\)/.test(code), `${rel}: invalidating everything also refetches the balance a second time`);
  }
  assert.deepEqual(found, expected, "every file that imports a credit-moving API helper, and its mutations");

  // 5. credits the server moves without a user action (#28): a failed scan is refunded by the status poll that sees it
  // fail (backend utilities/celery/celery_connection.py), and a CBOM sources run is refunded job by job as its jobs
  // fail, expire or are cancelled (utilities/cbom_sources/jobs.py refund_job). The app's query client watches every
  // response: a scan seen failing, or a run whose refunded total changed, refreshes the balance once.
  const { makeQueryClient } = await import("./query_client");
  const app = makeQueryClient();
  let teamsFetches = 0;
  const balanceView = new QueryObserver<Teams>(app, {
    queryKey: [...CREDIT_BALANCE_QUERY_KEY],
    queryFn: async () => {
      teamsFetches += 1;
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
  stopBalance();
  // the scan pages use this client: the team layout makes it
  assert.match(read("app/[team_id]/layout.tsx"), /makeQueryClient\(\)/);
  // CBOM's own refresh when a scan finished is replaced by the watcher (it would send GET /teams twice)
  assert.ok(!/scan_status === "failure"\) \{\s*refreshCreditBalance/.test(read("components/cbom-options-sidebar.tsx")),
    "cbom-options-sidebar.tsx: the query client already refreshes the balance when a scan fails");

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

const API_MODULE = String.raw`["'](?:@\/utils\/|(?:\.\.?\/)+(?:utils\/)?)backend_api["']`;

/** Where the import statements of utils/backend_api are (their names are not uses). */
function importRanges(src: string): [number, number][] {
  return [...src.matchAll(new RegExp(String.raw`import\s*[^;]*?from\s*` + API_MODULE, "g"))]
    .map((m) => [m.index!, m.index! + m[0].length]);
}

/** The names a source file takes from utils/backend_api: named imports (by their exported name), and the members it
 * reads from a namespace or dynamic import of the module. */
function backendApiImports(src: string): string[] {
  const names = new Set<string>();
  for (const m of src.matchAll(new RegExp(String.raw`import\s*(?:type\s*)?\{([^}]*)\}\s*from\s*` + API_MODULE, "g"))) {
    for (const part of m[1].split(",")) {
      const name = part.trim().split(/\s+as\s+/)[0].trim();
      if (name && !/^type\s/.test(name)) names.add(name);
    }
  }
  const aliases = [
    ...src.matchAll(new RegExp(String.raw`import\s*\*\s*as\s+(\w+)\s*from\s*` + API_MODULE, "g")),
    ...src.matchAll(new RegExp(String.raw`(?:const|let|var)\s+(\w+)\s*=\s*await\s+import\(\s*` + API_MODULE + String.raw`\s*\)`, "g")),
  ].map((m) => m[1]);
  for (const alias of aliases) {
    for (const m of src.matchAll(new RegExp(String.raw`\b${alias}\.(\w+)`, "g"))) names.add(m[1]);
  }
  return [...names];
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
