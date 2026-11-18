/**
 * #13, #28: the credit balance in the team sidebar (TeamSwitcher in app/[team_id]/layout.tsx: GET /teams, cached under
 * ["teams"]) stayed stale until a reload after credits moved. Starting or re-running a SAST, IaC, SCA + SBOM, AI BOM,
 * MCP, LLM or DAST scan charges the team; the status check that sees a scan fail refunds it (backend
 * utilities/celery/celery_connection.py); a cancel refunds it (utilities/scan/cancel_scan.py); running a saved DAST
 * profile charges it; every scan chat message is charged (routers/scans.py, deduct_credits_from_team_for_message).
 * Start, re-run and cancel call refreshCredits (utils/creditRefresh.ts) when they settle. The refund on a failed
 * scan is creditBalanceWatcher, which refetches when the failure response arrives. A status effect that also calls
 * refreshCredits runs after paint and starts a second GET /teams (same-turn refreshCredits and refreshCreditBalance
 * in onSettled are one request; the later effect is not).
 * Browser check: note the balance, start a SAST scan: it drops without a reload; a scan that fails (an unreachable
 * repository) gives it back when the sidebar shows the failure, with one GET /teams; a chat message on a results
 * page charges it.
 * Run: npx --yes tsx@4.23.15 utils/creditRefresh.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { MutationObserver, QueryClient, QueryObserver } from "@tanstack/react-query";

import { finallyBlocks, ifBranches, mutationOptions } from "./sourceChecks";

const root = path.join(__dirname, "..");
const read = (rel: string) => fs.readFileSync(path.join(root, rel), "utf8");
const settle = () => new Promise((r) => setTimeout(r, 20));
const refreshes = (text: string | undefined) => /\brefreshCredits\(queryClient\)/.test(text ?? "");
const isFailure = (condition: string) => condition === 'query.data?.scan_status==="failure"';

async function main() {
  // 1. every action that moves credits refreshes the balance when it settles (onSettled: a refused start or cancel
  //    still shows the server's balance, which another tab may have changed)
  const problems: string[] = [];
  for (const name of ["sast", "iac", "sca-sbom", "ai-bom", "mcp", "llm", "dast"]) {
    const file = `components/${name}-options-sidebar.tsx`;
    const src = read(file);
    for (const m of ["startScanMutation", "reinitializeScanMutation"]) {
      const options = mutationOptions(src, m);
      if (!options) problems.push(`${file}: no ${m}`);
      else if (!refreshes(options.get("onSettled"))) problems.push(`${file}: ${m} does not refresh the balance when it settles`);
    }
    // The failure response already refreshes through creditBalanceWatcher. This branch paints later.
    if (ifBranches(src, isFailure).some(refreshes)) {
      problems.push(`${file}: a failed scan refreshes the balance again after it paints`);
    }
  }
  if (!refreshes(mutationOptions(read("components/scan-cancel.tsx"), "cancel")?.get("onSettled"))) {
    problems.push("components/scan-cancel.tsx: a cancel does not refresh the balance");
  }
  if (!finallyBlocks(read("components/ai/ChatWindow.tsx"), "sendMessageToScan(").some(refreshes)) {
    problems.push("components/ai/ChatWindow.tsx: a chat message does not refresh the balance (in the finally of its try)");
  }
  if (!refreshes(mutationOptions(read("components/dast/DastProfilesTab.tsx"), "runMutation")?.get("onSettled"))) {
    problems.push("components/dast/DastProfilesTab.tsx: running a saved DAST profile does not refresh the balance");
  }
  // CBOM refreshes on start. Success moves no credits, and a failure is the watcher: neither status may refresh again.
  const cbom = read("components/cbom-options-sidebar.tsx");
  const cbomRefresh = (text: string | undefined) =>
    refreshes(text) || /invalidateQueries\(\{ queryKey: \["teams"\] \}\)/.test(text ?? "");
  const cbomStart = mutationOptions(cbom, "startScanMutation");
  if (!cbomStart || ![...cbomStart.values()].some(cbomRefresh)) {
    problems.push("components/cbom-options-sidebar.tsx: CBOM no longer refreshes the balance on start");
  }
  const finished = (c: string) => c.includes('scan_status==="failure"') || c.includes('scan_status==="success"');
  if (ifBranches(cbom, finished).some(cbomRefresh)) {
    problems.push("components/cbom-options-sidebar.tsx: a finished scan refreshes the balance again after it paints");
  }
  assert.deepEqual(problems, [], `credit refresh wiring:\n  ${problems.join("\n  ")}`);

  // 2. the helper refreshes the query the header reads, and only that one
  const layout = read("app/[team_id]/layout.tsx");
  const switcher = layout.slice(layout.indexOf("function TeamSwitcher()"), layout.indexOf("const homeItem"));
  assert.ok(switcher.includes('queryKey: ["teams"],') && switcher.includes("team_credit_balance"),
    'the header shows the balance from the ["teams"] query');
  const { CREDITS_QUERY_KEY, isCreditsQuery, refreshCredits } = await import("./creditRefresh");
  assert.deepEqual([...CREDITS_QUERY_KEY], ["teams"]);
  assert.equal(isCreditsQuery({ queryKey: ["teams"] }), true);
  assert.equal(isCreditsQuery({ queryKey: ["team-details", "13"] }), false);
  assert.equal(isCreditsQuery({ queryKey: ["sast-conversation-data", 13, 7] }), false);

  type Teams = { team_id: number; team_credit_balance: number }[];
  const client = new QueryClient();
  let balance = 10;
  let fetches = 0;
  const header = new QueryObserver<Teams>(client, {
    queryKey: [...CREDITS_QUERY_KEY],
    queryFn: async () => {
      fetches += 1;
      return [{ team_id: 13, team_credit_balance: balance }];
    },
  });
  const shown: number[] = [];
  const stop = header.subscribe((r) => {
    if (r.data) shown.push(r.data[0].team_credit_balance);
  });
  await settle();
  assert.deepEqual(shown, [10]);
  const scanKey = ["sast-conversation-data", 13, 7];
  client.setQueryData(scanKey, { scan_status: "pending" });

  // a start charges 3 credits: when its mutation settles the header shows 7, with one GET /teams
  fetches = 0;
  balance = 7;
  const start = new MutationObserver(client, {
    mutationFn: async () => ({ message: "Scan started" }),
    onSettled: () => {
      refreshCredits(client);
    },
  });
  await start.mutate();
  await settle();
  assert.equal(fetches, 1, "one GET /teams");
  assert.equal(shown.at(-1), 7, "the charge shows without a reload");
  assert.equal(client.getQueryState(scanKey)?.isInvalidated, false, "only the balance is read again");

  // a refused start (too few credits) moves nothing, and the header still shows what the server says
  fetches = 0;
  const refused = new MutationObserver(client, {
    mutationFn: async () => {
      throw new Error("The team does not have enough credits");
    },
    onSettled: () => {
      refreshCredits(client);
    },
  });
  await refused.mutate().catch(() => undefined);
  await settle();
  assert.equal(fetches, 1);
  assert.equal(shown.at(-1), 7);

  // a cancel refunds: the balance and every other query of the page are read again, GET /teams once (scan-cancel.tsx)
  fetches = 0;
  balance = 10;
  await Promise.all([refreshCredits(client), client.invalidateQueries({ predicate: (q) => !isCreditsQuery(q) })]);
  await settle();
  assert.equal(fetches, 1, "one GET /teams after a cancel");
  assert.equal(shown.at(-1), 10, "the refund shows without a reload");
  assert.equal(client.getQueryState(scanKey)?.isInvalidated, true, "the scan's status is read again");
  stop();

  // 3. the cancel button reads the balance once: its other refresh leaves the ["teams"] query to refreshCredits
  const onSettled = mutationOptions(read("components/scan-cancel.tsx"), "cancel")?.get("onSettled") ?? "";
  assert.ok(!/invalidateQueries\(\)/.test(onSettled), "invalidating every query also reads the balance a second time");

  console.log("credit balance refresh: tests passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
