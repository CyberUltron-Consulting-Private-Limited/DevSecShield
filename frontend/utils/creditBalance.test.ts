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
  const root = path.join(__dirname, "..");
  const read = (rel: string) => fs.readFileSync(path.join(root, rel), "utf8");
  const layout = read("app/[team_id]/layout.tsx");
  const switcher = layout.slice(layout.indexOf("function TeamSwitcher()"), layout.indexOf("const homeItem"));
  assert.ok(switcher.includes('queryKey: ["teams"],') && switcher.includes("team_credit_balance"),
    "the team switcher shows the balance from the [\"teams\"] query");
  assert.deepEqual([...CREDIT_BALANCE_QUERY_KEY], ["teams"]);

  // 4. wiring: every mutation that starts or cancels a scan (it charges or refunds credits) refreshes the balance
  // when it settles, through the helper. A new start or cancel path must be added here and wired the same way.
  // (the API helpers whose endpoints charge or refund; the DAST sidebar calls startDASTScan through handleStartScan,
  // the unused discovery and leakage sidebars call routes the backend no longer has)
  const charging = /\b(startScan|startDASTScan|runDASTProfile|startCbomRun|cancelScan|cancelCbomRun)\(/;
  const charges = (block: string, src: string) =>
    charging.test(block) || (/mutationFn: handleStartScan\b/.test(block) && /return startDASTScan\(/.test(src));
  const found: Record<string, number> = {};
  for (const file of ["app", "components"].flatMap((d) => walk(path.join(root, d)))) {
    const rel = path.relative(root, file);
    const src = fs.readFileSync(file, "utf8");
    for (const block of mutations(src)) {
      if (!charges(block, src)) continue;
      found[rel] = (found[rel] ?? 0) + 1;
      const settled = block.slice(block.indexOf("onSettled"));
      assert.ok(block.includes("onSettled") && settled.includes("refreshCreditBalance(queryClient)"),
        `${rel}: a scan start or cancel does not refresh the credit balance when it settles:\n${block}`);
    }
    if (found[rel]) {
      assert.ok(!/invalidateQueries\(\{ queryKey: \["teams"\] \}\)/.test(src), `${rel}: refresh the balance through refreshCreditBalance`);
      assert.ok(!/invalidateQueries\(\)/.test(src), `${rel}: invalidating everything also refetches the balance a second time`);
    }
  }
  assert.deepEqual(found, {
    "components/ai-bom-options-sidebar.tsx": 1,
    "components/cbom-options-sidebar.tsx": 2, // the code scan and its linked sources run
    "components/cbom/sources/ReviewRunTab.tsx": 2, // start and cancel a sources run
    "components/dast-options-sidebar.tsx": 1,
    "components/dast/DastProfilesTab.tsx": 1, // run a saved DAST profile
    "components/iac-options-sidebar.tsx": 1,
    "components/llm-options-sidebar.tsx": 1,
    "components/mcp-options-sidebar.tsx": 1,
    "components/sast-options-sidebar.tsx": 1,
    "components/sca-sbom-options-sidebar.tsx": 1,
    "components/scan-cancel.tsx": 1, // cancel a SAST, IaC, SCA + SBOM, CBOM or AI BOM scan
  });

  // CBOM also refreshes it when a scan finishes (a failed one is refunded): through the same helper
  const cbom = read("components/cbom-options-sidebar.tsx");
  assert.match(cbom, /scan_status === "failure"\) \{\s*refreshCreditBalance\(queryClient\);/);

  console.log("credit balance refresh: tests passed");
}

/** The object literal of every useMutation({ ... }) in a source file. */
function mutations(src: string): string[] {
  const blocks: string[] = [];
  for (let i = src.indexOf("useMutation({"); i >= 0; i = src.indexOf("useMutation({", i + 1)) {
    const open = i + "useMutation(".length;
    let depth = 0;
    for (let j = open; j < src.length; j++) {
      if (src[j] === "{") depth += 1;
      else if (src[j] === "}" && --depth === 0) {
        blocks.push(src.slice(open, j + 1));
        break;
      }
    }
  }
  return blocks;
}

function walk(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(dir, e.name))
      : /\.tsx?$/.test(e.name) && !e.name.endsWith(".test.ts") ? [path.join(dir, e.name)] : []);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
