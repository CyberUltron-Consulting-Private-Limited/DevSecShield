/**
 * Customer QA of the CMDB import dialog (#362 #363 #367): only registered agentless nodes are offered, segment pickers
 * appear only for the file's segments that need a choice, the per-engine CA is sent, and merged / unchanged rows and
 * host conflicts are shown.
 * Run: npx --yes tsx components/cbom/sources/cmdbImportQa.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import type { CmdbPlan } from "@/utils/api/integrations";
import type { CbomScanNode } from "@/utils/backend_api";

import { PlanView } from "./CmdbImportDialog";
import { CA_ENGINES, importNodes, leftOutLine, segmentPickers } from "./cmdbLogic";

const node = (id: number, name: string, status: string, mode?: string) =>
  ({ id, name, status, mode, segment: "" }) as unknown as CbomScanNode;
const nodes = [node(1, "mum-01", "online"), node(2, "mum-02", "offline"), node(3, "rgrg", "pending_registration"),
  node(4, "old", "registration_expired"), node(5, "cbom-lab-2-a", "online", "agent"), node(6, "cbom-lab-2-b", "online", "agent")];
const offered = importNodes(nodes);
assert.deepEqual(offered.usable.map((n) => n.name), ["mum-01", "mum-02"]);
assert.equal(offered.agents, 2);
assert.equal(offered.waiting, 2);
assert.equal(leftOutLine(offered), "Not offered: 2 host-agent nodes (they collect only their own host); 2 nodes not registered yet.");
assert.equal(leftOutLine({ agents: 0, waiting: 0 }), null);

const plan = {
  rows: 3, digest: "d", unchanged: 1, truncated: false, warnings: [],
  counts: { create: 0, update: 0, conflict: 1, skipped: 0, new_targets: 0, merged: 1 },
  creates: [], updates: [], skipped: [],
  conflicts: [{ source_id: null, source: null, host: "qa-dup.bank.local", field: "owner", values: { "team-a": [30], "team-b": [31] } }],
  merged: [{ label: "qa-dup.bank.local", kind: "linux_servers", lines: [30, 31], notes: [] }],
  unchanged_items: [{ source_id: 7, source: "CMDB hsm luna payments-01", kind: "key_manager", lines: [12] }],
  segments: [
    { segment: "Data centre", rows: 4, nodes: [{ id: 1, name: "mum-01" }, { id: 2, name: "mum-02" }], chosen: null },
    { segment: "lab", rows: 2, nodes: [{ id: 1, name: "mum-01" }], chosen: 1 },
  ],
} as CmdbPlan;
const pickers = segmentPickers(plan, offered.usable);
assert.deepEqual(pickers.map((p) => [p.segment, p.rows, p.nodes.map((n) => n.name)]), [["Data centre", 4, ["mum-01", "mum-02"]]]);
assert.deepEqual(segmentPickers(null, offered.usable), []); // no picker before a preview names the file's segments

const html = renderToStaticMarkup(h(PlanView, { plan }));
assert.match(html, /qa-dup\.bank\.local \(new\): rows disagree on owner \(team-a on line 30; team-b on line 31\)/);
assert.match(html, /data-testid="cmdb-merged"/);
assert.match(html, /lines 30, 31/);
assert.match(html, /data-testid="cmdb-unchanged"/);
assert.match(html, /CMDB hsm luna payments-01<\/span>: line 12, nothing to change/);
assert.match(html, /1 hosts on several rows \(merged\)/);

assert.deepEqual(CA_ENGINES.map((e) => e.value), ["*", "mysql", "mssql", "oracle", "mongodb", "redis"]);
const here = path.dirname(new URL(import.meta.url).pathname);
const backend = fs.readFileSync(path.join(here, "../../../../backend/routers/integrations.py"), "utf8");
assert.match(backend, /CMDB_CA_ENGINES = \("mysql", "mssql", "oracle", "mongodb", "redis", "\*"\)/);
const dialog = fs.readFileSync(path.join(here, "CmdbImportDialog.tsx"), "utf8");
assert.match(dialog, /<NodeSelect id="cmdb-node" nodes=\{offered\.usable\}/);
assert.match(dialog, /const shared = segmentPickers\(plan, offered\.usable\)/);
assert.match(dialog, /database_ca: Object\.keys\(databaseCa\)\.length/);
console.log("cmdbImportQa.test.ts: ok");
