/**
 * Issue #225: the source tables search, filter and page on the server, and the CMDB dialog offers the segment, vault
 * and Windows choices and describes every new source with its scan node.
 * Run: npx --yes tsx components/cbom/sources/sourceQuery.test.ts
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { createLine, sharedSegments } from "./cmdbLogic";
import { EMPTY_FILTERS, filtersActive, segmentOptions, shownLine, SOURCE_PAGE_SIZE, sourceListParams } from "./sourceQuery";

// request parameters: keyset paging, kinds the table shows unless one is chosen, trimmed search, filters
assert.deepEqual(sourceListParams("servers", ["linux_servers", "windows_servers"], EMPTY_FILTERS, null),
  { limit: SOURCE_PAGE_SIZE, group: "servers", kind: "linux_servers,windows_servers" });
assert.deepEqual(
  sourceListParams("servers", ["linux_servers", "windows_servers"],
    { q: "  10.0.16.3 ", kind: "windows_servers", segment: "dc-mumbai", status: "failed" }, 4099, 50),
  { limit: 50, group: "servers", kind: "windows_servers", q: "10.0.16.3", segment: "dc-mumbai", status: "failed", after: 4099 });
assert.deepEqual(sourceListParams(undefined, [], EMPTY_FILTERS, 0), { limit: SOURCE_PAGE_SIZE, after: 0 });
assert.equal((sourceListParams(undefined, [], { ...EMPTY_FILTERS, q: "x".repeat(300) }, null).q as string).length, 128);

// segments: agentless nodes only, one entry per segment whatever its case, sorted
assert.deepEqual(segmentOptions([
  { segment: "dc-mumbai" }, { segment: "DC-Mumbai" }, { segment: "dc-chennai" }, { segment: "" }, { segment: null },
  { segment: "k8s-pool", mode: "agent" },
]), ["dc-chennai", "dc-mumbai"]);

assert.equal(filtersActive(EMPTY_FILTERS), false);
assert.equal(filtersActive({ ...EMPTY_FILTERS, q: "  " }), false);
assert.equal(filtersActive({ ...EMPTY_FILTERS, status: "disabled" }), true);
assert.equal(shownLine(100, 6000, EMPTY_FILTERS), "Showing 100 of 6,000 sources");
assert.equal(shownLine(1, 1, { ...EMPTY_FILTERS, q: "src" }), "1 matching source");

// CMDB: segments served by several nodes need a choice; each new source says what it is and where it runs
type Node = Parameters<typeof sharedSegments>[0][number];
const node = (id: number, name: string, segment: string, mode = "agentless") => ({ id, name, segment, mode }) as unknown as Node;
const shared = sharedSegments([node(1, "mum-01", "dc-mumbai"), node(2, "mum-02", "DC-Mumbai"), node(3, "che-01", "dc-chennai"),
  node(4, "pool", "dc-mumbai", "agent")]);
assert.deepEqual(shared.map((s) => [s.segment, s.nodes.map((n) => n.name)]), [["dc-mumbai", ["mum-01", "mum-02"]]]);
assert.equal(createLine({ kind: "windows_servers", name: "w", targets: ["a", "b"], metadata: {}, lines: [2], node_id: 3,
  node_name: "che-01", segment: "dc-chennai" }), "2 Windows hosts, WinRM login from the vault on che-01 (segment dc-chennai)");
assert.equal(createLine({ kind: "database", name: "d", config: { engine: "postgres", host: "pg1", port: 5432 }, metadata: {},
  lines: [2], node_id: null, node_name: null }), "postgres database pg1:5432 on the chosen scan node");
assert.equal(createLine({ kind: "key_manager", name: "h", config: { module: "luna", token_label: "pay" }, metadata: {}, lines: [3],
  node_id: 1, node_name: "mum-01", segment: "dc-mumbai" }), "HSM luna token pay on mum-01 (segment dc-mumbai)");

// wired into the Servers tab, Review & Run and the CMDB dialog
const here = path.dirname(new URL(import.meta.url).pathname);
const read = (rel: string) => fs.readFileSync(path.join(here, rel), "utf8");
const servers = read("ServersTab.tsx");
assert.match(servers, /usePagedSources\(teamId, "servers"/);
assert.match(servers, /<SourceFilterBar /);
assert.match(servers, /<LoadMoreFooter /);
assert.doesNotMatch(servers, /listCbomSources\(teamId, "servers"\)/); // no more "load every source"
assert.match(read("ReviewRunTab.tsx"), /<SourceBrowser teamId=\{teamId\} \/>/);
const dialog = read("CmdbImportDialog.tsx");
for (const field of ["segment_nodes", "vault_provider", "windows_vault"]) assert.match(dialog, new RegExp(field));

// the Servers table lists every servers-group kind except host agents: the same set as the backend registry
const backend = path.join(here, "../../../../backend/utilities/cbom_sources");
const registry = fs.readFileSync(path.join(backend, "kinds.py"), "utf8") + fs.readFileSync(path.join(backend, "kinds_fleet.py"), "utf8");
const serverKinds = Array.from(registry.matchAll(/KindSpec\("([a-z_]+)", "servers"/g)).map((m) => m[1]).filter((k) => k !== "host_agent").sort();
const listed = Array.from(servers.matchAll(/\{ value: "([a-z_]+)", label: "[^"]+" \}/g)).map((m) => m[1]);
assert.ok(serverKinds.length >= 3);
for (const kind of serverKinds) assert.ok(listed.includes(kind), `Servers table misses kind ${kind}`);
console.log("sourceQuery.test.ts: ok");
