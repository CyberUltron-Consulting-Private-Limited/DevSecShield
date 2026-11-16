/**
 * Previous / Next of the Sources-run finding dialog (PLAN §4 footer): the snapshot is anchored by asset id, a row that
 * leaves the page keeps its slot, and the page edges ask for the previous / next table page and land on its last /
 * first row. Also the ←/→ guard (not in a tab list, text field or nested layer).
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/dialogNav.test.ts
 */
import assert from "node:assert/strict";

import {
  absoluteIndex,
  arrowKeysMove,
  canGo,
  landingAsset,
  navTarget,
  positionLabel,
  refreshSnapshot,
  removedFromView,
  snapshotOf,
} from "./dialogNav";
import { NAV_IDLE, nextNavState } from "./useDialogNav";

const rows = (...ids: number[]) => ids.map((id) => ({ id }));

// ---- snapshot and position, anchored by id
const s1 = snapshotOf(rows(11, 12, 13), 1, 3, 7);
assert.deepEqual(s1, { ids: [11, 12, 13], page: 1, pageSize: 3, total: 7 });
assert.equal(absoluteIndex(s1, 12), 1);
assert.equal(absoluteIndex(s1, 99), -1, "an asset not in the snapshot has no position");
const s2 = snapshotOf(rows(21, 22, 23), 2, 3, 7);
assert.equal(absoluteIndex(s2, 21), 3, "page 2 starts after page 1's rows");
assert.equal(positionLabel(absoluteIndex(s2, 21), 7), "4 of 7");
assert.equal(positionLabel(-1, 7), null);
assert.equal(positionLabel(0, 0), null);

// ---- moves within the page
assert.deepEqual(navTarget(s1, 2), { kind: "asset", assetId: 13 });
assert.deepEqual(navTarget(s1, 0), { kind: "asset", assetId: 11 });
assert.deepEqual(navTarget(s1, -1), { kind: "none" }, "nothing before the first row");
assert.deepEqual(navTarget(s1, 7), { kind: "none" }, "nothing past the total");
assert.deepEqual(navTarget(s1, 1.5), { kind: "none" });

// ---- page edges
assert.deepEqual(navTarget(s1, 3), { kind: "page", page: 2, edge: "next" }, "Next on the last row asks for page 2");
assert.deepEqual(navTarget(s2, 2), { kind: "page", page: 1, edge: "prev" }, "Previous on the first row asks for page 1");
assert.equal(landingAsset(snapshotOf(rows(21, 22, 23), 2, 3, 7), "next"), 21, "Next lands on the new page's first row");
assert.equal(landingAsset(snapshotOf(rows(11, 12, 13), 1, 3, 7), "prev"), 13, "Previous lands on its last row");
assert.equal(landingAsset(snapshotOf([], 3, 3, 7), "next"), null, "an empty page opens nothing");

// ---- removed ids keep their slot; new ids are appended
const live = rows(11, 13, 14);
const r = refreshSnapshot(s1, live, 7);
assert.deepEqual(r.ids, [11, 12, 13, 14], "12 left the page but keeps its slot; 14 joins at the end");
assert.equal(absoluteIndex(r, 13), 2, "positions do not shift under the open dialog");
assert.ok(removedFromView(12, live.map((x) => x.id)));
assert.ok(!removedFromView(13, live.map((x) => x.id)));
assert.ok(!removedFromView(12, undefined), "no live page: not judged");
assert.equal(refreshSnapshot(s1, rows(11, 12, 13), 7), s1, "an unchanged page keeps the same snapshot object");
assert.equal(refreshSnapshot(s1, rows(11, 12, 13), 9).total, 9, "the total follows the table");

// ---- buttons
assert.equal(canGo({ index: 0, total: 7 }, -1), false);
assert.equal(canGo({ index: 0, total: 7 }, 1), true);
assert.equal(canGo({ index: 6, total: 7 }, 1), false);
assert.equal(canGo({ index: 3, total: 7, pageEdge: "next" }, 1), false, "disabled while a page loads");
assert.equal(canGo({ index: -1, total: 7 }, 1), false);

// ---- ←/→ guard
const el = (tagName: string, inside: string[] = [], extra: object = {}) => ({
  tagName, closest: (sel: string) => (inside.some((i) => sel.includes(i)) ? {} : null), ...extra,
});
assert.equal(arrowKeysMove(el("BUTTON"), false), true);
assert.equal(arrowKeysMove(null, false), true);
assert.equal(arrowKeysMove(el("BUTTON"), true), false, "a nested layer is open");
assert.equal(arrowKeysMove(el("BUTTON", ["tablist"]), false), false, "a tab list uses the arrows itself");
assert.equal(arrowKeysMove(el("INPUT"), false), false);
assert.equal(arrowKeysMove(el("TEXTAREA"), false), false);
assert.equal(arrowKeysMove(el("SELECT"), false), false);
assert.equal(arrowKeysMove(el("DIV", [], { isContentEditable: true }), false), false);
assert.equal(arrowKeysMove(el("DIV", ["menu"]), false), false);

// ---- the hook's state (pure): page edge waits for the asked page, the landing row, closing, other subjects
{
  const base = { pageSize: 2, total: 4, placeholder: false };
  const opened = { snap: snapshotOf(rows(1, 2), 1, 2, 4), pending: null, landing: null };
  assert.equal(nextNavState(NAV_IDLE, { ...base, assetId: 1, items: rows(1, 2), page: 1 }), NAV_IDLE, "no snapshot: nothing to do");
  assert.equal(nextNavState(opened, { ...base, assetId: 2, items: rows(1, 2), page: 1 }), opened, "unchanged inputs keep the state");
  assert.equal(nextNavState(opened, { ...base, assetId: null, items: rows(1, 2), page: 1 }).snap, null, "closing drops the snapshot");
  assert.equal(nextNavState(opened, { ...base, assetId: 9, items: rows(1, 2), page: 1 }).snap, null, "another subject: no navigation");
  const waiting = { ...opened, pending: { page: 2, edge: "next" as const } };
  assert.equal(nextNavState(waiting, { ...base, assetId: 2, items: rows(1, 2), page: 2, placeholder: true }), waiting, "placeholder rows are not page 2");
  assert.equal(nextNavState(waiting, { ...base, assetId: 2, items: rows(1, 2), page: 1 }), waiting, "the table is not on page 2 yet");
  const landed = nextNavState(waiting, { ...base, assetId: 2, items: rows(3, 4), page: 2 });
  assert.deepEqual(landed.snap?.ids, [3, 4]);
  assert.deepEqual(landed.landing, { id: 3, n: 1, arrived: false }, "Next lands on page 2's first row");
  assert.equal(nextNavState(landed, { ...base, assetId: 2, items: rows(3, 4), page: 2 }), landed, "until the dialog shows it, the old row does not clear the snapshot");
  const arrived = nextNavState(landed, { ...base, assetId: 3, items: rows(3, 4), page: 2 });
  assert.equal(arrived.landing?.arrived, true);
  assert.deepEqual(nextNavState(arrived, { ...base, assetId: 3, items: rows(4), page: 2 }).snap?.ids, [3, 4], "a removed row keeps its slot");
  const back = nextNavState({ ...arrived, pending: { page: 1, edge: "prev" } }, { ...base, assetId: 3, items: rows(1, 2), page: 1 });
  assert.deepEqual(back.landing, { id: 2, n: 2, arrived: false }, "Previous lands on page 1's last row");
}
console.log("dialog nav tests passed");
