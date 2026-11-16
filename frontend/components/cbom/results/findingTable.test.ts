/**
 * #266 / #267 logic: the finding dialog's scroll layout classes, the findings tables' column defaults and per-user
 * localStorage persistence (never throws), and the row handlers that open the finding dialog on click / Enter / Space.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/findingTable.test.ts
 */
import assert from "node:assert/strict";

import {
  columnPrefsKey,
  columnsForUser,
  defaultColumns,
  FINDING_DIALOG_BODY,
  FINDING_DIALOG_CONTENT,
  FINDING_DIALOG_FULLSCREEN_SM,
  loadColumns,
  normalizeColumns,
  rowOpenProps,
  cardOpenProps,
  CLICKABLE_CARD,
  CARD_ARROW,
  RUN_TABLE_COLUMNS,
  saveColumns,
  SCAN_TABLE_COLUMNS,
  STICKY_ACTIONS,
  toggleColumn,
  type PrefsStorage,
} from "./findingTable";

const cls = (s: string) => new Set(s.split(/\s+/));

// ------------------------------------------------------------------ #266 dialog layout
const content = cls(FINDING_DIALOG_CONTENT);
for (const c of ["max-h-[90vh]", "flex", "flex-col", "overflow-hidden"]) assert.ok(content.has(c), `dialog has ${c}`);
const body = cls(FINDING_DIALOG_BODY);
// the body is the scroll container itself: a min-h-0 flex item shrinks to the clamped dialog and scrolls
for (const c of ["flex-1", "min-h-0", "overflow-y-auto"]) assert.ok(body.has(c), `body has ${c}`);
// nothing that needs a definite parent height (the bug: h-full under a max-height-only flexbox resolved to auto)
assert.ok(![...body].some((c) => /^(h-full|sm:h-|h-\[)/.test(c)), "the body has no percentage / fixed height");
assert.ok(cls(FINDING_DIALOG_FULLSCREEN_SM).has("max-sm:h-[100dvh]"), "full screen below 640 px");

// ------------------------------------------------------------------ #267 columns
// the defaults fit a 1366 px laptop: 6 data columns for a run (15 before), 6 for a code scan (11 before)
assert.deepEqual(defaultColumns(RUN_TABLE_COLUMNS), ["impact", "algorithm", "where", "quantum", "risk", "status"]);
assert.deepEqual(defaultColumns(SCAN_TABLE_COLUMNS), ["algorithm", "impact", "quantum", "risk", "location", "status"]);
// the less important columns the issue names are behind the chooser
for (const id of ["qgrade", "fixclass", "wave", "source"] as const) {
  assert.ok(!defaultColumns(RUN_TABLE_COLUMNS).includes(id), `${id} hidden by default`);
}
assert.equal(new Set(RUN_TABLE_COLUMNS.map((c) => c.id)).size, RUN_TABLE_COLUMNS.length, "unique run column ids");
assert.equal(new Set(SCAN_TABLE_COLUMNS.map((c) => c.id)).size, SCAN_TABLE_COLUMNS.length, "unique scan column ids");

// normalize: known ids in table order; junk -> defaults
assert.deepEqual(normalizeColumns(RUN_TABLE_COLUMNS, ["status", "bogus", "impact", 3]), ["impact", "status"]);
assert.deepEqual(normalizeColumns(RUN_TABLE_COLUMNS, []), defaultColumns(RUN_TABLE_COLUMNS));
assert.deepEqual(normalizeColumns(RUN_TABLE_COLUMNS, { impact: true }), defaultColumns(RUN_TABLE_COLUMNS));
assert.deepEqual(normalizeColumns(RUN_TABLE_COLUMNS, ["nope"]), defaultColumns(RUN_TABLE_COLUMNS));

// toggle: adds in table order, removes, never hides the last column
assert.deepEqual(toggleColumn(RUN_TABLE_COLUMNS, ["impact", "status"], "wave"), ["impact", "wave", "status"]);
assert.deepEqual(toggleColumn(RUN_TABLE_COLUMNS, ["impact", "status"], "impact"), ["status"]);
assert.deepEqual(toggleColumn(RUN_TABLE_COLUMNS, ["status"], "status"), ["status"], "the last column stays");

// per-user, per-table key
assert.equal(columnPrefsKey("run", " Ana@Example.COM "), "dss.cbom.results.columns.v1.run.ana@example.com");
assert.equal(columnPrefsKey("scan", null), null, "no key (nothing read or stored) until the user is known");
assert.equal(columnPrefsKey("scan", "  "), null);
assert.notEqual(columnPrefsKey("run", "a@x.io"), columnPrefsKey("run", "b@x.io"));
assert.notEqual(columnPrefsKey("run", "a@x.io"), columnPrefsKey("scan", "a@x.io"));

// storage round trip and every failure mode -> defaults, never a throw
const mem = (): PrefsStorage & { data: Map<string, string> } => {
  const data = new Map<string, string>();
  return { data, getItem: (k) => data.get(k) ?? null, setItem: (k, v) => void data.set(k, v) };
};
const s = mem();
const key = columnPrefsKey("run", "a@x.io")!;
assert.deepEqual(loadColumns(s, key, RUN_TABLE_COLUMNS), defaultColumns(RUN_TABLE_COLUMNS), "nothing stored");
assert.equal(saveColumns(s, key, ["impact", "wave"]), true);
assert.deepEqual(loadColumns(s, key, RUN_TABLE_COLUMNS), ["impact", "wave"], "stored choice comes back");
assert.deepEqual(loadColumns(s, columnPrefsKey("run", "b@x.io")!, RUN_TABLE_COLUMNS), defaultColumns(RUN_TABLE_COLUMNS), "other user unaffected");
s.data.set(key, "{not json");
assert.deepEqual(loadColumns(s, key, RUN_TABLE_COLUMNS), defaultColumns(RUN_TABLE_COLUMNS), "corrupt JSON");
const throwing: PrefsStorage = {
  getItem: () => { throw new Error("SecurityError"); },
  setItem: () => { throw new Error("QuotaExceededError"); },
};
assert.deepEqual(loadColumns(throwing, key, RUN_TABLE_COLUMNS), defaultColumns(RUN_TABLE_COLUMNS), "blocked storage");
assert.equal(saveColumns(throwing, key, ["impact"]), false, "full storage: not saved, no throw");
assert.deepEqual(loadColumns(null, key, RUN_TABLE_COLUMNS), defaultColumns(RUN_TABLE_COLUMNS), "no storage (SSR)");
assert.equal(saveColumns(undefined, key, ["impact"]), false);

// a choice made before the profile loaded (memory only) is stored under the user's key once known; else the stored one
const s2 = mem();
const k2 = columnPrefsKey("run", "late@x.io")!;
s2.data.set(k2, JSON.stringify(["impact"]));
assert.deepEqual(columnsForUser(s2, k2, RUN_TABLE_COLUMNS, null), ["impact"], "no early change: the stored choice");
assert.deepEqual(columnsForUser(s2, k2, RUN_TABLE_COLUMNS, ["wave", "impact"]), ["impact", "wave"], "early change wins, in table order");
assert.equal(s2.data.get(k2), JSON.stringify(["impact", "wave"]), "and is stored under the user's key");
assert.ok(![...s2.data.keys()].some((k) => k.endsWith("._")), "never a shared device key");
assert.deepEqual(columnsForUser(throwing, k2, RUN_TABLE_COLUMNS, ["wave"]), ["wave"], "blocked storage: kept in memory");

// ------------------------------------------------------------------ #267 row opens the finding dialog
let opened = 0;
let prevented = 0;
const row = { closest: () => row };
let selection = "";
const props = rowOpenProps(() => { opened += 1; }, "Open details of RSA", () => selection);
const ev = (o: Partial<{ key: string; target: unknown }>) =>
  ({ key: o.key, target: o.target ?? row, currentTarget: row, preventDefault: () => { prevented += 1; } });
assert.equal(props.tabIndex, 0, "the row is a tab stop");
assert.equal(props["aria-haspopup"], "dialog");
assert.equal(props["aria-label"], "Open details of RSA");

const cell = { closest: (sel: string) => (sel.includes("button") ? null : null) };  // a plain <td>
props.onClick(ev({ target: cell }));
assert.equal(opened, 1, "a click on a cell opens");
const inButton = { closest: () => ({ tagName: "BUTTON" }) };  // the Action menu, checkbox, name link...
props.onClick(ev({ target: inButton }));
assert.equal(opened, 1, "a click on a control in the row keeps its own action");
props.onClick(ev({ target: {} }));
assert.equal(opened, 2, "a target without closest (text node) still opens");

selection = "10.0.0.5:443";
props.onClick(ev({ target: cell }));
assert.equal(opened, 2, "a click that ends a text selection in the row (to copy it) does not open");
selection = "";
props.onKeyDown(ev({ key: "Enter" }));
props.onKeyDown(ev({ key: " " }));
assert.equal(opened, 4, "Enter and Space on the focused row open");
assert.equal(prevented, 2, "Space does not scroll the page");
props.onKeyDown(ev({ key: "a" }));
props.onKeyDown(ev({ key: "Tab" }));
assert.equal(opened, 4, "other keys do nothing");
props.onKeyDown(ev({ key: "Enter", target: inButton }));
assert.equal(opened, 4, "Enter on the Action button inside the row is the button's");

// ------------------------------------------------------------------ sticky actions
assert.ok(cls(STICKY_ACTIONS).has("md:sticky") && cls(STICKY_ACTIONS).has("md:right-0"), "actions pinned right");
assert.ok(cls(STICKY_ACTIONS).has("bg-white"), "opaque, so scrolled cells do not show through");


// ------------------------------------------------------------------ clickable cards (owner: whole card clickable, looks clickable)
{
  let opens = 0;
  let sel = "";
  const inside = new Set<unknown>();
  const card = { contains: (n: unknown) => inside.has(n), closest: () => card };
  const text = { closest: () => null };                        // plain text in the card
  const infoTip = { closest: () => ({ tagName: "BUTTON" }) };  // the ⓘ / the Open button / a link
  const portalText = { closest: () => null };                  // a tooltip's text, rendered in a portal
  inside.add(text); inside.add(infoTip);
  const p = cardOpenProps(() => { opens += 1; }, () => sel);
  p.onClick({ target: text, currentTarget: card });
  assert.equal(opens, 1, "a click on the card body opens it");
  p.onClick({ target: infoTip, currentTarget: card });
  assert.equal(opens, 1, "a click on a control inside the card (the ⓘ, a link) is left to that control");
  p.onClick({ target: portalText, currentTarget: card });
  assert.equal(opens, 1, "a click that bubbles in from a portal (tooltip text) does not open the card");
  sel = "RSA 1024";
  p.onClick({ target: text, currentTarget: card });
  assert.equal(opens, 1, "a click that ends a text selection does not open the card");
  for (const c of ["group", "cursor-pointer", "hover:border-blue-500/70", "hover:-translate-y-0.5", "hover:shadow-lg", "focus-within:border-blue-500/70", "motion-reduce:hover:translate-y-0"]) {
    assert.ok(cls(CLICKABLE_CARD).has(c), `clickable card has ${c}`);
  }
  assert.ok(cls(CARD_ARROW).has("group-hover:translate-x-1") && cls(CARD_ARROW).has("group-focus-within:translate-x-1"), "the arrow slides on hover and focus");
}

console.log("findingTable tests passed");
