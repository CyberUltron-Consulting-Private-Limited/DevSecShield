// Previous / Next in the Sources-run finding dialog (PLAN §4 footer 24-C). Pure logic, no React: the dialog walks a
// snapshot of the findings table's ordered ids taken when it was opened from the table, anchored by asset id. A row
// that leaves the page while the dialog is open (a status change under a status filter, a live refresh) keeps its
// slot, so Previous / Next still land where the customer expects; at the edge of the page the table moves one page
// and the dialog opens that page's first (Next) or last (Previous) row once the new page has loaded.

/** What the dialog's footer needs. Without it (asset-only subjects: top risks, certificates, PQC list, Unknown-grade items) the
 * footer has no Previous / Next. */
export type DialogNav = {
  /** the snapshot's ordered asset ids of the table page the dialog walks */
  ids: number[];
  /** 0-based position of the current asset among ALL rows of the table (across pages); -1 when it is not known */
  index: number;
  /** the table's total row count (N of "n of N") */
  total: number;
  /** go to the row at this 0-based position (across pages) */
  onGo(index: number): void;
  /** set while the table is loading the previous / next page for the dialog */
  pageEdge?: "prev" | "next" | null;
};

/** The table page the dialog was opened from (or moved to). */
export interface NavSnapshot {
  ids: number[];
  /** 1-based page number of the table */
  page: number;
  pageSize: number;
  total: number;
}

export function snapshotOf(items: readonly { id: number }[], page: number, pageSize: number, total: number): NavSnapshot {
  return { ids: items.map((i) => i.id), page: Math.max(1, page), pageSize: Math.max(1, pageSize), total: Math.max(0, total) };
}

/** A fresh copy of the same table page: ids already in the snapshot keep their order and slot (a removed id stays, so
 * positions do not shift under the open dialog); ids new to the page are appended. The total follows the table. */
export function refreshSnapshot(snap: NavSnapshot, items: readonly { id: number }[], total: number): NavSnapshot {
  const known = new Set(snap.ids);
  const added = items.map((i) => i.id).filter((id) => !known.has(id));
  if (added.length === 0 && total === snap.total) return snap;
  return { ...snap, ids: [...snap.ids, ...added], total: Math.max(0, total, snap.ids.length + added.length) };
}

/** 0-based position of an asset across all pages, or -1 when the snapshot does not hold it. */
export function absoluteIndex(snap: NavSnapshot, assetId: number): number {
  const local = snap.ids.indexOf(assetId);
  return local < 0 ? -1 : (snap.page - 1) * snap.pageSize + local;
}

/** Whether a row is no longer on the live table page (it keeps its slot in the snapshot). */
export function removedFromView(assetId: number, liveIds: readonly number[] | undefined): boolean {
  return !!liveIds && !liveIds.includes(assetId);
}

export type NavTarget =
  | { kind: "asset"; assetId: number }
  | { kind: "page"; page: number; edge: "prev" | "next" }
  | { kind: "none" };

/** Where a move to a 0-based position (across pages) goes: an asset of this page, the previous / next page, or nowhere
 * (before the first row or past the total). */
export function navTarget(snap: NavSnapshot, index: number): NavTarget {
  const total = Math.max(snap.total, (snap.page - 1) * snap.pageSize + snap.ids.length);
  if (!Number.isInteger(index) || index < 0 || index >= total) return { kind: "none" };
  const local = index - (snap.page - 1) * snap.pageSize;
  if (local >= 0 && local < snap.ids.length) return { kind: "asset", assetId: snap.ids[local] };
  if (local < 0) return snap.page > 1 ? { kind: "page", page: snap.page - 1, edge: "prev" } : { kind: "none" };
  return { kind: "page", page: snap.page + 1, edge: "next" };
}

/** The asset to open once the page asked for by a page edge has loaded: its first row (Next) or last row (Previous). */
export function landingAsset(snap: NavSnapshot, edge: "prev" | "next"): number | null {
  if (snap.ids.length === 0) return null;
  return edge === "next" ? snap.ids[0] : snap.ids[snap.ids.length - 1];
}

/** "n of N" (1-based), or null when the position is unknown. */
export function positionLabel(index: number, total: number): string | null {
  if (index < 0 || total <= 0) return null;
  return `${index + 1} of ${total}`;
}

export function canGo(nav: Pick<DialogNav, "index" | "total" | "pageEdge">, dir: -1 | 1): boolean {
  if (nav.pageEdge || nav.index < 0) return false;
  const next = nav.index + dir;
  return next >= 0 && next < nav.total;
}

/** ←/→ move only when focus is not where those keys already mean something (a tab list, a text field, a select, an
 * editable element, a slider) and no nested layer (AI sheet, explanations drawer, menu, tooltip) is open. */
export function arrowKeysMove(target: { closest?: (sel: string) => unknown; tagName?: string; isContentEditable?: boolean } | null,
  nestedOpen: boolean): boolean {
  if (nestedOpen) return false;
  if (!target) return true;
  const tag = (target.tagName ?? "").toUpperCase();
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return false;
  if (target.isContentEditable) return false;
  const inside = (sel: string) => !!target.closest?.(sel);
  return !inside('[role="tablist"]') && !inside('[role="slider"]') && !inside('[role="listbox"]') && !inside('[role="menu"]')
    && !inside('[role="combobox"]') && !inside("[contenteditable=true]");
}
