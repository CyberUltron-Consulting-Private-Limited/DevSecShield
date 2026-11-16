"use client";

// React glue for dialogNav.ts: holds the snapshot of the findings-table page a finding dialog was opened from, and
// turns Previous / Next into an asset (same page) or a page move (onFilters({ page })) followed by that page's first /
// last row once it has loaded (not while the table shows the previous page as placeholder data). Integration calls
// openFromTable(item) from the table's row / Details handlers and passes `nav` to <RunFindingDialog nav={…} />; a
// dialog opened any other way (top risks, certificates, PQC list, Unknown-grade items) gets nav === undefined.

import { useCallback, useEffect, useMemo, useState } from "react";

import {
  absoluteIndex,
  landingAsset,
  navTarget,
  refreshSnapshot,
  snapshotOf,
  type DialogNav,
  type NavSnapshot,
} from "./dialogNav";

export interface DialogNavInput {
  /** the asset the dialog shows (null: closed) */
  assetId: number | null;
  /** opens the dialog on another asset of the table */
  open: (assetId: number) => void;
  /** the live findings-table page */
  items: readonly { id: number }[] | undefined;
  page: number;
  pageSize: number;
  /** the table's total row count (N of "n of N") */
  total: number;
  /** true while the table still shows the previous page's rows (keepPreviousData) */
  placeholder: boolean;
  /** moves the table to another page */
  goToPage: (page: number) => void;
}

export interface NavState {
  snap: NavSnapshot | null;
  pending: { page: number; edge: "prev" | "next" } | null;
  /** the row to open once a page edge's page has loaded (`n` makes each landing new; `arrived` once the dialog shows it) */
  landing: { id: number; n: number; arrived: boolean } | null;
}

export const NAV_IDLE: NavState = { snap: null, pending: null, landing: null };

/** The state after this render's inputs. Pure: the hook stores it when it changed (React's "adjust state while
 * rendering" pattern), so no effect sets state. */
export function nextNavState(st: NavState, input: Pick<DialogNavInput, "assetId" | "items" | "page" | "pageSize" | "total" | "placeholder">): NavState {
  const { assetId, items, page, pageSize, total, placeholder } = input;
  if (!st.snap) return st;
  // the dialog closed: no navigation
  if (assetId == null) return { snap: null, pending: null, landing: st.landing && { ...st.landing, arrived: true } };
  // a page edge: wait for the asked page (not the placeholder rows of the page before), then take it and land on its
  // first (Next) or last (Previous) row
  if (st.pending) {
    if (placeholder || !items || page !== st.pending.page) return st;
    const snap = snapshotOf(items, page, pageSize, total);
    const id = landingAsset(snap, st.pending.edge);
    return { snap, pending: null, landing: id == null ? st.landing : { id, n: (st.landing?.n ?? 0) + 1, arrived: false } };
  }
  if (st.landing && !st.landing.arrived) {
    // until the dialog shows the landing row, it still shows the previous page's row
    return assetId === st.landing.id ? { ...st, landing: { ...st.landing, arrived: true } } : st;
  }
  // an asset the snapshot does not hold (opened some other way): no navigation
  if (!st.snap.ids.includes(assetId)) return { ...st, snap: null };
  // the same page refreshed (live run, a status change): new rows join, removed rows keep their slot
  if (!placeholder && items && page === st.snap.page) {
    const snap = refreshSnapshot(st.snap, items, total);
    if (snap !== st.snap) return { ...st, snap };
  }
  return st;
}

export function useDialogNav(input: DialogNavInput): { nav: DialogNav | undefined; openFromTable: (assetId: number) => void } {
  const { assetId, open, items, page, pageSize, total, placeholder, goToPage } = input;
  const [stored, setStored] = useState<NavState>(NAV_IDLE);
  const st = nextNavState(stored, { assetId, items, page, pageSize, total, placeholder });
  if (st !== stored) setStored(st);

  const openFromTable = useCallback((id: number) => {
    setStored((s) => ({ snap: snapshotOf(items ?? [], page, pageSize, total), pending: null, landing: s.landing && { ...s.landing, arrived: true } }));
    open(id);
  }, [items, page, pageSize, total, open]);

  // open the landing row of a page edge (the parent's state, so after render)
  const landingN = st.landing?.n;
  const landingId = st.landing?.id;
  useEffect(() => {
    if (landingId != null) open(landingId);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per landing (n), not when `open` changes identity
  }, [landingN]);

  const { snap, pending } = st;
  const nav = useMemo<DialogNav | undefined>(() => {
    if (!snap || assetId == null) return undefined;
    return {
      ids: snap.ids,
      index: absoluteIndex(snap, assetId),
      total: Math.max(snap.total, snap.ids.length),
      pageEdge: pending?.edge ?? null,
      onGo: (index: number) => {
        const t = navTarget(snap, index);
        if (t.kind === "asset") open(t.assetId);
        else if (t.kind === "page") {
          setStored((s) => ({ ...s, pending: { page: t.page, edge: t.edge } }));
          goToPage(t.page);
        }
      },
    };
  }, [snap, assetId, pending, open, goToPage]);

  return { nav, openFromTable };
}
