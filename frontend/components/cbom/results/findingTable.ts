// #266 / #267: the results template's finding dialog layout, the findings tables' column chooser model (defaults,
// per-user localStorage persistence) and the row-opens-details handlers. Shared by the code-scan table
// (CbomResults.tsx) and the Sources-run table (RunFindingsTable.tsx); pure, so the tests run without a DOM.

/**
 * The finding dialogs (code scan and run) size to their content up to 90vh and the BODY scrolls (#266). DialogContent
 * is a column flexbox with only a max-height, so its height is not definite: a child's `h-full` (the old Radix
 * ScrollArea) resolved to auto and grew to the content (3,504 px) with nothing to scroll. A flex item with
 * `min-h-0` is shrunk to the container's clamped height, so `overflow-y-auto` on that item scrolls at every width.
 */
export const FINDING_DIALOG_CONTENT =
  "sm:max-w-3xl max-h-[90vh] flex flex-col p-0 gap-0 overflow-hidden bg-white dark:bg-zinc-900";
/** Below 640 px the dialog is full screen (PLAN §4.5). */
export const FINDING_DIALOG_FULLSCREEN_SM =
  "max-sm:max-w-none max-sm:w-screen max-sm:h-[100dvh] max-sm:max-h-[100dvh] max-sm:rounded-none max-sm:border-0";
/** The one scroll container of a finding dialog (wheel, touch, and keyboard once focused: it is a tab stop). */
export const FINDING_DIALOG_BODY =
  "flex-1 min-h-0 min-w-0 overflow-y-auto overflow-x-hidden overscroll-contain px-6 pb-6 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-500/60";

// ------------------------------------------------------------------------------------------------- columns

export interface ColumnDef<Id extends string = string> {
  id: Id;
  label: string;
  /** shown until the user changes it */
  defaultVisible: boolean;
}

/** Sources-run findings table: select and Actions are fixed; these are the chooser's columns, in table order. */
export const RUN_TABLE_COLUMNS = [
  { id: "impact", label: "Impact", defaultVisible: true },
  { id: "algorithm", label: "Algorithm", defaultVisible: true },
  { id: "type", label: "Type", defaultVisible: false },
  { id: "where", label: "Where", defaultVisible: true },
  { id: "finding", label: "Finding", defaultVisible: false },
  { id: "strength", label: "Strength", defaultVisible: false },
  { id: "quantum", label: "Quantum", defaultVisible: true },
  { id: "risk", label: "Risk score", defaultVisible: true },
  { id: "source", label: "Source", defaultVisible: false },
  { id: "wave", label: "Wave", defaultVisible: false },
  { id: "status", label: "Status", defaultVisible: true },
  { id: "qgrade", label: "Quantum risk", defaultVisible: false },
  { id: "fixclass", label: "Fix class", defaultVisible: false },
] as const satisfies readonly ColumnDef[];
export type RunColumnId = (typeof RUN_TABLE_COLUMNS)[number]["id"];

/** Code-scan findings table (same template): select and Actions are fixed. */
export const SCAN_TABLE_COLUMNS = [
  { id: "algorithm", label: "Algorithm", defaultVisible: true },
  { id: "type", label: "Type", defaultVisible: false },
  { id: "impact", label: "Impact", defaultVisible: true },
  { id: "strength", label: "Strength", defaultVisible: false },
  { id: "quantum", label: "Quantum", defaultVisible: true },
  { id: "fixclass", label: "Fix class", defaultVisible: false },
  { id: "risk", label: "Risk score", defaultVisible: true },
  { id: "location", label: "Location", defaultVisible: true },
  { id: "status", label: "Status", defaultVisible: true },
] as const satisfies readonly ColumnDef[];
export type ScanColumnId = (typeof SCAN_TABLE_COLUMNS)[number]["id"];

/** The table always keeps one data column, so a row has something to click besides its actions. */
export const MIN_VISIBLE_COLUMNS = 1;

export function defaultColumns<Id extends string>(defs: readonly ColumnDef<Id>[]): Id[] {
  return defs.filter((d) => d.defaultVisible).map((d) => d.id);
}

/** Known ids only, in table order; anything unusable (not an array, nothing known left) falls back to the defaults. */
export function normalizeColumns<Id extends string>(defs: readonly ColumnDef<Id>[], value: unknown): Id[] {
  if (!Array.isArray(value)) return defaultColumns(defs);
  const wanted = new Set(value.filter((v): v is string => typeof v === "string"));
  const ids = defs.filter((d) => wanted.has(d.id)).map((d) => d.id);
  return ids.length >= MIN_VISIBLE_COLUMNS ? ids : defaultColumns(defs);
}

/** Show or hide one column; hiding the last visible one is refused (the list is returned unchanged). */
export function toggleColumn<Id extends string>(defs: readonly ColumnDef<Id>[], visible: readonly Id[], id: Id): Id[] {
  const on = new Set(visible);
  if (on.has(id)) {
    if (on.size <= MIN_VISIBLE_COLUMNS) return [...visible];
    on.delete(id);
  } else {
    on.add(id);
  }
  return defs.filter((d) => on.has(d.id)).map((d) => d.id);
}

/** Per user (the signed-in email, case-folded) and per table; versioned so a later default change can start fresh. */
export function columnPrefsKey(table: "run" | "scan", user: string | null | undefined): string {
  return `dss.cbom.results.columns.v1.${table}.${(user ?? "").trim().toLowerCase() || "_"}`;
}

/** The subset of Storage the prefs use (window.localStorage in the browser; a Map-backed fake in tests). */
export type PrefsStorage = Pick<Storage, "getItem" | "setItem">;

/** Never throws: no storage (SSR, privacy mode), a SecurityError, or corrupt JSON all give the defaults. */
export function loadColumns<Id extends string>(storage: PrefsStorage | null | undefined, key: string,
                                               defs: readonly ColumnDef<Id>[]): Id[] {
  try {
    const raw = storage?.getItem(key);
    return raw == null ? defaultColumns(defs) : normalizeColumns(defs, JSON.parse(raw));
  } catch {
    return defaultColumns(defs);
  }
}

/** Best effort: a full or blocked storage keeps the choice for this page view only. Returns whether it was stored. */
export function saveColumns(storage: PrefsStorage | null | undefined, key: string, visible: readonly string[]): boolean {
  try {
    if (!storage) return false;
    storage.setItem(key, JSON.stringify(visible));
    return true;
  } catch {
    return false;
  }
}

/** window.localStorage, or null where reading it throws (sandboxed iframe, disabled storage) or there is no window. */
export function browserStorage(): PrefsStorage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------- row opens details

/** What a row's handlers need from a DOM event (structural, so tests pass plain objects). */
export interface RowEventLike {
  key?: string;
  target: unknown;
  currentTarget: unknown;
  preventDefault: () => void;
}

/** Controls inside a row keep their own click (checkbox, Action menu, links, the name button). */
export const ROW_INTERACTIVE_SELECTOR =
  "button, a[href], input, select, textarea, label, [role=checkbox], [role=menuitem], [role=menu], [data-row-click-ignore]";

function insideControl(target: unknown, row: unknown): boolean {
  const el = target as { closest?: (s: string) => unknown } | null;
  if (!el || typeof el.closest !== "function") return false;
  const hit = el.closest(ROW_INTERACTIVE_SELECTOR);
  return hit != null && hit !== row;
}

/**
 * Props for a findings row (#267): a click anywhere on the row, or Enter / Space while the row itself has focus,
 * opens the finding dialog. Keys pressed on a control inside the row (Action menu, checkbox) are left alone, and so
 * are clicks on those controls.
 */
export function rowOpenProps(open: () => void, label: string) {
  return {
    tabIndex: 0,
    "aria-haspopup": "dialog" as const,
    "aria-label": label,
    onClick: (e: RowEventLike) => {
      if (insideControl(e.target, e.currentTarget)) return;
      open();
    },
    onKeyDown: (e: RowEventLike) => {
      if (e.target !== e.currentTarget) return;
      if (e.key === "Enter" || e.key === " " || e.key === "Spacebar") {
        e.preventDefault();  // Space would scroll the page
        open();
      }
    },
  };
}

/** Pinned to the right edge at 768 px and up, so Action and Details stay on screen while the table scrolls sideways
 * (below 768 px the select and name columns are the sticky ones and a tap on the row opens the details). */
export const STICKY_ACTIONS =
  "md:sticky md:right-0 md:z-10 bg-white dark:bg-zinc-900 md:shadow-[-6px_0_6px_-6px_rgba(0,0,0,0.15)]";
