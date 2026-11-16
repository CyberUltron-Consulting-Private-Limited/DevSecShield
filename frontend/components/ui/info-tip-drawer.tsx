"use client";

/**
 * The Explanations drawer (results redesign, board 36-D): every (i) tip of a view in one searchable list, opened from
 * an "Explanations" button or from a tip's "More in Explanations ›" link, scrolled to that tip. Opt-in: only below an
 * <InfoTipDrawerProvider>; without one, <InfoTip> renders exactly as before and the button renders nothing.
 *
 * The text is the registry's (what / why it matters / example), loaded per area with loadTipArea like the tips
 * themselves; the drawer shows loading and error states (with a retry) per area. Entries carry `data-infotip-entry`,
 * never `data-infotip` (that attribute marks the (i) buttons, which tests and the staging id collection count).
 *
 * mode "sheet" (a page): a Radix Sheet on the right. mode "inline" (inside a Radix Dialog, so the dialog keeps focus
 * and does not close): an absolutely positioned panel over the right of the host, which must be positioned (a
 * DialogContent is) and should close it on Escape (useInfoTipDrawer().isOpen / close()).
 */
import { BookOpen, Search, X } from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  useSyncExternalStore,
  type ReactNode,
} from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import {
  INFO_TIP_LABELS,
  areaOf,
  loadTipArea,
  subscribeTipAreas,
  tipAreaState,
  type InfoTipId,
  type InfoTipText,
  type TipArea,
} from "@/content/infotips";
import { DRAWER_VIEW_LABEL, drawerIds, type DrawerView } from "@/content/infotips/drawerManifest";
import { cn } from "@/lib/utils";

import { DrawerContext, useInfoTipDrawer, type InfoTipDrawerApi } from "./info-tip-drawer-context";

export { useInfoTipDrawer, type InfoTipDrawerApi };

export function InfoTipDrawerProvider({ view, mode = "sheet", children }: {
  view: DrawerView;
  mode?: "sheet" | "inline";
  children?: ReactNode;
}) {
  const [isOpen, setIsOpen] = useState(false);
  const [focusId, setFocusId] = useState<InfoTipId | null>(null);
  // a new request for the same id scrolls again
  const [request, setRequest] = useState(0);
  // the search, here so a request for one tip can clear it (the entry is then there to scroll to)
  const [query, setQuery] = useState("");
  const returnFocus = useRef<HTMLElement | null>(null);
  const open = useCallback((id?: InfoTipId) => {
    if (typeof document !== "undefined" && document.activeElement instanceof HTMLElement) returnFocus.current = document.activeElement;
    setFocusId(id ?? null);
    if (id) setQuery("");
    setRequest((n) => n + 1);
    setIsOpen(true);
  }, []);
  const close = useCallback(() => {
    setIsOpen(false);
    if (mode === "inline") {
      const el = returnFocus.current;
      returnFocus.current = null;
      if (el && el.isConnected) queueMicrotask(() => el.focus());
    }
  }, [mode]);
  const api = useMemo<InfoTipDrawerApi>(() => ({ open, close, isOpen, view }), [open, close, isOpen, view]);
  const body = <DrawerBody view={view} focusId={focusId} request={request} open={isOpen} onClose={close} inline={mode === "inline"}
                           query={query} setQuery={setQuery} />;
  return (
    <DrawerContext.Provider value={api}>
      {children}
      {mode === "sheet" ? (
        <Sheet open={isOpen} onOpenChange={(o) => (o ? setIsOpen(true) : close())}>
          <SheetContent side="right" className="w-full sm:max-w-md gap-0 p-0" data-testid="infotip-drawer">
            <SheetHeader className="border-b border-zinc-200 dark:border-zinc-800">
              <SheetTitle>Explanations</SheetTitle>
              <SheetDescription>{DRAWER_VIEW_LABEL[view]}: what each (i) on this page explains</SheetDescription>
            </SheetHeader>
            {body}
          </SheetContent>
        </Sheet>
      ) : (
        <aside hidden={!isOpen} aria-label="Explanations" data-testid="infotip-drawer"
               className="absolute inset-y-0 right-0 z-30 flex w-full sm:w-[380px] flex-col border-l border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 shadow-2xl">
          <div className="flex items-start justify-between gap-2 border-b border-zinc-200 dark:border-zinc-800 p-4">
            <div className="min-w-0">
              <div className="font-semibold text-zinc-900 dark:text-zinc-100">Explanations</div>
              <div className="text-xs text-zinc-500 dark:text-zinc-400">{DRAWER_VIEW_LABEL[view]}: what each (i) here explains</div>
            </div>
            <Button type="button" variant="ghost" size="sm" className="h-7 w-7 p-0 cursor-pointer" aria-label="Close explanations"
                    onClick={close} data-testid="infotip-drawer-close">
              <X className="h-4 w-4" />
            </Button>
          </div>
          {body}
        </aside>
      )}
    </DrawerContext.Provider>
  );
}

/** The "Explanations" button of a page or dialog header; nothing without a provider. */
export function ExplanationsButton({ className, testId = "infotip-drawer-open" }: { className?: string; testId?: string }) {
  const drawer = useInfoTipDrawer();
  if (!drawer) return null;
  return (
    <Button type="button" variant="outline" size="sm" className={cn("h-8 gap-1.5 cursor-pointer", className)}
            aria-haspopup="dialog" aria-expanded={drawer.isOpen} data-testid={testId} onClick={() => drawer.open()}>
      <BookOpen className="h-3.5 w-3.5" aria-hidden="true" /> Explanations
    </Button>
  );
}

/** The areas' load states as one string (a stable snapshot for useSyncExternalStore). */
function useAreaStates(areas: TipArea[]): string {
  return useSyncExternalStore(
    subscribeTipAreas,
    () => areas.map((a) => tipAreaState(a)?.status ?? "idle").join(","),
    () => areas.map(() => "idle").join(","),
  );
}

export function matchesQuery(label: string, text: InfoTipText | undefined, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [label, text?.what, text?.why, text?.example].some((s) => !!s && s.toLowerCase().includes(q));
}

function DrawerBody({ view, focusId, request, open, onClose, inline, query, setQuery }: {
  view: DrawerView; focusId: InfoTipId | null; request: number; open: boolean; onClose: () => void; inline: boolean;
  query: string; setQuery: (q: string) => void;
}) {
  const searchId = useId();
  const listRef = useRef<HTMLDivElement | null>(null);
  const searchRef = useRef<HTMLInputElement | null>(null);
  const ids = useMemo(() => {
    const listed = drawerIds(view);
    return focusId && !listed.includes(focusId) ? [focusId, ...listed] : listed;
  }, [view, focusId]);
  const areas = useMemo(() => [...new Set(ids.map((id) => areaOf(id)).filter((a): a is TipArea => !!a))], [ids]);
  const states = useAreaStates(areas);
  const load = useCallback(() => {
    for (const a of areas) loadTipArea(a).catch(() => {});
  }, [areas]);
  useEffect(() => {
    if (open) load();
  }, [open, load]);
  // inline (no Radix focus management): the search field takes focus when the drawer opens without a tip
  useEffect(() => {
    if (open && inline && !focusId) searchRef.current?.focus();
  }, [open, inline, focusId, request]);
  // scroll to the asked tip once per request (its entry is there from the first render; its text may follow)
  const scrolled = useRef(-1);
  useEffect(() => {
    if (!open) {
      scrolled.current = -1;
      return;
    }
    if (!focusId || scrolled.current === request) return;
    const el = listRef.current?.querySelector<HTMLElement>(`[data-infotip-entry="${focusId}"]`);
    if (!el) return;
    scrolled.current = request;
    if (typeof el.scrollIntoView === "function") el.scrollIntoView({ block: "start" });
    el.focus({ preventScroll: true });
  }, [open, focusId, request, states, query]);
  // inline: Escape inside the panel closes it (the host dialog also asks via isOpen)
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (inline && e.key === "Escape") {
      e.stopPropagation();
      onClose();
    }
  };
  const statusOf = (area: TipArea | undefined) => (area ? tipAreaState(area)?.status : undefined);
  const loading = areas.some((a) => statusOf(a) === "loading" || statusOf(a) === undefined);
  const failed = areas.filter((a) => statusOf(a) === "error");
  const textOf = (id: InfoTipId): InfoTipText | undefined => {
    const st = statusOf(areaOf(id));
    const s = st === "ready" ? tipAreaState(areaOf(id) as TipArea) : undefined;
    return s && s.status === "ready" ? s.text[id] : undefined;
  };
  const shown = ids.filter((id) => matchesQuery(INFO_TIP_LABELS[id], textOf(id), query));
  return (
    <div className="flex min-h-0 flex-1 flex-col" onKeyDown={onKeyDown}>
      <div className="p-3 border-b border-zinc-200 dark:border-zinc-800">
        <label htmlFor={searchId} className="sr-only">Search explanations</label>
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-400" aria-hidden="true" />
          <Input id={searchId} ref={searchRef} type="search" value={query} onChange={(e) => setQuery(e.target.value)}
                 placeholder="Search explanations…" className="h-8 pl-8 text-sm" data-testid="infotip-drawer-search" />
        </div>
        {loading && <p className="mt-2 text-xs text-zinc-500" data-testid="infotip-drawer-loading">Loading explanations…</p>}
        {failed.length > 0 && (
          <p className="mt-2 flex flex-wrap items-center gap-2 text-xs text-amber-700 dark:text-amber-400" role="alert" data-testid="infotip-drawer-error">
            Some explanations could not be loaded.
            <Button type="button" variant="outline" size="sm" className="h-6 text-xs cursor-pointer" onClick={load}>Retry</Button>
          </p>
        )}
      </div>
      <div ref={listRef} className="min-h-0 flex-1 overflow-y-auto overscroll-contain p-3 space-y-2" data-testid="infotip-drawer-list"
           data-states={states}>
        {shown.length === 0 && <p className="text-xs text-zinc-500">No explanation matches “{query}”.</p>}
        {shown.map((id) => {
          const text = textOf(id);
          const st = statusOf(areaOf(id));
          return (
            <section key={id} data-infotip-entry={id} tabIndex={-1} aria-label={INFO_TIP_LABELS[id]}
                     className={cn("rounded-lg border p-3 text-xs scroll-mt-2 focus:outline-none",
                       id === focusId ? "border-blue-500 bg-blue-50/60 dark:bg-blue-950/30" : "border-zinc-200 dark:border-zinc-800")}>
              <div className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{INFO_TIP_LABELS[id]}</div>
              {text ? (
                <>
                  <div className="mt-1 text-zinc-700 dark:text-zinc-300">{text.what}</div>
                  {text.why && <div className="mt-1 text-zinc-700 dark:text-zinc-300"><span className="text-zinc-500">Why it matters: </span>{text.why}</div>}
                  <div className="mt-1 text-zinc-600 dark:text-zinc-400"><span className="text-zinc-500">Example: </span>{text.example}</div>
                </>
              ) : (
                <div className="mt-1 text-zinc-500">{st === "error" ? "This explanation could not be loaded." : "Loading…"}</div>
              )}
            </section>
          );
        })}
      </div>
    </div>
  );
}
