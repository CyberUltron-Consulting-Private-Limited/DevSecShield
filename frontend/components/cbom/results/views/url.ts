"use client";

// The run results page's URL (results redesign §1): `section` (which view: the summary, or one detail view), `view`
// (the findings table's Findings / All assets toggle) and `origin` (where the Back button returns). One writer: every
// change goes through `patch`, which merges into the URL as it is at call time, so two changes in the same tick (a
// drill that switches the table to All assets and returns to the summary) never drop each other. Tile clicks and
// "Back to summary" push a history entry; filters and in-view changes replace the current one.

import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo } from "react";

export const DETAIL_SECTIONS = ["collection", "quantum", "inventory", "migration", "compliance", "remediation"] as const;
export type DetailSection = (typeof DETAIL_SECTIONS)[number];
/** "" is the summary (no `section` in the URL) */
export type ResultsSection = "" | DetailSection;
export type TableView = "findings" | "all";

export function parseSection(raw: string | null | undefined): ResultsSection {
  return (DETAIL_SECTIONS as readonly string[]).includes(raw ?? "") ? (raw as DetailSection) : "";
}

export function parseView(raw: string | null | undefined): TableView {
  return raw === "all" ? "all" : "findings";
}

export interface UrlPatch {
  section?: ResultsSection;
  view?: TableView;
}

/** The query string (with "?", or "" when empty) after applying `patch` to `search`; other keys (run, origin …) kept. */
export function mergeResultsSearch(search: string, patch: UrlPatch): string {
  const qs = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  if (patch.section !== undefined) {
    if (patch.section) qs.set("section", patch.section);
    else qs.delete("section");
  }
  if (patch.view !== undefined) qs.set("view", patch.view);
  const out = qs.toString();
  return out ? `?${out}` : "";
}

/** How long a written URL is the base of the next write while the router has not shown it yet. */
export const PENDING_MS = 1500;

/** The single URL writer, without React or Next (unit-tested): `read` is the URL's query now, `write` navigates.
 * A write the router has not committed yet is the base of the next one (`settle` clears it once the URL shows it). */
export function createUrlWriter(io: {
  read: () => string;
  write: (search: string, push: boolean) => void;
  now?: () => number;
}) {
  const now = io.now ?? (() => Date.now());
  let pending: { search: string; at: number } | null = null;
  const norm = (s: string) => (s.startsWith("?") ? s.slice(1) : s);
  return {
    patch(p: UrlPatch, opts: { push?: boolean } = {}): string {
      const base = pending && now() - pending.at < PENDING_MS ? pending.search : io.read();
      const next = mergeResultsSearch(base, p);
      pending = { search: next, at: now() };
      io.write(next, !!opts.push);
      return next;
    },
    /** the URL now shows `search`: a pending write that it matches is done */
    settle(search: string) {
      if (pending && norm(pending.search) === norm(search)) pending = null;
    },
  };
}

// one writer per page: the route (the table's Findings / All assets toggle) and the template (the section) both write
const nav: { go: (search: string, push: boolean) => void } = { go: () => undefined };
const writer = createUrlWriter({
  read: () => (typeof window !== "undefined" ? window.location.search : ""),
  write: (search, push) => nav.go(search, push),
});

export function useResultsUrl() {
  const search = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const section = parseSection(search?.get("section"));
  const view = parseView(search?.get("view"));
  const origin = search?.get("origin") ?? null;
  const qs = search?.toString() ?? "";

  // the URL now shows what was written: the next write reads it again
  useEffect(() => writer.settle(qs), [qs]);

  const patch = useCallback((p: UrlPatch, opts?: { push?: boolean }) => {
    nav.go = (s, push) => {
      const href = `${pathname ?? ""}${s}`;
      if (push) router.push(href, { scroll: false });
      else router.replace(href, { scroll: false });
    };
    writer.patch(p, opts);
  }, [router, pathname]);

  return useMemo(() => ({ section, view, origin, patch }), [section, view, origin, patch]);
}
