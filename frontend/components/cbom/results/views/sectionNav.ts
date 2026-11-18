"use client";

// Moving between the run's summary and its detail views (results redesign §3, review R-ux items 5 and 7).
// - A tile's Open pushes a history entry, so the browser's Back returns to the summary.
// - "Back to summary" uses the browser's Back when the summary pushed this view (no extra history entry, so Back does
//   not return to the view just left); otherwise (a reload, a shared link, a drill from another view) it pushes the
//   summary.
// - Focus follows the view, because the clicked control unmounts: the new view's heading after Open, the tile's Open
//   button after returning.

import { useCallback, useEffect, useRef } from "react";

import type { ResultsSection } from "./url";

type Patch = (patch: { section: ResultsSection }, opts: { push: boolean }) => void;

export function useSectionNav(section: ResultsSection, patch: Patch) {
  const focusAfter = useRef<string | null>(null);
  const summaryBehind = useRef(false);

  const goSection = useCallback((next: ResultsSection) => {
    summaryBehind.current = section === "" && next !== "";
    focusAfter.current = next ? `#results-section-${next}-title` : null;
    patch({ section: next }, { push: true });
  }, [patch, section]);

  const backToSummary = useCallback(() => {
    const returnTo = section ? `[data-testid="results-tile-${section}-open"]` : null;
    if (summaryBehind.current && typeof window !== "undefined") {
      summaryBehind.current = false;
      focusAfter.current = returnTo;
      window.history.back();
    } else {
      goSection("");
      focusAfter.current = returnTo;
    }
  }, [goSection, section]);

  useEffect(() => {
    const sel = focusAfter.current;
    if (!sel) return;
    focusAfter.current = null;
    const raf = requestAnimationFrame(() => document.querySelector<HTMLElement>(sel)?.focus({ preventScroll: true }));
    return () => cancelAnimationFrame(raf);
  }, [section]);

  return { goSection, backToSummary };
}
