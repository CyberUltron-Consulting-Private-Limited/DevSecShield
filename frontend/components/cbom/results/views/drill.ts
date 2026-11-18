"use client";

// Drill-downs of the run results page (results redesign §1): every "show these assets" link (compliance counts,
// readiness actions, RBI / CERT-In requirements, the posture's "Show these N") filters the findings table, makes sure a
// view with the table is on screen (the summary, or the remediation view, which also lists it), then scrolls to
// #bom-findings from an effect once the table is mounted (not from requestAnimationFrame: after a view switch the table
// mounts a render later).

import { useCallback, useEffect, useRef } from "react";

import type { CbomFinding } from "@/utils/backend_api";

import { runAssetId, runDrillFilters } from "../complianceSummary";
import type { RunTableFilters } from "../model";
import type { ResultsSection } from "./url";

export const FINDINGS_ANCHOR = "bom-findings";

/** The views that render the findings table. */
export const SECTIONS_WITH_FINDINGS: readonly ResultsSection[] = ["", "remediation"];

/** Where a drill goes: null stays in the current view (it has the table), else the summary. */
export function drillTarget(section: ResultsSection): ResultsSection | null {
  return SECTIONS_WITH_FINDINGS.includes(section) ? null : "";
}

export type DrillToFindings = (patch: Partial<RunTableFilters>) => void;

/** drillToFindings without React (unit-tested): filter, switch view when needed (a pushed history entry, so Back
 * returns to the view the drill started from), ask for the scroll. */
export function createDrill(io: {
  onFilters: (patch: Partial<RunTableFilters>) => void;
  section: ResultsSection;
  goSection: (section: ResultsSection) => void;
  requestScroll: () => void;
}): DrillToFindings {
  return (patch) => {
    io.onFilters(patch);
    const to = drillTarget(io.section);
    if (to !== null) io.goSection(to);
    io.requestScroll();
  };
}

/** Scrolls to the findings table when it is in the document; false when it is not mounted (yet). */
export function scrollToFindings(doc: Pick<Document, "getElementById"> | undefined): boolean {
  const el = doc?.getElementById(FINDINGS_ANCHOR);
  if (!el) return false;
  el.scrollIntoView({ behavior: "smooth", block: "start" });
  return true;
}

/** The page's scrolling: to the top when the section changes (unless a drill is taking it to the table), and to the
 * findings table after a drill, as soon as the table is mounted. Returns the drill's "scroll when ready" request. */
export function useResultsScroll(section: ResultsSection, enabled: boolean): () => void {
  const pending = useRef(false);
  const shown = useRef(section);
  useEffect(() => {
    if (!enabled || shown.current === section) return;
    shown.current = section;
    if (!pending.current && typeof window !== "undefined") window.scrollTo({ top: 0 });
  }, [section, enabled]);
  // every render: the table may mount on any of them (a view switch, a page of results arriving)
  useEffect(() => {
    if (pending.current && scrollToFindings(typeof document !== "undefined" ? document : undefined)) pending.current = false;
  });
  return useCallback(() => {
    pending.current = true;
    // already on screen (a drill in the summary): scroll now; else the effect above does once the table mounts
    if (scrollToFindings(typeof document !== "undefined" ? document : undefined)) pending.current = false;
  }, []);
}

/** RBI CSF / CERT-In "view findings" on a run: their refs name run assets (`zs-asset-<id>`); null when none does, so
 * the page says so instead of opening an unfiltered table under a drill label. */
export function runRefsDrill(refs: string[], label: string): { patch: Partial<RunTableFilters>; truncated: boolean } | null {
  if (!refs.some((r) => runAssetId(r) != null)) return null;
  return runDrillFilters({ kind: "refs", refs, label });
}

/** The run asset behind a PQC list item (its migration row's asset_id, else its bom-ref `zs-asset-<id>`): the run's
 * finding dialog opens it, never the code scan's dialog. */
export function pqcRunAssetId(f: Pick<CbomFinding, "bom_ref" | "id"> & { asset_id?: number | null }): number | null {
  if (typeof f.asset_id === "number" && f.asset_id > 0) return f.asset_id;
  return runAssetId(f.bom_ref ?? "") ?? runAssetId(f.id ?? "");
}
