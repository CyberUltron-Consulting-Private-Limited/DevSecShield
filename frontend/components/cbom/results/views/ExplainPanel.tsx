"use client";

// "What PQC readiness N% means" (issue #271) as a full-width panel under the posture card (results redesign 37-B,
// revised: horizontal). Collapsed by default behind "Explain N% ▾"; the ReadinessExplainer text is unchanged, laid out
// in three columns from 1024 px. Hidden when the run has no posture or read no asset (as the posture summary is).

import { ChevronDown, ChevronUp } from "lucide-react";
import { useId, useState } from "react";

import type { CbomPostureWithExposure } from "@/utils/api/cbom_outputs";

import { ReadinessExplainer } from "../ReadinessExplainer";
import { readinessExplanation, type ReadinessAction } from "../readinessExplain";

/** The toggle's words: "Explain 16.7%" for a percentage; otherwise ("—", "Not enough identified") "Explain PQC readiness". */
export function explainLabel(value: string): string {
  return /^\d+(\.\d+)?%$/.test(value) ? `Explain ${value}` : "Explain PQC readiness";
}

export function ExplainPanel({ posture, onShowAssets, defaultOpen = false }: {
  posture: CbomPostureWithExposure | null;
  onShowAssets: (action?: ReadinessAction) => void;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = `readiness-explain-${useId().replace(/[^a-zA-Z0-9_-]/g, "")}`;
  if (!posture || posture.assets === 0) return null;
  const value = readinessExplanation(posture).value;
  return (
    <div className="space-y-2" data-testid="readiness-explain">
      <button type="button" aria-expanded={open} aria-controls={panelId} onClick={() => setOpen(!open)}
              className="inline-flex items-center gap-1 rounded-full border border-blue-600/60 px-3 py-1 text-sm font-medium text-blue-700 hover:bg-blue-50 dark:border-blue-400/60 dark:text-blue-300 dark:hover:bg-blue-950/40 cursor-pointer"
              data-testid="readiness-explain-toggle">
        {open ? "Hide the explanation" : explainLabel(value)}
        {open ? <ChevronUp className="h-4 w-4" aria-hidden /> : <ChevronDown className="h-4 w-4" aria-hidden />}
      </button>
      {/* in the DOM while collapsed (hidden), so the toggle always controls an element */}
      <div id={panelId} hidden={!open}>
        <ReadinessExplainer posture={posture} onShowAssets={onShowAssets} layout="columns" />
      </div>
    </div>
  );
}
