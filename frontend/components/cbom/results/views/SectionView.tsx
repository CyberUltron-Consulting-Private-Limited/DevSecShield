"use client";

// The frame of a detail view (results redesign §3): "‹ Back to summary" (the browser's Back when the summary opened it),
// the view's title with its tip, then its content, or a loader while the data it needs is still loading. A view whose
// data is not available renders its sections' own one-line notes (never an empty page, never a silent redirect).

import { ChevronLeft } from "lucide-react";
import type { ReactNode } from "react";

import { InfoTip } from "@/components/ui/info-tip";
import { LoadingBlock } from "@/components/cbom/sources/shared";

import { SECTION_META } from "./types";
import type { DetailSection } from "./url";

export function SectionView({ section, onBack, loading = false, children }: {
  section: DetailSection;
  onBack: () => void;
  loading?: boolean;
  children: ReactNode;
}) {
  const meta = SECTION_META[section];
  return (
    <section className="space-y-6 min-w-0" data-testid={`results-section-${section}`} aria-labelledby={`results-section-${section}-title`}>
      <div className="space-y-2">
        <button type="button" onClick={onBack} data-testid="results-back"
                className="inline-flex items-center gap-0.5 text-sm font-medium text-blue-600 hover:underline dark:text-blue-400 cursor-pointer">
          <ChevronLeft className="h-4 w-4" aria-hidden /> Back to summary
        </button>
        {/* focus lands here after a tile's Open (CbomResults), so keyboard users start in the new view */}
        <h2 id={`results-section-${section}-title`} tabIndex={-1} data-testid="results-section-title"
            className="text-xl font-semibold text-zinc-900 dark:text-white rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500">
          {meta.title} <InfoTip id={meta.tip} />
        </h2>
      </div>
      {loading ? <div data-testid={`results-section-${section}-loading`}><LoadingBlock /></div> : children}
    </section>
  );
}
