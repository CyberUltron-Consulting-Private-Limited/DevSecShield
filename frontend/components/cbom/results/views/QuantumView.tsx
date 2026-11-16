"use client";

// Quantum grades & fix effort (results redesign 05-C + 06-B): the run's quantum-risk grade distribution (why an asset
// is unknown, what was not read, the model line, "How grades are computed") and the crypto-agility card (who fixes it),
// both from GET /runs/{id}/posture, with its loading and error-with-retry states. A run that read no asset still lists
// its unread items here.

import { AgilityPostureCard, QDistributionCard } from "@/components/cbom/grade";
import { useRunPostureQuery } from "@/components/cbom/sources/RunPosture";
import { ErrorBlock, LoadingBlock } from "@/components/cbom/sources/shared";

import { SectionNote } from "../RunSections";
import type { RunViewCtx } from "./types";

export function QuantumView({ ctx }: { ctx: RunViewCtx }) {
  const { run } = ctx;
  const query = useRunPostureQuery(run.teamId, run.runId, run.active);
  if (query.isLoading) return <LoadingBlock />;
  if (query.isError || !query.data) return <ErrorBlock error={query.error} onRetry={() => query.refetch()} />;
  const p = query.data;
  if (p.assets === 0) {
    return (p.q0_items_total ?? 0) > 0
      ? <QDistributionCard teamId={run.teamId} posture={p} onOpenAsset={(id) => run.openAsset(id)} variant="run" />
      : <SectionNote testId="run-quantum-empty">This run read no asset, so there is nothing to grade.</SectionNote>;
  }
  return (
    // stacked at every width (mockup F3): side by side, the agility card's five "who fixes it" cards were ~90 px wide
    <div className="grid grid-cols-1 gap-6 items-start" data-testid="run-quantum-cards">
      <QDistributionCard teamId={run.teamId} posture={p} onOpenAsset={(id) => run.openAsset(id)} variant="run" />
      <AgilityPostureCard teamId={run.teamId} posture={p} variant="run" />
    </div>
  );
}
