"use client";

// Collection jobs and targets (results redesign 03-B): every job, the sources skipped at the start, the provenance per
// source and each target's outcome (RunCoverageSection, with the lab-mode note and the "No jobs in this run" state).

import { RunCoverageSection } from "../RunSections";
import type { RunViewCtx } from "./types";

export function CollectionView({ ctx }: { ctx: RunViewCtx }) {
  const { run } = ctx;
  if (!run.run) return null;
  return <RunCoverageSection run={run.run} targets={run.page?.targets ?? null} provenance={run.results?.provenance} />;
}
