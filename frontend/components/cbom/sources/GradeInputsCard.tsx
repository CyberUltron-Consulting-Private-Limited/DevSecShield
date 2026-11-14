"use client";

// CB-19 PR-2, Review & Run: the quantum risk grade inputs the next run records at Start. The run grades with these
// (the record); a change made after Start applies to new runs and is shown on the run page beside the record.

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { getCbomEvidence, getCbomSourcesSettings, listCbomSources } from "@/utils/backend_api";

import { moscaText } from "@/components/cbom/grade/inputs";
import { cbomSourcesKeys } from "./keys";
import { pluralize } from "./logic";
import { MoscaEditor } from "./RunPosture";
import { SectionCard, StatusBadge, Truncate } from "./shared";

export default function GradeInputsCard({ teamId, isAdmin }: { teamId: number; isAdmin: boolean }) {
  const [edit, setEdit] = useState(false);
  const settings = useQuery({ queryKey: cbomSourcesKeys.settings(teamId), queryFn: () => getCbomSourcesSettings(teamId), retry: 1 });
  const sources = useQuery({ queryKey: cbomSourcesKeys.sources(teamId, "all"), queryFn: () => listCbomSources(teamId), retry: 1 });
  const evidence = useQuery({ queryKey: cbomSourcesKeys.evidence(teamId), queryFn: () => getCbomEvidence(teamId), retry: 1 });
  if (!settings.data) return null;
  const rm = settings.data.risk_model ?? { data_shelf_life_years: null, migration_years: null, threat_years: null };
  const mosca = { x: rm.data_shelf_life_years ?? null, y: rm.migration_years ?? null, z: rm.threat_years ?? null };
  const set = mosca.x != null && mosca.y != null && mosca.z != null;
  const withLifetime = (sources.data?.sources ?? []).filter((s) => typeof s.config?.data_lifetime_years === "number");
  const gaps = (evidence.data?.q0_gaps ?? []).filter((g) => g.counted);
  return (
    <SectionCard title="Grade inputs"
                 description="Recorded when you start a run: the run's quantum risk grades use these, whatever changes later">
      <div className="space-y-3 text-sm" data-testid="grade-inputs-card">
        <div className="flex flex-wrap items-center gap-2" data-testid="grade-inputs-mosca" data-mosca={moscaText(mosca)}>
          <span className="text-zinc-700 dark:text-zinc-300">Mosca X/Y/Z (years):</span>
          <span className="font-mono">{moscaText(mosca)}</span>
          {!set && <StatusBadge tone="amber">Not set: quantum-vulnerable assets grade as Unknown</StatusBadge>}
          {isAdmin ? (
            <button type="button" className="text-xs text-blue-600 dark:text-blue-400 cursor-pointer"
                    data-testid="grade-inputs-mosca-edit" onClick={() => setEdit(!edit)}>
              {set ? "Change X, Y, Z" : "Set X, Y, Z"}
            </button>
          ) : (
            <span className="text-xs text-zinc-500">A team admin sets X, Y and Z</span>
          )}
        </div>
        {edit && isAdmin && <MoscaEditor teamId={teamId} onDone={() => setEdit(false)} />}
        <div>
          <p className="text-xs text-zinc-500">
            Data lifetime per source (X for that source&apos;s assets; others use the team&apos;s X)
          </p>
          {withLifetime.length === 0 ? (
            <p className="text-xs text-zinc-500" data-testid="grade-inputs-lifetimes-none">No source sets its own data lifetime</p>
          ) : (
            <ul className="text-xs text-zinc-700 dark:text-zinc-300" data-testid="grade-inputs-lifetimes">
              {withLifetime.map((s) => (
                <li key={s.id} className="flex gap-2"><Truncate text={s.name} /> <span>{s.config.data_lifetime_years} y</span></li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <p className="text-xs text-zinc-500">
            Evidence recorded with the run: {pluralize(gaps.length, "Q0 gap")}
          </p>
          {gaps.length > 0 && (
            <ul className="text-xs text-zinc-700 dark:text-zinc-300" data-testid="grade-inputs-gaps">
              {gaps.map((g) => (
                <li key={g.id} data-testid={`grade-inputs-gap-${g.id}`} data-reason={g.reason}>
                  {g.title}: {g.text}
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </SectionCard>
  );
}
