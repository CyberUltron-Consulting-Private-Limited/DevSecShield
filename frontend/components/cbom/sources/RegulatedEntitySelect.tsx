"use client";

// FIX-A3 (SOW audit A-11): the regulated-entity type the regulatory mapping uses. An NBFC is mapped to the RBI NBFC
// Directions 2026, never to the Commercial Banks Directions; a bank team switches it here (admins only).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { InfoTip } from "@/components/ui/info-tip";
import { getCbomSourcesSettings, updateCbomSourcesSettings } from "@/utils/backend_api";
import { handleApiError } from "@/utils/error-handler";

import { cbomSourcesKeys } from "./keys";
import { REGULATED_ENTITY_CHOICES, type RegulatedEntity, regulatedEntityOf } from "./regulatedEntity";

export default function RegulatedEntitySelect({ teamId, isAdmin }: { teamId: number; isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: cbomSourcesKeys.settings(teamId), queryFn: () => getCbomSourcesSettings(teamId) });
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (regulated_entity: RegulatedEntity) =>
      updateCbomSourcesSettings(teamId, { regulated_entity, expected_version: settings.data?.row_version }),
    onSuccess: () => {
      setError(null);
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
    },
    onError: (err) => {
      setError(handleApiError(err).message);
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
    },
  });
  if (!settings.data) return null;
  const current = regulatedEntityOf(settings.data.regulated_entity);
  const chosen = REGULATED_ENTITY_CHOICES.find((c) => c.value === current) ?? REGULATED_ENTITY_CHOICES[0];
  return (
    <div className="space-y-1" data-testid="regulated-entity" data-entity={current}>
      <label className="flex flex-wrap items-center gap-2" htmlFor={`regulated-entity-${teamId}`}>
        <span className="text-zinc-700 dark:text-zinc-300">
          Regulated entity (RBI mapping) <InfoTip id="cbsrc.rr.regulated_entity" />:
        </span>
        <select
          id={`regulated-entity-${teamId}`}
          className="rounded-md border border-zinc-300 dark:border-zinc-600 bg-white dark:bg-zinc-900 px-2 py-1 text-sm"
          data-testid="regulated-entity-select"
          value={current}
          disabled={!isAdmin || save.isPending}
          onChange={(e) => save.mutate(regulatedEntityOf(e.target.value))}
        >
          {REGULATED_ENTITY_CHOICES.map((c) => (
            <option key={c.value} value={c.value}>{c.label}</option>
          ))}
        </select>
      </label>
      <p className="text-xs text-zinc-500" data-testid="regulated-entity-instrument">
        The deliverables cite the {chosen.instrument}.{isAdmin ? "" : " A team admin can change this."}
      </p>
      {error && <p className="text-xs text-red-600 dark:text-red-400" role="alert">{error}</p>}
    </div>
  );
}
