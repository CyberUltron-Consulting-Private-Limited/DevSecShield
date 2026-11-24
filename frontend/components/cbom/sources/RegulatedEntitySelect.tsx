"use client";

// SOW audit A-11: the team's regulatory profile. The regulated-entity type picks the RBI instrument the regulatory
// mapping cites (an NBFC is mapped to the RBI NBFC Directions 2026, never to the Commercial Banks Directions); three
// facts decide whether PCI DSS, SEBI CSCRF and the CERT-In government guidelines apply. Admins only.
// Review m7 (deploy skew): rendered only when the server sends the setting, so an older backend shows nothing.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { InfoTip } from "@/components/ui/info-tip";
import { getCbomSourcesSettings, updateCbomSourcesSettings, type CbomSettingsWrite } from "@/utils/backend_api";
import { handleApiError } from "@/utils/error-handler";

import { cbomSourcesKeys } from "./keys";
import {
  REGULATED_ENTITY_CHOICES,
  REGULATORY_FLAGS,
  hasRegulatoryProfile,
  regulatedEntityOf,
  regulatoryFlagsOf,
} from "./regulatedEntity";

export default function RegulatedEntitySelect({ teamId, isAdmin }: { teamId: number; isAdmin: boolean }) {
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: cbomSourcesKeys.settings(teamId), queryFn: () => getCbomSourcesSettings(teamId) });
  const [error, setError] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (change: CbomSettingsWrite) =>
      updateCbomSourcesSettings(teamId, { ...change, expected_version: settings.data?.row_version }),
    onSuccess: () => {
      setError(null);
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
    },
    onError: (err) => {
      setError(handleApiError(err).message);
      queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });
    },
  });
  if (!settings.data || !hasRegulatoryProfile(settings.data)) return null;
  const current = regulatedEntityOf(settings.data.regulated_entity);
  const chosen = REGULATED_ENTITY_CHOICES.find((c) => c.value === current) ?? REGULATED_ENTITY_CHOICES[0];
  const flags = regulatoryFlagsOf(settings.data);
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
          onChange={(e) => save.mutate({ regulated_entity: regulatedEntityOf(e.target.value) })}
        >
          {REGULATED_ENTITY_CHOICES.map((c) => (
            <option key={c.value} value={c.value}>{c.label}</option>
          ))}
        </select>
      </label>
      <p className="text-xs text-zinc-500" data-testid="regulated-entity-instrument">
        {chosen.instrument
          ? `The deliverables cite the ${chosen.instrument}.`
          : "No RBI cybersecurity direction binds this entity type, so no RBI clause is cited."}
        {isAdmin ? "" : " A team admin can change this."}
      </p>
      {REGULATORY_FLAGS.filter((f) => f.value in flags).map((f) => (
        <label key={f.value} className="flex items-center gap-2 text-sm" htmlFor={`regulatory-${f.value}-${teamId}`}>
          <input
            id={`regulatory-${f.value}-${teamId}`}
            type="checkbox"
            data-testid={`regulatory-flag-${f.value}`}
            checked={flags[f.value] === true}
            disabled={!isAdmin || save.isPending}
            onChange={(e) => save.mutate({ [f.value]: e.target.checked })}
          />
          <span className="text-zinc-700 dark:text-zinc-300">{f.label}</span>
          <InfoTip id={f.tip} />
        </label>
      ))}
      {error && <p className="text-xs text-red-600 dark:text-red-400" role="alert">{error}</p>}
    </div>
  );
}
