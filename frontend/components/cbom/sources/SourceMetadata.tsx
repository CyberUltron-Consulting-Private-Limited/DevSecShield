"use client";

// Source metadata: owner, application, data classification and data lifetime (next to business criticality). They
// describe the source, not how it is reached, so saving them never cancels a job or resets the connection test. A
// form block for the source tabs, and a bulk editor for Review & Run.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { listCbomSources, updateCbomSource, type CbomSource } from "@/utils/backend_api";

import { cbomSourcesKeys } from "./keys";
import { Field, SectionCard, StatusBadge, Truncate } from "./shared";

export const CLASSIFICATIONS = ["public", "internal", "confidential", "restricted"] as const;
export type Classification = (typeof CLASSIFICATIONS)[number];

export interface SourceMetadata {
  owner: string;
  application: string;
  data_classification: Classification | "";
  data_lifetime_years: string;
}

export function metadataFrom(config: Record<string, unknown> | null | undefined): SourceMetadata {
  const c = config ?? {};
  return {
    owner: typeof c.owner === "string" ? c.owner : "",
    application: typeof c.application === "string" ? c.application : "",
    data_classification: (CLASSIFICATIONS as readonly string[]).includes(String(c.data_classification))
      ? (c.data_classification as Classification) : "",
    data_lifetime_years: typeof c.data_lifetime_years === "number" ? String(c.data_lifetime_years) : "",
  };
}

/** The config fields to send (empty clears). Returns null with a message when the lifetime is not 0-100. */
export function metadataConfig(m: SourceMetadata): Record<string, unknown> | string {
  const years = m.data_lifetime_years.trim();
  if (years !== "" && (!/^\d{1,3}$/.test(years) || Number(years) > 100)) return "Data lifetime: a whole number of years from 0 to 100";
  return {
    owner: m.owner.trim() || null,
    application: m.application.trim() || null,
    data_classification: m.data_classification || null,
    data_lifetime_years: years === "" ? null : Number(years),
  };
}

export function MetadataFields({ value, onChange, idPrefix }: {
  value: SourceMetadata;
  onChange: (v: SourceMetadata) => void;
  idPrefix: string;
}) {
  const set = (patch: Partial<SourceMetadata>) => onChange({ ...value, ...patch });
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4" data-testid={`${idPrefix}-metadata`}>
      <Field label="Owner" htmlFor={`${idPrefix}-owner`} hint="Team or person who answers for this source">
        <Input id={`${idPrefix}-owner`} maxLength={128} value={value.owner} onChange={(e) => set({ owner: e.target.value })} />
      </Field>
      <Field label="Application" htmlFor={`${idPrefix}-application`} hint="The business application it serves">
        <Input id={`${idPrefix}-application`} maxLength={128} value={value.application} onChange={(e) => set({ application: e.target.value })} />
      </Field>
      <Field label="Data classification" htmlFor={`${idPrefix}-classification`}>
        <Select value={value.data_classification || "unset"}
                onValueChange={(v) => set({ data_classification: v === "unset" ? "" : (v as Classification) })}>
          <SelectTrigger id={`${idPrefix}-classification`} className="cursor-pointer"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="unset" className="cursor-pointer">Not set</SelectItem>
            {CLASSIFICATIONS.map((c) => <SelectItem key={c} value={c} className="cursor-pointer capitalize">{c}</SelectItem>)}
          </SelectContent>
        </Select>
      </Field>
      <Field label="Data must stay secret for (years)" htmlFor={`${idPrefix}-lifetime`} hint="Mosca's X for this source's data">
        <Input id={`${idPrefix}-lifetime`} inputMode="numeric" value={value.data_lifetime_years}
               onChange={(e) => set({ data_lifetime_years: e.target.value })} />
      </Field>
    </div>
  );
}

/** Review & Run: select sources and set owner / application / classification / lifetime / criticality at once. */
export function SourceMetadataCard({ teamId }: { teamId: number }) {
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: cbomSourcesKeys.sources(teamId, "all"), queryFn: () => listCbomSources(teamId), retry: 1 });
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [draft, setDraft] = useState<SourceMetadata>({ owner: "", application: "", data_classification: "", data_lifetime_years: "" });
  const [criticality, setCriticality] = useState("keep");
  const [error, setError] = useState<string | null>(null);
  const sources = query.data?.sources ?? [];
  const apply = useMutation({
    mutationFn: async (targets: CbomSource[]) => {
      const changes: Record<string, unknown> = {};
      if (draft.owner.trim()) changes.owner = draft.owner.trim();
      if (draft.application.trim()) changes.application = draft.application.trim();
      if (draft.data_classification) changes.data_classification = draft.data_classification;
      if (draft.data_lifetime_years.trim()) {
        const parsed = metadataConfig(draft);
        if (typeof parsed === "string") throw new Error(parsed);
        changes.data_lifetime_years = parsed.data_lifetime_years;
      }
      if (criticality !== "keep") changes.business_criticality = criticality;
      if (Object.keys(changes).length === 0) throw new Error("Enter at least one value to set");
      let done = 0;
      for (const src of targets) {  // one at a time: each keeps its own expected version (a stale one gets a 409)
        await updateCbomSource(teamId, src.id, { config: { ...src.config, ...changes }, expected_version: src.row_version });
        done += 1;
      }
      return done;
    },
    onSuccess: (done) => {
      toast.success(`Updated ${done} source${done === 1 ? "" : "s"}`);
      setSelected(new Set());
      setError(null);
    },
    onError: (err) => setError(err instanceof Error && !("response" in err) ? err.message : "Some sources could not be saved; reload and try again"),
    onSettled: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) }),
  });
  if (query.isLoading || sources.length === 0) return null;
  const toggle = (id: number) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  return (
    <SectionCard title="Owners, applications and data" description="Who answers for each source and how sensitive its data is; set several at once">
      <div className="space-y-3" data-testid="metadata-bulk">
        <ul className="divide-y divide-zinc-200 dark:divide-zinc-800">
          <li className="py-1.5 flex items-center gap-2 text-xs text-zinc-500">
            <input type="checkbox" aria-label="Select all sources" checked={selected.size === sources.length}
                   onChange={(e) => setSelected(e.target.checked ? new Set(sources.map((s) => s.id)) : new Set())} />
            Select all
          </li>
          {sources.map((src) => {
            const m = metadataFrom(src.config);
            return (
              <li key={src.id} className="py-1.5 flex flex-wrap items-center gap-2" data-testid={`metadata-row-${src.id}`}>
                <input type="checkbox" aria-label={`Select ${src.name}`} checked={selected.has(src.id)} onChange={() => toggle(src.id)} />
                <div className="min-w-0 w-48"><Truncate text={src.name} className="text-sm text-zinc-900 dark:text-white" /></div>
                <span className="text-xs text-zinc-500">{m.owner || "no owner"}</span>
                {m.application && <span className="text-xs text-zinc-500">· {m.application}</span>}
                {m.data_classification && <StatusBadge tone={m.data_classification === "restricted" ? "red" : "zinc"}>{m.data_classification}</StatusBadge>}
                {m.data_lifetime_years && <span className="text-xs text-zinc-500">· {m.data_lifetime_years} y</span>}
              </li>
            );
          })}
        </ul>
        <MetadataFields value={draft} onChange={setDraft} idPrefix="bulk" />
        <div className="flex flex-wrap items-end gap-2">
          <Field label="Business criticality" htmlFor="bulk-criticality">
            <Select value={criticality} onValueChange={setCriticality}>
              <SelectTrigger id="bulk-criticality" className="w-[160px] cursor-pointer"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="keep" className="cursor-pointer">Keep</SelectItem>
                {["low", "medium", "high", "critical"].map((c) => <SelectItem key={c} value={c} className="cursor-pointer capitalize">{c}</SelectItem>)}
              </SelectContent>
            </Select>
          </Field>
          <Button size="sm" className="cursor-pointer" disabled={selected.size === 0 || apply.isPending} data-testid="metadata-apply"
                  onClick={() => apply.mutate(sources.filter((s) => selected.has(s.id)))}>
            Apply to {selected.size} source{selected.size === 1 ? "" : "s"}
          </Button>
        </div>
        {error && <p className="text-xs text-red-600 dark:text-red-400" role="alert">{error}</p>}
        <p className="text-xs text-zinc-500">Empty fields are left as they are. Saving never stops a running scan.</p>
      </div>
    </SectionCard>
  );
}
