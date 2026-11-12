"use client";

// Include / exclude rules for repositories: a connection's import filters and a policy's selector use the same form
// (backend/utilities/scm/filters.py). Lists are typed as text (commas or new lines) and parsed on change.

import { useState } from "react";

import { Checkbox2, Field } from "@/components/cbom/sources/shared";
import { Input } from "@/components/ui/input";
import type { ScmFilters, ScmVisibility } from "@/utils/api/scm";

import { joinList, listError, parseList } from "./logic";

type ListKey = "include_names" | "exclude_names" | "topics_any" | "exclude_topics" | "languages";

const LISTS: { key: ListKey; label: string; hint: string; placeholder: string }[] = [
  { key: "include_names", label: "Only names matching", hint: "Shell globs on owner/name or name; empty: every repository.", placeholder: "payments-*, core/*" },
  { key: "exclude_names", label: "Exclude names matching", hint: "Exclusions win over inclusions.", placeholder: "*-sandbox, archive-*" },
  { key: "topics_any", label: "Only repositories with one of these topics", hint: "GitHub and GitLab topics; empty: no topic needed.", placeholder: "pci, production" },
  { key: "exclude_topics", label: "Exclude repositories with these topics", hint: "For example deprecated or experimental.", placeholder: "deprecated" },
  { key: "languages", label: "Only these primary languages", hint: "As the provider reports them (GitLab does not report one).", placeholder: "Python, Java, TypeScript" },
];

const VIS: ScmVisibility[] = ["private", "internal", "public"];

export default function FiltersForm({ idPrefix, value, onChange, disabled }: {
  idPrefix: string;
  value: ScmFilters;
  onChange: (next: ScmFilters) => void;
  disabled?: boolean;
}) {
  const [text, setText] = useState<Record<ListKey, string>>(() =>
    Object.fromEntries(LISTS.map((l) => [l.key, joinList(value[l.key])])) as Record<ListKey, string>);
  const [size, setSize] = useState(value.max_size_mb === null ? "" : String(value.max_size_mb));

  return (
    <fieldset disabled={disabled} className="grid grid-cols-1 md:grid-cols-2 gap-4 min-w-0">
      {LISTS.map((l) => {
        const parsed = parseList(text[l.key]);
        return (
          <Field key={l.key} label={l.label} htmlFor={`${idPrefix}-${l.key}`} hint={l.hint} error={listError(parsed)}>
            <Input
              id={`${idPrefix}-${l.key}`}
              value={text[l.key]}
              placeholder={l.placeholder}
              onChange={(e) => {
                setText((t) => ({ ...t, [l.key]: e.target.value }));
                onChange({ ...value, [l.key]: parseList(e.target.value) });
              }}
            />
          </Field>
        );
      })}
      <Field label="Skip repositories larger than (MB)" htmlFor={`${idPrefix}-size`}
             hint="Size as the provider reports it (GitHub includes history). Empty: no limit.">
        <Input
          id={`${idPrefix}-size`}
          inputMode="decimal"
          value={size}
          placeholder="No limit"
          onChange={(e) => {
            setSize(e.target.value);
            const n = e.target.value.trim() === "" ? null : Number(e.target.value);
            onChange({ ...value, max_size_mb: n === null || Number.isNaN(n) ? null : n });
          }}
        />
      </Field>
      <div className="space-y-2 md:col-span-2">
        <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100">Also include</p>
        <div className="flex flex-wrap gap-x-6 gap-y-2">
          <Checkbox2 id={`${idPrefix}-archived`} checked={value.include_archived}
                     onChange={(v) => onChange({ ...value, include_archived: v })}>Archived repositories</Checkbox2>
          <Checkbox2 id={`${idPrefix}-forks`} checked={value.include_forks}
                     onChange={(v) => onChange({ ...value, include_forks: v })}>Forks</Checkbox2>
        </div>
        <p className="text-sm font-medium text-zinc-900 dark:text-zinc-100 pt-2">Visibility (none ticked: all)</p>
        <div className="flex flex-wrap gap-x-6 gap-y-2">
          {VIS.map((v) => (
            <Checkbox2 key={v} id={`${idPrefix}-vis-${v}`} checked={value.visibility.includes(v)}
                       onChange={(on) => onChange({ ...value, visibility: on ? [...value.visibility, v] : value.visibility.filter((x) => x !== v) })}>
              {v[0].toUpperCase() + v.slice(1)}
            </Checkbox2>
          ))}
        </div>
      </div>
    </fieldset>
  );
}
