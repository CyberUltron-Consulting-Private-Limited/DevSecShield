// "Configuration mentions (not counted)": where a code scan read an algorithm name as a mention, not a use (a label,
// a comparison, a case label, an Enum member, code held in a string). Nothing here is inventory or counted; the list
// makes the dropped names visible (PR #500 review 6061095673). Collapsed by default, first CONFIG_MENTIONS_SHOWN rows.

export interface ConfigMention {
  location?: string | null;
  line?: number | null;
  algorithm?: string | null;
  binding?: string | null;
  value?: string | null;
}

export const CONFIG_MENTIONS_SHOWN = 50;

export function ConfigMentions({ mentions, total }: { mentions: ConfigMention[] | null | undefined; total?: number | null }) {
  const rows = (mentions ?? []).filter((m) => m && typeof m === "object").slice(0, CONFIG_MENTIONS_SHOWN);
  if (rows.length === 0) return null;
  const count = typeof total === "number" && total >= rows.length ? total : rows.length;
  return (
    <details className="mt-6 rounded-xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3"
             data-testid="cbom-config-mentions">
      <summary className="cursor-pointer text-sm font-medium text-zinc-800 dark:text-zinc-200">
        Configuration mentions (not counted) · {count.toLocaleString()}
      </summary>
      <p className="mt-2 text-xs text-zinc-500 dark:text-zinc-400">
        Places that name an algorithm without using it: a label, a comparison, a case label, an Enum member or code
        held in a string. They are not in the inventory or any total.
        {count > rows.length ? ` The first ${rows.length} of ${count.toLocaleString()} are listed.` : ""}
      </p>
      <ul className="mt-2 space-y-1.5" data-testid="cbom-config-mentions-list">
        {rows.map((m, i) => (
          <li key={`${m.location}:${m.line}:${i}`} className="min-w-0 rounded-md border border-zinc-100 dark:border-zinc-800 px-2 py-1.5 text-xs">
            <span className="block break-all font-mono text-zinc-700 dark:text-zinc-300">
              {m.location ?? "—"}{m.line ? `:${m.line}` : ""}
            </span>
            <span className="block text-zinc-500 dark:text-zinc-400 break-words">
              {(m.algorithm ?? "").toUpperCase()}{m.binding ? ` · ${m.binding}` : ""}{m.value ? ` · “${m.value}”` : ""}
            </span>
          </li>
        ))}
      </ul>
    </details>
  );
}
