"use client";

// "Certificates: orphaned and unmanaged" on the CBOM team page (diagram output 04). Data: GET /{team}/cbom/certificates/
// hygiene (keyset pages, "Load more") and …/hygiene.csv. A flag chip filters the list; a row opens its observations.
import { useState } from "react";

import {
  FLAG_LABEL,
  FLAG_TONE,
  HYGIENE_FLAGS,
  downloadHygieneCsv,
  expiryText,
  flagLabel,
  stateNote,
  useHygiene,
  type HygieneCert,
  type HygieneFilters,
  type HygieneFlag,
  type HygienePage,
} from "./certHygiene";

const BTN = "rounded border px-2 py-0.5 text-xs cursor-pointer border-zinc-300 text-zinc-700 hover:border-blue-500 dark:border-zinc-700 dark:text-zinc-300";

export function FlagChip({ flag, title }: { flag: string; title?: string }) {
  const tone = (FLAG_TONE as Record<string, string>)[flag] ?? "border-zinc-400 text-zinc-700";
  return (
    <span className={`inline-flex whitespace-nowrap rounded-md border px-1.5 py-0.5 text-xs ${tone}`} title={title} data-flag={flag}>
      {flagLabel(flag)}
    </span>
  );
}

/** The flag counts as filter buttons (every flag listed, 0 included). */
export function HygieneSummary({ page, active, onPick }: {
  page: Pick<HygienePage, "counts" | "flags">;
  active: HygieneFlag | null;
  onPick?: (f: HygieneFlag | null) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2 text-xs" role="group" aria-label="Filter by flag" data-testid="cert-hygiene-summary"
         data-certificates={page.counts.certificates} data-flagged={page.counts.flagged}>
      <button type="button" aria-pressed={active == null} className={`${BTN} ${active == null ? "border-blue-500" : ""}`}
              onClick={() => onPick?.(null)}>
        Flagged {page.counts.flagged} of {page.counts.certificates}
      </button>
      {HYGIENE_FLAGS.map((f) => (
        <button key={f} type="button" aria-pressed={active === f} title={page.flags[f]}
                className={`${BTN} ${active === f ? "border-blue-500" : ""}`} onClick={() => onPick?.(active === f ? null : f)}
                data-testid={`cert-hygiene-flag-${f}`} data-count={page.counts.by_flag[f] ?? 0}>
          {FLAG_LABEL[f]} <span className="font-semibold tabular-nums">{page.counts.by_flag[f] ?? 0}</span>
        </button>
      ))}
    </div>
  );
}

function Observations({ cert }: { cert: HygieneCert }) {
  return (
    <ul className="mt-1 space-y-0.5 text-zinc-600 dark:text-zinc-400" data-testid="cert-hygiene-observations">
      {cert.observations.map((o, i) => (
        <li key={`${o.source_name}-${o.location}-${i}`} className="break-all">
          {o.source_name}{o.source_kind ? ` (${o.source_kind})` : ""}: {o.location || "—"}
          {o.served ? " · served" : ""}{o.managing ? " · managing system" : ""}
          {o.presence !== "present" ? ` · not seen for ${o.not_seen_runs} collection${o.not_seen_runs === 1 ? "" : "s"}` : ""}
        </li>
      ))}
    </ul>
  );
}

export function HygieneTable({ items, flags }: { items: HygieneCert[]; flags: Record<string, string> }) {
  const [open, setOpen] = useState<string | null>(null);
  if (items.length === 0) {
    return <p className="text-xs text-zinc-500 dark:text-zinc-400" data-testid="cert-hygiene-empty">No certificate matches.</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs" data-testid="cert-hygiene-table">
        <thead>
          <tr className="text-left text-zinc-500 dark:text-zinc-400">
            <th className="py-1 pr-3 font-normal">Certificate</th>
            <th className="py-1 pr-3 font-normal">Expiry</th>
            <th className="py-1 pr-3 font-normal">Flags</th>
            <th className="py-1 pr-3 font-normal">Owner / application</th>
            <th className="py-1 font-normal">Seen by</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.key} className="border-t border-zinc-100 dark:border-zinc-800 align-top" data-testid="cert-hygiene-row"
                data-key={c.key} data-flags={c.flags.join(" ")}>
              <td className="py-1 pr-3 min-w-[12rem]">
                <button type="button" className="text-left text-blue-600 dark:text-blue-400 cursor-pointer break-all"
                        aria-expanded={open === c.key} onClick={() => setOpen(open === c.key ? null : c.key)}>
                  {c.subject || c.label || c.key}
                </button>
                <p className="text-zinc-500 dark:text-zinc-400 break-all">{c.issuer ? `Issuer ${c.issuer}` : ""}{c.serial ? ` · serial ${c.serial}` : ""}</p>
                {open === c.key && <Observations cert={c} />}
              </td>
              <td className={`py-1 pr-3 whitespace-nowrap ${c.expired ? "text-red-600 dark:text-red-400" : ""}`}>{expiryText(c)}</td>
              <td className="py-1 pr-3">
                <div className="flex flex-wrap gap-1">{c.flags.map((f) => <FlagChip key={f} flag={f} title={flags[f]} />)}</div>
              </td>
              <td className="py-1 pr-3 break-all">{[...c.owners, ...c.applications].join(", ") || "—"}</td>
              <td className="py-1 break-all">{c.sources.join(", ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function CertHygieneSection({ teamId }: { teamId: number }) {
  const [filters, setFilters] = useState<HygieneFilters>({ flag: null, q: "", all: false });
  const [downloading, setDownloading] = useState(false);
  const query = useHygiene(teamId, filters);
  const first = query.data?.pages[0];
  const items = query.data?.pages.flatMap((p) => p.items) ?? [];
  const note = first ? stateNote(first) : null;
  return (
    <section className="space-y-3 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 min-w-0" aria-labelledby="cert-hygiene-title"
             data-testid="cert-hygiene">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 id="cert-hygiene-title" className="text-base font-semibold text-zinc-900 dark:text-white">Certificates: orphaned and unmanaged</h2>
          <p className="text-xs text-zinc-500 dark:text-zinc-400">
            Every certificate in the estate, one row per certificate however many sources read it.
          </p>
        </div>
        <button type="button" className={BTN} disabled={downloading || !first} data-testid="cert-hygiene-csv"
                onClick={async () => {
                  setDownloading(true);
                  try { await downloadHygieneCsv(teamId, filters); } finally { setDownloading(false); }
                }}>
          {downloading ? "Preparing…" : "Download CSV"}
        </button>
      </div>
      {query.isError ? (
        <p className="text-sm text-red-600 dark:text-red-400" role="alert">Couldn&apos;t load the certificates. Try again later.</p>
      ) : !first ? (
        <p className="text-sm text-zinc-500">Loading…</p>
      ) : (
        <>
          <HygieneSummary page={first} active={filters.flag} onPick={(flag) => setFilters({ ...filters, flag })} />
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <input type="search" placeholder="Search subject, issuer, serial" aria-label="Search certificates"
                   className="rounded border border-zinc-300 dark:border-zinc-700 bg-transparent px-2 py-1 min-w-[12rem]"
                   value={filters.q} maxLength={128} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
            <label className="inline-flex items-center gap-1">
              <input type="checkbox" checked={filters.all} onChange={(e) => setFilters({ ...filters, all: e.target.checked })} />
              Show unflagged certificates too
            </label>
            <span className="text-zinc-500">{first.total} shown</span>
          </div>
          {note && <p className="text-xs text-amber-700 dark:text-amber-400" role="status" data-testid="cert-hygiene-note">{note}</p>}
          <HygieneTable items={items} flags={first.flags} />
          {query.hasNextPage && (
            <button type="button" className={BTN} disabled={query.isFetchingNextPage} onClick={() => query.fetchNextPage()}
                    data-testid="cert-hygiene-more">
              {query.isFetchingNextPage ? "Loading…" : `Load more (${items.length} of ${first.total})`}
            </button>
          )}
          <p className="text-xs text-zinc-500 dark:text-zinc-400">
            &quot;Not seen lately&quot; = not read for {first.stale_runs} or more collections of the sources that knew it.
          </p>
        </>
      )}
    </section>
  );
}
