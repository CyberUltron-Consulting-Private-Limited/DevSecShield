"use client";

// A code scan's results page lists the certificates THIS scan found (staging QA N1: it showed the team's 145 Sources
// certificates while the scan had none). The team's orphaned and unmanaged certificates stay on the CBOM dashboard,
// one link away.

import Link from "next/link";

import { scanCertificates, teamCertificatesHref } from "./scanCertificates";

export function ScanCertificates({ teamId, rows }: { teamId: number; rows: unknown[] }) {
  const certs = scanCertificates(rows);
  return (
    <section className="space-y-2 rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 min-w-0" data-testid="scan-certificates"
             aria-labelledby="scan-certificates-title">
      <h2 id="scan-certificates-title" className="text-base font-semibold text-zinc-900 dark:text-white">
        Certificates in this scan ({certs.length})
      </h2>
      {certs.length === 0 ? (
        <p className="text-sm text-zinc-500 dark:text-zinc-400">This scan found no certificates in the repository.</p>
      ) : (
        <ul className="divide-y divide-zinc-200 dark:divide-zinc-800 text-sm">
          {certs.map((c, i) => (
            <li key={i} className="py-1.5 flex flex-wrap items-baseline justify-between gap-2 min-w-0">
              <span className="font-medium text-zinc-900 dark:text-zinc-100 break-all">{c.algorithm_name || c.title || "Certificate"}</span>
              <span className="text-xs text-zinc-500 dark:text-zinc-400 break-all">
                {[c.location ? `${c.location}${c.line ? `:${c.line}` : ""}` : null,
                  c.not_valid_after ? `${c.expired ? "expired" : "valid until"} ${c.not_valid_after.slice(0, 10)}` : null,
                  c.self_signed ? "self-signed" : null].filter(Boolean).join(" · ")}
              </span>
            </li>
          ))}
        </ul>
      )}
      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        The team&apos;s orphaned and unmanaged certificates, from every source, are on the{" "}
        <Link href={teamCertificatesHref(teamId)} className="text-blue-600 dark:text-blue-400 hover:underline"
              data-testid="scan-certificates-team-link">CBOM dashboard</Link>.
      </p>
    </section>
  );
}
