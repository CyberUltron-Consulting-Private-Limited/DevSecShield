"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Check, Copy, ExternalLink } from "lucide-react";
import type { KbFindingDetail } from "@/utils/backend_api";

function CopyCommand({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      variant="ghost"
      size="sm"
      className="h-7 gap-1.5 text-xs"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        } catch {
          /* clipboard unavailable (insecure context); the command stays selectable */
        }
      }}
    >
      {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

const sevClass: Record<string, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-400 text-zinc-900",
  LOW: "bg-blue-500 text-white",
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1.5">
      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{title}</div>
      {children}
    </div>
  );
}

/** Everything the knowledge base knows about one finding code: what it is, how it is attacked, mappings, the fix
 * and read-only proof commands. Used for code-scan findings and scan-node assets alike. */
export function KbFindingCard({ d, showRemediation = true }: { d: KbFindingDetail; showRemediation?: boolean }) {
  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-700 p-3 space-y-3" data-testid={`kb-${d.code}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">{d.title}</span>
        <Badge variant="outline" className="text-[10px] font-mono">{d.code}</Badge>
        {d.pqc && <Badge variant="outline" className="text-[10px]">{d.pqc}</Badge>}
      </div>
      {d.observed && <p className="text-xs text-zinc-600 dark:text-zinc-300">Observed: {d.observed}</p>}
      <p className="text-sm text-zinc-700 dark:text-zinc-300">{d.description}</p>
      <Section title="How it is attacked">
        <p className="text-sm text-zinc-700 dark:text-zinc-300">{d.attack}</p>
      </Section>
      <Section title="Mapping">
        <div className="flex flex-wrap gap-1.5">
          {d.cwe.map((c) => (
            <a key={c.id} href={c.url} target="_blank" rel="noreferrer noopener" className="max-w-full">
              <Badge variant="secondary" className="text-[11px] whitespace-normal max-w-full text-left" title={c.name ?? undefined}>{c.id}{c.name ? `: ${c.name}` : ""}</Badge>
            </a>
          ))}
        </div>
        <div className="flex flex-wrap gap-1.5">
          {d.owasp_2021.map((o) => (
            <Badge key={o.id} variant="outline" className="text-[11px] whitespace-normal max-w-full text-left" title={o.basis}>{o.label}</Badge>
          ))}
          {d.owasp_2025.map((o) => (
            <Badge key={o.id} variant="outline" className="text-[11px] whitespace-normal max-w-full text-left" title={o.basis}>{o.label}</Badge>
          ))}
        </div>
      </Section>
      {d.cves.length > 0 && (
        <Section title={`CVEs (${d.cves.length})`}>
          <ul className="space-y-1.5">
            {d.cves.map((c) => (
              <li key={c.id} className="text-xs text-zinc-700 dark:text-zinc-300">
                <a href={c.url} target="_blank" rel="noreferrer noopener" className="font-mono font-semibold text-blue-600 dark:text-blue-400 inline-flex items-center gap-1">
                  {c.id} <ExternalLink className="h-3 w-3" />
                </a>
                {c.cvss?.score != null && (
                  <Badge className={`ml-2 text-[10px] ${sevClass[(c.cvss.severity || "").toUpperCase()] || ""}`}>
                    CVSS {c.cvss.version} {c.cvss.score} {c.cvss.severity}
                  </Badge>
                )}
                {c.matched_on && <span className="ml-2 text-zinc-500">matched on: {c.matched_on}</span>}
                {c.summary && <p className="mt-0.5 line-clamp-3">{c.summary}</p>}
              </li>
            ))}
          </ul>
        </Section>
      )}
      {showRemediation && (
        <Section title="Fix">
          <p className="text-sm text-zinc-700 dark:text-zinc-300">{d.remediation.summary}</p>
          {d.remediation.steps.length > 0 && (
            <ul className="space-y-1">
              {d.remediation.steps.map((s, i) => (
                <li key={i} className="text-xs text-zinc-700 dark:text-zinc-300">
                  <span className="font-semibold">{s.platform}:</span> <span className="font-mono break-words">{s.how}</span>
                </li>
              ))}
            </ul>
          )}
        </Section>
      )}
      {d.verify.length > 0 && (
        <Section title="Proof of exposure (read-only)">
          {d.verify.map((v, i) => (
            <div key={i} className="rounded border border-zinc-200 dark:border-zinc-700">
              <div className="flex items-center justify-between px-2 py-1 bg-zinc-50 dark:bg-zinc-900 text-xs text-zinc-500">
                <span>{v.label}</span>
                <CopyCommand text={v.command} />
              </div>
              <pre className="text-xs font-mono p-2 whitespace-pre-wrap break-all">{v.command}</pre>
            </div>
          ))}
        </Section>
      )}
      {(d.compliance.length > 0 || d.standards.length > 0) && (
        <Section title="Standards and regulations">
          {d.standards.length > 0 && <p className="text-xs text-zinc-600 dark:text-zinc-400">{d.standards.join(" · ")}</p>}
          <ul className="space-y-1">
            {d.compliance.map((r, i) => (
              <li key={i} className="text-xs text-zinc-700 dark:text-zinc-300">
                <a href={r.source} target="_blank" rel="noreferrer noopener" className="font-semibold text-blue-600 dark:text-blue-400">
                  {r.framework}: {r.id}
                </a>
                <span className="block text-zinc-600 dark:text-zinc-400 line-clamp-3">{r.text}</span>
                {r.note && <span className="block text-zinc-500 italic">{r.note}</span>}
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

export default function KbFindingDetails({ details, showRemediation = true }: { details: KbFindingDetail[]; showRemediation?: boolean }) {
  if (!details.length) {
    return <p className="text-xs text-zinc-500">No weakness is flagged on this asset.</p>;
  }
  return (
    <div className="space-y-3">
      {details.map((d) => (
        <KbFindingCard key={d.code} d={d} showRemediation={showRemediation} />
      ))}
    </div>
  );
}
