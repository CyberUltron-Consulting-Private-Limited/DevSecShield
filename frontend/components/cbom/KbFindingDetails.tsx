"use client";

import { useId, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Check, Copy, ExternalLink } from "lucide-react";
import type { KbComplianceRef, KbFindingDetail } from "@/utils/backend_api";

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
export function KbFindingCard({ d, showRemediation = true, showStandards = true }: { d: KbFindingDetail; showRemediation?: boolean; showStandards?: boolean }) {
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
      {showStandards && <StandardsSection standards={d.standards} compliance={d.compliance} />}
    </div>
  );
}

export function StandardsSection({ standards, compliance }: { standards: string[]; compliance: KbComplianceRef[] }) {
  if (compliance.length === 0 && standards.length === 0) return null;
  return (
    <Section title="Standards and regulations">
      {standards.length > 0 && <p className="text-xs text-zinc-600 dark:text-zinc-400">{standards.join(" · ")}</p>}
      <ul className="space-y-1">
        {compliance.map((r, i) => (
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
  );
}

/** The standards and clauses of every finding code of an asset, each once, in first-seen order (#266: in the run
 * finding dialog two codes citing the same RBI clause printed it twice, in two "Standards and regulations" blocks). */
export function mergeStandards(details: Pick<KbFindingDetail, "standards" | "compliance">[]): { standards: string[]; compliance: KbComplianceRef[] } {
  const standards = [...new Set(details.flatMap((d) => d.standards ?? []))];
  const seen = new Set<string>();
  const compliance = details.flatMap((d) => d.compliance ?? []).filter((r) => {
    const key = `${r.framework}\u0000${r.id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return { standards, compliance };
}

/**
 * The KB cards of a finding or asset. By default each card keeps its own "Standards and regulations" (per-code
 * attribution, as the code-scan Standards tab and the Sources asset drawer always showed). With `mergedStandards`
 * (the run finding dialog, #266) the cards drop theirs and one de-duplicated section follows them.
 */
export default function KbFindingDetails({ details, showRemediation = true, mergedStandards = false, variant = "cards" }: {
  details: KbFindingDetail[];
  showRemediation?: boolean;
  mergedStandards?: boolean;
  /** "cards" (default, every caller before the run dialog redesign): one card per code. "steps" (the run finding
   * dialog's Issues tab): a five-step strip per code, CVE cards, a platform command grid, and ONE Verify block that
   * lists each proof command once with the issues it proves. No per-code standards in "steps" (the dialog's Standards
   * tab shows them once); `mergedStandards` still appends the merged block. */
  variant?: "cards" | "steps";
}) {
  if (!details.length) {
    return <p className="text-xs text-zinc-500">No weakness is flagged on this asset.</p>;
  }
  const merged = mergedStandards ? mergeStandards(details) : null;
  if (variant === "steps") {
    return (
      <div className="space-y-3" data-testid="kb-steps">
        {details.map((d) => <KbIssueSteps key={d.code} d={d} showRemediation={showRemediation} />)}
        <VerifyBlock details={details} />
        {merged && (merged.standards.length > 0 || merged.compliance.length > 0) && (
          <div className="rounded-md border border-zinc-200 dark:border-zinc-700 p-3" data-testid="kb-standards">
            <StandardsSection standards={merged.standards} compliance={merged.compliance} />
          </div>
        )}
      </div>
    );
  }
  return (
    <div className="space-y-3">
      {details.map((d) => (
        <KbFindingCard key={d.code} d={d} showRemediation={showRemediation} showStandards={!mergedStandards} />
      ))}
      {merged && (merged.standards.length > 0 || merged.compliance.length > 0) && (
        <div className="rounded-md border border-zinc-200 dark:border-zinc-700 p-3" data-testid="kb-standards">
          <StandardsSection standards={merged.standards} compliance={merged.compliance} />
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------------------------------------ "steps" variant (run dialog)

/** How many CVE cards and proof commands show before "Show all (n)"; the rest stay in the DOM, hidden. */
export const CVE_CAP = 12;
export const VERIFY_CAP = 6;

type StepId = "observed" | "why" | "attack" | "fix" | "verify";

/** One proof command, once, with every issue (code and title) it proves, in first-seen order. */
export interface VerifyCommand {
  label: string;
  command: string;
  issues: { code: string; title: string }[];
}

/** The read-only proof commands of an asset's issues, each command once (the same nmap / openssl line is shared by
 * several codes), tagged with the issues it proves. */
export function verifyCommands(details: Pick<KbFindingDetail, "code" | "title" | "verify">[]): VerifyCommand[] {
  const byCommand = new Map<string, VerifyCommand>();
  for (const d of details) {
    for (const v of d.verify ?? []) {
      const key = v.command.trim();
      const hit = byCommand.get(key);
      if (!hit) byCommand.set(key, { label: v.label, command: v.command, issues: [{ code: d.code, title: d.title }] });
      else if (!hit.issues.some((i) => i.code === d.code)) hit.issues.push({ code: d.code, title: d.title });
    }
  }
  return [...byCommand.values()];
}

function ShowAll({ shown, total, open, onToggle, controls, noun }: {
  shown: number; total: number; open: boolean; onToggle: () => void; controls: string; noun: string;
}) {
  if (total <= shown) return null;
  return (
    <Button type="button" variant="ghost" size="sm" className="h-7 text-xs text-blue-600 dark:text-blue-400"
            aria-expanded={open} aria-controls={controls} onClick={onToggle}>
      {open ? `Show fewer ${noun}` : `Show all (${total})`}
    </Button>
  );
}

function Mapping({ d }: { d: KbFindingDetail }) {
  if (d.cwe.length + d.owasp_2021.length + d.owasp_2025.length === 0) return null;
  return (
    <Section title="Mapping">
      <div className="flex flex-wrap gap-1.5">
        {d.cwe.map((c) => (
          <a key={c.id} href={c.url} target="_blank" rel="noreferrer noopener" className="max-w-full">
            <Badge variant="secondary" className="text-[11px] whitespace-normal max-w-full text-left" title={c.name ?? undefined}>{c.id}{c.name ? `: ${c.name}` : ""}</Badge>
          </a>
        ))}
        {d.owasp_2021.map((o) => (
          <Badge key={o.id} variant="outline" className="text-[11px] whitespace-normal max-w-full text-left border-violet-300 text-violet-800 dark:border-violet-700 dark:text-violet-300" title={o.basis}>{o.label}</Badge>
        ))}
        {d.owasp_2025.map((o) => (
          <Badge key={o.id} variant="outline" className="text-[11px] whitespace-normal max-w-full text-left border-violet-300 text-violet-800 dark:border-violet-700 dark:text-violet-300" title={o.basis}>{o.label}</Badge>
        ))}
      </div>
    </Section>
  );
}

/** One knowledge-base issue as a five-step story (Observed · Why it matters · How it is attacked · Fix · Verify). Each
 * step is a button (click, Enter, Space) that reveals its full text and the issue's mapping in the panel below the
 * strip; the strip's own text is only clamped, never cut from the DOM. */
function KbIssueSteps({ d, showRemediation }: { d: KbFindingDetail; showRemediation: boolean }) {
  const [step, setStep] = useState<StepId | null>(null);
  const [allCves, setAllCves] = useState(false);
  const uid = useId();
  const panelId = `${uid}-panel`;
  const cveId = `${uid}-cves`;
  const steps: { id: StepId; title: string; text: string }[] = [
    { id: "observed", title: "Observed", text: d.observed || "—" },
    { id: "why", title: "Why it matters", text: d.description },
    { id: "attack", title: "How it is attacked", text: d.attack },
    ...(showRemediation ? [{ id: "fix" as const, title: "Fix", text: d.remediation.summary }] : []),
    {
      id: "verify", title: "Verify",
      text: d.verify.length > 0
        ? `${d.verify.length} read-only ${d.verify.length === 1 ? "command" : "commands"} in "Proof of exposure (read-only)" below`
        : "No read-only proof command for this issue",
    },
  ];
  const current = steps.find((s) => s.id === step) ?? null;
  return (
    <div className="rounded-xl border border-zinc-200 dark:border-zinc-700 border-l-4 border-l-red-500/80 dark:border-l-red-500/70 p-3 space-y-3 min-w-0"
         data-testid={`kb-${d.code}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2 min-w-0">
          <span className="text-sm font-semibold text-zinc-800 dark:text-zinc-100 break-words">{d.title}</span>
          <Badge variant="outline" className="text-[10px] font-mono">{d.code}</Badge>
          {d.pqc && <Badge variant="outline" className="text-[10px]">{d.pqc}</Badge>}
        </div>
        {d.cves.length > 0 && <Badge variant="secondary" className="text-[10px]">{d.cves.length} {d.cves.length === 1 ? "CVE" : "CVEs"}</Badge>}
      </div>
      <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2" aria-label={`${d.title}: steps`}>
        {steps.map((s, i) => (
          <li key={s.id} className="min-w-0">
            <button type="button" aria-expanded={step === s.id} aria-controls={panelId} data-testid={`kb-step-${d.code}-${s.id}`}
                    onClick={() => setStep(step === s.id ? null : s.id)}
                    className={`w-full h-full text-left rounded-lg border p-2 cursor-pointer transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 ${
                      step === s.id
                        ? "border-blue-500 bg-blue-50 dark:bg-blue-950/40"
                        : "border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900/60 hover:border-zinc-300 dark:hover:border-zinc-600"}`}>
              <span className="flex items-center gap-1.5">
                <span className="inline-flex size-5 shrink-0 items-center justify-center rounded-full bg-blue-600 text-[10px] font-semibold text-white">{i + 1}</span>
                <span className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">{s.title}</span>
              </span>
              <span className="mt-1 block text-xs text-zinc-600 dark:text-zinc-400 line-clamp-2 break-words">{s.text}</span>
            </button>
          </li>
        ))}
      </ol>
      <div id={panelId} role="region" aria-label={current ? `${d.title}: ${current.title}` : `${d.title}: details`} hidden={!current}
           className="rounded-lg border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-950 p-3 space-y-2">
        {current && (
          <Section title={`${current.title}: full text`}>
            <p className="text-sm text-zinc-700 dark:text-zinc-300 whitespace-pre-wrap break-words">{current.text}</p>
          </Section>
        )}
        <Mapping d={d} />
      </div>
      {d.cves.length > 0 && (
        <Section title={`CVEs (${d.cves.length})`}>
          <ul id={cveId} className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
            {d.cves.map((c, i) => (
              <li key={c.id} hidden={!allCves && i >= CVE_CAP}
                  className="rounded-lg border border-zinc-200 dark:border-zinc-700 p-2 text-xs text-zinc-700 dark:text-zinc-300 min-w-0">
                <div className="flex flex-wrap items-center justify-between gap-1">
                  <a href={c.url} target="_blank" rel="noreferrer noopener" className="font-mono font-semibold text-blue-600 dark:text-blue-400 inline-flex items-center gap-1">
                    {c.id} <ExternalLink className="h-3 w-3" />
                  </a>
                  {c.cvss?.score != null && (
                    <Badge className={`text-[10px] ${sevClass[(c.cvss.severity || "").toUpperCase()] || ""}`}>
                      CVSS {c.cvss.version} {c.cvss.score} {c.cvss.severity}
                    </Badge>
                  )}
                </div>
                {c.matched_on && <span className="mt-1 block text-zinc-500">matched on: {c.matched_on}</span>}
                {c.summary && <p className="mt-1 line-clamp-3">{c.summary}</p>}
              </li>
            ))}
          </ul>
          <ShowAll shown={CVE_CAP} total={d.cves.length} open={allCves} onToggle={() => setAllCves(!allCves)} controls={cveId} noun="CVEs" />
        </Section>
      )}
      {showRemediation && d.remediation.steps.length > 0 && (
        <Section title="Fix commands by platform">
          <ul className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
            {d.remediation.steps.map((s, i) => (
              <li key={i} className="rounded-lg border border-zinc-200 dark:border-zinc-700 p-2 min-w-0">
                <div className="flex items-center justify-between gap-1">
                  <span className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">{s.platform}</span>
                  <CopyCommand text={s.how} />
                </div>
                <span className="mt-1 block font-mono text-xs text-zinc-600 dark:text-zinc-400 break-words">{s.how}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}

/** One "Proof of exposure (read-only)" block for all issues of the asset: each command once, tagged with its issues. */
function VerifyBlock({ details }: { details: KbFindingDetail[] }) {
  const [all, setAll] = useState(false);
  const id = useId();
  const cmds = verifyCommands(details);
  if (cmds.length === 0) return null;
  return (
    <div className="rounded-xl border border-zinc-200 dark:border-zinc-700 p-3 space-y-2" data-testid="kb-verify">
      <Section title="Proof of exposure (read-only)">
        <ul id={id} className="space-y-2">
          {cmds.map((v, i) => (
            <li key={v.command} hidden={!all && i >= VERIFY_CAP} className="rounded border border-zinc-200 dark:border-zinc-700">
              <div className="flex flex-wrap items-center justify-between gap-1 px-2 py-1 bg-zinc-50 dark:bg-zinc-900 text-xs text-zinc-500">
                <span># {v.label}</span>
                <span className="flex flex-wrap items-center gap-1">
                  {v.issues.map((iss) => (
                    <Badge key={iss.code} variant="outline" className="text-[10px] whitespace-normal" title={iss.code}>{iss.title}</Badge>
                  ))}
                  <CopyCommand text={v.command} />
                </span>
              </div>
              <pre className="text-xs font-mono p-2 whitespace-pre-wrap break-all">{v.command}</pre>
            </li>
          ))}
        </ul>
        <ShowAll shown={VERIFY_CAP} total={cmds.length} open={all} onToggle={() => setAll(!all)} controls={id} noun="commands" />
      </Section>
    </div>
  );
}

/** The asset's standards and regulatory clauses, each once (mergeStandards), as regulator tabs: "Standards" (the
 * named standards) and one tab per framework with its clauses, quoted text and note. Every tab's content stays in the
 * DOM (inactive tabs are hidden), so nothing is dropped. One "Standards and regulations" heading. */
export function StandardsTabs({ details }: { details: Pick<KbFindingDetail, "standards" | "compliance">[] }) {
  const { standards, compliance } = mergeStandards(details);
  const frameworks = [...new Set(compliance.map((r) => r.framework))];
  const [tab, setTab] = useState<string>(standards.length > 0 ? "standards" : `fw-${frameworks[0] ?? ""}`);
  if (standards.length === 0 && compliance.length === 0) {
    return <p className="text-xs text-zinc-500" data-testid="kb-standards-empty">No standard or regulatory clause is mapped to this asset&apos;s issues.</p>;
  }
  return (
    <div className="space-y-2" data-testid="kb-standards">
      <div className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Standards and regulations</div>
      <Tabs value={tab} onValueChange={setTab} className="w-full">
        <TabsList className="h-auto w-full justify-start overflow-x-auto flex-nowrap">
          {standards.length > 0 && <TabsTrigger value="standards" className="text-xs cursor-pointer">Standards {standards.length}</TabsTrigger>}
          {frameworks.map((f) => (
            <TabsTrigger key={f} value={`fw-${f}`} className="text-xs cursor-pointer">
              {f} {compliance.filter((r) => r.framework === f).length}
            </TabsTrigger>
          ))}
        </TabsList>
        {standards.length > 0 && (
          <TabsContent value="standards" forceMount className="data-[state=inactive]:hidden">
            <div className="flex flex-wrap gap-1.5">
              {standards.map((st) => <Badge key={st} variant="outline" className="text-[11px] whitespace-normal max-w-full text-left">{st}</Badge>)}
            </div>
          </TabsContent>
        )}
        {frameworks.map((f) => (
          <TabsContent key={f} value={`fw-${f}`} forceMount className="data-[state=inactive]:hidden">
            <ul className="space-y-2">
              {compliance.filter((r) => r.framework === f).map((r) => (
                <li key={`${r.framework}-${r.id}`} className="rounded-lg border border-zinc-200 dark:border-zinc-700 p-2 text-xs text-zinc-700 dark:text-zinc-300">
                  <a href={r.source} target="_blank" rel="noreferrer noopener" className="font-semibold text-blue-600 dark:text-blue-400">
                    {r.framework}: {r.id}
                  </a>
                  <span className="block mt-1 text-zinc-600 dark:text-zinc-400">{r.text}</span>
                  {r.note && <span className="block mt-1 text-zinc-500 italic">{r.note}</span>}
                </li>
              ))}
            </ul>
          </TabsContent>
        ))}
      </Tabs>
    </div>
  );
}
