"use client";

/**
 * The PDF export dialog (plan §7): what a scan's or a Sources run's PDF report holds (preset, sections, severity and
 * status filters, cover fields, label, code snippets), and the cover options of the team-wide CBOM deliverables.
 *
 * The opener owns the build: `useExportPdf` keeps one pending flag per report (team, family, scan or run), so the
 * opener's button spins and a second build of the same report cannot start, even from another opener of it. The
 * dialog shows the server's refusals inline (422, 409 with "Remove status filter", 429 with the retry time, 503, 400)
 * and never touches the opener's own state; it is the one place that says an export's outcome (one toast).
 * Options: utils/reportOptions.ts (the mirror of backend/utilities/pdf/report_options.py).
 */
import { useCallback, useEffect, useId, useMemo, useRef, useState, useSyncExternalStore, type ReactElement } from "react";
import { AlertCircle, Download, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { FieldLabel, InfoTip } from "@/components/ui/info-tip";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Checkbox2, ChoiceCards } from "@/components/cbom/sources/shared";
import type { InfoTipId } from "@/content/infotips";
import { cn } from "@/lib/utils";
import {
  ReportDownloadError,
  downloadRunReport,
  downloadScanReport,
  type ReportMeta,
} from "@/utils/backend_api";
import { saveBlob } from "@/utils/download";
import {
  LABELS,
  LABEL_CHOICE_TEXT,
  PRESET_TEXT,
  SEVERITIES,
  SEVERITY_TEXT,
  STATUSES,
  STATUS_TEXT,
  TEXT_MAX,
  availableSections,
  getSessionPreparedFor,
  initialOptions,
  optionProblems,
  presetFor,
  presetSections,
  saveRemembered,
  setSessionPreparedFor,
  summaryText,
  textLength,
  validateText,
  type DialogFamily,
  type FindingStatus,
  type Preset,
  type ReportLabel,
  type ReportOptions,
  type ReportScanType,
  type ReportSection,
  type Severity,
  type TextField,
} from "@/utils/reportOptions";
import { toast } from "@/utils/toast";

export type ExportTarget =
  | { family: "scan"; type: ReportScanType; scanId: number }
  | { family: "run"; runId: number }
  | { family: "deliverable" };

/** The dialog's layout (components/reports/exportDialogLayout.test.ts measures it in a browser): the content scrolls
 * inside the viewport and the footer with Download stays visible at its bottom. */
export const EXPORT_DIALOG_LAYOUT = {
  content: "sm:max-w-2xl max-h-[calc(100dvh-2rem)] overflow-y-auto overflow-x-hidden p-0 gap-0",
  header: "px-6 pt-6 pb-4 pr-12",
  body: "space-y-5 px-6 pb-4 min-w-0",
  footer: "sticky bottom-0 z-10 flex flex-wrap items-center justify-end gap-2 border-t bg-background px-6 py-3",
  text: "min-w-0 break-words [overflow-wrap:anywhere]",
} as const;

// ------------------------------------------------------------------------------------------- words and tips
export const SECTION_TEXT: Record<ReportSection, { title: string; hint: string }> = {
  summary: { title: "Executive summary", hint: "Risk overview and key figures" },
  catalog: { title: "Findings catalog", hint: "One line per finding" },
  details: { title: "Finding details", hint: "A card per finding with its evidence" },
  remediation: { title: "Remediation", hint: "How to fix, inside each finding's details" },
  mappings: { title: "Standards mappings", hint: "CWE, OWASP and other references, inside the details" },
  compliance: { title: "Compliance appendices", hint: "RBI and CERT-In appendices" },
  inventory: { title: "Package inventory", hint: "The SBOM's package tables" },
  notes: { title: "Scan notes", hint: "Notes and errors the scan recorded" },
  posture: { title: "Posture", hint: "Run identity, algorithms, certificate expiry, top risks, compliance and VEX tables" },
  provenance: { title: "Provenance", hint: "Where each asset was collected" },
};

/** One tip per section control; a word that means something else in a run report has its own id. */
const SECTION_TIP: Record<string, InfoTipId> = {
  "scan.summary": "export.section.scan.summary",
  "scan.catalog": "export.section.scan.catalog",
  "scan.details": "export.section.scan.details",
  "scan.remediation": "export.section.scan.remediation",
  "scan.mappings": "export.section.scan.mappings",
  "scan.compliance": "export.section.scan.compliance",
  "scan.inventory": "export.section.scan.inventory",
  "scan.notes": "export.section.scan.notes",
  "run.summary": "export.section.run.summary",
  "run.posture": "export.section.run.posture",
  "run.catalog": "export.section.run.catalog",
  "run.provenance": "export.section.run.provenance",
};
const STATUS_TIP: Record<FindingStatus, InfoTipId> = {
  not_started: "export.status.not_started",
  in_progress: "export.status.in_progress",
  fixed: "export.status.fixed",
  ignored: "export.status.ignored",
};
const PRESET_TIP: Record<"scan" | "run", InfoTipId> = { scan: "export.preset.scan", run: "export.preset.run" };

const PRESET_DESCRIPTION: Record<"scan" | "run", Record<Preset | "custom", string>> = {
  scan: {
    executive: "Summary and compliance appendices, for management",
    technical: "Summary, findings, details, remediation and mappings, for engineers",
    full: "Every section (today's report)",
    custom: "The sections you tick below",
  },
  run: {
    executive: "Summary and posture",
    technical: "Summary and the findings catalog",
    full: "Every section (today's report)",
    custom: "The sections you tick below",
  },
};

export function successMessage(base: string, meta: ReportMeta): string {
  const notes: string[] = [];
  if (meta.shown != null && meta.total != null && meta.shown !== meta.total) notes.push(`${meta.shown} of ${meta.total} findings`);
  if (meta.logo === "skipped") notes.push("team logo skipped: it could not be read");
  return notes.length ? `${base} (${notes.join("; ")})` : base;
}

// ------------------------------------------------------------------------------------------- pending, keyed by report
const pendingKeys = new Set<string>();
const listeners = new Set<() => void>();
const subscribe = (l: () => void) => {
  listeners.add(l);
  return () => listeners.delete(l);
};
function setPending(key: string, on: boolean) {
  if (on) pendingKeys.add(key);
  else pendingKeys.delete(key);
  for (const l of [...listeners]) l();
}

export function exportKey(teamId: number, target: ExportTarget): string {
  if (target.family === "scan") return `${teamId}:scan:${target.type}:${target.scanId}`;
  if (target.family === "run") return `${teamId}:run:${target.runId}`;
  return `${teamId}:deliverable`;
}

/** Whether this report is being built (by any opener of it). */
export function useExportPending(key: string): boolean {
  return useSyncExternalStore(subscribe, () => pendingKeys.has(key), () => false);
}

// ------------------------------------------------------------------------------------------- the opener's hook
export interface UseExportPdf {
  teamId: number;
  target: ExportTarget;
  /** The file name the opener has always used (evaluated when the file is saved). */
  fileName?: string | (() => string);
  /** The success toast's text before the notes from the server ("Report downloaded"). */
  successText?: string;
  /** deliverable family: called after the cover options are applied */
  onApplied?: () => void;
}

/** The export dialog and its build for one report. Render `dialog` anywhere in the opener; `open` from its button,
 * which shows `pending` (a spinner) and stays disabled while the report is being built. */
export function useExportPdf({ teamId, target, fileName, successText, onApplied }: UseExportPdf): {
  open: () => void;
  pending: boolean;
  dialog: ReactElement;
} {
  const key = exportKey(teamId, target);
  const pending = useExportPending(key);
  const [isOpen, setIsOpen] = useState(false);
  const [error, setError] = useState<ReportDownloadError | null>(null);
  // read when a build ends: is the opener still there, and is its dialog still open?
  const mounted = useRef(true);
  const openNow = useRef(false);
  useEffect(() => {
    const m = mounted;
    m.current = true;
    return () => {
      m.current = false;
    };
  }, []);
  useEffect(() => {
    openNow.current = isOpen;
  }, [isOpen]);

  const setOpen = useCallback((next: boolean) => {
    setIsOpen(next);
    if (next) setError(null);
  }, []);

  const targetRef = useRef(target);
  targetRef.current = target;
  const fileRef = useRef(fileName);
  fileRef.current = fileName;

  const start = useCallback(async (options: ReportOptions) => {
    const t = targetRef.current;
    if (t.family === "deliverable") {
      saveRemembered(teamId, "deliverable", options);
      setSessionPreparedFor(teamId, validateText("prepared_for", options.prepared_for).value);
      setIsOpen(false);
      onApplied?.();
      return;
    }
    if (pendingKeys.has(key)) return; // one build per report at a time
    setPending(key, true);
    setError(null);
    saveRemembered(teamId, t.family, options);
    try {
      const { blob, meta } = t.family === "scan"
        ? await downloadScanReport(teamId, t.type, t.scanId, options)
        : await downloadRunReport(teamId, t.runId, options);
      const name = typeof fileRef.current === "function" ? fileRef.current() : fileRef.current;
      saveBlob(blob, name ?? "report.pdf");
      toast.success(successMessage(successText ?? "Report downloaded", meta));
      if (mounted.current) setIsOpen(false);
    } catch (e) {
      const err = e instanceof ReportDownloadError
        ? e
        : new ReportDownloadError(e instanceof Error ? e.message : "The report could not be built.", { status: null, detail: null, retryAfter: null, field: null, cause: e });
      // the dialog says it while it is open; closed (or its opener gone), one error toast instead
      if (mounted.current && openNow.current) setError(err);
      else toast.error(`The PDF report was not downloaded: ${err.message}`);
    } finally {
      setPending(key, false);
    }
  }, [key, onApplied, successText, teamId]);

  const dialog = (
    <ExportPdfDialog
      open={isOpen}
      onOpenChange={setOpen}
      teamId={teamId}
      target={target}
      pending={pending}
      error={error}
      onDownload={(o) => void start(o)}
      onClearError={() => setError(null)}
    />
  );
  return { open: () => setOpen(true), pending, dialog };
}

// ------------------------------------------------------------------------------------------- the dialog
export interface ExportPdfDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  teamId: number;
  target: ExportTarget;
  pending: boolean;
  error: ReportDownloadError | null;
  /** Download (scan, run) or "Use for downloads" (deliverable). */
  onDownload: (options: ReportOptions) => void;
  onClearError: () => void;
}

export function ExportPdfDialog(props: ExportPdfDialogProps) {
  const { open, onOpenChange, target } = props;
  const deliverable = target.family === "deliverable";
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className={EXPORT_DIALOG_LAYOUT.content} data-testid="export-pdf-dialog">
        <DialogHeader className={EXPORT_DIALOG_LAYOUT.header}>
          <DialogTitle className={EXPORT_DIALOG_LAYOUT.text}>
            {deliverable ? "Cover options for deliverables" : "Download PDF report"} <InfoTip id={deliverable ? "export.dialog.deliverable" : "export.dialog"} />
          </DialogTitle>
          <DialogDescription className={EXPORT_DIALOG_LAYOUT.text}>
            {deliverable
              ? "Who the documents are prepared for and how they are labelled. Used by each deliverable you download from this menu; the label is remembered, the name only until you leave this page."
              : "Choose what the report holds. Leaving everything as it is gives the full report."}
          </DialogDescription>
        </DialogHeader>
        {/* mounted while open: each opening starts from the remembered options */}
        {open && <ExportPdfForm {...props} />}
      </DialogContent>
    </Dialog>
  );
}

export function ExportPdfForm({ teamId, target, pending, error, onDownload, onClearError, onOpenChange }: ExportPdfDialogProps) {
  const family: DialogFamily = target.family;
  const scanType = target.family === "scan" ? target.type : null;
  const [options, setOptions] = useState<ReportOptions>(() => {
    const o = initialOptions(teamId, family, scanType);
    return family === "deliverable" ? { ...o, prepared_for: getSessionPreparedFor(teamId) } : o;
  });
  const uid = useId();
  const ids = { prepared: `${uid}-prepared`, title: `${uid}-title`, label: `${uid}-label`, hide: `${uid}-hide`, section: `${uid}-section` };
  const problems = useMemo(() => optionProblems(options, family, scanType), [options, family, scanType]);
  const available = availableSections(family, scanType);
  const chosen = options.sections ?? [...available];
  const set = (patch: Partial<ReportOptions>) => setOptions((o) => ({ ...o, ...patch }));

  // 429: Download waits out the server's Retry-After
  const waitS = useCountdown(error?.retryAt ?? null);

  const blocked = Object.keys(problems).length > 0;
  const statusFiltered = family === "scan" && options.statuses != null;

  const toggleSection = (s: ReportSection, on: boolean) => {
    const next = available.filter((a) => (a === s ? on : chosen.includes(a)));
    set({ sections: next, preset: presetFor(family, next, scanType) });
  };
  const toggleIn = <T extends string>(all: readonly T[], current: T[] | null, v: T): T[] => {
    const base = current ?? [...all];
    return base.includes(v) ? base.filter((x) => x !== v) : all.filter((x) => x === v || base.includes(x));
  };

  return (
    <>
      <div className={EXPORT_DIALOG_LAYOUT.body}>
        {(family === "scan" || family === "run") && (
          <>
            <section className="space-y-2">
              <h3 className="text-sm font-medium">Preset</h3>
              <ChoiceCards<Preset | "custom">
                infoId={PRESET_TIP[family]}
                name={`${uid}-preset`}
                label="Preset"
                columns={2}
                value={options.preset ?? "custom"}
                onChange={(v) => {
                  if (v === "custom") set({ preset: null });
                  else set({ preset: v, sections: presetSections(family, v, scanType) });
                }}
                options={(["executive", "technical", "full", "custom"] as const).map((p) => ({
                  value: p,
                  title: p === "custom" ? "Custom" : PRESET_TEXT[p],
                  description: PRESET_DESCRIPTION[family][p],
                }))}
              />
            </section>
            <section className="space-y-2" data-testid="export-sections">
              <h3 className="text-sm font-medium">Sections</h3>
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {available.map((s) => (
                  <Checkbox2 key={s} id={`${ids.section}-${s}`} checked={chosen.includes(s)} onChange={(on) => toggleSection(s, on)}
                             infoId={SECTION_TIP[`${family}.${s}`]}>
                    <span className="block">{SECTION_TEXT[s].title}</span>
                    <span className="block text-xs text-zinc-500">{SECTION_TEXT[s].hint}</span>
                  </Checkbox2>
                ))}
              </div>
              {problems.sections && <p className="text-xs text-red-500" role="alert">{problems.sections}</p>}
            </section>
            <section className="space-y-2">
              <h3 className="text-sm font-medium flex items-center gap-1">Severities <InfoTip id="export.severities" /></h3>
              <div className="flex flex-wrap gap-2" role="group" aria-label="Severities">
                {SEVERITIES.map((s) => {
                  const on = options.severities == null || options.severities.includes(s);
                  return (
                    <button
                      key={s}
                      type="button"
                      aria-pressed={on}
                      data-testid={`export-severity-${s}`}
                      onClick={() => set({ severities: toggleIn<Severity>(SEVERITIES, options.severities, s) })}
                      className={cn(
                        "rounded-full border px-3 py-1 text-xs font-medium cursor-pointer transition-colors",
                        on ? "border-blue-500/70 bg-blue-500/10 text-blue-700 dark:text-blue-300" : "border-zinc-300 text-zinc-500 dark:border-zinc-700",
                      )}
                    >
                      {SEVERITY_TEXT[s]}
                    </button>
                  );
                })}
              </div>
              {problems.severities && <p className="text-xs text-red-500" role="alert">{problems.severities}</p>}
            </section>
          </>
        )}
        {family === "scan" && (
          <section className="space-y-2" data-testid="export-statuses">
            <h3 className="text-sm font-medium">Finding status</h3>
            <div className="grid grid-cols-2 gap-2">
              {STATUSES.map((s) => (
                <Checkbox2 key={s} id={`${uid}-status-${s}`} checked={options.statuses == null || options.statuses.includes(s)}
                           onChange={() => set({ statuses: toggleIn<FindingStatus>(STATUSES, options.statuses, s) })} infoId={STATUS_TIP[s]}>
                  {STATUS_TEXT[s]}
                </Checkbox2>
              ))}
            </div>
            {problems.statuses && <p className="text-xs text-red-500" role="alert">{problems.statuses}</p>}
          </section>
        )}
        <section className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <TextInput
            id={ids.prepared}
            field="prepared_for"
            label="Prepared for"
            infoId={family === "deliverable" ? "export.prepared_for.deliverable" : "export.prepared_for"}
            placeholder="Client name"
            value={options.prepared_for}
            error={problems.prepared_for}
            onChange={(v) => set({ prepared_for: v })}
          />
          {family !== "deliverable" && (
            <TextInput
              id={ids.title}
              field="title"
              label="Report title"
              infoId="export.title"
              placeholder="Leave empty for the usual title"
              value={options.title}
              error={problems.title}
              onChange={(v) => set({ title: v })}
            />
          )}
          <div className="space-y-1.5 min-w-0">
            <FieldLabel htmlFor={ids.label} infoId="export.label">Classification label</FieldLabel>
            <Select value={options.label} onValueChange={(v) => set({ label: v as ReportLabel })}>
              <SelectTrigger id={ids.label} className="w-full" data-testid="export-label">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LABELS.map((l) => <SelectItem key={l} value={l}>{LABEL_CHOICE_TEXT[l]}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          {family === "scan" && (
            <div className="space-y-1.5 min-w-0">
              <FieldLabel htmlFor={ids.hide} infoId="export.hide_evidence">Hide code snippets</FieldLabel>
              <div className="flex h-9 items-center gap-2">
                <Switch id={ids.hide} checked={options.hide_evidence} onCheckedChange={(v) => set({ hide_evidence: v })} data-testid="export-hide-evidence" />
                <span className="text-xs text-zinc-500">{options.hide_evidence ? "Evidence blocks and snippets left out" : "Snippets shown as found"}</span>
              </div>
            </div>
          )}
        </section>
        <p className={cn("text-sm text-zinc-600 dark:text-zinc-400", EXPORT_DIALOG_LAYOUT.text)} data-testid="export-summary">
          {summaryText(options, family, scanType)}
        </p>
        {error && (
          <ErrorPanel
            error={error}
            waitS={waitS}
            statusFiltered={statusFiltered}
            onRemoveStatusFilter={() => {
              set({ statuses: null });
              onClearError();
            }}
          />
        )}
      </div>
      <div className={EXPORT_DIALOG_LAYOUT.footer} data-testid="export-footer">
        <Button variant="outline" className="cursor-pointer" onClick={() => onOpenChange(false)}>
          {pending ? "Close" : "Cancel"}
        </Button>
        <Button
          className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
          data-testid="export-download"
          disabled={pending || blocked || waitS > 0}
          title={blocked ? Object.values(problems)[0] : waitS > 0 ? `Try again in ${waitS} s` : undefined}
          onClick={() => {
            if (pending || blocked || waitS > 0) return;
            onDownload(options);
          }}
        >
          {pending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
          {family === "deliverable" ? "Use for downloads" : pending ? "Building…" : "Download"}
        </Button>
      </div>
    </>
  );
}

/** Whole seconds left until `until` (0 when null or past), ticking every second. */
function useCountdown(until: number | null): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (until == null) return;
    const tick = () => {
      const t = Date.now();
      setNow(t);
      if (t >= until) clearInterval(timer);
    };
    const first = setTimeout(tick, 0);
    const timer = setInterval(tick, 1000);
    return () => {
      clearTimeout(first);
      clearInterval(timer);
    };
  }, [until]);
  return until == null ? 0 : Math.max(0, Math.ceil((until - now) / 1000));
}

function TextInput({ id, field, label, infoId, placeholder, value, error, onChange }: {
  id: string; field: TextField; label: string; infoId: InfoTipId; placeholder: string; value: string; error?: string;
  onChange: (v: string) => void;
}) {
  const max = TEXT_MAX[field];
  const length = textLength(value);
  return (
    <div className="space-y-1.5 min-w-0">
      <FieldLabel htmlFor={id} infoId={infoId}>{label}</FieldLabel>
      <Input id={id} value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} aria-invalid={!!error}
             aria-describedby={`${id}-hint`} data-testid={`export-${field}`} />
      <div id={`${id}-hint`} className="flex justify-between gap-2 text-xs">
        <span className={cn("min-w-0", error ? "text-red-500" : "text-zinc-500")} role={error ? "alert" : undefined}>
          {error ? `${label} ${error}.` : "Optional. Latin letters, one line."}
        </span>
        <span className={cn("shrink-0 tabular-nums", length > max ? "text-red-500" : "text-zinc-500")} data-testid={`export-${field}-count`}>
          {length}/{max}
        </span>
      </div>
    </div>
  );
}

function ErrorPanel({ error, waitS, statusFiltered, onRemoveStatusFilter }: {
  error: ReportDownloadError; waitS: number; statusFiltered: boolean; onRemoveStatusFilter: () => void;
}) {
  let title = "The report could not be built";
  let body = error.message;
  if (error.status === 409) title = "Finding statuses aren't available for this scan yet";
  else if (error.status === 503) title = "Finding statuses are unavailable right now";
  else if (error.status === 429) {
    title = "The server is busy building other reports";
    body = waitS > 0 ? `Try again in ${waitS} s.` : "You can try again now.";
  } else if (error.status === 400) title = "This report is not available yet";
  else if (error.status === 422) title = "The server refused an option";
  const offerRemove = (error.status === 409 || error.status === 503) && statusFiltered;
  return (
    <div role="alert" data-testid="export-error" data-status={error.status ?? "network"}
         className="flex items-start gap-2 rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm">
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-red-500" aria-hidden />
      <div className={cn("space-y-1", EXPORT_DIALOG_LAYOUT.text)}>
        <p className="font-semibold">{title}</p>
        {body !== title && <p className="text-zinc-700 dark:text-zinc-300">{body}</p>}
        {offerRemove && (
          <Button variant="outline" size="sm" className="mt-1 cursor-pointer" onClick={onRemoveStatusFilter} data-testid="export-remove-status-filter">
            Remove status filter
          </Button>
        )}
      </div>
    </div>
  );
}
