"use client";

// Building blocks shared by the CBOM Sources tabs.  Styling follows the existing scanner pages:
// dark-first zinc surfaces, blue-600 primary actions, tinted outline badges, Loader2 spinners.

import { useQuery } from "@tanstack/react-query";
import { AlertCircle, Check, Copy, Loader2 } from "lucide-react";
import { useState, type ReactNode } from "react";
import { toast } from "@/utils/toast";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { CodeBlock } from "@/components/ui/shadcn-io/ai/code-block";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  getCbomJob,
  type CbomConfidence,
  type CbomQ0Gap,
  type CbomJob,
  type CbomJobStatus,
  type CbomNodeStatus,
  type CbomRunStatus,
  type CbomScanNode,
  type CbomTestStatus,
} from "@/utils/backend_api";

import { cbomSourcesKeys, TERMINAL_JOB } from "./keys";
import { refusalReason } from "./logic";
import { menuReveal, type MenuReveal } from "./reveal";

/** For a table's row menus whose items move to a form below: see reveal.ts. One per tab, shared by its row menus. */
export function useMenuReveal(): MenuReveal {
  const [reveal] = useState(() => menuReveal((id) => document.getElementById(id)));
  return reveal;
}

// ---------------------------------------------------------------------------- badges
export type Tone = "green" | "red" | "amber" | "blue" | "zinc";

const TONES: Record<Tone, string> = {
  green: "border-green-500/50 text-green-600 dark:text-green-400",
  red: "border-red-500/50 text-red-600 dark:text-red-400",
  amber: "border-amber-500/50 text-amber-600 dark:text-amber-400",
  blue: "border-blue-500/50 text-blue-600 dark:text-blue-400",
  zinc: "border-zinc-400/50 text-zinc-600 dark:text-zinc-400",
};

export function StatusBadge({ tone, children, title, className }: { tone: Tone; children: ReactNode; title?: string; className?: string }) {
  return (
    <Badge variant="outline" className={cn(TONES[tone], className)} title={title}>
      {children}
    </Badge>
  );
}

const NODE_STATUS: Record<CbomNodeStatus | "missing", [Tone, string]> = {
  online: ["green", "Online"],
  offline: ["red", "Offline"],
  pending_registration: ["blue", "Waiting to register"],
  registration_expired: ["amber", "Token expired"],
  missing: ["zinc", "No node"],
};
export function NodeStatusBadge({ status }: { status: CbomNodeStatus | "missing" | null | undefined }) {
  const [tone, label] = NODE_STATUS[status ?? "missing"] ?? NODE_STATUS.missing;
  return <StatusBadge tone={tone}>{label}</StatusBadge>;
}
export function nodeStatusLabel(status: CbomNodeStatus | "missing" | null | undefined): string {
  return (NODE_STATUS[status ?? "missing"] ?? NODE_STATUS.missing)[1];
}

const TEST_STATUS: Record<CbomTestStatus, [Tone, string]> = {
  never: ["zinc", "Not tested"],
  pending: ["blue", "Testing"],
  passed: ["green", "Passed"],
  partial: ["amber", "Partly ready"],
  failed: ["red", "Failed"],
  not_available: ["zinc", "Not available yet"],
  error: ["amber", "Could not test"],
};
export function TestStatusBadge({ status, title, detail }: { status: CbomTestStatus; title?: string | null; detail?: string | null }) {
  const [tone, label] = TEST_STATUS[status] ?? TEST_STATUS.never;
  return (
    <StatusBadge tone={tone} title={title ?? undefined}>
      {status === "pending" && <Loader2 className="animate-spin" />}
      {label}
      {detail ? ` · ${detail}` : null}
    </StatusBadge>
  );
}

const JOB_STATUS: Record<CbomJobStatus, [Tone, string]> = {
  pending: ["blue", "Waiting"],
  claimed: ["blue", "Running"],
  success: ["green", "Done"],
  failure: ["red", "Failed"],
  cancelled: ["zinc", "Cancelled"],
  expired: ["amber", "Expired"],
};
export function JobStatusBadge({ status, title }: { status: CbomJobStatus; title?: string | null }) {
  const [tone, label] = JOB_STATUS[status] ?? JOB_STATUS.pending;
  return (
    <StatusBadge tone={tone} title={title ?? undefined}>
      {status === "claimed" && <Loader2 className="animate-spin" />}
      {label}
    </StatusBadge>
  );
}

const RUN_STATUS: Record<CbomRunStatus, [Tone, string]> = {
  queued: ["blue", "Queued"],
  running: ["blue", "Running"],
  done: ["green", "Done"],
  partial: ["amber", "Partial"],
  failed: ["red", "Failed"],
  cancelled: ["zinc", "Cancelled"],
};
export function RunStatusBadge({ status }: { status: CbomRunStatus }) {
  const [tone, label] = RUN_STATUS[status] ?? RUN_STATUS.queued;
  return <StatusBadge tone={tone}>{label}</StatusBadge>;
}

/** Evidence confidence (CB-18, DA §2.3): E0..E3. Its own indigo palette with rising emphasis (E0 dashed outline, E1
 * outline, E2 tinted, E3 filled), never the risk-grade colours (red, orange, amber, green, grey). */
export const CONFIDENCE_LABEL: Record<CbomConfidence, string> = {
  E0: "Unknown",
  E1: "Self-attested",
  E2: "Documented",
  E3: "Verified",
};
export const CONFIDENCE_LEVELS: CbomConfidence[] = ["E0", "E1", "E2", "E3"];
const CONFIDENCE_STYLE: Record<CbomConfidence, string> = {
  E0: "border-dashed border-indigo-400/70 text-indigo-600 dark:text-indigo-300",
  E1: "border-indigo-500/60 text-indigo-700 dark:text-indigo-300",
  E2: "border-indigo-500/60 bg-indigo-50 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-200",
  E3: "border-indigo-700 bg-indigo-700 text-white dark:bg-indigo-500 dark:border-indigo-500",
};
export function ConfidenceBadge({ level, testId }: { level: CbomConfidence; testId?: string }) {
  const known = CONFIDENCE_LABEL[level] ? level : "E0";
  return (
    <Badge variant="outline" className={CONFIDENCE_STYLE[known]} data-testid={testId} data-level={known}>
      {known} {CONFIDENCE_LABEL[known]}
    </Badge>
  );
}

/** The risk-register entry an E0 item creates (DA §2.3): printed only as "Q0 gap", in the risk palette
 * (grey), with the server's reason as its tooltip and accessible name. */
export function Q0GapBadge({ gap, testId }: { gap: CbomQ0Gap | null | undefined; testId?: string }) {
  if (!gap) return null;
  const why = `Q0 gap: ${gap.text}${gap.detail ? ` (${gap.detail})` : ""}`;
  return (
    <span title={why} aria-label={why} data-testid={testId} data-reason={gap.reason}>
      <StatusBadge tone="zinc">Q0 gap</StatusBadge>
    </span>
  );
}

// ---------------------------------------------------------------------------- layout
export function SectionCard({
  title,
  description,
  actions,
  children,
  className,
  id,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
}) {
  return (
    <Card id={id} className={cn("border-zinc-200 dark:border-zinc-800 min-w-0", className)}>
      <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3">
        <div className="space-y-1.5 min-w-0">
          <CardTitle className="text-base">{title}</CardTitle>
          {description && <CardDescription>{description}</CardDescription>}
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </CardHeader>
      <CardContent className="min-w-0">{children}</CardContent>
    </Card>
  );
}

export function StatCard({ label, value, hint, tone }: { label: string; value: ReactNode; hint?: ReactNode; tone?: Tone }) {
  const color = tone === "green" ? "text-green-600 dark:text-green-400" : tone === "red" ? "text-red-600 dark:text-red-400" : "text-zinc-900 dark:text-white";
  return (
    <Card className="border-zinc-200 dark:border-zinc-800 py-4">
      <CardContent className="px-5">
        <p className="text-sm text-zinc-600 dark:text-zinc-400">{label}</p>
        <p className={cn("text-2xl font-semibold mt-1", color)}>{value}</p>
        {hint && <p className="text-xs text-zinc-500 mt-1">{hint}</p>}
      </CardContent>
    </Card>
  );
}

export function LoadingBlock() {
  return (
    <div className="flex h-48 items-center justify-center">
      <Loader2 className="size-8 animate-spin text-blue-600" />
    </div>
  );
}

/** ``error``: the failed query's error; a refusal shows the server's reason (refusalReason), never only "Could not
 * load this section". */
export function ErrorBlock({ message, error, onRetry }: { message?: string; error?: unknown; onRetry?: () => void }) {
  const reason = refusalReason(error);
  return (
    <div className="text-center py-10" role="alert">
      <p className="text-zinc-600 dark:text-zinc-400 mb-4">
        {message ?? reason ?? "Could not load this section. Please try again."}
        {message && reason && <span className="block mt-1 text-sm">{reason}</span>}
      </p>
      {onRetry && (
        <Button variant="outline" className="cursor-pointer" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

export function EmptyState({ title, body, action }: { title: string; body?: ReactNode; action?: ReactNode }) {
  return (
    <div className="text-center py-10 px-4 border border-dashed border-zinc-300 dark:border-zinc-700 rounded-lg">
      <p className="font-medium text-zinc-900 dark:text-white">{title}</p>
      {body && <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-1 max-w-xl mx-auto">{body}</p>}
      {action && <div className="mt-4 flex justify-center">{action}</div>}
    </div>
  );
}

export function Field({
  label,
  htmlFor,
  required,
  hint,
  error,
  children,
  className,
}: {
  label: ReactNode;
  htmlFor?: string;
  required?: boolean;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("space-y-2 min-w-0", className)}>
      <Label htmlFor={htmlFor}>
        {label}
        {required && <span className="text-red-500">*</span>}
      </Label>
      {children}
      {error ? (
        <p className="flex items-center gap-1.5 text-sm text-red-500 dark:text-red-400" role="alert">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </p>
      ) : (
        hint && <p className="text-xs text-zinc-500">{hint}</p>
      )}
    </div>
  );
}

/** Write-only secret input: never prefilled; on edit, blank keeps the stored value. */
export function SecretField({
  id,
  label,
  value,
  onChange,
  isSet,
  multiline,
  required,
  hint,
  error,
  placeholder,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  isSet?: boolean;
  multiline?: boolean;
  required?: boolean;
  hint?: ReactNode;
  error?: string | null;
  placeholder?: string;
}) {
  const ph = isSet ? "Saved. Leave blank to keep it" : placeholder ?? "";
  return (
    <Field label={label} htmlFor={id} required={required && !isSet} hint={hint ?? "Encrypted at rest by ZeroShield; sent only to the scan node that runs the job. Never shown again."} error={error}>
      {multiline ? (
        <Textarea
          id={id}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={ph}
          autoComplete="off"
          spellCheck={false}
          className="font-mono text-xs min-h-[96px] resize-y"
        />
      ) : (
        <Input id={id} type="password" value={value} onChange={(e) => onChange(e.target.value)} placeholder={ph} autoComplete="new-password" />
      )}
    </Field>
  );
}

// ---------------------------------------------------------------------------- copy and code
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to the legacy path */
  }
  try {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(area);
    return ok;
  } catch {
    return false;
  }
}

export function CopyButton({ text, label = "Copy", className }: { text: string; label?: string; className?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      className={cn("cursor-pointer", className)}
      onClick={async () => {
        if (await copyText(text)) {
          setDone(true);
          toast.success("Copied");
          setTimeout(() => setDone(false), 2000);
        } else {
          toast.error("Copy is blocked in this browser; select the text and copy it manually");
        }
      }}
    >
      {done ? <Check className="h-4 w-4 mr-1.5" /> : <Copy className="h-4 w-4 mr-1.5" />}
      {label}
    </Button>
  );
}

export function CodeSnippet({ code, language = "bash", className }: { code: string; language?: string; className?: string }) {
  return (
    <CodeBlock code={code} language={language} className={cn("text-xs [&_code]:!text-xs [&_pre]:!pr-24 [&_pre]:!whitespace-pre-wrap [&_pre]:!break-all", className)}>
      <CopyButton text={code} className="h-7 bg-background/80" />
    </CodeBlock>
  );
}

// ---------------------------------------------------------------------------- node picker
export function NodeSelect({
  id,
  nodes,
  value,
  onChange,
  placeholder = "Choose a scan node",
}: {
  id?: string;
  nodes: CbomScanNode[];
  value: number | null;
  onChange: (v: number | null) => void;
  placeholder?: string;
}) {
  return (
    <Select value={value ? String(value) : ""} onValueChange={(v) => onChange(v ? Number(v) : null)}>
      <SelectTrigger id={id} className="w-full cursor-pointer">
        <SelectValue placeholder={nodes.length ? placeholder : "Add a scan node first"} />
      </SelectTrigger>
      <SelectContent>
        {nodes.map((n) => (
          <SelectItem key={n.id} value={String(n.id)} className="cursor-pointer">
            {n.name}
            {n.segment ? ` · ${n.segment}` : ""} · {nodeStatusLabel(n.status)}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

// ---------------------------------------------------------------------------- dialogs
export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive,
  pending,
  onConfirm,
  onCloseAutoFocus,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  description: ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  pending?: boolean;
  onConfirm: () => void;
  /** where the focus goes when it closes (a plain Delete button is no DialogTrigger: see fleet/useOpener.ts) */
  onCloseAutoFocus?: (event: Event) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent onCloseAutoFocus={onCloseAutoFocus}>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant={destructive ? "destructive" : "default"}
            className={cn("cursor-pointer", !destructive && "bg-blue-600 hover:bg-blue-700 text-white")}
            disabled={pending}
            onClick={onConfirm}
          >
            {pending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------- polling
/** Poll a job every 6 s until it ends; stops on 404 and keeps trying through brief errors. */
export function usePolledJob(teamId: number, jobId: number | null) {
  return useQuery<CbomJob>({
    queryKey: cbomSourcesKeys.job(teamId, jobId ?? 0),
    queryFn: () => getCbomJob(teamId, jobId as number),
    enabled: Number.isFinite(teamId) && !!jobId,
    retry: 1,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      const httpStatus = (query.state.error as { response?: { status?: number } } | null)?.response?.status;
      if (httpStatus === 404) return false;
      return status && TERMINAL_JOB.has(status) ? false : 6000;
    },
  });
}

export function Truncate({ text, className }: { text: string | null | undefined; className?: string }) {
  return (
    <span className={cn("block truncate", className)} title={text ?? undefined}>
      {text ?? "—"}
    </span>
  );
}

export function KindLabel({ children }: { children: ReactNode }) {
  return <span className="text-xs font-medium uppercase tracking-wide text-zinc-500">{children}</span>;
}

// ---------------------------------------------------------------------------- choice cards (radio group)
export interface ChoiceOption<T extends string | number> {
  value: T;
  title: ReactNode;
  description?: ReactNode;
  disabled?: boolean;
}

/** Native radio inputs laid out as cards (there is no radio-group primitive in components/ui). */
export function ChoiceCards<T extends string | number>({
  name,
  value,
  onChange,
  options,
  columns = 2,
  label,
}: {
  name: string;
  value: T;
  onChange: (v: T) => void;
  options: ChoiceOption<T>[];
  columns?: 1 | 2 | 3 | 4;
  label?: string;
}) {
  const grid = { 1: "sm:grid-cols-1", 2: "sm:grid-cols-2", 3: "sm:grid-cols-3", 4: "sm:grid-cols-2 lg:grid-cols-4" }[columns];
  return (
    <div role="radiogroup" aria-label={label} className={cn("grid grid-cols-1 gap-2", grid)}>
      {options.map((opt) => {
        const checked = opt.value === value;
        return (
          <label
            key={String(opt.value)}
            className={cn(
              "flex items-start gap-3 rounded-lg border p-3 transition-colors",
              opt.disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer hover:border-zinc-400 dark:hover:border-zinc-600",
              checked ? "border-blue-500/70 bg-blue-500/5" : "border-zinc-200 dark:border-zinc-800",
            )}
          >
            <input
              type="radio"
              name={name}
              className="mt-0.5 h-4 w-4 accent-blue-600 shrink-0"
              checked={checked}
              disabled={opt.disabled}
              onChange={() => onChange(opt.value)}
            />
            <span className="min-w-0">
              <span className="block text-sm font-medium text-zinc-900 dark:text-white">{opt.title}</span>
              {opt.description && <span className="block text-xs text-zinc-600 dark:text-zinc-400 mt-0.5">{opt.description}</span>}
            </span>
          </label>
        );
      })}
    </div>
  );
}

export function Checkbox2({ id, checked, onChange, children }: { id: string; checked: boolean; onChange: (v: boolean) => void; children: ReactNode }) {
  return (
    <label htmlFor={id} className="flex items-start gap-2 text-sm text-zinc-700 dark:text-zinc-300 cursor-pointer">
      <input id={id} type="checkbox" className="mt-0.5 h-4 w-4 accent-blue-600 shrink-0" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span>{children}</span>
    </label>
  );
}
