import { AlertCircle, CheckCircle2, XCircle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import type { CicdCbomGate } from "@/utils/backend_api";

export interface PolicyGateView {
  label: string;
  /** true when the pipeline was blocked, false when it passed, null when no verdict was given (a log before the gate) */
  blocked: boolean | null;
  title?: string;
}

// The CBOM policy gate verdict as the pipeline received it (stored on the CI log). POST /cicd/cbom/scan answers
// gate_failed = (verdict != "pass"), so "fail", "no_result" and any other verdict all blocked the job.
// SOW S1: a verdict judged by the team's CBOM policy lists, per failing finding, the rules it broke; the hover text shows
// them under the reason (at most 10 findings), so the page tells the same story as the pipeline log.
export function gateTitle(gate: CicdCbomGate): string {
  const lines = gate.failing
    .filter((f) => f.rules && f.rules.length)
    .slice(0, 10)
    .map((f) => `• ${f.title}${f.location ? ` (${f.location}${f.line ? `:${f.line}` : ""})` : ""}: ` +
      (f.rules ?? []).filter((r) => r.outcome === "fail").map((r) => r.rule).join(", "));
  return lines.length ? `${gate.reason}\n${lines.join("\n")}` : gate.reason;
}

export function policyGateView(gate: CicdCbomGate | null | undefined): PolicyGateView {
  if (!gate) return { label: "—", blocked: null };
  if (gate.verdict === "pass") return { label: "Passed", blocked: false, title: gateTitle(gate) };
  if (gate.verdict === "fail") return { label: `Blocked (${gate.failing_count})`, blocked: true, title: gateTitle(gate) };
  return { label: "Blocked: no result", blocked: true, title: gateTitle(gate) };
}

export function PolicyGateBadge({ gate }: { gate: CicdCbomGate | null | undefined }) {
  const view = policyGateView(gate);
  if (view.blocked === null) return <span className="text-zinc-400">{view.label}</span>;
  if (!view.blocked) {
    return (
      <Badge className="bg-green-500 hover:bg-green-600 text-white" title={view.title}>
        <CheckCircle2 className="w-3 h-3 mr-1" />
        {view.label}
      </Badge>
    );
  }
  const Icon = gate?.verdict === "fail" ? XCircle : AlertCircle;
  return (
    <Badge className="bg-red-600 hover:bg-red-700 text-white" title={view.title}>
      <Icon className="w-3 h-3 mr-1" />
      {view.label}
    </Badge>
  );
}
