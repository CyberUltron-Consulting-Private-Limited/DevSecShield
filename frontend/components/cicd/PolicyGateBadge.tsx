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
export function policyGateView(gate: CicdCbomGate | null | undefined): PolicyGateView {
  if (!gate) return { label: "—", blocked: null };
  if (gate.verdict === "pass") return { label: "Passed", blocked: false, title: gate.reason };
  if (gate.verdict === "fail") return { label: `Blocked (${gate.failing_count})`, blocked: true, title: gate.reason };
  return { label: "Blocked: no result", blocked: true, title: gate.reason };
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
