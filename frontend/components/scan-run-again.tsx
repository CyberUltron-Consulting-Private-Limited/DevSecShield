"use client";

// "Run again" on a failed code scan, and the notice on the new scan it opens (utils/scanRerun.ts).

import { useMutation } from "@tanstack/react-query";
import { Loader2, RotateCcw } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import {
  createAIBOMScan,
  createCBOMScan,
  createDASTScan,
  createIACConversation,
  createSastConversation,
  createSBOMSCAScan,
} from "@/utils/backend_api";
import { showErrorToast } from "@/utils/error-handler";
import { dastRerunPrefill, saveDastRerun } from "@/utils/dastRerun";
import { readRerun, rerunNotes, rerunPrefill, rerunTitle, saveRerun, type CodeScanType, type RerunPrefill } from "@/utils/scanRerun";

const CREATE: Record<CodeScanType, (teamId: number, title: string) => Promise<number>> = {
  sast: createSastConversation,
  iac: createIACConversation,
  sbom_sca: createSBOMSCAScan,
  cbom: createCBOMScan,
  ai_bom: createAIBOMScan,
};

/** Creates a new scan with the failed scan's settings and opens it (nothing is charged until its Start). */
export function RunAgainButton({ type, teamId, scan }: { type: CodeScanType; teamId: number; scan: unknown }) {
  const router = useRouter();
  const create = useMutation({
    mutationFn: () => CREATE[type](teamId, rerunTitle((scan as { title?: unknown } | null)?.title)),
    onSuccess: (newId) => {
      const prefill = rerunPrefill(type, scan);
      if (prefill) saveRerun(type, newId, prefill);
      router.push(`/${teamId}/${type}/${newId}`);
    },
    onError: (err) => showErrorToast(err, "Could not create the new scan"),
  });
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => create.mutate()}
      disabled={create.isPending}
      data-testid="scan-run-again"
      className="w-full h-8 px-2 bg-blue-600 hover:bg-blue-700 text-white cursor-pointer hover:text-white disabled:opacity-50"
    >
      {create.isPending ? <Loader2 className="size-4 mr-2 animate-spin" /> : <RotateCcw className="size-4 mr-2" />}
      <span>Run again</span>
    </Button>
  );
}

/** "Run again" on a failed DAST scan: a new DAST scan with the failed scan's settings (utils/dastRerun.ts); the
 * customer enters the login password again. */
export function DastRunAgainButton({ teamId, scan }: { teamId: number; scan: unknown }) {
  const router = useRouter();
  const create = useMutation({
    mutationFn: () => createDASTScan(teamId, rerunTitle((scan as { title?: unknown } | null)?.title)),
    onSuccess: (newId) => {
      const prefill = dastRerunPrefill(scan);
      if (prefill) saveDastRerun(newId, prefill);
      router.push(`/${teamId}/dast/${newId}`);
    },
    onError: (err) => showErrorToast(err, "Could not create the new scan"),
  });
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => create.mutate()}
      disabled={create.isPending}
      data-testid="scan-run-again"
      className="w-full h-8 px-2 bg-blue-600 hover:bg-blue-700 text-white cursor-pointer hover:text-white disabled:opacity-50"
    >
      {create.isPending ? <Loader2 className="size-4 mr-2 animate-spin" /> : <RotateCcw className="size-4 mr-2" />}
      <span>Run again</span>
    </Button>
  );
}

/** On a scan opened by "Run again": hands the copied settings to ``apply`` once, and returns them for the notice. */
export function useRerunPrefill(type: CodeScanType, scanId: number, apply: (p: RerunPrefill) => void): RerunPrefill | null {
  const [prefill, setPrefill] = useState<RerunPrefill | null>(null);
  useEffect(() => {
    const p = Number.isFinite(scanId) ? readRerun(type, scanId) : null;
    if (!p) return;
    apply(p);
    setPrefill(p);
    // apply is a fresh closure every render; this runs once per scan
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [type, scanId]);
  return prefill;
}

export function RerunNotice({ prefill }: { prefill: RerunPrefill | null }) {
  if (!prefill) return null;
  return (
    <div className="rounded-md border border-blue-500/40 bg-blue-500/10 p-3 text-xs text-blue-200 space-y-1" role="status" data-testid="scan-rerun-notice">
      {rerunNotes(prefill).map((note) => <p key={note}>{note}</p>)}
    </div>
  );
}
