"use client";

// The code-scan page's VEX / Signature / Evidence pack / PDF Report buttons (components/CbomResults.tsx header), for a
// CBOM Sources run (CB-38 PR-8). Each saves the server's file as served: the signature covers the exact bytes of the
// run's CycloneDX JSON download. While the run is still collecting, every file says "as of" (the server writes the
// note into each one); the buttons stay enabled, as the run CBOM download does. VEX, Signature and Evidence pack are
// one click; PDF Report opens the export dialog (components/reports/ExportPdfDialog.tsx, family "run"), which builds
// the report and says its outcome.
import { useState } from "react";
import { Download, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { toast } from "@/utils/toast";
import { cbomRunDeliverableFilename, downloadCbomRunDeliverable, type CbomRunDeliverable } from "@/utils/backend_api";
import { useExportPdf } from "@/components/reports/ExportPdfDialog";
import { InfoTip } from "@/components/ui/info-tip";

export interface RunDeliverablesMenuProps {
  teamId: number;
  runId: number;
  active: boolean;
  /** its (i) tip after the buttons (false where the caller shows it, e.g. beside the run page's Export menu) */
  tip?: boolean;
}

export const RUN_DELIVERABLE_ITEMS: { kind: CbomRunDeliverable; label: string; title: string; done: string }[] = [
  {
    kind: "vex",
    label: "VEX",
    title: "CycloneDX 1.6 VEX: exploitable (weakness observed), in triage (quantum-only or inferred), resolved or will-not-fix from the remediation plan",
    done: "VEX downloaded",
  },
  {
    kind: "signature",
    label: "Signature",
    title: "HMAC-SHA256 signature over the exact bytes of this run's CycloneDX JSON download (the XML is not covered)",
    done: "BOM signature downloaded",
  },
  {
    kind: "evidence-pack",
    label: "Evidence pack",
    title: "Zip of the CycloneDX JSON and XML, OSCAL, VEX, signature and PDF report with a sha256 manifest",
    done: "Evidence pack downloaded",
  },
  {
    kind: "report.pdf",
    label: "PDF Report",
    title: "PDF report: posture, algorithm family by source, certificate expiry, top risks, compliance, findings and provenance",
    done: "PDF report downloaded",
  },
];

const AS_OF = " The run is still collecting: the file holds what has been collected so far.";

export default function RunDeliverablesMenu({ teamId, runId, active, tip = true }: RunDeliverablesMenuProps) {
  const [busy, setBusy] = useState<CbomRunDeliverable | null>(null);
  const pdf = useExportPdf({
    teamId,
    target: { family: "run", runId },
    fileName: cbomRunDeliverableFilename(runId, "report.pdf"),
    successText: active ? "PDF report downloaded as of now (the run is still collecting)" : "PDF report downloaded",
  });

  const download = async (kind: CbomRunDeliverable, done: string) => {
    setBusy(kind);
    try {
      await downloadCbomRunDeliverable(teamId, runId, kind);
      toast.success(active ? `${done} (as of now; the run is still collecting)` : done);
    } catch {
      // downloadCbomRunDeliverable already showed the error toast
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      {RUN_DELIVERABLE_ITEMS.map(({ kind, label, title, done }) => {
        const report = kind === "report.pdf";
        const working = report ? pdf.pending : busy === kind;
        return (
          <Button
            key={kind}
            variant="outline"
            className={report ? "cursor-pointer bg-zinc-700 hover:bg-zinc-600 text-white border-zinc-600" : "cursor-pointer"}
            title={active ? title + "." + AS_OF : title}
            onClick={() => (report ? pdf.open() : void download(kind, done))}
            disabled={working}
            data-testid={`run-download-${kind.replace(".", "-")}`}
          >
            {working ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Download className="h-4 w-4 mr-2" />}
            {report && working ? "Downloading..." : label}
          </Button>
        );
      })}
      {pdf.dialog}
      {tip && <InfoTip id="cbom.run.deliverables" />}
    </>
  );
}
