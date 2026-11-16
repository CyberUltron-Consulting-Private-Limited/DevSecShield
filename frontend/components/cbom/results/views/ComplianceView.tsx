"use client";

// Compliance (results redesign 12-A): crypto compliance readiness (the tri-state matrix, CbomCryptoCharts'
// "compliance" part), the RBI CSF roll-up, the CERT-In lane posture and the compliance mapping (each count filters the
// findings table on the summary), with the /parity and compliance notes. A run never attests (that is the code scan's
// flow); its "view findings" links go through drillToFindings.

import { CbomCryptoCharts, type CryptoChartPart } from "@/components/cbom/CbomCryptoCharts";
import { RbiCsfRollup, type RbiCsfRollupData } from "@/components/rbi/RbiCsfRollup";
import { CertInLanePosture } from "@/components/certin/CertInLanePosture";
import type { CertInRollupData } from "@/components/certin/certinShared";

import { ComplianceMappingSection } from "../ComplianceSummary";
import { SectionNote } from "../RunSections";
import type { RunViewCtx } from "./types";

export const COMPLIANCE_CHART_PARTS = ["compliance"] as const satisfies readonly CryptoChartPart[];

export function ComplianceView({ ctx }: { ctx: RunViewCtx }) {
  const { run, meta } = ctx;
  return (
    <div className="space-y-6 min-w-0">
      {/* variant "run" renders the compliance readiness from its own data when /results has no distributions */}
      <CbomCryptoCharts
        parts={COMPLIANCE_CHART_PARTS}
        variant="run"
        distributions={ctx.distributions}
        graph={ctx.graph}
        compliance={ctx.compliance}
        findings={[]}
        inventory={[]}
        showCodeHeatmap={false}
        readinessScope="run"
      />
      {ctx.parityNotes?.compliance && <SectionNote testId="run-compliance-readiness-note">{ctx.parityNotes.compliance}</SectionNote>}
      <RbiCsfRollup rollup={meta?.rbi_csf_rollup as RbiCsfRollupData | undefined} onViewFindings={ctx.onViewRefs} />
      {ctx.parityNotes?.rbi && <SectionNote testId="run-rbi-note">{ctx.parityNotes.rbi}</SectionNote>}
      {ctx.parityNotes?.certin && <SectionNote testId="run-certin-note">{ctx.parityNotes.certin}</SectionNote>}
      <CertInLanePosture lane="cbom" rollup={meta?.certin_posture as CertInRollupData | undefined} onViewFindings={ctx.onViewRefs} />
      {run.plan.compliance.show && (
        <ComplianceMappingSection frameworks={ctx.complianceMapping.frameworks} onDrill={ctx.onComplianceDrill} scope="run"
                                  note={run.plan.compliance.note ?? null}
                                  footnote={ctx.complianceMapping.basis === "posture" ? "From the run posture (this server does not send the run results summary yet)." : null} />
      )}
    </div>
  );
}
