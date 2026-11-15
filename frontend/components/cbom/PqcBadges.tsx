// Badges of the "Quantum-vulnerable algorithms" card (CbomCryptoCharts), on code scans and Sources runs alike.
//
// Staging QA round 4 (A): at 390 px the group card's badge row (count, "Fix N", "NIST Level N", impact) was a
// ``flex shrink-0`` row beside the title, so it overflowed the card and was clipped ("NIST Level 0" cut, the impact
// badge gone), and the instance badge "NIST Level 0: no quantum resistance" squeezed the file path to a few characters.
// The badge row now wraps (flex-wrap, gap) and sits under the title below the sm breakpoint; the instance badge reads
// "L0" there, with the full text in its title and aria-label.

import { Badge } from "@/components/ui/badge";
import { nistLevelInfo } from "@/components/cbom/results/readinessExplain";

/** Impact-badge tone matching CbomResults.getImpactBadgeClass (High=orange, Medium=amber, Low=blue), so the
 * quantum-vulnerable list reads identically to the findings table. */
export function pqcImpactBadgeClass(impact: string | null | undefined): string {
  const i = (impact ?? "").toLowerCase();
  if (i === "critical") return "border-red-500/50 text-red-600 dark:text-red-400";
  if (i === "high") return "border-orange-500/50 text-orange-600 dark:text-orange-400";
  if (i === "medium") return "border-amber-500/50 text-amber-600 dark:text-amber-400";
  return "border-blue-500/50 text-blue-600 dark:text-blue-400";
}

/** The group card's trigger row: title above the badges below sm, side by side from sm up. */
export const PQC_GROUP_TRIGGER_ROW =
  "flex min-w-0 flex-1 flex-col items-start gap-1.5 pr-2 sm:flex-row sm:items-center sm:justify-between sm:gap-2";

export function PqcGroupBadges({ count, fix, nistLevel, impact }: {
  count: number;
  /** the "Fix N" number of the distinct-fix list below the cards; none: no badge */
  fix: number | undefined;
  nistLevel: number;
  impact: string | null | undefined;
}) {
  const level = nistLevelInfo(nistLevel);
  return (
    <div className="flex flex-wrap items-center gap-1.5 sm:justify-end" data-testid="pqc-group-badges">
      <Badge variant="secondary" className="tabular-nums" data-testid="pqc-group-count">{count}</Badge>
      {fix != null && (
        <Badge variant="outline" className="tabular-nums" data-testid="pqc-group-fix">Fix {fix}</Badge>
      )}
      <Badge variant="outline" className="border-orange-500/50 text-orange-600 dark:text-orange-400"
             title={`${level.name}. ${level.meaning}`}>
        NIST Level {nistLevel}
      </Badge>
      <Badge variant="outline" className={pqcImpactBadgeClass(impact)}>{impact ?? "—"}</Badge>
    </div>
  );
}

/** One instance's NIST level: "L0" below sm (so the file path beside it keeps its room), the full name from sm up. */
export function PqcInstanceLevelBadge({ level, impact }: { level: number | null | undefined; impact: string | null | undefined }) {
  const info = nistLevelInfo(level);
  const full = `NIST ${info.name}`;
  return (
    <Badge variant="outline" className={`shrink-0 text-[10px] ${pqcImpactBadgeClass(impact)}`}
           title={`${info.name}. ${info.meaning} ${info.next}`.trim()} aria-label={full}
           data-testid="pqc-instance-level">
      <span className="sm:hidden" aria-hidden>{info.name.split(":")[0].replace("Level ", "L")}</span>
      <span className="hidden sm:inline">{full}</span>
    </Badge>
  );
}
