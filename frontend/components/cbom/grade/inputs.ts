// CB-19 PR-2: a run records the grade inputs it was started with (team Mosca X/Y/Z, evidence levels and Q0 gaps).
// Run views show that record; when the team's inputs differ now, the run page says so and shows the grades "with
// current inputs" beside the record, never in its place. Pure helpers for QDistributionCard (the banner),
// QGradeDrawerSection (the drawer line) and Review & Run's grade inputs card.
import { GRADE_KEYS, gradeText, type QPosture } from "./model";

export interface Mosca { x: number | null; y: number | null; z: number | null }

/** `q_now` of the asset detail: the grade with the team's inputs now (null when they equal the run's snapshot). */
export interface QGradeNow { q_grade: string | null; q_label: string | null; q_reason: string }

/** "10/5/12" (X/Y/Z), "—" for a value that is not set (0 is a value). */
export function moscaText(m: Mosca | null | undefined): string {
  if (!m) return "—";
  return [m.x, m.y, m.z].map((v) => (v == null ? "—" : String(v))).join("/");
}

/** The banner sentence, or null when the run's inputs equal the team's now (or the run has no snapshot). */
export function inputsChangedText(p: QPosture): string | null {
  if (!p.inputs_changed || !p.grade_inputs || !p.grade_inputs_now) return null;
  const n = p.q_changed_now ?? 0;
  const assets = n === 1 ? "1 asset grades" : `${n} assets grade`;
  return `Inputs changed since this run started: Mosca ${moscaText(p.grade_inputs.mosca)} → ` +
    `${moscaText(p.grade_inputs_now.mosca)} (X/Y/Z years); ${assets} differently now`;
}

/** The grade distribution in grade order as one line ("… · no grade 4"). */
export function distributionText(d: Partial<Record<string, number>> | null | undefined): string {
  if (!d) return "";
  const parts = GRADE_KEYS.map((k) => `${gradeText(k)} ${d[k] ?? 0}`);
  if (d.none) parts.push(`no grade ${d.none}`);
  return parts.join(" · ");
}

/** The drawer line under the record grade, or null when the current inputs give the same grade. */
export function gradeNowText(record: string | null | undefined, now: QGradeNow | null | undefined): string | null {
  if (!now) return null;
  return `Recorded at Start: ${gradeText(record) ?? "no grade"} · with current inputs: ${gradeText(now.q_grade) ?? "no grade"}`;
}

/** What the "Graded with" line says about where the Mosca came from. */
export function inputsSourceText(source: string | null | undefined): string {
  if (source === "snapshot") return " (recorded when the run started)";
  if (source === "current") return " (the team's settings now, not when the run started)";
  return "";
}
