// CB-19 PR-2: a run records the grade inputs it was started with (team Mosca X/Y/Z, evidence levels and gaps). Run
// views show that record; when the team's inputs differ now, the run page says so and shows the grades "with current
// inputs" beside the record, never in its place. Pure helpers, shared by the run page, the drawer and Review & Run.

export interface CbomMosca { x: number | null; y: number | null; z: number | null }

export interface CbomGradeInputsRef {
  source: "snapshot" | "current";
  mosca: CbomMosca;
  digest: string;
  snapshot_digest?: string | null;
  captured_at?: string | null;
}

/** The fields the run posture adds for the two clocks (absent on an older backend). */
export interface CbomPostureGrades {
  q_grades?: Record<string, number>;
  q_grades_now?: Record<string, number> | null;
  q_changed_now?: number | null;
  inputs_changed?: boolean;
  model_changed?: boolean;
  grade_inputs?: CbomGradeInputsRef;
  grade_inputs_now?: CbomGradeInputsRef | null;
}

export interface CbomGradeNow { q_grade: string | null; q_label: string | null; q_reason: string }

// index = the grade's digit (the API's codes are "Q" + digit); the word is always printed next to the code
const GRADE_WORDS = ["Unknown", "Critical", "High", "Medium", "Low"];
export const GRADE_CODES = GRADE_WORDS.map((_w, i) => `Q${i}`);

/** "Q3 Medium"; "No grade" for null / "none"; an unknown code is printed as it is. */
export function gradeText(code: string | null | undefined): string {
  if (!code || code === "none") return "No grade";
  const i = GRADE_CODES.indexOf(code);
  return i >= 0 ? `${code} ${GRADE_WORDS[i]}` : code;
}

/** "10/5/12" (X/Y/Z), "—" for a value that is not set. */
export function moscaText(m: CbomMosca | null | undefined): string {
  if (!m) return "—";
  return [m.x, m.y, m.z].map((v) => (v == null ? "—" : String(v))).join("/");
}

/** The banner sentence, or null when the run's inputs equal the team's now (or the run has no snapshot). */
export function inputsChangedText(p: CbomPostureGrades): string | null {
  if (!p.inputs_changed || !p.grade_inputs || !p.grade_inputs_now) return null;
  const n = p.q_changed_now ?? 0;
  const assets = n === 1 ? "1 asset grades" : `${n} assets grade`;
  return `Inputs changed since this run started: Mosca ${moscaText(p.grade_inputs.mosca)} → ${moscaText(p.grade_inputs_now.mosca)}` +
    ` (X/Y/Z years); ${assets} differently now`;
}

/** "Q1 Critical 2 · Q2 High 0 · …" in grade order, then "no grade". */
export function distributionText(d: Record<string, number> | null | undefined): string {
  if (!d) return "";
  const parts = GRADE_CODES.map((c) => `${gradeText(c)} ${d[c] ?? 0}`);
  if (d.none) parts.push(`no grade ${d.none}`);
  return parts.join(" · ");
}

/** The drawer line next to the record grade, or null when the current inputs give the same grade. */
export function gradeNowText(record: string | null | undefined, now: CbomGradeNow | null | undefined): string | null {
  if (!now) return null;
  return `Recorded at Start: ${gradeText(record)} · with current inputs: ${gradeText(now.q_grade)}`;
}
