// Staging QA round 2 (D7 grade, item 5): a probed TLS endpoint's grade in the run's endpoint dialog, exactly as D7 prints it. The backend sends the
// record (network_estate.Grade.record: grade, letter, score, caps, warnings); these helpers only format it.
import type { CbomTlsGrade } from "@/utils/backend_api";

/** "B* · score 92" (the grade text D7 prints, then its score). */
export function tlsGradeText(grade: CbomTlsGrade | null | undefined): string {
  if (!grade) return "—";
  return grade.score == null ? grade.grade : `${grade.grade} · score ${grade.score}`;
}

/** Every reason the grade is below A+ (the caps, trust and name issues, then the warnings), de-duplicated. */
export function tlsGradeReasonList(grade: CbomTlsGrade | null | undefined): string[] {
  if (!grade) return [];
  return Array.from(new Set([...(grade.caps ?? []), ...(grade.warnings ?? [])]));
}

/** The same reasons on one line (the grade's tooltip). */
export function tlsGradeReasons(grade: CbomTlsGrade | null | undefined): string {
  return tlsGradeReasonList(grade).join("; ");
}
