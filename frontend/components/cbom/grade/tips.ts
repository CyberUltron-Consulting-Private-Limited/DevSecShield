/**
 * (i) info tips of the crypto-agility and quantum-risk components. The text lives in F2's registry
 * (`frontend/content/infotips.ts`, the "crypto-agility and quantum-risk grade" section, each entry with its `// src:`
 * note); the components render it with <InfoTip />. This module keeps the ids the grade components use.
 *
 * The six fix-class texts are the backend's own (`agility.CLASS_TEXT`, `agility.INFERRED_TEXT`):
 * gradeContract.test.ts checks them against contracts/cbom/grade_keys.json, which a backend test keeps equal to
 * agility.py. A reworded class in the backend fails CI until the tip says the same.
 */
import { INFO_TIPS, type InfoTipEntry } from "@/content/infotips";

export type TipEntry = InfoTipEntry;

const GRADE_TIP_IDS = [
  "cbom.agility.configurable",
  "cbom.agility.code_fixed",
  "cbom.agility.vendor_fixed",
  "cbom.agility.hardware_fixed",
  "cbom.agility.unknown",
  "cbom.agility.inferred",
  "cbom.agility.self_fixable",
  "cbom.agility.excl_pq",
  "cbom.source.operated_by",
  "cbom.qgrade.distribution",
] as const;
export type GradeTipId = (typeof GRADE_TIP_IDS)[number];

export const GRADE_TIPS = Object.fromEntries(GRADE_TIP_IDS.map((id) => [id, INFO_TIPS[id]])) as Record<GradeTipId, TipEntry>;


/** The tip of a fix-class value (none has no tip). */
export function fixClassTipId(value: string): GradeTipId | null {
  const id = `cbom.agility.${value.replace(/-/g, "_")}`;
  return id in GRADE_TIPS ? (id as GradeTipId) : null;
}
