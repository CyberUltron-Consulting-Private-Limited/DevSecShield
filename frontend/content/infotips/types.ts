import type { InfoTipId } from "./labels";

/** The text of one (i) tip, loaded with its area (text/<area>.ts). */
export interface InfoTipText {
  /** What it is, in plain words, with the real limits, units and behaviour. */
  what: string;
  /** Why it matters: the risk or consequence, one or two sentences. */
  why: string;
  /** One concrete example. */
  example: string;
}

/** A whole tip: its label (labels.ts, eager) and its text (text/<area>.ts, loaded on demand). */
export interface InfoTipEntry extends InfoTipText {
  /** What the (i) button is about; the button is named "About <label>". */
  label: string;
}

/** The text module of one area: only known ids (an unknown or misspelt id fails tsc). */
export type TipAreaText = { readonly [K in InfoTipId]?: InfoTipText };
