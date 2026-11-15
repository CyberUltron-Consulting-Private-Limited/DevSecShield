/**
 * The (i) info tips: a label per stable id (`<surface>.<area>.<item>`, labels.ts, loaded with the page) and the text
 * per area (text/<area>.ts, loaded on demand by load.ts the first time a tip of that area renders), issue #145.
 *
 * Rules for the text (checked by content/infotips.test.ts):
 *  - "what" says what the field, metric or setting is and what the product really does with it (limits, units,
 *    credits, meaning of each value); "example" is one concrete example.
 *  - Every entry has a `// src:` comment directly above it naming the code it was checked against
 *    (`<repo-relative path>:<line>` or `:<from>-<to>`), so a reviewer can verify it. Behaviour that could not be
 *    verified in the code is left out of the text, never guessed.
 *  - An id shared by several products is used only where they run the same code.
 *  - The text describes what the product does today. Where an open issue will change that behaviour, the `// src:`
 *    note names the issue (e.g. "#47"), so the fix updates the tip in the same PR.
 *  - "why": why it matters (the risk or consequence); shown between the text and the example. Required.
 *
 * Adding a tip: its label in labels.ts, its text (with the `// src:` note) in the text module of its area
 * (areas.ts maps the id's prefix to the area; a new prefix goes there first).
 *
 * Components: <InfoTip id="…" /> and <FieldLabel infoId="…"> in components/ui/info-tip.tsx. App code never imports
 * the text modules or all.ts (content/infotipsBundle.test.ts).
 */
export { INFO_TIP_LABELS, type InfoTipId } from "./labels";
export { AREA_PREFIXES, TIP_AREAS, areaOf, type TipArea } from "./areas";
export { loadTipArea, subscribeTipAreas, tipAreaState, type TipAreaState } from "./load";
export type { InfoTipEntry, InfoTipText, TipAreaText } from "./types";
