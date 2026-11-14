// The team's source cap (issue #224): "145 of 10,000 sources", with a tone that warns as the team nears it. The cap
// is a deployment setting (CBOM_MAX_SOURCES, per team CBOM_MAX_SOURCES_TEAMS); the server sends used/max/remaining.

export interface CbomSourceUsage {
  used: number
  max: number
  remaining: number
  setting: string
}

export type UsageTone = "zinc" | "amber" | "red";

const n = (v: number) => v.toLocaleString("en-US");

export function sourceUsage(usage: CbomSourceUsage | null | undefined): { text: string; tone: UsageTone; title: string } | null {
  if (!usage || !Number.isFinite(usage.max) || usage.max <= 0) return null;
  const tone: UsageTone = usage.remaining <= 0 ? "red" : usage.used / usage.max >= 0.9 ? "amber" : "zinc";
  const text = `${n(usage.used)} of ${n(usage.max)} sources`;
  const title = usage.remaining <= 0
    ? `This team has reached its limit of ${n(usage.max)} sources. Delete unused sources, or ask your operator to raise ${usage.setting}.`
    : `This team can add ${n(usage.remaining)} more sources (limit ${n(usage.max)}, set by ${usage.setting}).`;
  return { text, tone, title };
}
