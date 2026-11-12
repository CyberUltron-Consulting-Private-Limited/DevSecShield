// Pure helpers of the Fleet tab (no React), so they can be tested with tsx.
import type { CbomFleetStatus } from "@/utils/api/cbom_fleet";

export const ALL_OFF: CbomFleetStatus = { inventory: false, policies: false, transports: false, ssh_ca: false };

/** The sections whose flag is on, in registry order. */
export function visibleSections<T extends { flag: keyof CbomFleetStatus }>(sections: readonly T[], status: CbomFleetStatus | undefined): T[] {
  if (!status) return [];
  return sections.filter((s) => status[s.flag] === true);
}

export type FleetTabMode = "on" | "off" | "pending" | "error";

/** What the deployment's status says about the Fleet tab:
 * - "on": at least one section registered in this build has its flag on (a flag without a section shows nothing,
 *   so nobody sees an empty tab);
 * - "off": every such flag is off, or an older server without the fleet routes answered 404;
 * - "pending": the status is loading or retrying (a 429 waits for Retry-After): not known yet, which is not "off";
 * - "error": the status failed for another reason.
 * After a failed background refetch TanStack keeps the last data, so the last flags still decide. */
export function fleetTabMode(
  q: { data?: CbomFleetStatus | null; isError: boolean; error?: unknown },
  sections: readonly { flag: keyof CbomFleetStatus }[],
): FleetTabMode {
  if (q.data) return visibleSections(sections, q.data).length > 0 ? "on" : "off";
  if (q.isError) return isNotFound(q.error) ? "off" : "error";
  return "pending";
}

/** Whether the Fleet tab is shown. Before the status is known, only a deep link to it (?tab=fleet) shows it, with its
 * loading or error block, so the page does not open another tab and then jump to Fleet when the status arrives. */
export function fleetTabShown(mode: FleetTabMode, requested: string | null): boolean {
  if (mode === "on") return true;
  return requested === "fleet" && (mode === "pending" || mode === "error");
}

/** The tab to show for ``?tab=``: the requested one when it exists and is shown, otherwise the first tab. */
export function pickTab<T extends string>(requested: string | null, tabs: readonly T[], shown: (tab: T) => boolean): T {
  const hit = tabs.find((t) => t === requested);
  return hit !== undefined && shown(hit) ? hit : tabs[0];
}

/** What the Fleet tab renders for its status query. Data wins: after a failed background refetch TanStack keeps the
 * last data and sets isError, and the sections must stay mounted ("stale"); the error block is only for a first load
 * that failed. */
export function fleetTabState(q: { data?: unknown; isError: boolean; isLoading?: boolean }): "loading" | "error" | "stale" | "ok" {
  if (q.data !== undefined && q.data !== null) return q.isError ? "stale" : "ok";
  return q.isError ? "error" : "loading";
}

/** A 409: the row changed since it was loaded (another tab or person); the form offers the latest version. */
export function isConflict(error: unknown): boolean {
  return (error as { response?: { status?: number } } | null)?.response?.status === 409;
}

/** A 404 from the API (an older server without the fleet routes): not worth retrying. */
export function isNotFound(error: unknown): boolean {
  return (error as { response?: { status?: number } } | null)?.response?.status === 404;
}

// ---------------------------------------------------------------------------- policies (F1.2)
export type ConditionOp = "eq" | "ne" | "in" | "exists" | "prefix";
export interface Condition {
  on: "tag" | "field";
  key: string; // tag key, or kind / account_id / region / platform
  op: ConditionOp;
  value: string; // "in": comma-separated
}
export interface SelectorDraft {
  mode: "all" | "any";
  conditions: Condition[];
}

export const OP_LABEL: Record<ConditionOp, string> = {
  eq: "is",
  ne: "is not",
  in: "is one of",
  exists: "is set",
  prefix: "starts with",
};

function splitValues(value: string): string[] {
  return value.split(",").map((v) => v.trim()).filter(Boolean);
}

/** What stops the conditions from being saved, one line per condition ("Condition 2: enter a tag key"). A condition
 * is never dropped: dropping "Tag (empty) is prod" left {}, which matches every target. */
export function conditionProblems(draft: SelectorDraft): string[] {
  return draft.conditions.flatMap((c, i) => {
    const which = `Condition ${i + 1}`;
    if (c.on === "tag" && c.key.trim() === "") return [`${which}: enter a tag key`];
    if (c.op === "exists") return [];
    if (c.op === "in") return splitValues(c.value).length ? [] : [`${which}: enter at least one value`];
    return c.value.trim() === "" ? [`${which}: enter a value`] : [];
  });
}

/** The selector the API takes: {} (no condition: every target), one condition, or {all|any: [...]}. Throws the first
 * problem when a condition is incomplete. */
export function selectorFromDraft(draft: SelectorDraft): Record<string, unknown> {
  const problems = conditionProblems(draft);
  if (problems.length) throw new Error(problems[0]);
  const leaves = draft.conditions.map((c) => {
    const leaf: Record<string, unknown> = c.on === "tag" ? { tag: c.key.trim().toLowerCase() } : { field: c.key };
    leaf.op = c.op;
    if (c.op === "in") leaf.value = splitValues(c.value);
    else if (c.op !== "exists") leaf.value = c.value.trim();
    return leaf;
  });
  if (leaves.length === 0) return {};
  if (leaves.length === 1) return leaves[0];
  return { [draft.mode]: leaves };
}

function leafCondition(node: Record<string, unknown>): Condition | null {
  const op = node.op as ConditionOp;
  if (!(op in OP_LABEL)) return null;
  const value = op === "in" ? ((node.value as string[]) ?? []).join(", ") : op === "exists" ? "" : String(node.value ?? "");
  if (typeof node.tag === "string") return { on: "tag", key: node.tag, op, value };
  if (typeof node.field === "string") return { on: "field", key: node.field, op, value };
  return null;
}

/** The builder's view of a stored selector, or null when it uses what the builder cannot show (not, nesting): the
 * form then edits it as JSON. */
export function draftFromSelector(selector: Record<string, unknown> | null | undefined): SelectorDraft | null {
  if (!selector || Object.keys(selector).length === 0) return { mode: "all", conditions: [] };
  const single = leafCondition(selector);
  if (single) return { mode: "all", conditions: [single] };
  for (const mode of ["all", "any"] as const) {
    const items = selector[mode];
    if (Array.isArray(items)) {
      const conditions = items.map((i) => (i && typeof i === "object" ? leafCondition(i as Record<string, unknown>) : null));
      return conditions.every(Boolean) ? { mode, conditions: conditions as Condition[] } : null;
    }
  }
  return null;
}

/** One line a person reads: "env is prod and team is one of pay, ops"; "every target" for {}. */
export function selectorText(selector: Record<string, unknown> | null | undefined): string {
  const draft = draftFromSelector(selector);
  if (!draft) return JSON.stringify(selector);
  if (draft.conditions.length === 0) return "every target";
  const parts = draft.conditions.map(
    (c) => `${c.on === "tag" ? c.key : c.key.replace("_", " ")} ${OP_LABEL[c.op]}${c.op === "exists" ? "" : ` ${c.value}`}`,
  );
  return parts.join(draft.mode === "all" ? " and " : " or ");
}

const WEEKDAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

export interface ActionView {
  never_scan?: boolean;
  transport?: string;
  tier?: number;
  batch_size?: number;
  schedule?: { frequency: string; time_of_day: string; weekday: number | null; monthday: number | null } | null;
}

export function actionText(action: ActionView): string {
  if (action.never_scan) return "Never scan";
  const how = `Collect over ${(action.transport ?? "ssh").toUpperCase()}, tier ${action.tier ?? 1}, batches of ${action.batch_size ?? 100}`;
  const s = action.schedule;
  if (!s) return `${how}; run on demand`;
  const when =
    s.frequency === "daily"
      ? `daily at ${s.time_of_day}`
      : s.frequency === "weekly"
        ? `${WEEKDAYS[s.weekday ?? 0]}s at ${s.time_of_day}`
        : `monthly on day ${s.monthday} at ${s.time_of_day}`;
  return `${how}; ${when}`;
}

/** Who decided a target: the winning policy and how many others also matched, or the never-scan list. */
export function decisionText(
  decision: { action: string; policy_id: number | null; matched_policy_ids: number[] },
  policies: Record<string, { name: string; priority: number }>,
): string {
  const matched = decision.matched_policy_ids.length;
  if (decision.policy_id == null) {
    if (decision.action === "never_scan") {
      return matched ? `Never-scan list (overrides ${matched} matching ${matched === 1 ? "policy" : "policies"})` : "Never-scan list";
    }
    return "No policy matches";
  }
  const others = decision.matched_policy_ids.filter((id) => id !== decision.policy_id).length;
  const p = policies[String(decision.policy_id)];
  const name = p ? `${p.name} (priority ${p.priority})` : `Policy #${decision.policy_id}`;
  return others ? `${name} (also matched ${others} more)` : name;
}

export const DECISION_LABEL: Record<string, string> = { collect: "Collect", never_scan: "Never scan", unmanaged: "Not collected" };

const COVERAGE_LABEL: Record<string, string> = {
  denied: "access denied",
  not_enabled: "region not enabled",
  not_available: "not offered in this region",
  unreachable: "could not be reached",
  "skipped:region_unreachable": "skipped (the region could not be reached)",
  cancelled: "stopped (the sync ran out of time)",
  truncated: "more than 5,000; the rest not read",
};

/** What an AWS inventory sync could not read, as "region/service: why" lines (ok scopes are left out). */
export function coverageGaps(coverage: Record<string, Record<string, string>> | null | undefined): string[] {
  const out: string[] = [];
  for (const [region, services] of Object.entries(coverage ?? {})) {
    for (const [service, status] of Object.entries(services)) {
      if (status === "ok") continue;
      const why = COVERAGE_LABEL[status] ?? (status.startsWith("error:") ? `error ${status.slice(6)}` : status);
      out.push(`${region}/${service}: ${why}`);
    }
  }
  return out;
}

/** What a person calls a target: its host name or address, else the name its cloud gives it (a certificate's domain,
 * a secret's or load balancer's name, a database identifier, a key id), else its external id. */
export function targetLabel(t: {
  hostname?: string | null;
  address?: string | null;
  external_id: string;
  attributes?: Record<string, unknown> | null;
}): string {
  const a = t.attributes ?? {};
  for (const v of [t.hostname, t.address, a.domain, a.name, a.identifier, a.key_id]) {
    if (typeof v === "string" && v.trim() !== "") return v;
  }
  return t.external_id;
}
