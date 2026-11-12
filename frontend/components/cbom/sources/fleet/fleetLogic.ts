// Pure helpers of the Fleet tab (no React), so they can be tested with tsx.
import type { CbomFleetStatus } from "@/utils/api/cbom_fleet";

export const ALL_OFF: CbomFleetStatus = { inventory: false, policies: false, transports: false, ssh_ca: false };

/** The Fleet tab shows when at least one fleet feature is on. While the status loads, or when it failed (a server
 * without the fleet routes answers 404), the tab stays hidden. */
export function fleetTabVisible(status: CbomFleetStatus | undefined): boolean {
  if (!status) return false;
  return Object.values({ ...ALL_OFF, ...status }).some(Boolean);
}

/** The sections whose flag is on, in registry order. */
export function visibleSections<T extends { flag: keyof CbomFleetStatus }>(sections: readonly T[], status: CbomFleetStatus | undefined): T[] {
  if (!status) return [];
  return sections.filter((s) => status[s.flag] === true);
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

/** The selector the API takes: {} (every target), one condition, or {all|any: [...]}. */
export function selectorFromDraft(draft: SelectorDraft): Record<string, unknown> {
  const leaves = draft.conditions
    .filter((c) => c.key.trim() !== "")
    .map((c) => {
      const leaf: Record<string, unknown> = c.on === "tag" ? { tag: c.key.trim().toLowerCase() } : { field: c.key };
      leaf.op = c.op;
      if (c.op === "in") leaf.value = c.value.split(",").map((v) => v.trim()).filter(Boolean);
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
