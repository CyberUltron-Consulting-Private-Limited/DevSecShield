// One query-key factory for every CBOM Sources query.  Keys always use a numeric team id so that
// invalidating the ["cbom-sources", teamId] prefix after a mutation refreshes every tab, the
// overview and the CBOM scan sidebar together.
export const cbomSourcesKeys = {
  all: (teamId: number) => ["cbom-sources", teamId] as const,
  overview: (teamId: number) => ["cbom-sources", teamId, "overview"] as const,
  nodes: (teamId: number) => ["cbom-sources", teamId, "nodes"] as const,
  sources: (teamId: number, group?: string) => ["cbom-sources", teamId, "items", group ?? "all"] as const,
  job: (teamId: number, jobId: number) => ["cbom-sources", teamId, "job", jobId] as const,
  settings: (teamId: number) => ["cbom-sources", teamId, "settings"] as const,
  evidence: (teamId: number) => ["cbom-sources", teamId, "evidence"] as const,
  runs: (teamId: number, scanId?: number) => ["cbom-sources", teamId, "runs", scanId ?? "all"] as const,
  run: (teamId: number, runId: number) => ["cbom-sources", teamId, "run", runId] as const,
  runAssets: (teamId: number, runId: number, filters: string) => ["cbom-sources", teamId, "run", runId, "assets", filters] as const,
  jobAssets: (teamId: number, jobId: number) => ["cbom-sources", teamId, "job", jobId, "assets"] as const,
  estimate: (teamId: number, include: string) => ["cbom-sources", teamId, "estimate", include] as const,
  template: (teamId: number, name: string) => ["cbom-sources", teamId, "template", name] as const,
}

export const TERMINAL_JOB = new Set(["success", "failure", "cancelled", "expired"])
export const TERMINAL_RUN = new Set(["done", "partial", "failed", "cancelled"])
