// One query-key factory for the Repositories pages: invalidating ["scm", teamId] refreshes every tab.
export const scmKeys = {
  all: (teamId: number) => ["scm", teamId] as const,
  team: (teamId: number) => ["team-details", String(teamId)] as const,
  connections: (teamId: number) => ["scm", teamId, "connections"] as const,
  connection: (teamId: number, id: number) => ["scm", teamId, "connection", id] as const,
  repos: (teamId: number, query: string) => ["scm", teamId, "repos", query] as const,
  policies: (teamId: number) => ["scm", teamId, "policies"] as const,
  runs: (teamId: number) => ["scm", teamId, "runs"] as const,
  run: (teamId: number, id: number, page: number) => ["scm", teamId, "run", id, page] as const,
  findings: (teamId: number, query: string) => ["scm", teamId, "findings", query] as const,
  finding: (teamId: number, id: number) => ["scm", teamId, "finding", id] as const,
  rollup: (teamId: number) => ["scm", teamId, "rollup"] as const,
}
