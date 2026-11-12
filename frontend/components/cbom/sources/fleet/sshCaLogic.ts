// Fleet > SSH CA (F1.4): pure helpers of SshCaSection, tested with
//   npx --yes tsx components/cbom/sources/fleet/sshCaLogic.test.ts

export interface Readiness {
  age_s: number
  min_age_s: number
  promote_after: string | null
  fetchers_total: number
  fetchers_ready: number
}

/** "3 of 5 servers that fetch the trust bundle have this key", and whether promoting now needs force (the key is
 * younger than the minimum age the server enforces). */
export function readinessText(r: Readiness | null | undefined, formatDate: (iso: string | null) => string): { text: string; early: boolean } | null {
  if (!r) return null
  const early = r.age_s < r.min_age_s
  const servers = r.fetchers_total
    ? `${r.fetchers_ready} of ${r.fetchers_total} servers that fetch the trust bundle have this key`
    : "No server fetches the trust bundle with a trust token yet"
  return { text: early ? `${servers}. Promote after ${formatDate(r.promote_after)}, or force it.` : `${servers}.`, early }
}

/** A principal of THIS team, spelled the one way the server accepts (zs-<team>-<group>, no leading zeros). */
export function principalOk(principal: string, teamId: number): boolean {
  return /^zs-(0|[1-9]\d{0,9})-[a-z0-9][a-z0-9._-]{0,47}$/.test(principal) && principal.startsWith(`zs-${teamId}-`)
}
