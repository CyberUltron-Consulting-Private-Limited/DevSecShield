// What a job's credits note says (CB-14): a failed, cancelled or nothing-read job is refunded in full; a partly read
// one gives back the share of its targets skipped at runtime (scan window, Stop all, deadline, never-scan list,
// refused credential), so its note names the amount.

export function refundLabel(job: { credits: number; refunded: boolean; credits_refunded?: number }): string | null {
  const back = job.credits_refunded ?? (job.refunded ? job.credits : 0)
  if (!job.refunded || back <= 0) return null
  if (back >= job.credits) return "refunded"
  return `${Number(back.toFixed(2))} refunded`
}
