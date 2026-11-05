// Which validation the Cloud & Identity tab shows: the result this browser just received, or the server's record.

export interface LiveResult {
  sourceId: number
  status: string
  at: string | null // validated_at, the same instant the server stores as last_test_at
}

export interface ListedSource {
  id: number
  last_test_status: string
  last_test_at: string | null
}

/**
 * A result this browser received stays shown only while the server still holds it. Once a source list read after
 * the validation (its server_time is not older) shows that account's test differently — a newer test, or a
 * connection change that reset it to "never" so runs skip the account — the server's state wins.
 * `editingId`: the account in the form, which may be missing from a list fetched before it was created.
 */
export function keepLiveValidation(
  live: LiveResult | null,
  sources: ListedSource[],
  listedAt: string | null | undefined,
  editingId: number | null | undefined,
): boolean {
  if (!live) return false
  const source = sources.find((s) => s.id === live.sourceId)
  if (!source) return editingId === live.sourceId
  const listIsNewer = !!listedAt && !!live.at && listedAt >= live.at // ISO-8601 UTC strings of one format
  if (!listIsNewer) return true
  return source.last_test_at === live.at && source.last_test_status === live.status
}
