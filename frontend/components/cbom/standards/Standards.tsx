// The asset drawer's "Standards" section (CB-16): which standards the asset meets or fails, and why.
// Fed only by the asset detail API (`standards`); renders nothing on an older backend or for an asset that names no
// algorithm (an empty list).
import { statusText, statusTone, TONE_CLASS, type StandardRow } from "./model"

export function StandardsDrawerSection({ standards }: { standards: StandardRow[] | null | undefined }) {
  if (!standards || standards.length === 0) return null
  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-700 p-3 space-y-2 min-w-0" data-testid="asset-standards">
      <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200">Standards</p>
      <ul className="text-xs divide-y divide-zinc-100 dark:divide-zinc-800">
        {standards.map((row) => {
          const tone = statusTone(row.status)
          return (
            <li key={row.id} className="py-1.5 space-y-0.5 min-w-0" data-testid={`asset-standard-${row.id}`}
                data-status={row.status} data-tone={tone} data-category={row.category ?? undefined}>
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <span className="text-zinc-800 dark:text-zinc-200">{row.label}</span>
                <span className={`inline-flex items-center rounded border px-1.5 py-0.5 ${TONE_CLASS[tone]}`}>
                  {statusText(row)}
                </span>
              </div>
              {row.reasons.map((reason) => (
                <p key={reason} className="text-zinc-600 dark:text-zinc-400 break-words">{reason}</p>
              ))}
            </li>
          )
        })}
      </ul>
    </div>
  )
}
