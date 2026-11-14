// Lab mode (backend lab_mode.py): on a test deployment with CBOM_AWS_LAB_SAME_ACCOUNT=1, an AWS role in the
// deployment's own account is accepted so AWS collection can be tested end to end. The AWS source form and every run
// of such a source carry this notice; it cannot be dismissed. Same sentence as the backend's lab_mode.LAB_BANNER.
// It is a permanent, informational note (#272): role="note" (never "alert", which screen readers announce as urgent
// on every render), a 1 px border like the other notes on the Sources pages, only the key phrase bold, and on a phone
// one line with the detail behind "Details". Spacing comes from the caller (className) or the parent's space-y.
import { FlaskConical } from "lucide-react";

import { cn } from "@/lib/utils";

export const AWS_LAB_BANNER = "Lab mode: same-account collection — not for production";
const KEY_PHRASE = "Lab mode:";
const REST = AWS_LAB_BANNER.slice(KEY_PHRASE.length);

export function LabModeBanner({ testId, detail, className }: { testId: string; detail?: string; className?: string }) {
  return (
    <div
      role="note"
      data-testid={testId}
      className={cn(
        "flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-sm text-zinc-700 dark:text-zinc-300",
        className,
      )}
    >
      <FlaskConical className="h-4 w-4 mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden />
      <div className="min-w-0">
        <p>
          <strong className="font-semibold text-amber-700 dark:text-amber-400">{KEY_PHRASE}</strong>
          {REST}
        </p>
        {detail && (
          <>
            <p className="hidden sm:block text-zinc-600 dark:text-zinc-400">{detail}</p>
            <details className="sm:hidden text-zinc-600 dark:text-zinc-400">
              <summary className="cursor-pointer text-xs">Details</summary>
              <p className="mt-1">{detail}</p>
            </details>
          </>
        )}
      </div>
    </div>
  );
}
