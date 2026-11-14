// Lab mode (backend lab_mode.py): on a test deployment with CBOM_AWS_LAB_SAME_ACCOUNT=1, an AWS role in the
// deployment's own account is accepted so AWS collection can be tested end to end. The AWS source form and every run
// of such a source carry this banner; it cannot be dismissed. Same sentence as the backend's lab_mode.LAB_BANNER.
import { FlaskConical } from "lucide-react";

export const AWS_LAB_BANNER = "Lab mode: same-account collection — not for production";

export function LabModeBanner({ testId, detail }: { testId: string; detail?: string }) {
  return (
    <div
      role="alert"
      data-testid={testId}
      className="flex items-start gap-2 rounded-lg border-2 border-amber-400 dark:border-amber-600 bg-amber-100 dark:bg-amber-950/40 p-3 text-sm font-semibold text-amber-950 dark:text-amber-100"
    >
      <FlaskConical className="h-4 w-4 mt-0.5 shrink-0" aria-hidden />
      <span>
        {AWS_LAB_BANNER}
        {detail && <span className="block font-normal text-amber-900 dark:text-amber-200">{detail}</span>}
      </span>
    </div>
  );
}
