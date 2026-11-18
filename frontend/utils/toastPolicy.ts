// How long toasts stay and how many are visible (utils/toast.ts, app/layout.tsx). No "sonner" import here: the root
// layout is a server component and only needs the numbers.
export const TOAST_SUCCESS_MS = 4000;
export const TOAST_ERROR_MS = 8000;
export const TOASTS_VISIBLE = 3;

/** Who shows an API call's toast (#12, #27): one toast per outcome, never one from the API helper (utils/backend_api.ts)
 * and another from its caller. A helper whose callers all show the error only throws it. A helper with callers of both
 * kinds (an export: the options sidebar shows no toast of its own, a results page does) toasts unless the caller passes
 * { toast: false }. utils/toastOwnership.test.ts checks every caller of these helpers. */
export interface HelperToastOptions {
  /** false: the caller shows the success and the error toast itself */
  toast?: boolean;
}
