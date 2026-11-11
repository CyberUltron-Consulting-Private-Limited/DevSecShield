// How long toasts stay and how many are visible (utils/toast.ts, app/layout.tsx). No "sonner" import here: the root
// layout is a server component and only needs the numbers.
export const TOAST_SUCCESS_MS = 4000;
export const TOAST_ERROR_MS = 8000;
export const TOASTS_VISIBLE = 3;
