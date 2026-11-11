/**
 * The app's toasts (X1, Nov 11): every toast lasted 1.5 s and only one was visible, so a validation error flashed past
 * before it could be read, and a second message replaced it. Errors and warnings now stay 8 s with a close button,
 * successes and notes 4 s, and up to 3 are visible (app/layout.tsx). Import `toast` from here, not from "sonner".
 */
import { toast as sonner, type ExternalToast } from "sonner";

import { TOAST_ERROR_MS, TOAST_SUCCESS_MS, TOASTS_VISIBLE } from "./toastPolicy";

export { TOAST_ERROR_MS, TOAST_SUCCESS_MS, TOASTS_VISIBLE };

type Message = Parameters<typeof sonner.success>[0];

const quick = (data?: ExternalToast): ExternalToast => ({ duration: TOAST_SUCCESS_MS, ...data });
const lasting = (data?: ExternalToast): ExternalToast => ({ duration: TOAST_ERROR_MS, closeButton: true, ...data });

export const toast: typeof sonner = Object.assign(
  (message: Message, data?: ExternalToast) => sonner(message, quick(data)),
  {
    ...sonner,
    success: (message: Message, data?: ExternalToast) => sonner.success(message, quick(data)),
    info: (message: Message, data?: ExternalToast) => sonner.info(message, quick(data)),
    message: (message: Message, data?: ExternalToast) => sonner.message(message, quick(data)),
    warning: (message: Message, data?: ExternalToast) => sonner.warning(message, lasting(data)),
    error: (message: Message, data?: ExternalToast) => sonner.error(message, lasting(data)),
  },
);
