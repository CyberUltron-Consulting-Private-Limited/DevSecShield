import { useCallback, useEffect, useState } from "react";

/**
 * The "Resend in Ns" wait after "Send Verification Code" (sign-in, sign-up, password reset).
 *
 * One timeout per second, re-armed by the effect while time is left. The forms used one setInterval whose effect
 * cleared it whenever the remaining time changed, so it stopped after its first tick: the button stayed disabled
 * at "Resend in 29s" until the page was reloaded (found on the local production stack, round 5).
 */
export function useResendCountdown(seconds: number) {
  const [left, setLeft] = useState(0);

  useEffect(() => {
    if (left <= 0) return;
    const id = setTimeout(() => setLeft((s) => Math.max(0, s - 1)), 1000);
    return () => clearTimeout(id);
  }, [left]);

  /** Start (or restart) the wait; `forSeconds` e.g. a 429's Retry-After. */
  const start = useCallback((forSeconds?: number) => {
    setLeft(Math.max(0, Math.ceil(forSeconds ?? seconds)));
  }, [seconds]);
  /** End the wait at once (the code was not sent, so there is nothing to wait for). */
  const stop = useCallback(() => setLeft(0), []);

  return { left, running: left > 0, start, stop };
}

/** The text of the send button. */
export function resendLabel(sending: boolean, left: number): string {
  if (sending) return "Sending code...";
  if (left > 0) return `Resend in ${left}s`;
  return "Send Verification Code";
}

/** How long to wait after a failed send: a 429's Retry-After (capped at two minutes), otherwise not at all. */
export function waitAfterFailedSend(status: number | undefined, retryAfter: number | null): number {
  if (status === 429 && retryAfter != null) return Math.min(Math.max(1, Math.ceil(retryAfter)), 120);
  return 0;
}
