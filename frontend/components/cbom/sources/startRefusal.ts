// What Review & Run says when the server refuses "Start scan" (local lab, round 5: a team with 0 credits pressed
// Start, the API answered 400 "Not enough credits: ..." and the only sign was a toast that was gone a few seconds
// later). The server's own reason stays on the card until the next estimate or start; a 409 also clears the estimate
// (the price changed, or every source is already queued), so the next Start needs a fresh one.

import { handleApiError } from "@/utils/error-handler";

export interface StartRefusal {
  tone: "amber" | "red";
  text: string;
  /** The estimate no longer holds: estimate again before the next Start. */
  clearEstimate: boolean;
}

export function startRefusal(err: unknown): StartRefusal {
  const { message, status } = handleApiError(err);
  const text = (typeof message === "string" && message.trim()) || "The run could not be started. Try again.";
  return status === 409 ? { tone: "amber", text, clearEstimate: true } : { tone: "red", text, clearEstimate: false };
}
