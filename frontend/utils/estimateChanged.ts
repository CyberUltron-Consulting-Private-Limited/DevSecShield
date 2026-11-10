/**
 * /start answers 409 { code: "estimate_changed", credits_required, previous_credits, detail } when the input or the
 * pricing changed since the estimate the customer saw: nothing was charged, and the new price must be shown before
 * the customer starts again (the next start charges exactly that price).
 */
export type EstimateChanged = {
  detail: string;
  credits_required: number;
  previous_credits: number | null;
  minimum_credits: number | null;
};

export function estimateChangedOf(error: unknown): EstimateChanged | null {
  const response = (error as { response?: { status?: number; data?: unknown } } | null)?.response;
  if (!response || response.status !== 409) return null;
  const data = response.data as Record<string, unknown> | null | undefined;
  if (!data || data.code !== "estimate_changed" || typeof data.credits_required !== "number") return null;
  return {
    detail: typeof data.detail === "string" ? data.detail : `The price of this scan changed to ${data.credits_required} credits. Nothing was charged.`,
    credits_required: data.credits_required,
    previous_credits: typeof data.previous_credits === "number" ? data.previous_credits : null,
    minimum_credits: typeof data.minimum_credits === "number" ? data.minimum_credits : null,
  };
}
