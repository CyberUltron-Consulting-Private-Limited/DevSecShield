import { QueryClient } from "@tanstack/react-query";
import { AxiosError } from "axios";
import { retryAfterSeconds } from "@/utils/interceptors";

// A 429 means "not now", not "failed": queries wait for Retry-After and try again, so the 6-second status
// polling of the scan pages (it re-arms on every successful fetch) keeps going instead of stopping on an
// error screen. Other errors keep react-query's defaults (3 retries, exponential delay up to 30 s).
const MAX_RATE_LIMITED_RETRIES = 10;
const MAX_RETRY_AFTER_MS = 120_000;

function isRateLimited(error: unknown): boolean {
  return error instanceof AxiosError && error.response?.status === 429;
}

export function queryRetry(failureCount: number, error: unknown): boolean {
  return isRateLimited(error) ? failureCount < MAX_RATE_LIMITED_RETRIES : failureCount < 3;
}

export function queryRetryDelay(attempt: number, error: unknown): number {
  if (isRateLimited(error)) {
    const seconds = retryAfterSeconds(error);
    if (seconds != null) return Math.min(Math.max(1, seconds) * 1000, MAX_RETRY_AFTER_MS);
  }
  return Math.min(1000 * 2 ** attempt, 30_000);
}

export function makeQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: queryRetry, retryDelay: queryRetryDelay },
    },
  });
}
