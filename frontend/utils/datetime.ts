/**
 * Display-only datetime helpers. Stored/API timestamps stay UTC ISO;
 * the UI formats them in Asia/Kolkata (IST).
 */

export const DISPLAY_TIMEZONE = "Asia/Kolkata" as const;
export const DISPLAY_TZ_LABEL = "IST" as const;

export type DateInput = string | number | Date | null | undefined;

/** Parse ISO / epoch / Date for display. Returns null if unusable. */
export function parseDisplayDate(input: DateInput): Date | null {
  if (input == null || input === "") return null;
  const date = input instanceof Date ? input : new Date(input);
  if (Number.isNaN(date.getTime())) return null;
  return date;
}

type IstFormatOptions = {
  /** Append " IST" (default true for datetime, false for date-only helpers that pass false). */
  withLabel?: boolean;
  dateStyle?: "full" | "long" | "medium" | "short";
  timeStyle?: "full" | "long" | "medium" | "short";
} & Intl.DateTimeFormatOptions;

function formatInIst(
  input: DateInput,
  options: IstFormatOptions,
  fallback: string = "—",
): string {
  const date = parseDisplayDate(input);
  if (!date) {
    if (typeof input === "string" && input.trim()) return input;
    return fallback;
  }
  const { withLabel = false, ...intlOptions } = options;
  const formatted = date.toLocaleString("en-IN", {
    timeZone: DISPLAY_TIMEZONE,
    ...intlOptions,
  });
  return withLabel ? `${formatted} ${DISPLAY_TZ_LABEL}` : formatted;
}

/**
 * Absolute datetime for tables / headers.
 * Example: `9 Aug 2026, 07:30 pm IST`
 */
export function formatDateIst(input: DateInput): string {
  return formatInIst(
    input,
    {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: true,
      withLabel: true,
    },
    "—",
  );
}

/** Date-only (no time), e.g. tooltips / team created. */
export function formatDateOnlyIst(input: DateInput): string {
  return formatInIst(input, {
    year: "numeric",
    month: "short",
    day: "numeric",
    withLabel: false,
  });
}

/** Short chart axis / tick label (month + day in IST). */
export function formatChartDateIst(input: DateInput): string {
  return formatInIst(input, {
    month: "short",
    day: "numeric",
    withLabel: false,
  });
}

/** Medium date for chart tooltips (dateStyle medium, IST). */
export function formatMediumDateIst(input: DateInput): string {
  return formatInIst(input, {
    dateStyle: "medium",
    withLabel: false,
  });
}

/** Compact MM/DD tick for dense chart axes (IST calendar day). */
export function formatSlashDateIst(input: DateInput): string {
  const date = parseDisplayDate(input);
  if (!date) return typeof input === "string" ? input : "—";
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: DISPLAY_TIMEZONE,
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(date);
  const month = parts.find((p) => p.type === "month")?.value ?? "00";
  const day = parts.find((p) => p.type === "day")?.value ?? "00";
  return `${month}/${day}`;
}

/** Alias matching existing call-site name `formatDate`. */
export const formatDate = formatDateIst;
