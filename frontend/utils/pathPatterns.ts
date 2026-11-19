/**
 * SAST exclude path patterns: a pattern made only of "*" / "**" names matches every file, so the scan would analyse
 * nothing (#443 review, finding 4). The backend refuses it too (backend/utilities/scan/path_patterns.py
 * matches_everything); this check gives the message before the estimate. Names split on "/" as the worker does.
 */
export function matchesEverything(pattern: readonly string[]): boolean {
  const names = pattern.flatMap((box) => box.trim().split("/")).map((n) => n.trim()).filter(Boolean);
  return names.length > 0 && names.every((n) => /^\*+$/.test(n));
}

/** The message for the first exclude that matches every file, or null when none does. */
export function everythingExcludeMessage(patterns: readonly (readonly string[])[]): string | null {
  const hit = patterns.find((p) => matchesEverything(p));
  if (!hit) return null;
  const shown = hit.flatMap((b) => b.split("/")).map((n) => n.trim()).filter(Boolean).join("/");
  return `The exclude pattern "${shown}" matches every file, so nothing would be scanned. Remove it, or name the folders or files to skip (for example tests or *.min.js).`;
}
