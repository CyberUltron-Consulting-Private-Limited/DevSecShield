/**
 * Why a scan failed, in the words the server stored. The worker's failure reason is written to the scan's `info`
 * (`{ error: "<first line>" }`, backend/utilities/celery/celery_connection.py); the scan sidebars read
 * `scan_metadata.error_message`, which nothing writes, so every failed scan only said "The scan failed." (lab UI run
 * u2, round 5). A failed scan cannot be started again: "Run again" (utils/scanRerun.ts) starts a new one with its settings.
 */
export function scanFailureMessage(data: unknown): string {
  const record = data && typeof data === "object" ? (data as Record<string, unknown>) : {};
  let info = record.info;
  if (typeof info === "string") {
    try {
      info = JSON.parse(info);
    } catch {
      info = null;
    }
  }
  const fromInfo = info && typeof info === "object" ? (info as Record<string, unknown>).error : undefined;
  const meta = record.scan_metadata;
  const fromMeta = meta && typeof meta === "object" ? (meta as Record<string, unknown>).error_message : undefined;
  const reason = [fromInfo, fromMeta].find((v): v is string => typeof v === "string" && v.trim() !== "");
  const head = reason ? `The scan failed: ${reason.trim().replace(/[.\s]+$/, "")}.` : "The scan failed.";
  return `${head} Use Run again to start it as a new scan with the same settings.`;
}
