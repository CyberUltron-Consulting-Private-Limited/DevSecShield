/**
 * Saving a downloaded file, and reading the server's error out of a failed blob request: shared by every download of
 * the app (the PDF reports, the CycloneDX and OSCAL files, the run deliverables).
 */

/** Saves `blob` as `filename`: a link is added to the page, clicked and removed; the object URL is revoked after 1 s
 * (revoking it at once can cancel the download in some browsers). */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** A blob request's error body arrives as a Blob, so the server's ``detail`` ("retry in 30 s") would be lost: read it
 * back into ``error.response.data`` before the error is shown. Returns that data (undefined when there is none). */
export async function readBlobErrorDetail(error: unknown): Promise<unknown> {
  const response = (error as { response?: { data?: unknown } } | null)?.response;
  const data = response?.data;
  if (!response) return undefined;
  // a browser hands a blob request's body over as a Blob; Node's adapter as text or bytes
  let text: string | null = null;
  if (typeof Blob !== "undefined" && data instanceof Blob) text = await data.text();
  else if (typeof data === "string") text = data;
  else if (data instanceof ArrayBuffer) text = new TextDecoder().decode(data);
  if (text === null) return data;
  try {
    response.data = JSON.parse(text);
  } catch {
    // not JSON: keep the generic message
  }
  return response.data;
}
