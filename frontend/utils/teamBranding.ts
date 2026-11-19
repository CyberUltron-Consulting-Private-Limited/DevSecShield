/**
 * The team's report logo (plan §5): what the upload accepts, checked in the browser before anything is sent. The
 * server decides again from the file's own bytes (backend PUT /team/{team_id}/branding/logo): PNG, JPEG or WebP, at most
 * 2 MB; the Content-Type sent is the one the magic bytes say, never the file name's or the browser's guess.
 */

export const LOGO_MAX_BYTES = 2 * 1024 * 1024;
export const LOGO_TYPES = ["image/png", "image/jpeg", "image/webp"] as const;
export type LogoType = (typeof LOGO_TYPES)[number];
/** For the file picker only (the check is the sniff below). */
export const LOGO_ACCEPT = ".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp";

/** The image type the first bytes of a file say it is, or null for anything else (SVG, GIF, BMP, a renamed file). */
export function sniffImageType(head: Uint8Array): LogoType | null {
  const at = (i: number, bytes: number[]) => bytes.every((b, n) => head[i + n] === b);
  if (at(0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return "image/png";
  if (at(0, [0xff, 0xd8, 0xff])) return "image/jpeg";
  // RIFF....WEBP
  if (at(0, [0x52, 0x49, 0x46, 0x46]) && at(8, [0x57, 0x45, 0x42, 0x50])) return "image/webp";
  return null;
}

async function headOf(file: Blob, n = 16): Promise<Uint8Array> {
  const part = file.slice(0, n);
  // Blob.arrayBuffer is everywhere the app runs; FileReader for older engines (and jsdom)
  if (typeof part.arrayBuffer === "function") return new Uint8Array(await part.arrayBuffer());
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(part);
  });
}

/** The file's real type, or why it cannot be a logo. */
export async function checkLogoFile(file: Blob): Promise<{ type: LogoType; error: null } | { type: null; error: string }> {
  if (file.size === 0) return { type: null, error: "The file is empty." };
  if (file.size > LOGO_MAX_BYTES) return { type: null, error: "The logo must be 2 MB or smaller." };
  const type = sniffImageType(await headOf(file));
  if (!type) return { type: null, error: "Use a PNG, JPEG or WebP image (SVG, GIF and other formats are not accepted)." };
  return { type, error: null };
}
