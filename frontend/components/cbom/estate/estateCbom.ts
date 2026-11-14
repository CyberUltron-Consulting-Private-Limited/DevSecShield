// The team's estate CBOM (CB-26): GET /{team}/cbom/estate-export?format=json|xml&application&source&type. One
// CycloneDX 1.6 file for the whole estate, one component per asset across sources. Unsigned: the response carries the
// SHA-256 of the exact bytes (X-Cbom-Sha256), which the page shows so it can be checked outside ZeroShield.
import api from "@/utils/interceptors";

export type EstateFormat = "json" | "xml";

export interface EstateFilters {
  application?: string;
  source?: string;
  type?: string;
}

export interface EstateDownload {
  fileName: string;
  sha256: string | null;
  signature: string | null;
  assets: number | null;
}

/** Query parameters: the format and the non-empty filters, trimmed. */
export function estateParams(format: EstateFormat, f: EstateFilters): Record<string, string> {
  const out: Record<string, string> = { format };
  for (const [k, v] of Object.entries(f)) if (typeof v === "string" && v.trim()) out[k] = v.trim();
  return out;
}

/** The server's file name from Content-Disposition, else the same name built here (UTC date). */
export function estateFileName(teamId: number, format: EstateFormat, disposition: string | null | undefined,
                               now = new Date()): string {
  const m = /filename="([^"]+)"/.exec(disposition ?? "");
  return m ? m[1] : `cbom-estate-team${teamId}-${now.toISOString().slice(0, 10)}.cdx.${format}`;
}

/** What the response headers say about the file (lower-case header names, as axios gives them). */
export function readEstateHeaders(teamId: number, format: EstateFormat, headers: Record<string, unknown>,
                                  now = new Date()): EstateDownload {
  const text = (name: string) => (typeof headers[name] === "string" ? (headers[name] as string) : null);
  const assets = Number(text("x-cbom-assets"));
  return {
    fileName: estateFileName(teamId, format, text("content-disposition"), now),
    sha256: text("x-cbom-sha256"),
    signature: text("x-cbom-signature"),
    assets: Number.isFinite(assets) && text("x-cbom-assets") !== null ? assets : null,
  };
}

/** Download the estate CBOM and save it; returns what the headers said (shown next to the button). */
export async function downloadEstateCbom(teamId: number, format: EstateFormat, f: EstateFilters = {}
): Promise<EstateDownload> {
  const response = await api.get(`/${teamId}/cbom/estate-export`, { params: estateParams(format, f), responseType: "blob" });
  const info = readEstateHeaders(teamId, format, response.headers as Record<string, unknown>);
  const url = URL.createObjectURL(response.data as Blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = info.fileName;
  a.click();
  URL.revokeObjectURL(url);
  return info;
}
