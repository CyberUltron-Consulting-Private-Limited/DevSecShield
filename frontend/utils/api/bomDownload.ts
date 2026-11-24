/**
 * The results pages' CycloneDX downloads (SBOM, CBOM, AI BOM): the server's signed document, saved byte for byte.
 *
 * `GET /{team}/{type}/scan/{id}/bom` (JSON; `format=xml` for a CBOM) and `GET .../vex` serve the document every route
 * signs (backend/utilities/compliance/served_bom.py): an embedded JSF ES256 signature and the detached
 * `X-ZS-Signature` header over the exact bytes. A copy rebuilt in the browser from the scan metadata (the SBOM and AI
 * BOM pages used to do that) has none of the server's stamps and other bytes, so it never verified. These helpers
 * save the response body as received, under the server's file name (Content-Disposition), and return what the
 * signature headers say, so the page can say whether the file is signed.
 */
import api from "@/utils/interceptors";
import { saveBlob } from "@/utils/download";

export type BomScanType = "sbom_sca" | "cbom" | "ai_bom";
export type BomFormat = "json" | "xml";

export type SignedDownload = {
  filename: string;
  /** base64 DER ES256 signature over the file's bytes (`X-ZS-Signature`), null when the deployment has no key */
  signature: string | null;
  alg: string | null;
  keyId: string | null;
  /** hex SHA-256 of the file as served (`X-Cbom-Sha256`) */
  sha256: string | null;
};

/** The server's file name for a download (backend/routers/certin.py): `{type}-cyclonedx-{id}.cdx.json`, a CBOM's XML
 * `cbom-cyclonedx-{id}.cdx.xml`, the VEX `{type}-vex-{id}.cdx.json`. Used when Content-Disposition is not readable. */
export function servedFileName(scanType: BomScanType, scanId: string | number, kind: "bom" | "vex",
                               format: BomFormat = "json"): string {
  return kind === "vex" ? `${scanType}-vex-${scanId}.cdx.json` : `${scanType}-cyclonedx-${scanId}.cdx.${format}`;
}

/** `filename*=UTF-8''…` or `filename="…"` of a Content-Disposition header; the fallback when there is none. Only a
 * plain file name is kept (no directory part). */
export function fileNameFromDisposition(header: string | null | undefined, fallback: string): string {
  const text = String(header || "");
  let name = "";
  const star = /filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/.exec(text);
  if (star) {
    try {
      name = decodeURIComponent(star[1].trim().replace(/^"|"$/g, ""));
    } catch {
      name = "";
    }
  }
  if (!name) {
    const plain = /filename\s*=\s*("([^"]*)"|[^;]+)/.exec(text);
    name = plain ? (plain[2] ?? plain[1]).trim() : "";
  }
  name = name.split(/[\\/]/).pop()?.trim() || "";
  return name && name !== "." && name !== ".." ? name : fallback;
}

type HeaderBag = Record<string, unknown> & { get?: (name: string) => unknown };

function header(headers: unknown, name: string): string | null {
  const bag = (headers || {}) as HeaderBag;
  const value = typeof bag.get === "function" ? bag.get(name) : (bag[name.toLowerCase()] ?? bag[name]);
  return value === undefined || value === null || value === "" ? null : String(value);
}

/** What the response's signature headers say (`X-ZS-Signature: unsigned` without a signing key). */
export function signatureFromHeaders(headers: unknown): Omit<SignedDownload, "filename"> {
  const sig = header(headers, "x-zs-signature");
  return {
    signature: sig && sig !== "unsigned" ? sig : null,
    alg: header(headers, "x-zs-signature-alg"),
    keyId: header(headers, "x-zs-signature-key-id"),
    sha256: header(headers, "x-cbom-sha256"),
  };
}

/** One line for the download toast. */
export function signatureNote(download: SignedDownload): string {
  return download.signature
    ? `signed ${download.alg || "ES256"}${download.keyId ? `, key ${download.keyId}` : ""}`
    : "unsigned: this deployment has no signing key";
}

async function saveServed(url: string, params: Record<string, string> | undefined,
                          fallback: string): Promise<SignedDownload> {
  // a blob: the body as received, never parsed and re-serialised (the signature covers these exact bytes)
  const response = await api.get(url, { params, responseType: "blob" });
  const filename = fileNameFromDisposition(header(response.headers, "content-disposition"), fallback);
  saveBlob(response.data as Blob, filename);
  return { filename, ...signatureFromHeaders(response.headers) };
}

/** Saves the scan's CycloneDX document as `GET /bom` serves it (XML only for a CBOM scan). */
export function downloadServedBom(teamId: string | number, scanType: BomScanType, scanId: string | number,
                                  format: BomFormat = "json"): Promise<SignedDownload> {
  return saveServed(`/${teamId}/${scanType}/scan/${scanId}/bom`, { format },
                    servedFileName(scanType, scanId, "bom", format));
}

/** Saves the scan's CycloneDX VEX as `GET /vex` serves it (signed like the BOM). */
export function downloadServedVex(teamId: string | number, scanType: BomScanType,
                                  scanId: string | number): Promise<SignedDownload> {
  return saveServed(`/${teamId}/${scanType}/scan/${scanId}/vex`, undefined, servedFileName(scanType, scanId, "vex"));
}
