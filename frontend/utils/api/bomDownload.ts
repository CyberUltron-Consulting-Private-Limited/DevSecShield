/**
 * The results pages' BOM downloads (SBOM, CBOM, AI BOM): the server's signed files, saved byte for byte.
 *
 * `GET /{team}/{type}/scan/{id}/bom` (JSON; `format=xml` for a CBOM), `GET .../vex`, and for an AI BOM
 * `GET /{team}/ai_bom/scan/{id}/spdx` and `/sarif` serve the files every route signs (an embedded JSF ES256 signature
 * in the CycloneDX JSON, and the detached `X-ZS-Signature` header over the exact bytes). A copy rebuilt in the browser
 * from the scan metadata (what the SBOM and AI BOM pages used to save) has other bytes and no signature. These helpers
 * save the response body as received, under the server's file name (Content-Disposition), and say what the signature
 * headers say. They never toast: the page says the outcome once (`downloadOutcome`, utils/toastPolicy.ts).
 *
 * A download is refused, and nothing is saved, when the response is not a JSON or XML file (a proxy's sign-in page
 * served with 200), or when its bytes do not hash to the `X-Cbom-Sha256` the server sent. A failed request's error
 * body (a Blob) is read back first, so the page shows the server's reason and a closed session logs out
 * (utils/error-handler.ts) as for any other request (review 6036875286 M2).
 */
import api from "@/utils/interceptors";
import { readBlobErrorDetail, saveBlob } from "@/utils/download";

export type BomScanType = "sbom_sca" | "cbom" | "ai_bom";
export type BomFormat = "json" | "xml";
export type AiBomArtifact = "spdx" | "sarif";
/** `signed`: X-ZS-Signature holds a signature; `unsigned`: the server said so (no usable key); `not_stated`: the
 * response carried no X-ZS-Signature at all (an older server, a proxy, or a CORS setup that hides the header). */
export type SignatureState = "signed" | "unsigned" | "not_stated";

export type SignedDownload = {
  filename: string;
  state: SignatureState;
  /** base64 DER ES256 signature over the file's bytes (`X-ZS-Signature`) when signed */
  signature: string | null;
  alg: string | null;
  keyId: string | null;
  /** hex SHA-256 the server stated (`X-Cbom-Sha256`), checked against the bytes before saving */
  sha256: string | null;
};

/** A download the helper refused to save (wrong content, digest mismatch); its message is shown as is. */
export class DownloadRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DownloadRefused";
  }
}

/** The server's file name (backend/routers/certin.py), used when Content-Disposition is not readable. */
export function servedFileName(scanType: BomScanType, scanId: string | number, kind: "bom" | "vex" | AiBomArtifact,
                               format: BomFormat = "json"): string {
  if (kind === "vex") return `${scanType}-vex-${scanId}.cdx.json`;
  if (kind === "spdx") return `ai_bom-${scanId}.spdx.json`;
  if (kind === "sarif") return `ai_bom-${scanId}.sarif`;
  return `${scanType}-cyclonedx-${scanId}.cdx.${format}`;
}

const CONTROL = /[\u0000-\u001f\u007f]/g;

/** `filename*=UTF-8''…` or `filename="…"` of a Content-Disposition header; the fallback when there is none. Only a
 * plain file name is kept (no directory part, no control character). */
export function fileNameFromDisposition(header: string | null | undefined, fallback: string): string {
  const text = String(header || "");
  let name = "";
  const star = /filename\*\s*=\s*utf-8''([^;]+)/i.exec(text);
  if (star) {
    try {
      name = decodeURIComponent(star[1].trim().replace(/^"|"$/g, ""));
    } catch {
      name = "";
    }
  }
  if (!name) {
    const plain = /filename\s*=\s*("([^"]*)"|[^;]+)/i.exec(text);
    name = plain ? (plain[2] ?? plain[1]).trim() : "";
  }
  name = (name.split(/[\\/]/).pop() || "").replace(CONTROL, "").trim();
  return name && name !== "." && name !== ".." ? name : fallback;
}

type HeaderBag = Record<string, unknown> & { get?: (name: string) => unknown };

function header(headers: unknown, name: string): string | null {
  const bag = (headers || {}) as HeaderBag;
  const value = typeof bag.get === "function" ? bag.get(name) : (bag[name.toLowerCase()] ?? bag[name]);
  return value === undefined || value === null || value === "" ? null : String(value);
}

/** What the response's signature headers say. */
export function signatureFromHeaders(headers: unknown): Omit<SignedDownload, "filename"> {
  const sig = header(headers, "x-zs-signature");
  const state: SignatureState = sig === null ? "not_stated" : sig === "unsigned" ? "unsigned" : "signed";
  return {
    state,
    signature: state === "signed" ? sig : null,
    alg: header(headers, "x-zs-signature-alg"),
    keyId: header(headers, "x-zs-signature-key-id"),
    sha256: header(headers, "x-cbom-sha256"),
  };
}

/** The part of the download message that says how the file is signed. */
export function signatureNote(download: Pick<SignedDownload, "state" | "alg" | "keyId">): string {
  if (download.state === "signed") {
    return `signed ${download.alg || "ES256"}${download.keyId ? `, key ${download.keyId}` : ""}`;
  }
  if (download.state === "unsigned") return "unsigned: this deployment has no usable signing key";
  return "the server did not say whether this file is signed";
}

/** The page's one message for a saved file: a success when it is signed, a warning when it is not or nobody said. */
export function downloadOutcome(label: string, download: SignedDownload): { level: "success" | "warning"; text: string } {
  return { level: download.state === "signed" ? "success" : "warning", text: `${label} downloaded (${signatureNote(download)})` };
}

const SAVABLE = /(^|[/+])(json|xml)(\s*;|$)/i;

async function bytesOf(data: unknown): Promise<Uint8Array> {
  if (typeof Blob !== "undefined" && data instanceof Blob) return new Uint8Array(await data.arrayBuffer());
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new TextEncoder().encode(typeof data === "string" ? data : String(data ?? ""));
}

async function sha256Hex(bytes: Uint8Array): Promise<string | null> {
  const subtle = (globalThis.crypto as Crypto | undefined)?.subtle;
  if (!subtle) return null; // an insecure (plain http, non-localhost) page has no SubtleCrypto: not checked
  const digest = new Uint8Array(await subtle.digest("SHA-256", bytes as BufferSource));
  return Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
}

async function saveServed(url: string, params: Record<string, string> | undefined, fallback: string,
                          what: string): Promise<SignedDownload> {
  let response;
  try {
    // a blob: the body as received, never parsed and re-serialised (the signature covers these exact bytes)
    response = await api.get(url, { params, responseType: "blob" });
  } catch (error) {
    await readBlobErrorDetail(error); // the server's detail, for the message and the closed-session logout
    throw error;
  }
  const type = header(response.headers, "content-type") || (response.data as Blob | undefined)?.type || "";
  if (!SAVABLE.test(type.trim())) {
    throw new DownloadRefused(`The ${what} was not downloaded: the server sent ${type ? `a ${type.split(";")[0]} page` : "no file type"}, not the file. Reload the page and try again.`);
  }
  const signed = signatureFromHeaders(response.headers);
  if (signed.sha256) {
    const got = await sha256Hex(await bytesOf(response.data));
    if (got !== null && got !== signed.sha256.trim().toLowerCase()) {
      throw new DownloadRefused(`The ${what} was not saved: its bytes do not match the SHA-256 the server stated. Try again.`);
    }
  }
  const filename = fileNameFromDisposition(header(response.headers, "content-disposition"), fallback);
  saveBlob(response.data as Blob, filename);
  return { filename, ...signed };
}

/** Saves the scan's CycloneDX document as `GET /bom` serves it (XML only for a CBOM scan). */
export function downloadServedBom(teamId: string | number, scanType: BomScanType, scanId: string | number,
                                  format: BomFormat = "json"): Promise<SignedDownload> {
  return saveServed(`/${teamId}/${scanType}/scan/${scanId}/bom`, { format },
                    servedFileName(scanType, scanId, "bom", format), `CycloneDX ${format.toUpperCase()} file`);
}

/** Saves the scan's CycloneDX VEX as `GET /vex` serves it (signed like the BOM). */
export function downloadServedVex(teamId: string | number, scanType: BomScanType,
                                  scanId: string | number): Promise<SignedDownload> {
  return saveServed(`/${teamId}/${scanType}/scan/${scanId}/vex`, undefined, servedFileName(scanType, scanId, "vex"),
                    "VEX file");
}

/** Saves an AI BOM scan's SPDX 3.0 or SARIF 2.1.0 file as `GET /spdx` / `GET /sarif` serves it (signed detached). */
export function downloadServedAiBomArtifact(teamId: string | number, scanId: string | number,
                                            artifact: AiBomArtifact): Promise<SignedDownload> {
  return saveServed(`/${teamId}/ai_bom/scan/${scanId}/${artifact}`, undefined,
                    servedFileName("ai_bom", scanId, artifact), artifact === "spdx" ? "SPDX 3.0 file" : "SARIF file");
}
