// CBOM outputs: CycloneDX downloads in JSON or XML, and the fields the API added for one set of numbers (clean
// inventory as "informational"), internet exposure and library end of life as of a run.

import api from "@/utils/interceptors"
import { showErrorToast } from "@/utils/error-handler"
import type { CbomAssetDetail, CbomRunPosture } from "@/utils/backend_api"
import type { AgilityDetail, AgilityPosture, QExplain, QGradeFields, QPosture } from "@/components/cbom/grade/model"

export type CycloneDxFormat = "json" | "xml"
export type CbomExposure = "internet" | "internal" | "unknown"

export const EXPOSURE_LABEL: Record<CbomExposure, string> = {
  internet: "Internet-facing",
  internal: "Internal",
  unknown: "Unknown exposure",
}

/** Label for clean inventory rows: listed in the CBOM, never a finding. */
export const INFORMATIONAL_LABEL = "Informational / Inventory"

/** What an uploaded CBOM file's import read, skipped or truncated (scan metadata ``cbom_input``). */
export interface CbomImportReport {
  components_total?: number
  crypto_assets?: number
  imported?: number
  skipped_not_crypto?: number
  skipped_invalid?: number
  duplicates?: number
  truncated: boolean
  spec_version: string | null
  notes: string[]
}

/** What a code scan left out or only counted (scan metadata ``cbom_coverage``, from the CycloneDX
 * ``crypto:coverage:*`` properties): archives, container images, binaries, firmware, symlinks, oversized files. */
export interface CbomCoverageReport {
  notes: { key: string; text: string; kind: "skipped" | "info" }[]
  skipped: number
}

export type CbomTopRisk =CbomRunPosture["top_risks"][number] & {
  exposure?: CbomExposure
  exposure_basis?: string
}

export type CbomPostureWithExposure = Omit<CbomRunPosture, "top_risks"> & {
  top_risks: CbomTopRisk[]
  exposure?: Record<CbomExposure, number>
  exposure_factors?: Record<CbomExposure, number>
} & QPosture & AgilityPosture  // quantum risk grade (CB-19) and fix classes (CB-24); absent on an older backend

type Eol = { branch: string; date: string; passed: boolean; sources: string[] }

export type CbomAssetDetailWithExposure = Omit<CbomAssetDetail, "library"> & {
  exposure?: CbomExposure
  exposure_basis?: string
  exposure_factor?: number
  library: null | (NonNullable<CbomAssetDetail["library"]> & { eol_as_of?: string; eol_today?: Eol | null })
  q_explain?: QExplain | null  // CB-19
  agility?: AgilityDetail | null  // CB-24
} & QGradeFields

function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const link = document.createElement("a")
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

/** The code scan's CycloneDX document. XML is the same document written as CycloneDX 1.6 XML; the BOM signature
 * covers the JSON form. */
export async function downloadCbomScanBom(teamId: string | number, scanId: string | number, format: CycloneDxFormat) {
  try {
    const response = await api.get(`/${teamId}/cbom/scan/${scanId}/bom`, { params: { format }, responseType: "blob" })
    saveBlob(response.data as Blob, `cbom-cyclonedx-${scanId}.cdx.${format}`)
  } catch (error) {
    showErrorToast(error, `Failed to download the CycloneDX ${format.toUpperCase()}`)
    throw error
  }
}

/** A scan-node run's CycloneDX 1.6 CBOM, through the authenticated client (a plain link would carry no token). */
export async function downloadCbomRunBom(teamId: number, runId: number, format: CycloneDxFormat) {
  try {
    const response = await api.get(`/${teamId}/cbom/sources/runs/${runId}/cbom`, {
      params: { format },
      responseType: "blob",
    })
    saveBlob(response.data as Blob, `cbom-sources-run-${runId}.cdx.${format}`)
  } catch (error) {
    showErrorToast(error, `Error downloading the CBOM (${format.toUpperCase()})`)
    throw error
  }
}
