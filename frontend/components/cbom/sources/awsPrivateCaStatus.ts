/**
 * AWS availability and the status of an AWS Private CA connector (issue #223).
 *
 * An AWS Private CA is read by the AWS account source it names (aws_collect reads acm-pca with that account's role),
 * so its card shows that account's last real result: the newer of its last validation and its last collection
 * (caCardStatus, "Not checked since ..." after a day). "Not available" when this deployment has no AWS collection,
 * "Not read" when the AWS account was removed. Never a bare "Connected". Pure, so awsPrivateCaStatus.test.ts pins it.
 */
import { caCardStatus, formatUtc, type CaStatusInput, type CaStatusKind } from "./caCardStatus"
import type { Tone } from "./shared"

export const AWS_SUPPORT_EMAIL = "support@zeroshield.ai"

/** The backend's sentence (templates.AWS_NOT_CONFIGURED): template download 409, Validate, the AWS form. */
export const AWS_NOT_CONFIGURED = `AWS collection isn't enabled on this ZeroShield deployment. Contact ZeroShield support at ${AWS_SUPPORT_EMAIL} to have it turned on.`

export interface AwsAccountStatusInput extends CaStatusInput {
  name: string
}

/** #368: what the account's newest finished collection read of ACM Private CA (backend serialize.pca_reads). */
export interface AwsPcaRead {
  account_source_id: number
  job_id: number
  run_id: number | null
  at: string | null
  status: "read" | "partial" | "not_read"
  cas: number
  reason: string | null
  regions: { region: string; status: string; cas: number; error: string | null }[]
}

/** "no Private CA found in ap-south-1", "2 private CAs in us-east-1; none in ap-south-1", "us-east-1 not read (…)". */
export function pcaReadText(read: AwsPcaRead): string {
  const ok = read.regions.filter((r) => r.status === "ok" || r.status === "partial")
  const unread = read.regions.filter((r) => !(r.status === "ok" || r.status === "partial"))
  if (read.regions.length === 0) return `Private CAs not read: ${read.reason ?? "the account was not read"}`
  const parts: string[] = []
  if (ok.length && ok.every((r) => r.cas === 0)) {
    parts.push(`no Private CA found in ${ok.map((r) => r.region).join(", ")}`)
  } else {
    for (const r of ok.filter((x) => x.cas > 0)) parts.push(`${r.cas} private ${r.cas === 1 ? "CA" : "CAs"} in ${r.region}`)
    const none = ok.filter((x) => x.cas === 0)
    if (none.length) parts.push(`none in ${none.map((r) => r.region).join(", ")}`)
  }
  for (const r of unread) parts.push(`${r.region} not read${r.error ? ` (${r.error})` : ""}`)
  return parts.join("; ")
}

const PCA_STATUS: Record<AwsPcaRead["status"], [CaStatusKind, Tone, string]> = {
  read: ["passed", "green", "Read"],
  partial: ["partial", "amber", "Partly read"],
  not_read: ["failed", "red", "Not read"],
}

export type AwsPrivateCaStatusKind = CaStatusKind | "unavailable" | "removed"

export interface AwsPrivateCaStatus {
  kind: AwsPrivateCaStatusKind
  tone: Tone
  label: string
  /** what the status rests on: which result of which AWS account, when, and its own summary */
  detail: string | null
}

/**
 * @param aws the AWS account source the connector names (null: removed)
 * @param awsConfigured settings.aws_collection_configured (undefined while the settings load: judged on the account)
 */
export function awsPrivateCaStatus(aws: AwsAccountStatusInput | null | undefined, awsConfigured: boolean | undefined,
                                   now: Date = new Date(), pca: AwsPcaRead | null = null): AwsPrivateCaStatus {
  if (awsConfigured === false) return { kind: "unavailable", tone: "zinc", label: "Not available", detail: AWS_NOT_CONFIGURED }
  if (!aws) {
    return { kind: "removed", tone: "red", label: "Not read",
             detail: "Its AWS account was removed: edit it and pick a connected AWS account" }
  }
  const base = caCardStatus(aws, now)
  if (base.kind === "never") {
    return { kind: "never", tone: base.tone, label: base.label,
             detail: `AWS account ${aws.name} has not been validated or collected yet: validate it to read this CA` }
  }
  // #368: the latest result is the collection that read ACM PCA: say what it found, per region
  if (pca && base.basis === "collection" && aws.last_collect?.job_id === pca.job_id) {
    const [kind, tone, label] = PCA_STATUS[pca.status]
    const when = pca.at ? `, ${formatUtc(pca.at)}` : ""
    const detail = `Last collection of AWS account ${aws.name}${when}: ${pcaReadText(pca)}`
    return base.kind === "stale" ? { kind: "stale", tone: base.tone, label: base.label, detail } : { kind, tone, label, detail }
  }
  let detail = base.detail?.replace(/^Last (test|collection):/, (_, what: string) =>
    `Last ${what === "test" ? "validation" : "collection"} of AWS account ${aws.name}:`) ?? null
  if (pca && detail) detail = `${detail}. At its last collection${pca.at ? ` (${formatUtc(pca.at)})` : ""}: ${pcaReadText(pca)}`
  return { kind: base.kind, tone: base.tone, label: base.label, detail }
}

const ORDER: AwsPrivateCaStatusKind[] = ["removed", "failed", "error", "stale", "partial", "testing", "never", "passed", "unavailable"]

/** The status a row of several AWS Private CAs shows: the worst one. */
export function worstAwsPrivateCaStatus(list: AwsPrivateCaStatus[]): AwsPrivateCaStatus {
  if (list.length === 0) return { kind: "never", tone: "zinc", label: "Not checked", detail: null }
  return list.reduce((a, b) => (ORDER.indexOf(b.kind) < ORDER.indexOf(a.kind) ? b : a))
}
