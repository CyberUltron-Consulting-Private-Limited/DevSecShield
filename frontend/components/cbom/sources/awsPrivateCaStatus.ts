/**
 * AWS availability and the status of an AWS Private CA connector (issue #223).
 *
 * An AWS Private CA is read by the AWS account source it names (aws_collect reads acm-pca with that account's role),
 * so its card shows that account's last real result: the newer of its last validation and its last collection
 * (caCardStatus, "Not checked since ..." after a day). "Not available" when this deployment has no AWS collection,
 * "Not read" when the AWS account was removed. Never a bare "Connected". Pure, so awsPrivateCaStatus.test.ts pins it.
 */
import { caCardStatus, type CaStatusInput, type CaStatusKind } from "./caCardStatus"
import type { Tone } from "./shared"

export const AWS_SUPPORT_EMAIL = "support@zeroshield.ai"

/** The backend's sentence (templates.AWS_NOT_CONFIGURED): template download 409, Validate, the AWS form. */
export const AWS_NOT_CONFIGURED = `AWS collection isn't enabled on this ZeroShield deployment. Contact ZeroShield support at ${AWS_SUPPORT_EMAIL} to have it turned on.`

export interface AwsAccountStatusInput extends CaStatusInput {
  name: string
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
                                   now: Date = new Date()): AwsPrivateCaStatus {
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
  const detail = base.detail?.replace(/^Last (test|collection):/, (_, what: string) =>
    `Last ${what === "test" ? "validation" : "collection"} of AWS account ${aws.name}:`) ?? null
  return { kind: base.kind, tone: base.tone, label: base.label, detail }
}

const ORDER: AwsPrivateCaStatusKind[] = ["removed", "failed", "error", "stale", "partial", "testing", "never", "passed", "unavailable"]

/** The status a row of several AWS Private CAs shows: the worst one. */
export function worstAwsPrivateCaStatus(list: AwsPrivateCaStatus[]): AwsPrivateCaStatus {
  if (list.length === 0) return { kind: "never", tone: "zinc", label: "Not checked", detail: null }
  return list.reduce((a, b) => (ORDER.indexOf(b.kind) < ORDER.indexOf(a.kind) ? b : a))
}
