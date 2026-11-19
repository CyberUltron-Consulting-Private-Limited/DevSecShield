// Oracle Cloud (OCI) tenancy sources: field rules, the read-only policy shown in the form, and the helpers of the
// three ways to connect (Resource Manager stack, key added in the Console, the customer's own API key).
// Pure functions only, so ociTenancy.test.ts can check them without a browser.

/** How the customer connects. "stack" and "console" use a key pair ZeroShield generates; "own" uploads theirs. */
export type OciMethod = "stack" | "console" | "own"
export type OciKeyOrigin = "generated" | "uploaded"

// Client-side shapes only; the server's rules (backend kinds.OciConfig) are the ones that decide.
export const OCI_TENANCY_RE = /^ocid1\.tenancy\.oc1\.\.[a-z0-9]+$/
export const OCI_USER_RE = /^ocid1\.user\.oc1\.\.[a-z0-9]+$/
export const OCI_COMPARTMENT_RE = /^ocid1\.(compartment|tenancy)\.oc1\.\.[a-z0-9]+$/
/** Region identifiers such as us-ashburn-1, eu-frankfurt-1, ap-mumbai-1, me-dubai-1, sa-saopaulo-1. */
export const OCI_REGION_RE = /^[a-z]{2,}-[a-z]+-\d$/
export const OCI_MAX_REGIONS = 60
export const OCI_MAX_COMPARTMENTS = 200
const MAX_KEY_BYTES = 64 * 1024

/** The group the stack and the reader script create; every statement below names it. */
export const OCI_GROUP = "ZeroShieldCBOMReaders"
/** The policy verbs and resource types ZeroShield needs: inspect and read only, never use or manage. */
export const OCI_POLICY_GRANTS = [
  "inspect compartments",
  "read vaults",
  "read keys",
  "inspect secrets",
  "inspect certificate-authority-family",
  "read load-balancers",
  "read objectstorage-namespaces",
  "read buckets",
]
/** Grants that would expose key use or secret and certificate contents; neither the stack nor the script gives them. */
export const OCI_NEVER_GRANTED = ["use keys", "read secret-bundles", "read leaf-certificate-bundles"]

export const OCI_STACK_FILENAME = "zeroshield-cbom-oci-stack.zip"
/** The line of the oci-reader script that the source's public key replaces. */
export const OCI_PUBLIC_KEY_PLACEHOLDER = "<public key PEM shown in ZeroShield>"

/** One policy statement as written in OCI: "Allow group ZeroShieldCBOMReaders to read keys in tenancy". */
export function ociPolicyStatement(grant: string): string {
  return `Allow group ${OCI_GROUP} to ${grant} in tenancy`
}

/** The Resource Manager "Create stack" page in the tenancy's home region (IAM changes are made there). */
export function ociResourceManagerUrl(homeRegion: string): string {
  const region = homeRegion.trim().toLowerCase()
  const base = "https://cloud.oracle.com/resourcemanager/stacks/create"
  return OCI_REGION_RE.test(region) ? `${base}?region=${encodeURIComponent(region)}` : base
}

/** The reader script with the source's public key in place of the placeholder; unchanged without a key. */
export function fillOciPublicKey(script: string, publicKeyPem: string | null | undefined): string {
  const pem = (publicKeyPem ?? "").trim()
  if (!pem || !pem.includes("PUBLIC KEY-----")) return script
  return script.split(OCI_PUBLIC_KEY_PLACEHOLDER).join(pem)
}

/** The method an existing source was saved with: an uploaded key is "own"; a generated one opens on the stack. */
export function ociMethodOf(keyOrigin: string | null | undefined): OciMethod {
  return keyOrigin === "uploaded" ? "own" : "stack"
}

export function ociKeyOriginOf(method: OciMethod): OciKeyOrigin {
  return method === "own" ? "uploaded" : "generated"
}

function lines(text: string): string[] {
  return Array.from(new Set(text.replace(/﻿/g, "").split(/\r?\n/).map((l) => l.split("#")[0].trim()).filter(Boolean)))
}

/** A pasted private key: an unencrypted PEM private key (RSA; the server checks the type and size). */
export function ociPrivateKeyError(text: string): string | null {
  const pem = text.trim()
  if (!pem) return "Upload or paste the private key"
  if (pem.length > MAX_KEY_BYTES) return "The key is larger than 64 KB"
  if (/ENCRYPTED PRIVATE KEY|Proc-Type:\s*4,ENCRYPTED/.test(pem)) return "The key is encrypted; paste it without a passphrase"
  if (!/-----BEGIN (RSA )?PRIVATE KEY-----/.test(pem)) {
    return /PUBLIC KEY-----/.test(pem)
      ? "This is the public key; paste the private key (-----BEGIN PRIVATE KEY-----)"
      : "Paste the PEM private key (-----BEGIN PRIVATE KEY----- or -----BEGIN RSA PRIVATE KEY-----)"
  }
  return null
}

export interface OciFormValues {
  method: OciMethod
  tenancy: string
  homeRegion: string
  regions: string
  compartments: string
  userOcid: string
  privateKey: string
}

/** What is saved on the server already, so the form can tell what still has to be entered. */
export interface OciSaved {
  tenancy: string
  keyOrigin: OciKeyOrigin
  keySet: boolean
}

export interface OciConfigBody {
  tenancy_ocid: string
  user_ocid: string | null
  home_region: string
  regions: string[]
  compartment_ocids: string[]
  key_origin: OciKeyOrigin
}

export interface OciCheck {
  errors: { tenancy: string | null; homeRegion: string | null; regions: string | null; compartments: string | null; userOcid: string | null; privateKey: string | null }
  config: OciConfigBody
}

/**
 * The OCI field errors and the config to send. `validate`: Save and validate, which needs the user OCID (and, for
 * an uploaded key, a key unless the same one is kept); without it the generated-key save that creates the key pair.
 * The server clears a stored key when the tenancy changes (where field), so an uploaded key must then be re-entered.
 */
export function checkOciForm(v: OciFormValues, saved: OciSaved | null, validate: boolean): OciCheck {
  const tenancy = v.tenancy.trim()
  const homeRegion = v.homeRegion.trim().toLowerCase()
  const regions = lines(v.regions.toLowerCase())
  const compartments = lines(v.compartments)
  const user = v.userOcid.trim()
  const origin = ociKeyOriginOf(v.method)
  const badRegion = regions.find((r) => !OCI_REGION_RE.test(r))
  const badCompartment = compartments.find((c) => !OCI_COMPARTMENT_RE.test(c))
  const keepsUploaded = !!saved && saved.keyOrigin === "uploaded" && saved.keySet && saved.tenancy === tenancy
  const errors: OciCheck["errors"] = {
    tenancy: OCI_TENANCY_RE.test(tenancy) ? null : "Enter the tenancy OCID, like ocid1.tenancy.oc1..aaaa…",
    homeRegion: OCI_REGION_RE.test(homeRegion) ? null : "Enter the home region identifier, like us-ashburn-1",
    regions: badRegion
      ? `${badRegion} is not a region identifier like eu-frankfurt-1`
      : regions.length > OCI_MAX_REGIONS
        ? `At most ${OCI_MAX_REGIONS} regions`
        : null,
    compartments: badCompartment
      ? `${badCompartment} is not a compartment OCID (ocid1.compartment.oc1..…)`
      : compartments.length > OCI_MAX_COMPARTMENTS
        ? `At most ${OCI_MAX_COMPARTMENTS} compartments`
        : null,
    userOcid: user
      ? OCI_USER_RE.test(user) ? null : "Enter the user OCID, like ocid1.user.oc1..aaaa…"
      : validate
        ? v.method === "stack" ? "Enter the user OCID: the stack's user_ocid output" : "Enter the user OCID"
        : null,
    privateKey: origin !== "uploaded"
      ? null
      : v.privateKey.trim()
        ? ociPrivateKeyError(v.privateKey)
        : keepsUploaded
          ? null
          : saved?.keyOrigin === "uploaded" && saved.keySet
            ? "Re-enter the private key: it is cleared when the tenancy OCID changes"
            : "Upload or paste the private key",
  }
  return {
    errors,
    config: {
      tenancy_ocid: tenancy,
      user_ocid: user || null,
      home_region: homeRegion,
      regions,
      compartment_ocids: compartments,
      key_origin: origin,
    },
  }
}

/** The secrets part of a save: the uploaded key when one was entered, and the stored key to drop when a generated
 * key must be created in its place (switching from an uploaded key, or "Generate a new key"). */
export function ociSecretsOf(v: OciFormValues, saved: OciSaved | null, replaceGenerated = false): { secrets: Record<string, string>; clear: string[] } {
  if (v.method === "own") return { secrets: v.privateKey.trim() ? { api_signing_key: v.privateKey.trim() + "\n" } : {}, clear: [] }
  const drop = !!saved && (saved.keyOrigin === "uploaded" ? saved.keySet : replaceGenerated)
  return { secrets: {}, clear: drop ? ["api_signing_key"] : [] }
}
