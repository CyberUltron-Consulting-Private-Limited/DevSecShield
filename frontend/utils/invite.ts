/**
 * The invitation page /invite/<token> (S2, round 5): what it shows for an invitation and who is signed in.
 * Backend: backend/routers/invitations.py.  No password is ever mailed: a new address chooses its own here, an
 * existing account signs in as the invited address and then accepts or declines.
 */
import { newPasswordProblem } from "./password_rules"

export interface InviteInfo {
  email: string
  team_name: string
  invited_by: string
  expires_at: string | null
  account_exists: boolean
}

/** register: choose a password (new address) - sign_in: sign in as the address first - wrong_account: signed in
 * as somebody else - respond: signed in as the address, Accept or Decline. */
export type InviteView = "register" | "sign_in" | "wrong_account" | "respond"

export function sameAddress(a: string | null | undefined, b: string | null | undefined): boolean {
  return !!a && !!b && a.trim().toLowerCase() === b.trim().toLowerCase()
}

export function inviteView(info: InviteInfo, signedInEmail: string | null): InviteView {
  if (!info.account_exists) return "register"
  if (!signedInEmail) return "sign_in"
  return sameAddress(signedInEmail, info.email) ? "respond" : "wrong_account"
}

/** The sign-in page brings the invitee back here afterwards. LoginForm decodes redirect_url by turning "-" into
 * "/", and tokens are hex, so the path survives. */
export function inviteLoginHref(token: string): string {
  return `/login?redirect_url=${encodeURIComponent(`/invite/${token}`.split("/").join("-"))}`
}

export const INVITE_NAME_MAX = 64

/** Why the "create your account" form cannot be sent yet, or null (same password rules as sign-up). */
export function registerProblem(firstName: string, lastName: string, password: string, confirm: string): string | null {
  for (const [label, value] of [["First name", firstName], ["Last name", lastName]] as const) {
    const v = value.trim()
    if (!v) return `${label} is required.`
    if ([...v].length > INVITE_NAME_MAX) return `${label} is at most ${INVITE_NAME_MAX} characters.`
    if (/[<>]/.test(v)) return `${label} cannot contain < or >.`
  }
  const problem = newPasswordProblem(password)
  if (problem) return problem
  if (password !== confirm) return "The two passwords do not match."
  return null
}

/** The page reads the API with plain fetch (the shared axios client sends a 401 to /login and clears storage); this
 * turns any error body into one sentence. */
export function detailText(body: unknown, fallback = "Something went wrong. Please try again."): string {
  const detail = (body as { detail?: unknown } | null)?.detail
  if (typeof detail === "string" && detail.trim()) return detail
  if (Array.isArray(detail) && typeof detail[0]?.msg === "string") return String(detail[0].msg).replace(/^Value error, /, "")
  return fallback
}
