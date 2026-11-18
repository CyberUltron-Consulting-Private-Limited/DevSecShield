/**
 * Certificate domains and CA connector examples of the Cloud & Identity tab (#368). Pure, so certDomain.test.ts pins
 * them.
 *  - normalizeDomain: the name as the server stores it (lower case, no trailing dot, internationalised names in their
 *    ASCII form, xn--...). The server converts a Unicode name the same way and drops duplicates silently, so the form
 *    must compare the ASCII form to say "already in the list".
 *  - CA_API_URL_EXAMPLE: each CLM product's own API address example (the Venafi TPP path was shown for all of them).
 */
export const DOMAIN_LABEL_RE = /^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$/

/** The ASCII (IDNA) form of a host name, as WHATWG URL parsing gives it; null when it is not a host name. */
function asciiHost(value: string): string | null {
  if (/[\s/?#@:\\[\]%]/.test(value)) return null
  try {
    return new URL(`http://${value}`).hostname || null
  } catch {
    return null
  }
}

export function normalizeDomain(raw: string): { value: string; error: string | null } {
  let value = raw.trim().toLowerCase().replace(/\.$/, "")
  if (!value) return { value, error: "Enter a domain such as example.com" }
  const bad = { value, error: `${raw.trim()} is not a domain name such as example.com` }
  if (/[^\x00-\x7f]/.test(value)) {
    const ascii = asciiHost(value)
    if (!ascii) return bad
    value = ascii.replace(/\.$/, "")
  }
  const labels = value.split(".")
  if (value.length > 253 || labels.length < 2 || !labels.every((l) => DOMAIN_LABEL_RE.test(l)) || /^\d+$/.test(labels[labels.length - 1])) {
    return { ...bad, value }
  }
  return { value, error: null }
}

/** "bücher.example is already in the list (as xn--bcher-kva.example)" when what was typed differs from its stored form. */
export function alreadyListed(raw: string, value: string): string {
  const typed = raw.trim().toLowerCase().replace(/\.$/, "")
  return typed === value ? `${value} is already in the list` : `${raw.trim()} is already in the list (as ${value})`
}

/** The API address example each CA or CLM product's Connect dialog shows. */
export const CA_API_URL_EXAMPLE: Record<string, string> = {
  venafi: "https://tpp.example.com/vedsdk",
  keyfactor: "https://keyfactor.example.com/KeyfactorAPI",
  digicert: "https://www.digicert.com/services/v2",
  sectigo: "https://cert-manager.com/api",
  other: "https://clm.example.com/api",
  vault: "https://vault.corp.example.com:8200",
  ejbca: "https://ejbca.corp.example.com",
}
