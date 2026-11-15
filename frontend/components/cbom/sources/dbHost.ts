/**
 * The host field of a database or KMIP source (#217): a host name or an IP address, never "name:port". Only an IPv6
 * address has colons (it has at least two); "db.bank.local:5433" is a name and a port, and the port has its own field.
 * The API applies the same rule (backend kinds.check_host); null when the value is fine.
 */
const HOST_RE = /^[A-Za-z0-9._:-]{1,253}$/;

export function dbHostError(value: string, empty = "Enter a host name or IP address"): string | null {
  const text = value.trim();
  if (!HOST_RE.test(text)) return empty;
  if (text.includes(":") && (text.match(/:/g) ?? []).length < 2) {
    return "Enter the host name or IP address only; put the port in the Port field";
  }
  return null;
}
