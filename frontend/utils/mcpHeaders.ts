/**
 * The MCP form's optional "Headers (JSON)" field (X1, Nov 11). Any JSON was accepted: `null`, `[]`, `"x"` or
 * `{"X-Retries": 3}` showed "Valid JSON" and were sent as they were (null meaning no headers at all), so the scan ran
 * without the header the customer meant to give. Headers are a JSON object of header names to text values; anything
 * else is refused with a field error and the estimate stays disabled.
 */
export type ParsedHeaders = { headers: Record<string, string> | null; error: string | null };

const EXAMPLE = 'for example {"Authorization": "Bearer ..."}';

export function parseMcpHeaders(value: string): ParsedHeaders {
  if (!value.trim()) return { headers: null, error: null };
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return { headers: null, error: `Headers must be valid JSON, ${EXAMPLE}.` };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { headers: null, error: `Headers must be a JSON object of header names and values, ${EXAMPLE}.` };
  }
  const headers: Record<string, string> = {};
  for (const [name, v] of Object.entries(parsed as Record<string, unknown>)) {
    if (!name.trim() || /[\s:]/.test(name.trim())) {
      return { headers: null, error: `"${name.slice(0, 40)}" is not a valid header name.` };
    }
    if (typeof v !== "string") {
      return { headers: null, error: `The value of header "${name.slice(0, 40)}" must be text in quotes.` };
    }
    headers[name.trim()] = v;
  }
  return { headers: Object.keys(headers).length ? headers : null, error: null };
}
