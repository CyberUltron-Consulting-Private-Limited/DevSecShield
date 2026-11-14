/**
 * CB-09: host names are stored as their IDNA 2008 A-label (`xn--fa-hia.lab`) and shown as the name the customer
 * typed (`faß.lab`). The API normalises a shown name back to the same A-label, so a form that shows U-labels saves
 * the same list. Labels that do not decode are shown as stored.
 */

const BASE = 36
const T_MIN = 1
const T_MAX = 26
const SKEW = 38
const DAMP = 700
const INITIAL_BIAS = 72
const INITIAL_N = 128

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1
  d += Math.floor(d / numPoints)
  let k = 0
  while (d > ((BASE - T_MIN) * T_MAX) >> 1) {
    d = Math.floor(d / (BASE - T_MIN))
    k += BASE
  }
  return k + Math.floor(((BASE - T_MIN + 1) * d) / (d + SKEW))
}

function digit(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 22 // 0-9 -> 26-35
  if (code >= 0x61 && code <= 0x7a) return code - 0x61 // a-z -> 0-25
  if (code >= 0x41 && code <= 0x5a) return code - 0x41
  return BASE
}

/** RFC 3492 decoding of one label's punycode part (after `xn--`); null when it is not valid punycode. */
export function decodePunycode(input: string): string | null {
  const output: number[] = []
  const basic = input.lastIndexOf("-")
  for (let j = 0; j < Math.max(basic, 0); j++) {
    const code = input.charCodeAt(j)
    if (code >= 0x80) return null
    output.push(code)
  }
  let n = INITIAL_N
  let bias = INITIAL_BIAS
  let i = 0
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
    const oldi = i
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) return null
      const d = digit(input.charCodeAt(index++))
      if (d >= BASE) return null
      i += d * w
      if (i > 0x10ffff * 64) return null
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias
      if (d < t) break
      w *= BASE - t
    }
    bias = adapt(i - oldi, output.length + 1, oldi === 0)
    n += Math.floor(i / (output.length + 1))
    i %= output.length + 1
    if (n > 0x10ffff) return null
    output.splice(i++, 0, n)
  }
  return String.fromCodePoint(...output)
}

/** The form to show for a stored host name: each `xn--` label decoded (the stored text when one does not decode). */
export function toUnicodeHost(name: string): string {
  if (!/(^|\.)xn--/i.test(name)) return name
  const labels = name.split(".")
  const out: string[] = []
  for (const label of labels) {
    if (!/^xn--/i.test(label)) {
      out.push(label)
      continue
    }
    const decoded = decodePunycode(label.slice(4).toLowerCase())
    // not a name: invalid punycode, all ASCII (never an A-label), a control character, or not in NFC form
    if (decoded === null || /^[\x00-\x7f]*$/.test(decoded) || /[\x00-\x1f\x7f-\x9f]/.test(decoded)) return name
    if (decoded.normalize("NFC") !== decoded) return name
    out.push(decoded)
  }
  return out.join(".")
}

/** Stored target or never-scan lines as the textarea shows them (one per line, host names as U-labels). */
export function displayHostLines(lines: unknown): string {
  return Array.isArray(lines) ? lines.map((line) => toUnicodeHost(String(line))).join("\n") : ""
}
