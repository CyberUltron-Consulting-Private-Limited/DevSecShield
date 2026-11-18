/**
 * For the unit tests (Node only, reads files): the source of the (i) tip text modules, where each entry's `// src:`
 * note sits directly above it.
 */
import fs from "node:fs";
import path from "node:path";

export const TIP_TEXT_DIR = path.join(__dirname, "infotips", "text");

/** Each text module (content/infotips/text/<area>.ts) with its source. */
export function tipTextSources(): { file: string; text: string }[] {
  return fs
    .readdirSync(TIP_TEXT_DIR)
    .filter((n) => n.endsWith(".ts"))
    .sort()
    .map((n) => ({ file: path.join(TIP_TEXT_DIR, n), text: fs.readFileSync(path.join(TIP_TEXT_DIR, n), "utf8") }));
}

/** All text modules in one string, for searches over the whole registry. */
export function tipTextSource(): string {
  return tipTextSources().map((s) => s.text).join("\n");
}
