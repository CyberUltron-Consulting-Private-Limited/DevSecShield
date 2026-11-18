// The G3 allowed-diff rule (DEVILS-ADVOCATE.md §4.1): the executed `docker run` = the UI's command, token for token,
// plus only
//   * `--network cbom-e2e-net`, when nginx carries the alias api.dss.test on that network (CB-03);
//   * until CB-15 merges: `-e ZS_CA_FILE=/lab/ca.pem -v <lab-ca>:/lab/ca.pem:ro`.
// When the stack cannot honour the rule yet (no node image, no alias), the plan still starts the node so the later
// steps judge real product output, but it records every extra token: G3 then fails (ledger row PRE-node-on-L).
import { spawnSync } from "node:child_process";
import { isIP } from "node:net";

/** Split a POSIX-shell command line (single/double quotes, backslash-newline continuations) into argv. */
export function splitCommand(text) {
  const src = text.replace(/\\\r?\n/g, " ");
  const out = [];
  let cur = "", inArg = false, q = null;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q === "'") { if (c === "'") q = null; else cur += c; continue; }
    if (q === '"') {
      if (c === '"') q = null;
      else if (c === "\\" && i + 1 < src.length && '"\\$`'.includes(src[i + 1])) cur += src[++i];
      else cur += c;
      continue;
    }
    if (c === "'" || c === '"') { q = c; inArg = true; continue; }
    if (c === "\\" && i + 1 < src.length) { cur += src[++i]; inArg = true; continue; }
    if (/\s/.test(c)) { if (inArg) { out.push(cur); cur = ""; inArg = false; } continue; }
    cur += c; inArg = true;
  }
  if (q) throw new Error("unterminated quote in the install command");
  if (inArg) out.push(cur);
  return out;
}

function docker(...a) { return spawnSync("docker", a, { encoding: "utf8", timeout: 60000 }); }

/** Does `cbom-e2e-net` exist with nginx answering as api.dss.test on it (CB-03's stack change)? */
export function labNetworkHasApiAlias(network = "cbom-e2e-net", host = "api.dss.test") {
  const r = docker("network", "inspect", network, "--format", "{{json .Containers}}");
  if (r.status !== 0) return false;
  let containers = {};
  try { containers = JSON.parse(r.stdout || "{}") || {}; } catch { return false; }
  for (const c of Object.values(containers)) {
    if (!/nginx/.test(c.Name || "")) continue;
    const ins = docker("inspect", c.Name, "--format", `{{json (index .NetworkSettings.Networks "${network}").Aliases}}`);
    try { if ((JSON.parse(ins.stdout || "[]") || []).includes(host)) return true; } catch { /* not attached */ }
  }
  return false;
}

export function imageExists(image) { return docker("image", "inspect", image).status === 0; }

/**
 * Plan the node launch. Returns {argv, allowed, extra, removed, imageServed, imageNote, container, volume}.
 * `allowed`/`extra` are lists of human-readable token groups; `removed` lists UI tokens that were not kept.
 */
export function allowedDiff(command, { image = null, ca = null, network = "cbom-e2e-net", hasAlias = labNetworkHasApiAlias,
  exists = imageExists } = {}) {
  const ui = splitCommand(command);
  if (ui[0] !== "docker" || ui[1] !== "run") throw new Error(`not a docker run command: ${ui.slice(0, 2).join(" ")}`);
  const argv = [...ui];
  const allowed = [], extra = [], removed = [];
  const uiImage = argv[argv.length - 1];
  const nameAt = argv.indexOf("--name");
  const container = nameAt > 0 ? argv[nameAt + 1] : "zs-scan-node";
  const vol = argv.find((a, i) => argv[i - 1] === "-v" && a.endsWith(":/var/lib/zs-node"));
  const volume = vol ? vol.split(":")[0] : null;
  const insert = (...tokens) => argv.splice(argv.length - 1, 0, ...tokens);

  if (hasAlias(network)) {
    insert("--network", network);
    allowed.push(`--network ${network}`);
  } else {
    // pre-CB-03 bridge: the host's network namespace resolves api.dss.test (127.0.0.1, nginx) and routes to the lab
    insert("--network", "host");
    extra.push("--network host (cbom-e2e-net has no nginx alias api.dss.test yet: CB-03)");
  }
  if (ca) {
    insert("-e", "ZS_CA_FILE=/lab/ca.pem", "-v", `${ca}:/lab/ca.pem:ro`);
    allowed.push("-e ZS_CA_FILE=/lab/ca.pem -v <lab-ca>:/lab/ca.pem:ro (until CB-15)");
  }
  let imageServed = exists(uiImage), imageNote = imageServed ? `${uiImage} present` : `${uiImage} not on this stack`;
  if (!imageServed) {
    if (image && exists(image)) {
      argv[argv.length - 1] = image;
      removed.push(uiImage);
      extra.push(`image ${image} instead of ${uiImage} (no scan-node image on L: CB-03)`);
      imageNote += `; ran ${image}`;
    } else {
      imageNote += "; no local replacement image";
    }
  }
  return { argv, allowed, extra, removed, imageServed, imageNote, container, volume, uiImage };
}

/** The tokens the allowed diff may add (DA §4.1), as a multiset: the lab network, and until CB-15 the lab CA. */
export function allowedTokens({ network = "cbom-e2e-net", ca = null } = {}) {
  return ["--network", network, ...(ca ? ["-e", "ZS_CA_FILE=/lab/ca.pem", "-v", `${ca}:/lab/ca.pem:ro`] : [])];
}

/** True when two token lists are equal as multisets. */
export function sameTokens(a, b) {
  return JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
}

/** The token-level diff between the UI command and an executed argv (for the evidence file). */
export function tokenDiff(uiArgv, runArgv) {
  const left = [...uiArgv];
  const added = [];
  for (const t of runArgv) {
    const i = left.indexOf(t);
    if (i >= 0) left.splice(i, 1); else added.push(t);
  }
  return { added, removed: left };
}

// ---------------------------------------------------------------------------- exact comparisons (review 5878413538)
/** Every IP address in a text, as whole tokens: a database array (`{10.231.0.2}`), a JSON list or one table cell.
 * Never a substring: "10.231.0.25".includes("10.231.0.2") is true, an address compare must not be. */
export function ipTokens(text) {
  return String(text ?? "").split(/[\s,;{}[\]"'()]+/).filter((t) => t && isIP(t) !== 0);
}

/** The node's address is one of the cells' addresses exactly (cells read one by one, never the row's joined text). */
export function cellsHaveIp(cells, ips) {
  const seen = new Set((cells || []).flatMap((c) => ipTokens(c)));
  return (ips || []).length > 0 && (ips || []).some((ip) => seen.has(ip));
}

/** The export's zs:engine_version names the build: a git SHA prefix of at least 7 hex characters of `sha`, or text
 * that contains `sha`'s first 12 characters. A shorter prefix ("b") would match every SHA that starts with it. */
export function engineMatchesBuild(engine, sha) {
  const e = String(engine ?? "").trim().toLowerCase();
  const s = String(sha ?? "").trim().toLowerCase();
  if (!e || !/^[0-9a-f]{40}$/.test(s)) return false;
  if (/^[0-9a-f]{7,40}$/.test(e)) return s.startsWith(e);
  return e.includes(s.slice(0, 12));
}
