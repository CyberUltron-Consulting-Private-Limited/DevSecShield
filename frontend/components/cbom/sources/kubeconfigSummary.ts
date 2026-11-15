/**
 * What the Kubernetes form reads from an uploaded kubeconfig before it is sent (#208, #209). The server parses the
 * file again at save (backend kinds.check_kubeconfig) and is the rule; this only lets the form offer the file's
 * contexts, fill the API server URL from the chosen one, and say early what the save will refuse.
 *
 * kubectl writes kubeconfigs in block style (`- name: x` items under `clusters:`, `contexts:`, `users:`); that is
 * what is read here. A file this cannot read yields no contexts and the form simply offers none.
 */
export interface KubeconfigSummary {
  contexts: string[];
  current: string | null;
  servers: Record<string, string>; // context name -> its cluster's API server URL
}

const unquote = (v: string) => v.trim().replace(/^(["'])(.*)\1$/, "$2");

export function kubeconfigSummary(text: string): KubeconfigSummary {
  const clusters: Record<string, string> = {};
  const contexts: { name: string; cluster: string }[] = [];
  let section = "";
  let item: Record<string, string> | null = null;
  let current: string | null = null;
  const flush = () => {
    if (!item) return;
    if (section === "clusters" && item.name) clusters[item.name] = item.server ?? "";
    if (section === "contexts" && item.name) contexts.push({ name: item.name, cluster: item.cluster ?? "" });
    item = null;
  };
  for (const raw of text.replace(/\r\n/g, "\n").split("\n")) {
    if (!raw.trim() || raw.trim().startsWith("#")) continue;
    const top = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(raw);
    if (top) {
      flush();
      section = top[1];
      if (section === "current-context") current = unquote(top[2]) || null;
      continue;
    }
    const entry = /^\s*(-\s+)?([A-Za-z][\w-]*):\s*(.*)$/.exec(raw);
    if (!entry) continue;
    if (entry[1] && /^\s{0,2}-/.test(raw)) {
      flush();
      item = {};
    }
    if (item && ["name", "server", "cluster"].includes(entry[2]) && entry[3] && !entry[3].startsWith("{")) {
      item[entry[2]] = unquote(entry[3]);
    }
  }
  flush();
  const servers: Record<string, string> = {};
  for (const c of contexts) servers[c.name] = clusters[c.cluster] ?? "";
  return { contexts: contexts.map((c) => c.name), current, servers };
}

/** #209: settings the save refuses, in the server's words (null when there is none). */
export function kubeconfigSettingProblem(text: string): string | null {
  if (/^\s*["']?insecure-skip-tls-verify["']?\s*:\s*true\b/im.test(text)) {
    return "This kubeconfig disables certificate checks (insecure-skip-tls-verify); remove it";
  }
  if (/^\s*["']?proxy-url["']?\s*:\s*\S/im.test(text)) {
    return "This kubeconfig sets proxy-url, which the scan node does not use (it connects to the API server directly); remove it";
  }
  return null;
}

/** #208: why a typed context cannot be used with this kubeconfig (null when it can, or when the file offers none). */
export function contextProblem(context: string, summary: KubeconfigSummary): string | null {
  const name = context.trim();
  if (!name || summary.contexts.length === 0 || summary.contexts.includes(name)) return null;
  return `"${name}" is not in this kubeconfig; its contexts are ${summary.contexts.join(", ")}`;
}
