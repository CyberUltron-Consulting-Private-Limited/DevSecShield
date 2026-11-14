"use client";

// Scan node install pieces that depend on the ZeroShield API address (CB-08, review 5876424957). The node accepts an
// http:// API only with the lab switch ZS_ALLOW_INSECURE_HTTP=1 (scan_node agent.py; Helm `allowInsecureHttp`; the AMI's
// /etc/zs-node/env), so on a plain-HTTP deployment every command (with the token it was created for) is shown inside a
// "Test lab only" block that carries the switch, and no port is advised. The warning itself is logic.insecureApiWarning
// (CB-03), shown in the wizard and the pool form. Rendered by httpDeployment.test.ts.

import type { ReactNode } from "react";

import { TableCell, TableRow } from "@/components/ui/table";

import {
  OVA_NO_INSECURE_SWITCH,
  helmAgentCommand,
  installCommand,
  labSwitchHelps,
  nodeApiPort,
  onePasteInstall,
  type DeployMethod,
  type InstallLinks,
  type NodeImage,
} from "./logic";
import { CodeSnippet } from "./shared";

export const LAB_ONLY_WARNING =
  "ZS_ALLOW_INSECURE_HTTP=1 lets this node use a plain-HTTP API, so its credentials travel unencrypted, with the decrypted secrets of every job. Never use it on a network you do not control; serve the API over HTTPS instead.";

export function apiHost(apiUrl: string): string {
  try {
    return new URL(apiUrl).hostname;
  } catch {
    return apiUrl;
  }
}

function LabOnly({ children }: { children: ReactNode }) {
  return (
    <div className="space-y-2 rounded-lg border border-amber-500/50 p-3" data-testid="node-command-lab-only">
      <p className="text-sm font-medium text-amber-700 dark:text-amber-400">Test lab only</p>
      <p className="text-xs text-zinc-700 dark:text-zinc-300">{LAB_ONLY_WARNING}</p>
      {children}
    </div>
  );
}

/** The install command of a node just created (or given a new token): the token is always shown. */
export function NodeInstallCommand({
  apiUrl,
  method,
  token,
  name,
  proxyUrl,
  image,
  source,
}: {
  apiUrl: string;
  method: DeployMethod;
  token: string;
  name: string;
  proxyUrl?: string | null;
  /** the image to run: the name the downloaded file loads as (default), or a registry image with source.pull */
  image: string;
  source?: Omit<NodeImage, "image">;
}) {
  const lab = labSwitchHelps(apiUrl);
  const language = method === "ami" ? "yaml" : "bash";
  const code = installCommand(method, { token, apiUrl, proxyUrl, image, name, insecureHttp: lab && method !== "ova", ...source });
  if (!lab) return <CodeSnippet code={code} language={language} />;
  if (method === "ova") {
    return (
      <div className="space-y-2" data-testid="node-command-ova-http">
        <p role="alert" className="text-xs text-amber-700 dark:text-amber-400">{OVA_NO_INSECURE_SWITCH}</p>
        <CodeSnippet code={code} language={language} />
      </div>
    );
  }
  return (
    <LabOnly>
      <CodeSnippet code={code} language={language} />
    </LabOnly>
  );
}

/** A command that talks to this deployment's API: inside the "Test lab only" block on a plain-HTTP API (CB-08). */
export function NodeCommandBlock({ apiUrl, code, language = "bash" }: { apiUrl: string; code: string; language?: string }) {
  if (!labSwitchHelps(apiUrl)) return <CodeSnippet code={code} language={language} />;
  return (
    <LabOnly>
      <CodeSnippet code={code} language={language} />
    </LabOnly>
  );
}

export const INSTALL_LINK_NOTE =
  "The download links in this command work only for this node's files and only until the node registers, its registration token is replaced, or the token expires. Like the token, they stay in your shell history: start the command with a space (bash with HISTCONTROL=ignorespace) or clear the history afterwards.";

/** Terminal-only hosts: ONE paste that downloads the node's files from this server with its install links, checks
 * their SHA-256 and installs (logic.onePasteInstall), with curl, and the same with wget for hosts without curl.
 * Nothing when the server sent no install links (no files on this server). Rendered by nodeDownloads.test.ts. */
export function NodeOnePaste({
  apiUrl,
  method,
  links,
  token,
  name,
  proxyUrl,
  caFile,
  image,
}: {
  apiUrl: string;
  method: DeployMethod;
  links: InstallLinks | null | undefined;
  token: string;
  name: string;
  proxyUrl?: string | null;
  /** the proxy CA's file name on the host, only when the proxy inspects TLS */
  caFile?: string | null;
  /** the name the image file loads as */
  image: string;
}) {
  const opts = { apiUrl, token, name, proxyUrl, caFile, image, insecureHttp: labSwitchHelps(apiUrl) };
  const curl = onePasteInstall(method, links, opts);
  if (!curl) return null;
  const wget = onePasteInstall(method, links, { ...opts, fetcher: "wget" });
  const kit = method === "ova" || method === "ami";
  return (
    <div className="space-y-2" data-testid="node-one-paste">
      <p className="text-sm font-medium text-zinc-900 dark:text-white">
        {kit ? "Terminal only: build the image on your build machine with one paste" : "Terminal only: install with one paste on the host"}
      </p>
      <p className="text-xs text-zinc-600 dark:text-zinc-400">
        Downloads the files from ZeroShield, checks their SHA-256 and {method === "docker" ? "starts the node"
          : method === "helm" ? "installs the chart (set REGISTRY first)" : "builds the image with Packer"}. Needs curl
        and sha256sum{method === "docker" ? " and Docker" : method === "helm" ? ", Docker and Helm" : ", unzip and Packer"}.
      </p>
      <NodeCommandBlock apiUrl={apiUrl} code={curl} />
      {wget && (
        <details className="text-xs" data-testid="node-one-paste-wget">
          <summary className="cursor-pointer text-zinc-600 dark:text-zinc-400">No curl on the host? The same with wget</summary>
          <div className="mt-2"><NodeCommandBlock apiUrl={apiUrl} code={wget} /></div>
        </details>
      )}
      <p className="text-xs text-zinc-500" data-testid="node-one-paste-note">{INSTALL_LINK_NOTE}</p>
    </div>
  );
}

/** The Helm command for a host-agent pool token: the token is always shown. */
export function PoolHelmCommand({ apiUrl, poolToken, image, proxyUrl, source }: {
  apiUrl: string; poolToken: string; image: string; proxyUrl?: string | null; source?: Omit<NodeImage, "image">;
}) {
  const lab = labSwitchHelps(apiUrl);
  const code = helmAgentCommand({ poolToken, apiUrl, image, proxyUrl, insecureHttp: lab, ...source });
  if (!lab) return <CodeSnippet code={code} language="bash" />;
  return (
    <LabOnly>
      <CodeSnippet code={code} language="bash" />
    </LabOnly>
  );
}

/** The wizard's egress row for the ZeroShield API: its HTTPS port, never a plain-HTTP port. */
export function ApiEgressRow({ apiUrl }: { apiUrl: string }) {
  const port = nodeApiPort(apiUrl);
  const usedFor = port ? "Jobs in, results out (HTTPS)"
    : labSwitchHelps(apiUrl) ? "Plain HTTP: test-lab nodes only (ZS_ALLOW_INSECURE_HTTP=1)"
    : "Not usable as it is: see the warning above";
  return (
    <TableRow>
      <TableCell className="font-mono text-xs">{apiHost(apiUrl)}</TableCell>
      <TableCell>{port ?? "—"}</TableCell>
      <TableCell className="text-zinc-600 dark:text-zinc-400">
        {usedFor}
      </TableCell>
    </TableRow>
  );
}
