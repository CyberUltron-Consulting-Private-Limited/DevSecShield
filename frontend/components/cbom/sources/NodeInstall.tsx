"use client";

// Scan node install pieces that depend on the ZeroShield API address (CB-08, review 5876424957). The node accepts an
// http:// API only with the lab switch ZS_ALLOW_INSECURE_HTTP=1 (scan_node agent.py; Helm `allowInsecureHttp`; the AMI's
// /etc/zs-node/env), so on a plain-HTTP deployment every command (with the token it was created for) is shown inside a
// "Test lab only" block that carries the switch, and no port is advised. The warning itself is logic.insecureApiWarning
// (CB-03), shown in the wizard and the pool form. Rendered by httpDeployment.test.ts.

import type { ReactNode } from "react";

import { TableCell, TableRow } from "@/components/ui/table";

import { OVA_NO_INSECURE_SWITCH, helmAgentCommand, installCommand, labSwitchHelps, nodeApiPort, type DeployMethod } from "./logic";
import { CodeSnippet } from "./shared";
import { InfoTip } from "@/components/ui/info-tip";

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
      <p className="text-sm font-medium text-amber-700 dark:text-amber-400">Test lab only <InfoTip id="cbsrc.nodes.lab_only" /></p>
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
}: {
  apiUrl: string;
  method: DeployMethod;
  token: string;
  name: string;
  proxyUrl?: string | null;
  image: string;
}) {
  const lab = labSwitchHelps(apiUrl);
  const language = method === "ami" ? "yaml" : "bash";
  const code = installCommand(method, { token, apiUrl, proxyUrl, image, name, insecureHttp: lab && method !== "ova" });
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

/** The Helm command for a host-agent pool token: the token is always shown. */
export function PoolHelmCommand({ apiUrl, poolToken, image, proxyUrl }: { apiUrl: string; poolToken: string; image: string; proxyUrl?: string | null }) {
  const lab = labSwitchHelps(apiUrl);
  const code = helmAgentCommand({ poolToken, apiUrl, image, proxyUrl, insecureHttp: lab });
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
