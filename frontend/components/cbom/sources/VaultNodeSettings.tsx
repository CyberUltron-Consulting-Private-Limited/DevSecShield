"use client";

/**
 * What the scan node's operator sets for the chosen vault (#364), and whether the chosen node reports it can read it.
 * Shown under the vault choice in the source forms, the fleet credential form and the CMDB import dialog.
 */
import type { CbomScanNode } from "@/utils/backend_api";

import { NODE_SETTINGS, nodeVaultProblem, unavailableProblem, vaultLabel } from "./vaultProviders";

export function VaultNodeSettings({
  provider,
  path = "",
  node = null,
  testId = "vault-node-settings",
  className = "",
}: {
  provider: string | null | undefined;
  path?: string;
  node?: Pick<CbomScanNode, "name" | "vault"> | null;
  testId?: string;
  className?: string;
}) {
  if (!provider) return null;
  const unavailable = unavailableProblem(provider);
  if (unavailable) {
    return (
      <p className={`text-xs text-amber-700 dark:text-amber-400 min-w-0 break-words ${className}`} role="status" data-testid={testId}>
        {unavailable}.
      </p>
    );
  }
  const settings = NODE_SETTINGS[provider as keyof typeof NODE_SETTINGS] ?? [];
  const problem = nodeVaultProblem(node, provider, path);
  return (
    <div className={`text-xs text-zinc-600 dark:text-zinc-400 space-y-1 min-w-0 break-words ${className}`} data-testid={testId}>
      <p>On the scan node, for {vaultLabel(provider)}, its operator sets:</p>
      <ul className="list-disc pl-5 space-y-0.5">
        {settings.map((s) => (
          <li key={s.name}>
            <code className="font-mono">{s.name}</code>: {s.what}
          </li>
        ))}
      </ul>
      {problem ? (
        <p className="text-amber-700 dark:text-amber-400" role="status" data-testid={`${testId}-problem`}>
          Not ready: {problem}.
        </p>
      ) : node?.vault?.enabled ? (
        <p data-testid={`${testId}-ready`}>
          Scan node {node.name} reports {vaultLabel(provider)} ready
          {node.vault.prefix ? <> (prefix <code className="font-mono">{node.vault.prefix}</code>)</> : null}.
        </p>
      ) : null}
    </div>
  );
}
