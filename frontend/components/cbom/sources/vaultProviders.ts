/**
 * Vaults the credential forms offer, and what a scan node's operator sets for each (#364, #365).
 *
 * The scan node reads HashiCorp Vault (KV v2) and AWS Secrets Manager (scan_node/zs_scan_node/vault.py). CyberArk
 * and Azure Key Vault are listed as "not available yet" (disabled, not hidden); the backend refuses to save them
 * (backend/utilities/cbom_sources/vault_support.py, which this file mirrors).
 */
import type { CbomScanNode } from "@/utils/backend_api";

export type VaultProviderId = "hashicorp" | "aws_secrets_manager" | "cyberark" | "azure_key_vault";

export interface VaultSetting {
  name: string;
  what: string;
}

export interface VaultProviderOption {
  value: VaultProviderId;
  label: string;
  available: boolean;
  /** shown in the drop-down: the label, with "(not available yet)" when no scan node reads it */
  optionLabel: string;
}

export const PREFIX_ENV = "ZS_VAULT_PATH_PREFIX";

const LABELS: Record<VaultProviderId, string> = {
  hashicorp: "HashiCorp Vault",
  aws_secrets_manager: "AWS Secrets Manager",
  cyberark: "CyberArk",
  azure_key_vault: "Azure Key Vault",
};
const AVAILABLE: VaultProviderId[] = ["hashicorp", "aws_secrets_manager"];

export const VAULT_PROVIDERS: VaultProviderOption[] = (Object.keys(LABELS) as VaultProviderId[]).map((value) => ({
  value,
  label: LABELS[value],
  available: AVAILABLE.includes(value),
  optionLabel: AVAILABLE.includes(value) ? LABELS[value] : `${LABELS[value]} (not available yet)`,
}));

export const NODE_SETTINGS: Partial<Record<VaultProviderId, VaultSetting[]>> = {
  hashicorp: [
    { name: PREFIX_ENV, what: "the path prefix this node may read, e.g. secret/cbom (secret/data/cbom works too)" },
    { name: "VAULT_ADDR", what: "the Vault address, e.g. https://vault.bank.local:8200" },
    { name: "VAULT_TOKEN", what: "a token whose policy can read <prefix>/* (KV v2: secret/data/cbom/*)" },
    { name: "ZS_VAULT_CA_FILE", what: "the CA certificate that issued Vault's TLS certificate, if it is private" },
  ],
  aws_secrets_manager: [
    { name: PREFIX_ENV, what: "the secret-name prefix this node may read, e.g. cbom" },
    {
      name: "AWS role",
      what: "the node's IAM role (or AWS_* credentials) allows secretsmanager:GetSecretValue on those secrets; AWS_REGION names the region",
    },
  ],
};

export function vaultLabel(provider: string): string {
  return LABELS[provider as VaultProviderId] ?? provider;
}

/** The backend's refusal for a vault no scan node reads, or null. */
export function unavailableProblem(provider: string | null | undefined): string | null {
  if (!provider || AVAILABLE.includes(provider as VaultProviderId)) return null;
  return `${vaultLabel(provider)} is not available yet: no scan node version reads it; use HashiCorp Vault or AWS Secrets Manager`;
}

function logical(path: string, provider: string): string[] {
  const parts = path.trim().split("/").filter(Boolean);
  if (provider === "hashicorp" && parts.length >= 2 && parts[1] === "data") return [parts[0], ...parts.slice(2)];
  return parts;
}

function forms(prefix: string): string {
  const parts = prefix.split("/");
  return `${prefix}/... or ${[parts[0], "data", ...parts.slice(1)].join("/")}/...`;
}

/**
 * Why `node` cannot read `provider` at `path` by what it reported at heartbeat, or null (also when it has not
 * reported). The same checks and wording as the CMDB import's pre-check (vault_support.node_problem).
 */
export function nodeVaultProblem(node: Pick<CbomScanNode, "name" | "vault"> | null | undefined, provider: string,
  path: string): string | null {
  const v = node?.vault;
  if (!node || !v || v.enabled === null || v.enabled === undefined) return null;
  if (v.enabled === false) {
    return `scan node ${node.name} has vault use off: its operator sets ${PREFIX_ENV} (and, for HashiCorp Vault, VAULT_ADDR and VAULT_TOKEN) on the node`;
  }
  if (Array.isArray(v.providers) && !v.providers.includes(provider)) {
    return `scan node ${node.name} cannot read ${vaultLabel(provider)} (update the node to a version that does)`;
  }
  if (provider === "hashicorp" && v.prefix && v.prefix.replace(/\//g, "") && path.trim()) {
    const want = logical(v.prefix, provider);
    const got = logical(path, provider);
    if (got.length <= want.length || want.some((part, i) => got[i] !== part)) {
      return `the path is outside the prefix scan node ${node.name} allows (${forms(want.join("/"))})`;
    }
  }
  const setup = v.setup?.[provider];
  if (setup && setup !== "ready") return `scan node ${node.name} is not set up for ${vaultLabel(provider)}: ${setup}`;
  return null;
}
