// The CI/CD API key as the UI handles it (issue #99). The plaintext key exists only in the answer of
// POST /{team}/cicd/integration (create) and POST /{team}/cicd/integration/{id}/api-key/rotate; it is shown once in
// ApiKeyRevealDialog and never stored client-side. Read routes give only its state and last four characters.
// The snippets name the secret the key goes into; none of them contains the key.

import { CI_SECRET_NAME, bambooScript, githubActionsWorkflow, gitlabCi, jenkinsfile } from "./ciTemplates";

export { CI_SECRET_NAME };

export const KEY_ONCE_NOTE =
  "Copy this key now and store it in your CI system's secret store. You won't see it again: DevSecShield keeps " +
  "only a hash of it. If you lose it, rotate the key to get a new one.";

export type ApiKeyState = "active" | "revoked";

export interface ApiKeyView {
  api_key_state?: ApiKeyState | null;
  api_key_hint?: string | null;
  api_key_issued_at?: string | null;
  api_key_issued_by?: string | null;
}

/** One line describing the stored key, without the key: "Active, ends in 1a2b" / "Revoked". */
export function keyStateLabel(view: ApiKeyView | null | undefined): string {
  if (!view || !view.api_key_state) return "Unknown";
  if (view.api_key_state === "revoked") return "Revoked";
  return view.api_key_hint ? `Active, ends in ${view.api_key_hint}` : "Active";
}

export interface CiSnippet {
  id: "github-actions" | "gitlab" | "jenkins" | "bamboo";
  label: string;
  file: string; // where the snippet goes
  secretHelp: string; // where the key goes
  text: string;
}

/** Ready-to-paste files of the CI templates the product ships, for a SAST / CBOM / AI-BOM integration. A DAST
 * integration has its own Jenkins guide (JenkinsDastGuide) and no zip-upload snippets: []. */
export function ciSnippets(scanType: string, endpoint: string, branch = "main"): CiSnippet[] {
  const kind = (scanType || "sast").toLowerCase();
  if (kind === "dast") return [];
  return [
    {
      id: "github-actions",
      label: "GitHub Actions",
      file: `.github/workflows/${kind}-check.yml`,
      secretHelp: `Repository Settings > Secrets and variables > Actions > New repository secret, name ${CI_SECRET_NAME}`,
      text: githubActionsWorkflow({ kind, endpoint, branch }),
    },
    {
      id: "gitlab",
      label: "GitLab CI",
      file: ".gitlab-ci.yml",
      secretHelp: `Settings > CI/CD > Variables > Add variable, key ${CI_SECRET_NAME}, masked`,
      text: gitlabCi({ kind, endpoint, branch }),
    },
    {
      id: "jenkins",
      label: "Jenkins",
      file: "Jenkinsfile",
      secretHelp: `Manage Jenkins > Credentials > Add Credentials, kind "Secret text", ID ${CI_SECRET_NAME}`,
      text: jenkinsfile({ kind, endpoint }),
    },
    {
      id: "bamboo",
      label: "Atlassian Bamboo",
      file: "Script task (/bin/sh)",
      secretHelp: "Plan configuration > Variables, name cicd_api_key, set as a secure (masked) variable",
      text: bambooScript({ kind, endpoint }),
    },
  ];
}

/** The answer of create and rotate that carries the one-time key. */
export interface IssuedApiKey {
  integration_id: number;
  api_key: string;
  warning?: string;
  api_key_state?: ApiKeyState;
  api_key_hint?: string;
}

/** True when an answer carries a usable one-time key (guards the reveal dialog against an older backend). */
export function hasIssuedKey(data: unknown): boolean {
  if (!data || typeof data !== "object") return false;
  const key = (data as { api_key?: unknown }).api_key;
  return typeof key === "string" && key.length > 20 && !key.includes("…") && !key.includes("...");
}
