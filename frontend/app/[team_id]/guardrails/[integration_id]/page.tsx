"use client";

/**
 * @deprecated Guardrails product UI is removed from user-facing surfaces.
 * Soft deprecation notice only — full prior UI lives in
 * `@/components/deprecated/DeprecatedGuardrailsIntegrationPage`.
 */
import { GuardrailsDeprecatedNotice } from "@/components/GuardrailsDeprecatedNotice";

export default function GuardrailsIntegrationDashboardPage() {
  return <GuardrailsDeprecatedNotice />;
}
