"use client";

/**
 * @deprecated Guardrails product UI is removed from user-facing surfaces.
 * Soft deprecation notice only — full prior UI lives in
 * `@/components/deprecated/DeprecatedGuardrailsPage`.
 */
import { GuardrailsDeprecatedNotice } from "@/components/GuardrailsDeprecatedNotice";

export default function GuardrailsPage() {
  return <GuardrailsDeprecatedNotice />;
}
