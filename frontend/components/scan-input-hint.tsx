/**
 * Why "Estimate credits required" is disabled. The sidebars disable the button until their inputs are valid and
 * only toasted the reason when the button was clicked, which a disabled button never is: a customer saw a grey
 * button and nothing else (DAST: the required Authentication section is collapsed; SAST: no language selected).
 * Found on the local production stack, round 5.
 */
export type ScanInputValidation = { valid: true } | { valid: false; message: string };

export function ScanInputHint({ validation }: { validation: ScanInputValidation }) {
  if (validation.valid) return null;
  return (
    <p className="text-xs text-amber-400 mt-2" role="status" data-testid="scan-input-hint">
      {validation.message}
    </p>
  );
}
