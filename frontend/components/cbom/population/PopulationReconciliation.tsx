"use client";
// The population reconciliation (SOW audit A-09, staging QA2 M4): the same block the D1, D12, D13 and D14 PDFs print,
// built by the backend (backend/utilities/cbom_sources/reconciliation.py). Rule P: the steps are rendered as served;
// the browser never adds or subtracts a count.
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export interface PopulationStep {
  key: string;
  value: number;
  text: string;
}

export interface PopulationBlock {
  title: string;
  steps: PopulationStep[];
}

/** The steps to show, or null when the API sent no block (an older backend, or the block failed to build). */
export function populationSteps(block: PopulationBlock | null | undefined): PopulationStep[] | null {
  if (!block || !Array.isArray(block.steps) || block.steps.length === 0) return null;
  return block.steps.filter((s) => s && typeof s.text === "string" && s.text.trim() !== "");
}

export default function PopulationReconciliation({ block }: { block: PopulationBlock | null | undefined }) {
  const steps = populationSteps(block);
  if (!steps || steps.length === 0) return null;
  return (
    <Card className="border-zinc-200 dark:border-zinc-800" data-testid="cbom-population-reconciliation">
      <CardHeader className="pb-2">
        <CardTitle className="text-base">{block?.title || "Population reconciliation"}</CardTitle>
        <CardDescription>
          How the Crypto Assets card, the deliverables and the Quantum risk register count the same estate. The
          deliverables print the same steps.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ol className="space-y-1.5 text-sm text-zinc-700 dark:text-zinc-300 break-words">
          {steps.map((s) => (
            <li key={s.key} data-step={s.key}>{s.text}</li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}
