"use client";

/**
 * TEMP verify route for PQC vulnerable-list UX — delete after verification.
 * Renders CbomCryptoCharts with fixture + #79-sized migration payloads.
 */
import { useMemo, useState } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { makeQueryClient } from "@/utils/query_client"
import {
  CbomCryptoCharts,
  type CbomDistributions,
} from "@/components/cbom/CbomCryptoCharts";
import type { CbomFinding } from "@/utils/backend_api";
import payload from "./payload.json";

const queryClient = makeQueryClient();

function Inner() {
  const [mode, setMode] = useState<"fixture" | "scan79">("scan79");
  const [opened, setOpened] = useState<string | null>(null);
  const distributions = useMemo(() => {
    const src =
      mode === "fixture"
        ? (payload as { fixture: { distributions: CbomDistributions } }).fixture
            .distributions
        : (payload as { scan79: { distributions: CbomDistributions } }).scan79
            .distributions;
    return src;
  }, [mode]);

  const findings: CbomFinding[] = useMemo(() => {
    const mig = distributions?.pqc?.migration ?? [];
    // Simulate live findings for legacy scan79 rows (no location/bom_ref on
    // migration[]): quantum_safe=false + per-instance paths so enrich join fills
    // HoverCard Location the same way CbomResults does for pre-enrichment scans.
    return mig.map((r, i) => {
      const loc =
        (r.location || "").trim() ||
        `src/crypto/${String(r.name).toLowerCase().replace(/[^a-z0-9]+/g, "_")}_${i}.py`;
      const ref =
        (r.bom_ref || "").trim() ||
        `crypto-algo-${String(r.name).toLowerCase().replace(/[^a-z0-9]+/g, "-")}-${i}`;
      return {
        id: `f-${i}`,
        bom_ref: ref,
        title: r.name,
        description:
          r.description ||
          `Quantum-vulnerable algorithm ${r.name} (NIST level ${r.nist_quantum_security_level ?? 0}).`,
        impact: r.impact || "Medium",
        risk_score: 5,
        status: "open",
        compliance_controls: [],
        owasp_top_10: [],
        suggested_fix:
          r.suggested_fix ||
          (r.migration_roadmap
            ? `Migrate to ${r.migration_roadmap}`
            : r.migration_target
              ? `Plan migration to ${r.migration_target}`
              : null),
        algorithm_name: r.name,
        location: loc,
        quantum_safe: false,
        quantum_vulnerable: true,
      } as CbomFinding;
    });
  }, [distributions]);

  const stats = (payload as { stats: Record<string, number> }).stats;

  return (
    <div className="min-h-screen bg-white p-6 dark:bg-zinc-950">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <h1 className="text-lg font-semibold">PQC vulnerable-list UX verify</h1>
        <button
          type="button"
          data-testid="mode-fixture"
          className="rounded border px-2 py-1 text-sm"
          onClick={() => setMode("fixture")}
        >
          Fixture
        </button>
        <button
          type="button"
          data-testid="mode-scan79"
          className="rounded border px-2 py-1 text-sm"
          onClick={() => setMode("scan79")}
        >
          Scan79-sized
        </button>
        <span data-testid="pqc-stats" className="text-xs text-zinc-500">
          before={stats.before_flat} after_groups={stats.after_groups} mode={mode}
        </span>
        {opened && (
          <span data-testid="opened-finding" className="text-xs text-emerald-600">
            opened:{opened}
          </span>
        )}
      </div>
      <CbomCryptoCharts
        distributions={distributions}
        findings={findings}
        onOpenFinding={(f) =>
          setOpened(String(f.bom_ref || f.algorithm_name || f.id))
        }
      />
    </div>
  );
}

export default function PqcVulnVerifyPage() {
  return (
    <QueryClientProvider client={queryClient}>
      <Inner />
    </QueryClientProvider>
  );
}
