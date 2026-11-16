"use client";

// 10-A (run results redesign): a run's certificates and key material as one tabbed card. "Expiry list": the crypto
// charts' Certificate expiry card (X.509 validity, then key / keystore material, with its empty texts). "Calendar": the
// run's expiry calendar (GET …/heatmap certificates, the query RunInsights makes, so one request serves both), with the
// "N certificates with an expiry date" line or the empty text. "Orphaned and unmanaged": RunCertificatesSection with
// its note and lists. Each tab keeps its loading, error-with-retry and not-available states.
// B1 mounts it in the inventory view; mount RunInsights there with calendar={false} so the calendar is not shown twice.

import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { CbomCertificateExpiry, type CbomDistributions } from "@/components/cbom/CbomCryptoCharts";
import CertCalendar from "@/components/cbom/CertCalendar";
import { pluralize } from "@/components/cbom/sources/logic";
import { ErrorBlock, LoadingBlock } from "@/components/cbom/sources/shared";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { InfoTip } from "@/components/ui/info-tip";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cbomOpsKeys, getCbomRunHeatmap } from "@/utils/api/cbom_ops";
import type { CbomGraph, CbomRunResults } from "@/utils/backend_api";

import type { SectionView } from "../model";
import { RunCertificatesSection, SectionNote } from "../RunSections";

export type CertificatesTab = "expiry" | "calendar" | "orphaned";

/** The run's expiry calendar: the same query (and cache entry) as RunInsights' default view. */
export function RunCertCalendar({ teamId, runId, active }: { teamId: number; runId: number; active: boolean }) {
  const q = useQuery({
    queryKey: cbomOpsKeys.heatmap(teamId, runId, "source", "impact"),
    queryFn: () => getCbomRunHeatmap(teamId, runId, "source", "impact"),
    retry: 1,
    refetchInterval: active ? 20000 : false,
  });
  if (q.isLoading) return <LoadingBlock />;
  if (q.isError || !q.data) return <ErrorBlock error={q.error} onRetry={() => q.refetch()} />;
  const certs = q.data.certificates ?? [];
  return (
    <div className="min-w-0" data-testid="run-cert-calendar-tab">
      {certs.length > 0 ? (
        <CertCalendar certs={certs} testId="run-cert-calendar" />
      ) : (
        <p className="text-xs text-zinc-500 dark:text-zinc-400">No certificates with an expiry date in this run.</p>
      )}
      {certs.length > 0 && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">{pluralize(certs.length, "certificate")} with an expiry date.</p>
      )}
    </div>
  );
}

// the nested cards (Certificate expiry) sit flat inside the tab
const FLAT = "min-w-0 [&>[data-slot=card]]:border-0 [&>[data-slot=card]]:shadow-none [&>[data-slot=card]]:py-0 " +
  "[&>[data-slot=card]>[data-slot=card-header]]:px-0 [&>[data-slot=card]>[data-slot=card-content]]:px-0";

export function CertificatesCard({ teamId, runId, active, distributions, graph, chartsView, certificatesView, results, onOpenAsset,
  defaultTab = "expiry" }: {
  teamId: number;
  runId: number;
  active: boolean;
  /** /results distributions (certificates, key_material); null while missing */
  distributions: CbomDistributions | null | undefined;
  graph?: CbomGraph | null;
  /** run.plan.cryptoCharts: pending (show: false) or why the distributions are missing (note) */
  chartsView: SectionView;
  /** run.plan.certificates */
  certificatesView: SectionView;
  results: CbomRunResults | null;
  onOpenAsset: (id: number) => void;
  defaultTab?: CertificatesTab;
}) {
  const [tab, setTab] = useState<CertificatesTab>(defaultTab);
  const trigger = "cursor-pointer";
  return (
    <Card className="border-zinc-200 dark:border-zinc-800 min-w-0" data-testid="run-certificates-card">
      <CardHeader>
        <CardTitle className="text-base">Certificates, keys and expiry <InfoTip id="cbom.run.certificates" /></CardTitle>
        <CardDescription>X.509 validity and key material, the expiry calendar, and the certificates nobody presents or manages</CardDescription>
      </CardHeader>
      <CardContent className="min-w-0">
        <Tabs value={tab} onValueChange={(v) => setTab(v as CertificatesTab)}>
          <div className="overflow-x-auto">
            <TabsList className="w-max" aria-label="Certificates views">
              <TabsTrigger value="expiry" className={trigger} data-testid="run-certificates-tab-expiry">Expiry list</TabsTrigger>
              <TabsTrigger value="calendar" className={trigger} data-testid="run-certificates-tab-calendar">Calendar</TabsTrigger>
              <TabsTrigger value="orphaned" className={trigger} data-testid="run-certificates-tab-orphaned">Orphaned and unmanaged</TabsTrigger>
            </TabsList>
          </div>
          <TabsContent value="expiry" className="mt-4">
            {!chartsView.show ? <LoadingBlock /> : distributions ? (
              <div className={FLAT}><CbomCertificateExpiry distributions={distributions} graph={graph} findings={[]} /></div>
            ) : (
              <SectionNote testId="run-certificates-expiry-note">{chartsView.note ?? "This run's results carry no certificate data."}</SectionNote>
            )}
          </TabsContent>
          <TabsContent value="calendar" className="mt-4">
            <RunCertCalendar teamId={teamId} runId={runId} active={active} />
          </TabsContent>
          <TabsContent value="orphaned" className="mt-4">
            {certificatesView.show
              ? <RunCertificatesSection bare view={certificatesView} results={results} onOpenAsset={onOpenAsset} />
              : <LoadingBlock />}
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
