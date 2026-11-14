"use client";

import Link from "next/link";
import { useParams, usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Loader2, RefreshCcw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { cbomSourcesKeys } from "@/components/cbom/sources/keys";
import ScanNodesTab from "@/components/cbom/sources/ScanNodesTab";
import ServersTab from "@/components/cbom/sources/ServersTab";
import ClustersDatabasesTab from "@/components/cbom/sources/ClustersDatabasesTab";
import CloudIdentityTab from "@/components/cbom/sources/CloudIdentityTab";
import NetworkTab from "@/components/cbom/sources/NetworkTab";
import EvidenceTab from "@/components/cbom/sources/EvidenceTab";
import ReviewRunTab from "@/components/cbom/sources/ReviewRunTab";
import CmdbImportDialog from "@/components/cbom/sources/CmdbImportDialog";
import FleetTab, { useFleetStatus } from "@/components/cbom/sources/fleet/FleetTab";
import { fleetTabMode, fleetTabShown, pickTab } from "@/components/cbom/sources/fleet/fleetLogic";
import { FLEET_SECTIONS } from "@/components/cbom/sources/fleet/sections";

const TABS = [
  { value: "scan-nodes", label: "Scan nodes" },
  { value: "servers", label: "Servers" },
  { value: "k8s-db", label: "Kubernetes & Databases" },
  { value: "cloud", label: "Cloud & Identity" },
  { value: "network", label: "Network TLS" },
  { value: "evidence", label: "Evidence" },
  { value: "fleet", label: "Fleet" },
  { value: "review", label: "Review & Run" },
] as const;
type TabValue = (typeof TABS)[number]["value"];

function SourcesPage() {
  const params = useParams();
  const router = useRouter();
  const pathname = usePathname();
  const search = useSearchParams();
  const queryClient = useQueryClient();
  const teamId = Number(params?.team_id);
  const requested = search.get("tab");
  // Fleet shows when a section of this build has its flag on (GET /fleet/status). While the status is not known yet,
  // a deep link to ?tab=fleet stays on Fleet (its loading or error block) instead of opening another tab first.
  const fleetMode = fleetTabMode(useFleetStatus(teamId), FLEET_SECTIONS);
  const showFleet = fleetTabShown(fleetMode, requested);
  const shown = (value: TabValue) => value !== "fleet" || showFleet;
  const tab: TabValue = pickTab(requested, TABS.map((t) => t.value), shown);

  const goTo = useCallback(
    (value: string) => {
      const next = new URLSearchParams(search.toString());
      next.set("tab", value);
      router.push(`${pathname}?${next.toString()}`, { scroll: false });
    },
    [pathname, router, search],
  );

  if (!Number.isFinite(teamId) || teamId <= 0) {
    return <div className="p-8 text-zinc-600 dark:text-zinc-400">Team not found.</div>;
  }

  return (
    <div className="flex min-h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 min-w-0 p-4 sm:p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
            <div className="min-w-0">
              <Link
                href={`/${teamId}/cbom`}
                className="inline-flex items-center gap-1.5 text-sm text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white mb-2"
              >
                <ArrowLeft className="h-4 w-4" />
                CBOM scans
              </Link>
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2">CBOM Sources</h1>
              <p className="text-zinc-600 dark:text-zinc-400 max-w-3xl">
                Connect the servers, clusters, cloud accounts and networks a CBOM scan should cover. Collection is read-only, and nothing is installed on the servers it reads unless you deploy host agents.
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <CmdbImportDialog teamId={teamId} />
              <Button
                className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                onClick={() => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) })}
              >
                <RefreshCcw className="h-4 w-4 mr-2" />
                Refresh
              </Button>
            </div>
          </div>

          <Tabs value={tab} onValueChange={goTo} className="w-full">
            <div className="overflow-x-auto -mx-1 px-1">
              <TabsList className="mb-4 bg-transparent h-auto flex-wrap justify-start gap-1">
                {TABS.filter((t) => shown(t.value)).map((t) => (
                  <TabsTrigger
                    key={t.value}
                    value={t.value}
                    className="cursor-pointer flex-none data-[state=active]:bg-blue-600 data-[state=active]:text-white"
                  >
                    {t.label}
                  </TabsTrigger>
                ))}
              </TabsList>
            </div>
            {/* Scan nodes, Network and Evidence stay mounted: one-time tokens, links, unsaved scope edits and discovery jobs survive a tab switch. */}
            <TabsContent value="scan-nodes" forceMount className="data-[state=inactive]:hidden">
              <ScanNodesTab teamId={teamId} onNavigate={goTo} />
            </TabsContent>
            <TabsContent value="servers">
              <ServersTab teamId={teamId} onNavigate={goTo} />
            </TabsContent>
            <TabsContent value="k8s-db">
              <ClustersDatabasesTab teamId={teamId} onNavigate={goTo} />
            </TabsContent>
            <TabsContent value="cloud">
              <CloudIdentityTab teamId={teamId} onNavigate={goTo} />
            </TabsContent>
            <TabsContent value="network" forceMount className="data-[state=inactive]:hidden">
              <NetworkTab teamId={teamId} onNavigate={goTo} />
            </TabsContent>
            <TabsContent value="evidence" forceMount className="data-[state=inactive]:hidden">
              <EvidenceTab teamId={teamId} onNavigate={goTo} />
            </TabsContent>
            {showFleet && (
              <TabsContent value="fleet">
                <FleetTab teamId={teamId} onNavigate={goTo} />
              </TabsContent>
            )}
            <TabsContent value="review">
              <ReviewRunTab teamId={teamId} onNavigate={goTo} />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
}

export default function Page() {
  return (
    <Suspense
      fallback={
        <div className="flex h-screen w-full items-center justify-center">
          <Loader2 className="size-10 animate-spin text-blue-600" />
        </div>
      }
    >
      <SourcesPage />
    </Suspense>
  );
}
