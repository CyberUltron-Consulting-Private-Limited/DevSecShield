"use client";

// Repositories (F3): import code repositories at the organisation / group / workspace level, keep the inventory,
// scan groups of them with policies (schedule, push), run bulk scans at a price shown first, and see findings
// de-duplicated across repositories.

import { useQuery, useQueryClient } from "@tanstack/react-query";
import { FolderGit2, RefreshCcw } from "lucide-react";
import { useParams, usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useState } from "react";

import { ErrorBlock, LoadingBlock } from "@/components/cbom/sources/shared";
import ConnectionsTab from "@/components/repositories/ConnectionsTab";
import FindingsTab from "@/components/repositories/FindingsTab";
import ImportWizard from "@/components/repositories/ImportWizard";
import InventoryTab from "@/components/repositories/InventoryTab";
import { scmKeys } from "@/components/repositories/keys";
import PoliciesTab from "@/components/repositories/PoliciesTab";
import RunsTab from "@/components/repositories/RunsTab";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { listScmConnections } from "@/utils/api/scm";
import { getTeam } from "@/utils/backend_api";

const TABS = [
  { value: "inventory", label: "Inventory" },
  { value: "connections", label: "Connections" },
  { value: "policies", label: "Policies" },
  { value: "runs", label: "Runs & queue" },
  { value: "findings", label: "Findings roll-up" },
] as const;
type TabValue = (typeof TABS)[number]["value"];

function RepositoriesPage() {
  const params = useParams();
  const router = useRouter();
  const pathname = usePathname();
  const search = useSearchParams();
  const qc = useQueryClient();
  const teamId = Number(params?.team_id);
  const requested = search.get("tab");
  const tab: TabValue = (TABS.find((t) => t.value === requested)?.value ?? "inventory") as TabValue;
  const [wizard, setWizard] = useState(0);
  const team = useQuery({ queryKey: scmKeys.team(teamId), queryFn: () => getTeam(teamId), enabled: teamId > 0 });
  const connections = useQuery({
    queryKey: scmKeys.connections(teamId),
    queryFn: () => listScmConnections(teamId),
    enabled: teamId > 0,
    refetchInterval: (q) => (q.state.data?.connections.some((c) => ["running", "queued"].includes(c.sync.status)) ? 4000 : 30000),
  });
  const isAdmin = Boolean(team.data?.is_team_admin);
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
  const list = connections.data?.connections ?? [];

  return (
    <div className="flex min-h-screen bg-white dark:bg-zinc-900">
      <div className="flex-1 min-w-0 p-4 sm:p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          <div className="flex flex-wrap items-start justify-between gap-4 mb-6">
            <div className="min-w-0">
              <h1 className="text-3xl font-bold text-zinc-900 dark:text-white mb-2 flex items-center gap-2">
                <FolderGit2 className="h-7 w-7 text-blue-600" />Repositories
              </h1>
              <p className="text-zinc-600 dark:text-zinc-400 max-w-3xl">
                Connect a GitHub organisation, GitLab group or Bitbucket workspace once: every repository is discovered,
                filters decide which are in scope, and policies scan them on a schedule or on every push. Each run shows its
                price before it starts. {isAdmin ? "" : "Only team admins can connect, change policies or start runs."}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {isAdmin && (
                <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => setWizard((n) => n + 1)}>
                  Import repositories
                </Button>
              )}
              <Button variant="outline" className="cursor-pointer" onClick={() => qc.invalidateQueries({ queryKey: scmKeys.all(teamId) })}>
                <RefreshCcw className="h-4 w-4 mr-2" />Refresh
              </Button>
            </div>
          </div>

          {connections.isLoading ? <LoadingBlock /> : connections.isError ? (
            <ErrorBlock error={connections.error} onRetry={() => connections.refetch()} />
          ) : (
            <Tabs value={tab} onValueChange={goTo} className="w-full">
              <TabsList className="mb-4 flex h-auto w-full flex-wrap justify-start gap-1">
                {TABS.map((t) => (
                  <TabsTrigger key={t.value} value={t.value} className="cursor-pointer">{t.label}</TabsTrigger>
                ))}
              </TabsList>
              <TabsContent value="inventory">
                <InventoryTab teamId={teamId} isAdmin={isAdmin} connections={list} onImport={() => setWizard((n) => n + 1)} />
              </TabsContent>
              <TabsContent value="connections">
                <ConnectionsTab teamId={teamId} isAdmin={isAdmin} connections={list} />
              </TabsContent>
              <TabsContent value="policies">
                <PoliciesTab teamId={teamId} isAdmin={isAdmin} />
              </TabsContent>
              <TabsContent value="runs">
                <RunsTab teamId={teamId} isAdmin={isAdmin} />
              </TabsContent>
              <TabsContent value="findings">
                <FindingsTab teamId={teamId} />
              </TabsContent>
            </Tabs>
          )}
          {wizard > 0 && (
            // a fresh wizard each time it is opened (key), so a closed import never leaves stale steps behind
            <ImportWizard key={wizard} teamId={teamId} open onOpenChange={(v) => !v && setWizard(0)} />
          )}
        </div>
      </div>
    </div>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<LoadingBlock />}>
      <RepositoriesPage />
    </Suspense>
  );
}
