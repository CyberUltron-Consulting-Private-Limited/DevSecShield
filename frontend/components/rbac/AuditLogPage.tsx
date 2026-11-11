"use client";

/**
 * F4 RBAC: the team's audit log (admins and owners). Who did what, to which object, from which address, when;
 * newest first, 50 at a time, filtered by outcome or by person. Read only: the log is append-only on the server.
 */
import Link from "next/link";
import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { ArrowLeft, Loader2, ShieldAlert, ShieldCheck } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { useTeamAccess } from "@/components/rbac/team-access";
import { getTeamAudit, type AuditEventItem } from "@/utils/api/rbac";
import { auditActionLabel, auditDetailText, auditObjectText } from "@/utils/auditLog";
import { formatDateIst } from "@/utils/datetime";
import { handleApiError } from "@/utils/error-handler";

export default function AuditLogPage({ teamId }: { teamId: number }) {
  const { can, loading } = useTeamAccess();
  const [outcome, setOutcome] = useState<"all" | "success" | "denied">("all");
  const [actor, setActor] = useState("");
  const [actorFilter, setActorFilter] = useState("");
  const allowed = can("team.audit.read");

  const query = useInfiniteQuery({
    queryKey: ["team-audit", teamId, outcome, actorFilter],
    queryFn: ({ pageParam }) =>
      getTeamAudit(teamId, {
        limit: 50,
        before_id: pageParam ?? null,
        outcome: outcome === "all" ? "" : outcome,
        actor_email: actorFilter || undefined,
      }),
    initialPageParam: null as number | null,
    getNextPageParam: (last) => last.next_before_id,
    enabled: allowed && !loading,
    retry: false,
  });

  const events: AuditEventItem[] = query.data?.pages.flatMap((p) => p.events) ?? [];
  const error = query.error ? handleApiError(query.error).message : null;

  return (
    <div className="flex flex-col h-full min-h-[calc(100vh-2rem)] bg-neutral-900">
      <header className="px-6 py-4 border-b border-border">
        <Link href={`/${teamId}/settings`} className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Settings
        </Link>
        <h1 className="text-xl font-semibold mt-2">Audit log</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Every change in this team and every refused attempt: who, what, which object, from which address, when.
          Entries can never be edited or deleted.
        </p>
      </header>

      <main className="flex-1 p-6 overflow-auto space-y-4">
        {!loading && !allowed ? (
          <p className="text-sm text-muted-foreground" data-testid="audit-not-allowed">
            Only team admins and owners can read the audit log.
          </p>
        ) : (
          <>
            <form
              className="flex flex-wrap items-end gap-3"
              onSubmit={(e) => {
                e.preventDefault();
                setActorFilter(actor.trim().toLowerCase());
              }}
            >
              <div className="space-y-1">
                <Label htmlFor="audit-outcome">Outcome</Label>
                <Select value={outcome} onValueChange={(v) => setOutcome(v as typeof outcome)}>
                  <SelectTrigger id="audit-outcome" className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All</SelectItem>
                    <SelectItem value="success">Done</SelectItem>
                    <SelectItem value="denied">Refused</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1 flex-1 min-w-[200px] max-w-sm">
                <Label htmlFor="audit-actor">Person (email)</Label>
                <Input id="audit-actor" type="email" value={actor} onChange={(e) => setActor(e.target.value)} placeholder="name@example.com" />
              </div>
              <Button type="submit" variant="outline" className="cursor-pointer">Filter</Button>
            </form>

            {error && (
              <p role="alert" className="text-sm text-red-400">{error}</p>
            )}

            {query.isLoading ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>
            ) : events.length === 0 && !error ? (
              <p className="text-sm text-muted-foreground" data-testid="audit-empty">No entries match.</p>
            ) : (
              <div className="overflow-x-auto">
                <Table data-testid="audit-table">
                  <TableHeader>
                    <TableRow>
                      <TableHead>When</TableHead>
                      <TableHead>Who</TableHead>
                      <TableHead>What</TableHead>
                      <TableHead>Object</TableHead>
                      <TableHead>From</TableHead>
                      <TableHead>Details</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {events.map((event) => (
                      <TableRow key={event.id} data-outcome={event.outcome}>
                        <TableCell className="whitespace-nowrap">{event.at ? formatDateIst(event.at) : "-"}</TableCell>
                        <TableCell className="break-all">{event.actor_email ?? event.actor_type}</TableCell>
                        <TableCell>
                          <span className="inline-flex items-center gap-1">
                            {event.outcome === "denied" ? (
                              <ShieldAlert className="h-4 w-4 text-red-400" aria-label="Refused" />
                            ) : (
                              <ShieldCheck className="h-4 w-4 text-emerald-400" aria-label="Done" />
                            )}
                            {auditActionLabel(event.action, event.outcome)}
                          </span>
                        </TableCell>
                        <TableCell className="break-all">{auditObjectText(event)}</TableCell>
                        <TableCell className="font-mono text-xs">{event.ip ?? "-"}</TableCell>
                        <TableCell className="text-xs text-muted-foreground break-all">{auditDetailText(event)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            )}

            {query.hasNextPage && (
              <Button variant="outline" className="cursor-pointer" disabled={query.isFetchingNextPage} onClick={() => query.fetchNextPage()}>
                {query.isFetchingNextPage && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                Older entries
              </Button>
            )}
          </>
        )}
      </main>
    </div>
  );
}
