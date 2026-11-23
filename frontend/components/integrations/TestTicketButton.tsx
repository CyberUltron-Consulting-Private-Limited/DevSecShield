"use client";

// "Raise test ticket" (SOW S2 evidence: a test ticket raised successfully) for Jira and ServiceNow. Each click sends a
// fresh click id; the server raises at most one ticket per click id (a repeated request answers with the same ticket),
// and the button stays disabled while a click is in flight, so a double click cannot raise two tickets.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Loader2, Ticket } from "lucide-react";
import { useRef } from "react";

import { Button } from "@/components/ui/button";
import { InfoTip } from "@/components/ui/info-tip";
import { integrationKeys, newClickId, raiseTestTicket, type TestTicket, type TicketingKind } from "@/utils/api/integrations";
import { showErrorToast } from "@/utils/error-handler";
import { toast } from "@/utils/toast";

export function TestTicketLink({ ticket }: { ticket: TestTicket | null | undefined }) {
  if (!ticket || ticket.status !== "created" || !ticket.ticket_key) return null;
  return (
    <p className="text-xs text-zinc-500" data-testid={`test-ticket-${ticket.kind}`}>
      Last test ticket {ticket.at ? `(${new Date(ticket.at).toLocaleString()})` : ""}:{" "}
      {ticket.ticket_url ? (
        <a href={ticket.ticket_url} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-blue-600 dark:text-blue-400 hover:underline">
          {ticket.ticket_key}<ExternalLink className="h-3 w-3" />
        </a>
      ) : <span className="font-mono">{ticket.ticket_key}</span>}
    </p>
  );
}

export default function TestTicketButton({ teamId, kind, disabled, title }: {
  teamId: number;
  kind: TicketingKind;
  disabled?: boolean;
  title?: string;
}) {
  const queryClient = useQueryClient();
  const clickId = useRef<string | null>(null);
  const raise = useMutation({
    mutationFn: () => raiseTestTicket(teamId, kind, clickId.current ?? newClickId()),
    onSuccess: (r) => {
      if (r.ok && r.ticket_key) toast.success(`${r.repeated ? "Already raised" : "Test ticket raised"}: ${r.ticket_key}`);
      else toast.error(`Test ticket not raised: ${r.message ?? r.status}`);
      queryClient.invalidateQueries({ queryKey: integrationKeys.all(teamId) });
    },
    onError: (e) => showErrorToast(e),
    onSettled: () => { clickId.current = null; },
  });
  return (
    <span className="inline-flex items-center gap-1">
      <Button variant="outline" className="cursor-pointer" disabled={disabled || raise.isPending} title={title}
              data-testid={`int-${kind}-test-ticket`}
              onClick={() => { clickId.current = newClickId(); raise.mutate(); }}>
        {raise.isPending ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Ticket className="h-4 w-4 mr-1.5" />}
        Raise test ticket
      </Button>
      <InfoTip id="int.test_ticket" />
    </span>
  );
}
