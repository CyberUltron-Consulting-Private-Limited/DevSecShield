"use client";

// "Cancel scan" on a pending or running code scan, and the panel a cancelled scan shows (utils/scanCancel.ts).

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Ban, Loader2 } from "lucide-react";
import { useState } from "react";
import { toast } from "@/utils/toast";

import { RunAgainButton } from "@/components/scan-run-again";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { cancelScan } from "@/utils/backend_api";
import { isCreditBalanceQuery, refreshCreditBalance } from "@/utils/creditBalance";
import { showErrorToast } from "@/utils/error-handler";
import { cancelConfirmText, cancelledSummary, canCancel, isAlreadyCancelled } from "@/utils/scanCancel";
import type { CodeScanType } from "@/utils/scanRerun";

export function CancelScanButton({ type, teamId, scanId, scan }: {
  type: CodeScanType; teamId: number; scanId: number; scan: unknown;
}) {
  const [open, setOpen] = useState(false);
  const queryClient = useQueryClient();
  const status = (scan as { scan_status?: unknown } | null)?.scan_status;
  const cancel = useMutation({
    mutationFn: () => cancelScan(teamId, type, scanId),
    onSuccess: (data) => {
      toast.success(data.message);
      setOpen(false);
    },
    onError: (err) => {
      setOpen(false);
      if (!isAlreadyCancelled(err)) showErrorToast(err, "Could not cancel the scan");
    },
    onSettled: () => {
      // the refund changes the credit balance in the app sidebar (#13)
      refreshCreditBalance(queryClient);
      // every other query of this page (sidebar, results, lists) reads the new status; the balance is left out
      // here, or GET /teams would be sent twice
      queryClient.invalidateQueries({ predicate: (query) => !isCreditBalanceQuery(query) });
    },
  });
  if (!canCancel(status)) return null;
  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        onClick={() => setOpen(true)}
        disabled={cancel.isPending}
        data-testid="scan-cancel"
        className="w-full h-8 px-2 bg-zinc-700 hover:bg-red-700 text-white cursor-pointer hover:text-white disabled:opacity-50"
      >
        {cancel.isPending ? <Loader2 className="size-4 mr-2 animate-spin" /> : <Ban className="size-4 mr-2" />}
        <span>Cancel scan</span>
      </Button>
      <Dialog open={open} onOpenChange={(next) => !cancel.isPending && setOpen(next)}>
        <DialogContent data-testid="scan-cancel-dialog">
          <DialogHeader>
            <DialogTitle>Cancel this scan?</DialogTitle>
            <DialogDescription>{cancelConfirmText(scan)}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setOpen(false)} disabled={cancel.isPending}>Keep scanning</Button>
            <Button
              onClick={() => cancel.mutate()}
              disabled={cancel.isPending}
              data-testid="scan-cancel-confirm"
              className="bg-red-600 hover:bg-red-700 text-white"
            >
              {cancel.isPending ? <Loader2 className="size-4 mr-2 animate-spin" /> : null}
              Cancel scan
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** What a cancelled scan shows in its sidebar: the refund, and Run again. */
export function CancelledScanPanel({ type, teamId, scan }: { type: CodeScanType; teamId: number; scan: unknown }) {
  return (
    <div className="p-6 flex flex-col items-center justify-center min-h-[200px] space-y-4" data-testid="scan-cancelled">
      <p className="text-zinc-300 text-center" role="status">{cancelledSummary(scan)}</p>
      <RunAgainButton type={type} teamId={teamId} scan={scan} />
    </div>
  );
}
