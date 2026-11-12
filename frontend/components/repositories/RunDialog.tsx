"use client";

// Estimate first, then start: a bulk run shows what it scans, what it costs and the team's balance before anything
// is charged; the start sends the price the customer saw, so a changed price is a 409 that shows the new estimate.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Loader2, Play } from "lucide-react";
import { useMemo, useState } from "react";

import { refusalReason } from "@/components/cbom/sources/logic";
import { Checkbox2 } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { createScmRun, estimateScmRun, type ScmEstimate, type ScmProduct, type ScmRunBody } from "@/utils/api/scm";
import { toast } from "@/utils/toast";

import { scmKeys } from "./keys";
import { estimateSentence, formatCredits, newClientRequestId, PRODUCT_LABEL, PRODUCTS, runEstimateChangedOf, skippedSentence } from "./logic";

export default function RunDialog({ teamId, open, onOpenChange, target, title, chooseProducts }: {
  teamId: number;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  /** repo_ids or policy_id */
  target: Pick<ScmRunBody, "repo_ids" | "policy_id">;
  title: string;
  /** repositories chosen by hand: pick products here (a policy brings its own) */
  chooseProducts?: boolean;
}) {
  const qc = useQueryClient();
  const [products, setProducts] = useState<ScmProduct[]>(["sbom_sca"]);
  const [requestId] = useState(newClientRequestId);
  const [changed, setChanged] = useState<ScmEstimate | null>(null);
  const body: ScmRunBody = useMemo(
    () => ({ ...target, ...(chooseProducts ? { products } : {}) }),
    [target, chooseProducts, products],
  );
  const estimate = useQuery({
    queryKey: ["scm", teamId, "estimate", JSON.stringify(body)],
    queryFn: () => estimateScmRun(teamId, body),
    enabled: open && (!chooseProducts || products.length > 0),
    retry: false,
  });
  const start = useMutation({
    mutationFn: (credits: number) => createScmRun(teamId, { ...body, expected_credits: credits, client_request_id: requestId }),
    onSuccess: (data) => {
      toast.success(`Queued ${data.run.queued} scans for ${formatCredits(data.run.credits)}`);
      qc.invalidateQueries({ queryKey: scmKeys.all(teamId) });
      qc.invalidateQueries({ queryKey: ["teams"] });
      qc.invalidateQueries({ queryKey: scmKeys.team(teamId) });
      onOpenChange(false);
    },
    onError: (err) => {
      const moved = runEstimateChangedOf(err);
      if (moved) {
        setChanged(moved);
        estimate.refetch();
      }
    },
  });
  const est = estimate.data;
  const why = start.isError ? refusalReason(start.error) : null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            The price is worked out before anything is charged. Scans run a few at a time (a fair share per team) and
            appear on each product&apos;s scan list as they finish.
          </DialogDescription>
        </DialogHeader>
        {chooseProducts && (
          <div className="space-y-2">
            <p className="text-sm font-medium">Scan with</p>
            <div className="flex flex-wrap gap-x-5 gap-y-2">
              {PRODUCTS.map((p) => (
                <Checkbox2 key={p} id={`run-product-${p}`} checked={products.includes(p)}
                           onChange={(on) => setProducts((cur) => (on ? [...cur, p] : cur.filter((x) => x !== p)))}>
                  {PRODUCT_LABEL[p]}
                </Checkbox2>
              ))}
            </div>
            {products.length === 0 && <p className="text-sm text-red-500" role="alert">Choose at least one product.</p>}
          </div>
        )}
        <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 space-y-2 text-sm" aria-live="polite">
          {estimate.isFetching && !est && (
            <p className="flex items-center gap-2 text-zinc-600 dark:text-zinc-400"><Loader2 className="h-4 w-4 animate-spin" />Working out the price…</p>
          )}
          {estimate.isError && <p className="text-red-500" role="alert">{refusalReason(estimate.error) ?? "Could not work out the price. Try again."}</p>}
          {est && (
            <>
              <p className="text-zinc-900 dark:text-white" data-testid="run-estimate">{estimateSentence(est)}</p>
              {Object.entries(est.per_product).length > 0 && (
                <ul className="text-zinc-600 dark:text-zinc-400 list-disc pl-5">
                  {Object.entries(est.per_product).map(([p, v]) => (
                    <li key={p}>{PRODUCT_LABEL[p as ScmProduct] ?? p}: {v?.scans} scans, {formatCredits(v?.credits)}</li>
                  ))}
                </ul>
              )}
              {skippedSentence(est.skipped_counts) && <p className="text-zinc-600 dark:text-zinc-400">{skippedSentence(est.skipped_counts)}</p>}
              <p className="text-xs text-zinc-500">
                Priced from the size the provider reports for each repository ({est.formula}); queued scans that are
                cancelled or cannot run are refunded.
              </p>
            </>
          )}
          {changed && (
            <p className="flex items-start gap-2 text-amber-600 dark:text-amber-400" role="status">
              <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
              The price changed to {formatCredits(changed.credits)} because repositories or the queue changed. Nothing was
              charged; check the new price and start again.
            </p>
          )}
          {why && !changed && <p className="text-red-500" role="alert">{why}</p>}
        </div>
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            disabled={!est || !est.scans || !est.affordable || start.isPending || estimate.isFetching}
            onClick={() => est && (setChanged(null), start.mutate(est.credits))}
          >
            {start.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Play className="h-4 w-4 mr-2" />}
            {est ? `Start for ${formatCredits(est.credits)}` : "Start"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
