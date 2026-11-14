"use client";

// The integration page's API key block (issue #99): the key's state and last four characters (never the key), and,
// for the integration's owner or a team admin, "Issue new key" (rotate) and "Revoke key". A new key is shown once in
// ApiKeyRevealDialog.

import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { KeyRound, Loader2, RotateCw, ShieldOff } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { toast } from "@/utils/toast";
import { formatDateIst } from "@/utils/datetime";
import { revokeCicdApiKey, rotateCicdApiKey } from "@/utils/backend_api";
import ApiKeyRevealDialog from "@/components/cicd/ApiKeyRevealDialog";
import { type ApiKeyView, hasIssuedKey, keyStateLabel } from "@/components/cicd/apiKey";

interface ApiKeyPanelProps {
  teamId: number;
  integrationId: number;
  scanType: string;
  view: ApiKeyView & { can_manage_api_key?: boolean };
  onChanged: () => void; // refetch the integration
}

export default function ApiKeyPanel({ teamId, integrationId, scanType, view, onChanged }: ApiKeyPanelProps) {
  const [confirm, setConfirm] = useState<"rotate" | "revoke" | null>(null);
  const [issuedKey, setIssuedKey] = useState<string | null>(null);
  const revoked = view.api_key_state === "revoked";

  const rotate = useMutation({
    mutationFn: () => rotateCicdApiKey(teamId, integrationId),
    onSuccess: (data) => {
      setConfirm(null);
      if (hasIssuedKey(data)) setIssuedKey(data.api_key);
      onChanged();
    },
  });
  const revoke = useMutation({
    mutationFn: () => revokeCicdApiKey(teamId, integrationId),
    onSuccess: () => {
      setConfirm(null);
      toast.success("API key revoked. Pipelines using it are now refused.");
      onChanged();
    },
  });
  const busy = rotate.isPending || revoke.isPending;

  return (
    <div className="mt-4 flex flex-col gap-2" data-testid="cicd-key-panel">
      <div className="flex flex-wrap items-center gap-2">
        <KeyRound className="h-4 w-4 text-zinc-500" />
        <span className="text-sm font-medium text-zinc-600 dark:text-zinc-400">API key:</span>
        <Badge
          variant="outline"
          data-testid="cicd-key-state"
          className={revoked ? "border-red-300 text-red-700 dark:text-red-300" : "border-green-300 text-green-700 dark:text-green-300"}
        >
          {keyStateLabel(view)}
        </Badge>
        {!revoked && view.api_key_issued_at && (
          <span className="text-xs text-zinc-500">
            issued {formatDateIst(view.api_key_issued_at)}
            {view.api_key_issued_by ? ` by ${view.api_key_issued_by}` : ""}
          </span>
        )}
      </div>
      <p className="text-xs text-zinc-500 max-w-2xl">
        {revoked
          ? "Pipelines using the old key are refused. Issue a new key to use this integration again."
          : "The key is shown only once, when it is issued. If you no longer have it, issue a new key; the old one stops working."}
      </p>
      {view.can_manage_api_key ? (
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" size="sm" className="cursor-pointer" disabled={busy} onClick={() => setConfirm("rotate")}
            data-testid="cicd-key-rotate">
            <RotateCw className="h-4 w-4 mr-2" />{revoked ? "Issue new key" : "Rotate key"}
          </Button>
          {!revoked && (
            <Button variant="outline" size="sm" className="cursor-pointer text-red-700 dark:text-red-300" disabled={busy}
              onClick={() => setConfirm("revoke")} data-testid="cicd-key-revoke">
              <ShieldOff className="h-4 w-4 mr-2" />Revoke key
            </Button>
          )}
        </div>
      ) : (
        <p className="text-xs text-zinc-500">Only the integration&apos;s owner or a team admin can rotate or revoke its key.</p>
      )}

      <Dialog open={confirm !== null} onOpenChange={(open) => { if (!open && !busy) setConfirm(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{confirm === "revoke" ? "Revoke the API key?" : revoked ? "Issue a new API key?" : "Rotate the API key?"}</DialogTitle>
            <DialogDescription>
              {confirm === "revoke"
                ? "Every pipeline using this key is refused from now on. The integration and its scan history stay; you can issue a new key later."
                : revoked
                  ? "A new key is issued and shown once."
                  : "A new key is issued and shown once. The current key stops working immediately: update the secret in every pipeline that uses it."}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" disabled={busy} onClick={() => setConfirm(null)}>Cancel</Button>
            <Button
              className={confirm === "revoke" ? "cursor-pointer bg-red-600 hover:bg-red-700 text-white" : "cursor-pointer"}
              disabled={busy}
              data-testid="cicd-key-confirm"
              onClick={() => (confirm === "revoke" ? revoke.mutate() : rotate.mutate())}
            >
              {busy && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
              {confirm === "revoke" ? "Revoke key" : "Issue new key"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ApiKeyRevealDialog apiKey={issuedKey} scanType={scanType} title="New API key issued" onDone={() => setIssuedKey(null)} />
    </div>
  );
}
