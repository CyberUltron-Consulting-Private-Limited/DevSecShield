"use client";

// Edit a connection (admin): name, API URL, organisation / group / workspace, the GitHub App ids, the discovery
// interval, and a new credential. The saved token or App key is write-only: the field starts empty ("leave blank to
// keep it") and is required only when the edit points the credential somewhere else (routers/scm.py
// _update_connection refuses that without it). The webhook URL and secret do not change. PATCH sends only what changed
// plus the row version the dialog opened at, so an edit made elsewhere meanwhile is a 409, never overwritten.

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { useMemo, useState } from "react";

import { refusalReason } from "@/components/cbom/sources/logic";
import { Field, SecretField } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { updateScmConnection, type ScmConnection } from "@/utils/api/scm";
import { toast } from "@/utils/toast";

import { scmKeys } from "./keys";
import { DEFAULT_API, editErrors, editFormFrom, editMovesCredential, editPatch, PROVIDER_LABEL, type ConnectionEditForm } from "./logic";

export default function EditConnectionDialog({ teamId, connection: c, open, onOpenChange }: {
  teamId: number;
  connection: ScmConnection;
  open: boolean;
  onOpenChange: (v: boolean) => void;
}) {
  const qc = useQueryClient();
  const defaultApi = DEFAULT_API[c.provider];
  const [form, setForm] = useState<ConnectionEditForm>(() => editFormFrom(c, defaultApi));
  const [touched, setTouched] = useState(false);
  const errors = useMemo(() => editErrors(c, form, defaultApi), [c, form, defaultApi]);
  const moves = editMovesCredential(c, form, defaultApi);
  const set = (patch: Partial<ConnectionEditForm>) => setForm((f) => ({ ...f, ...patch }));
  const save = useMutation({
    mutationFn: () => updateScmConnection(teamId, c.id, editPatch(c, form, defaultApi)),
    onSuccess: () => {
      toast.success("Connection saved");
      qc.invalidateQueries({ queryKey: scmKeys.all(teamId) });
      onOpenChange(false);
    },
  });
  const isApp = c.auth_kind === "github_app";
  const scopeLabel = c.provider === "gitlab" ? "Group path" : c.provider === "bitbucket" ? "Workspace" : "Organisation";
  const status = (save.error as { response?: { status?: number } } | null)?.response?.status;
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Edit {c.name}</DialogTitle>
          <DialogDescription>
            {PROVIDER_LABEL[c.provider]} connection. The saved {isApp ? "App private key" : "access token"} is never shown:
            leave it blank to keep it. The webhook URL and secret stay the same.
          </DialogDescription>
        </DialogHeader>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            setTouched(true);
            if (Object.keys(errors).length === 0) save.mutate();
          }}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field infoId="repos.connect.name" label="Name" htmlFor="edit-name" required error={touched ? errors.name : null}>
              <Input id="edit-name" value={form.name} onChange={(e) => set({ name: e.target.value })} />
            </Field>
            {c.scope_kind !== "user" && (
              <Field infoId="repos.connect.scope_name" label={c.scope_kind === "installation" ? "Organisation (for display)" : scopeLabel}
                     htmlFor="edit-scope" required={c.scope_kind !== "installation"} error={touched ? errors.scope_name : null}>
                <Input id="edit-scope" value={form.scope_name} onChange={(e) => set({ scope_name: e.target.value })} />
              </Field>
            )}
            {isApp && (
              <>
                <Field infoId="repos.connect.app_id" label="App id" htmlFor="edit-app-id" required error={touched ? errors.app_id : null}>
                  <Input id="edit-app-id" inputMode="numeric" value={form.app_id} onChange={(e) => set({ app_id: e.target.value })} />
                </Field>
                <Field infoId="repos.connect.installation_id" label="Installation id" htmlFor="edit-inst-id" required
                       error={touched ? errors.installation_id : null}>
                  <Input id="edit-inst-id" inputMode="numeric" value={form.installation_id} onChange={(e) => set({ installation_id: e.target.value })} />
                </Field>
              </>
            )}
            <Field infoId="repos.edit.sync_interval" label="Discover every (minutes)" htmlFor="edit-interval"
                   hint="15 to 10,080 (one week)" error={touched ? errors.sync_interval_min : null}>
              <Input id="edit-interval" inputMode="numeric" value={form.sync_interval_min} onChange={(e) => set({ sync_interval_min: e.target.value })} />
            </Field>
          </div>
          <Field infoId="repos.connect.api_base" label="API URL (self-hosted only)" htmlFor="edit-api" error={touched ? errors.api_base : null}
                 hint={`Empty: ${defaultApi}.`}>
            <Input id="edit-api" value={form.api_base} placeholder="https://" onChange={(e) => set({ api_base: e.target.value })} />
          </Field>
          <SecretField
            infoId={isApp ? "repos.edit.private_key" : "repos.edit.token"}
            id="edit-secret"
            label={isApp ? "New App private key (.pem)" : "New access token"}
            value={form.secret}
            onChange={(v) => set({ secret: v })}
            isSet={!moves}
            multiline={isApp}
            required={moves}
            error={touched ? errors.secret : null}
            hint={moves
              ? `The API URL, ${isApp ? "organisation or App" : "or the scope"} changed: enter the ${isApp ? "key" : "token"} again so it is never sent somewhere new unseen.`
              : "Leave blank to keep the saved one. A new value replaces it; the old one is never shown."}
          />
          {save.isError && (
            <p className="text-sm text-red-500" role="alert">
              {status === 409 && !/already exists/i.test(refusalReason(save.error) ?? "")
                ? "This connection was changed elsewhere. Close this dialog and open it again to see the current values."
                : refusalReason(save.error) ?? "Could not save. Try again."}
            </p>
          )}
          <DialogFooter>
            <Button type="button" variant="outline" className="cursor-pointer" onClick={() => onOpenChange(false)}>Cancel</Button>
            <Button type="submit" className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending}>
              {save.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}Save
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
