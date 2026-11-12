"use client";

// "Import repositories": connect an organisation (GitHub App or token), a GitLab group or a Bitbucket workspace ->
// discover every repository -> filter with a live count and the price of one scan of what is kept -> import.
// Opened on an existing connection it starts at the filter step (change what is in scope).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, ChevronLeft, Loader2, Search } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { refusalReason } from "@/components/cbom/sources/logic";
import { ChoiceCards, CopyButton, Field, SecretField, StatusBadge } from "@/components/cbom/sources/shared";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  applyScmFilters,
  createScmConnection,
  getScmConnection,
  previewScmFilters,
  syncScmConnection,
  type ScmConnection,
  type ScmFilters,
  type ScmProduct,
  type ScmProvider,
  type ScmWebhookOnce,
} from "@/utils/api/scm";
import { apiBaseURL } from "@/utils/interceptors";
import { toast } from "@/utils/toast";

import FiltersForm from "./FiltersForm";
import { scmKeys } from "./keys";
import {
  connectionBody,
  connectionErrors,
  emptyConnectionForm,
  filtersError,
  filtersFrom,
  formatCredits,
  PRODUCT_LABEL,
  PRODUCTS,
  PROVIDER_LABEL,
  reasonLabel,
  SCOPES,
  webhookHelp,
  webhookUrl,
  type ConnectionForm,
} from "./logic";

type Step = "connect" | "discover" | "filter" | "done";
const STEPS: { key: Step; label: string }[] = [
  { key: "connect", label: "Connect" },
  { key: "discover", label: "Discover" },
  { key: "filter", label: "Filter" },
  { key: "done", label: "Import" },
];

function StepBar({ step }: { step: Step }) {
  const at = STEPS.findIndex((s) => s.key === step);
  return (
    <ol className="flex flex-wrap items-center gap-2 text-xs" aria-label="Import steps">
      {STEPS.map((s, i) => (
        <li key={s.key} className="flex items-center gap-2" aria-current={i === at ? "step" : undefined}>
          <span className={i < at ? "text-green-600 dark:text-green-400" : i === at ? "font-semibold text-blue-600 dark:text-blue-400" : "text-zinc-500"}>
            {i < at ? <Check className="inline h-3.5 w-3.5 mr-1" /> : `${i + 1}. `}
            {s.label}
          </span>
          {i < STEPS.length - 1 && <span className="text-zinc-400">›</span>}
        </li>
      ))}
    </ol>
  );
}

export default function ImportWizard({ teamId, open, onOpenChange, existing }: {
  teamId: number;
  open: boolean;
  onOpenChange: (v: boolean) => void;
  existing?: ScmConnection | null;
}) {
  const qc = useQueryClient();
  const [step, setStep] = useState<Step>(existing ? "filter" : "connect");
  const [form, setForm] = useState<ConnectionForm>(() => emptyConnectionForm("github"));
  const [touched, setTouched] = useState(false);
  const [connection, setConnection] = useState<ScmConnection | null>(existing ?? null);
  const [webhook, setWebhook] = useState<ScmWebhookOnce | null>(null);
  // a new connection starts with the server's defaults (archived repositories and forks left out, nothing else)
  const [filters, setFilters] = useState<ScmFilters>(() => filtersFrom(existing?.filters));
  const [debounced, setDebounced] = useState<ScmFilters>(filters);
  const [products, setProducts] = useState<ScmProduct[]>(["sbom_sca"]);
  const [imported, setImported] = useState<number | null>(null);
  const errors = connectionErrors(form);
  const scopeChoice = SCOPES[form.provider].find((s) => s.auth === form.auth_kind && s.scope === form.scope_kind) ?? SCOPES[form.provider][0];

  useEffect(() => {
    const t = setTimeout(() => setDebounced(filters), 400);
    return () => clearTimeout(t);
  }, [filters]);

  const create = useMutation({
    mutationFn: async () => {
      const made = await createScmConnection(teamId, connectionBody(form, filters));
      // the connection exists from here on: a failed discovery request must not send the customer back to a form
      // whose next submit would be refused as a duplicate name
      let syncError: unknown = null;
      try {
        await syncScmConnection(teamId, made.connection.id);
      } catch (err) {
        syncError = err;
      }
      return { ...made, syncError };
    },
    onSuccess: (made) => {
      setConnection(made.connection);
      setWebhook(made.webhook);
      setStep("discover");
      if (made.syncError) toast.error(refusalReason(made.syncError) ?? "The connection was saved, but discovery did not start. Start it again below.");
      qc.invalidateQueries({ queryKey: scmKeys.all(teamId) });
    },
  });

  const status = useQuery({
    queryKey: scmKeys.connection(teamId, connection?.id ?? 0),
    queryFn: () => getScmConnection(teamId, connection!.id),
    enabled: open && Boolean(connection) && step === "discover",
    refetchInterval: (q) => (["ok", "partial", "failed", "never"].includes(q.state.data?.connection.sync.status ?? "") ? false : 2000),
  });
  const synced = status.data?.connection;
  const syncDone = synced && ["ok", "partial", "failed"].includes(synced.sync.status);
  const notStarted = synced?.sync.status === "never";

  const resync = useMutation({
    mutationFn: () => syncScmConnection(teamId, connection!.id),
    onSuccess: () => status.refetch(),
    onError: (err) => toast.error(refusalReason(err) ?? "Could not start discovery. Try again."),
  });

  const filterProblem = filtersError(debounced);
  const preview = useQuery({
    queryKey: ["scm", teamId, "preview", connection?.id ?? 0, JSON.stringify(debounced), products.join(",")],
    queryFn: () => previewScmFilters(teamId, connection!.id, debounced, products),
    enabled: open && Boolean(connection) && step === "filter" && !filterProblem,
    placeholderData: (prev) => prev,
  });

  const apply = useMutation({
    mutationFn: () => applyScmFilters(teamId, connection!.id, filters),
    onSuccess: (data) => {
      setImported(data.in_scope);
      setStep("done");
      toast.success(`${data.in_scope} repositories are in scope`);
      qc.invalidateQueries({ queryKey: scmKeys.all(teamId) });
    },
  });

  const close = (v: boolean) => {
    onOpenChange(v);
    if (!v) qc.invalidateQueries({ queryKey: scmKeys.all(teamId) });
  };
  const hookUrl = useMemo(() => (webhook ? webhookUrl(apiBaseURL, webhook.path) : ""), [webhook]);

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{existing ? `Repositories in scope: ${existing.name}` : "Import repositories"}</DialogTitle>
          <DialogDescription>
            Connect once at the organisation, group or workspace level: every repository is discovered, new ones are
            picked up on the next sync, and your filters decide which ones are scanned.
          </DialogDescription>
          <StepBar step={step} />
        </DialogHeader>

        {step === "connect" && (
          <form
            className="space-y-5"
            onSubmit={(e) => {
              e.preventDefault();
              setTouched(true);
              if (Object.keys(errors).length === 0) create.mutate();
            }}
          >
            <div className="space-y-2">
              <p className="text-sm font-medium">Provider</p>
              <ChoiceCards<ScmProvider>
                name="scm-provider"
                label="Provider"
                columns={3}
                value={form.provider}
                onChange={(p) => setForm((f) => ({ ...emptyConnectionForm(p), name: f.name }))}
                options={(["github", "gitlab", "bitbucket"] as ScmProvider[]).map((p) => ({ value: p, title: PROVIDER_LABEL[p] }))}
              />
            </div>
            <div className="space-y-2">
              <p className="text-sm font-medium">What to connect</p>
              <ChoiceCards<string>
                name="scm-scope"
                label="What to connect"
                columns={1}
                value={`${form.auth_kind}:${form.scope_kind}`}
                onChange={(v) => {
                  const [auth, scope] = v.split(":");
                  setForm((f) => ({ ...f, auth_kind: auth as ConnectionForm["auth_kind"], scope_kind: scope as ConnectionForm["scope_kind"] }));
                }}
                options={SCOPES[form.provider].map((s) => ({ value: `${s.auth}:${s.scope}`, title: s.label, description: s.hint }))}
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Field label="Name" htmlFor="scm-name" required error={touched ? errors.name : null} hint="How this connection is shown, e.g. Acme GitHub">
                <Input id="scm-name" value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="Acme GitHub" />
              </Field>
              {scopeChoice.scope !== "user" && (
                <Field
                  label={form.provider === "gitlab" ? "Group path" : form.provider === "bitbucket" ? "Workspace" : scopeChoice.scope === "installation" ? "Organisation (for display)" : "Organisation"}
                  htmlFor="scm-scope-name"
                  required={scopeChoice.scope !== "installation"}
                  error={touched ? errors.scope_name : null}
                  hint={form.provider === "gitlab" ? "e.g. bank/platform" : undefined}
                >
                  <Input id="scm-scope-name" value={form.scope_name} onChange={(e) => setForm((f) => ({ ...f, scope_name: e.target.value }))} />
                </Field>
              )}
              {form.auth_kind === "github_app" && (
                <>
                  <Field label="App id" htmlFor="scm-app-id" required error={touched ? errors.app_id : null}>
                    <Input id="scm-app-id" inputMode="numeric" value={form.app_id} onChange={(e) => setForm((f) => ({ ...f, app_id: e.target.value }))} />
                  </Field>
                  <Field label="Installation id" htmlFor="scm-inst-id" required error={touched ? errors.installation_id : null}>
                    <Input id="scm-inst-id" inputMode="numeric" value={form.installation_id} onChange={(e) => setForm((f) => ({ ...f, installation_id: e.target.value }))} />
                  </Field>
                </>
              )}
            </div>
            {form.auth_kind === "github_app" ? (
              <Field label="App private key (.pem)" htmlFor="scm-key" required error={touched ? errors.private_key : null}
                     hint="Encrypted at rest; used only to mint 1-hour installation tokens. Never shown again.">
                <Textarea id="scm-key" value={form.private_key} spellCheck={false} autoComplete="off"
                          className="font-mono text-xs min-h-[96px]" placeholder="-----BEGIN RSA PRIVATE KEY-----"
                          onChange={(e) => setForm((f) => ({ ...f, private_key: e.target.value }))} />
              </Field>
            ) : (
              <SecretField id="scm-token" label="Access token" value={form.token} required
                           onChange={(v) => setForm((f) => ({ ...f, token: v }))} error={touched ? errors.token : null}
                           hint="Encrypted at rest; used to list repositories and to clone them for scans. Never shown again." />
            )}
            <Field label="API URL (self-hosted only)" htmlFor="scm-api" error={touched ? errors.api_base : null}
                   hint={`Leave empty for ${PROVIDER_LABEL[form.provider]} in the cloud. A self-hosted server (e.g. https://ghe.example.com/api/v3) must be allowed by the ZeroShield operator in GIT_ALLOWED_HOSTS.`}>
              <Input id="scm-api" value={form.api_base} placeholder="https://" onChange={(e) => setForm((f) => ({ ...f, api_base: e.target.value }))} />
            </Field>
            {create.isError && <p className="text-sm text-red-500" role="alert">{refusalReason(create.error) ?? "Could not connect. Try again."}</p>}
            <DialogFooter>
              <Button type="button" variant="outline" className="cursor-pointer" onClick={() => close(false)}>Cancel</Button>
              <Button type="submit" className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={create.isPending}>
                {create.isPending ? <Loader2 className="h-4 w-4 mr-2 animate-spin" /> : <Search className="h-4 w-4 mr-2" />}
                Connect and discover
              </Button>
            </DialogFooter>
          </form>
        )}

        {step === "discover" && (
          <div className="space-y-4" aria-live="polite">
            {notStarted ? (
              <p className="text-sm text-zinc-700 dark:text-zinc-300" role="status">
                The connection is saved, but discovery has not started yet.
              </p>
            ) : !syncDone ? (
              <p className="flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
                <Loader2 className="h-4 w-4 animate-spin text-blue-600" />
                Listing every repository the connection can see (100 per page; rate limits are waited out)…
              </p>
            ) : synced.sync.status === "failed" ? (
              <div className="space-y-2" role="alert">
                <StatusBadge tone="red">Discovery failed</StatusBadge>
                <p className="text-sm text-zinc-700 dark:text-zinc-300 break-words">{synced.sync.error ?? "The provider could not be read."}</p>
                <p className="text-xs text-zinc-500">
                  A wrong token, App id or organisation can be corrected with Edit on the Connections tab; then choose Sync now.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                <StatusBadge tone={synced.sync.status === "ok" ? "green" : "amber"}>
                  {synced.sync.status === "ok" ? "Discovery complete" : "Partly discovered (rate limited; it resumes on its own)"}
                </StatusBadge>
                <p className="text-sm text-zinc-700 dark:text-zinc-300" data-testid="discovered-count">
                  {synced.sync.summary.discovered ?? 0} repositories found in {synced.sync.summary.pages ?? 0} pages
                  ({synced.sync.summary.api_calls ?? 0} API calls, {Math.round(synced.sync.summary.duration_s ?? 0)} s).
                </p>
              </div>
            )}
            <DialogFooter>
              {((syncDone && synced.sync.status === "failed") || notStarted) && (
                <Button variant="outline" className="cursor-pointer" onClick={() => resync.mutate()} disabled={resync.isPending}>
                  {notStarted ? "Start discovery" : "Try again"}
                </Button>
              )}
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={!syncDone || synced.sync.status === "failed"}
                      onClick={() => setStep("filter")}>
                Choose which to scan
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === "filter" && connection && (
          <div className="space-y-5">
            <FiltersForm idPrefix="wizard-filter" value={filters} onChange={setFilters} />
            <div className="space-y-2">
              <p className="text-sm font-medium">Price one scan of the kept repositories with</p>
              <div className="flex flex-wrap gap-x-5 gap-y-2">
                {PRODUCTS.map((p) => (
                  <label key={p} className="flex items-center gap-2 text-sm cursor-pointer">
                    <input type="checkbox" className="h-4 w-4 accent-blue-600" checked={products.includes(p)}
                           onChange={(e) => setProducts((cur) => (e.target.checked ? [...cur, p] : cur.filter((x) => x !== p)))} />
                    {PRODUCT_LABEL[p]}
                  </label>
                ))}
              </div>
            </div>
            <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-4 text-sm space-y-2" aria-live="polite" data-testid="filter-preview">
              {filterProblem ? <p className="text-red-500" role="alert">{filterProblem}</p> : preview.data ? (
                <>
                  <p className="text-base font-semibold text-zinc-900 dark:text-white">
                    {preview.data.in_scope.toLocaleString("en-US")} of {preview.data.discovered.toLocaleString("en-US")} repositories kept
                    {preview.isFetching && <Loader2 className="inline h-4 w-4 ml-2 animate-spin text-blue-600" />}
                  </p>
                  {products.length > 0 && (
                    <p className="text-zinc-700 dark:text-zinc-300">
                      One scan of them with {products.map((p) => PRODUCT_LABEL[p]).join(", ")}: about{" "}
                      <strong>{formatCredits(preview.data.estimate.credits)}</strong> (nothing is charged by importing).
                    </p>
                  )}
                  <ul className="flex flex-wrap gap-x-4 gap-y-1 text-zinc-600 dark:text-zinc-400">
                    {Object.entries(preview.data.reasons).sort((a, b) => b[1] - a[1]).map(([r, n]) => (
                      <li key={r}>{reasonLabel(r)}: {n}</li>
                    ))}
                  </ul>
                  {preview.data.sample_in.length > 0 && (
                    <p className="text-xs text-zinc-500 break-words">Kept, e.g.: {preview.data.sample_in.slice(0, 6).join(", ")}</p>
                  )}
                </>
              ) : preview.isError ? (
                <p className="text-red-500" role="alert">{refusalReason(preview.error) ?? "Could not preview. Try again."}</p>
              ) : (
                <p className="flex items-center gap-2 text-zinc-600"><Loader2 className="h-4 w-4 animate-spin" />Counting…</p>
              )}
            </div>
            {apply.isError && <p className="text-sm text-red-500" role="alert">{refusalReason(apply.error) ?? "Could not import. Try again."}</p>}
            <DialogFooter>
              {!existing && (
                <Button variant="outline" className="cursor-pointer" onClick={() => setStep("discover")}>
                  <ChevronLeft className="h-4 w-4 mr-1" />Back
                </Button>
              )}
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                      disabled={Boolean(filterProblem) || apply.isPending || !preview.data}
                      onClick={() => apply.mutate()}>
                {apply.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
                {existing ? "Save filters" : `Import ${preview.data ? preview.data.in_scope.toLocaleString("en-US") : ""} repositories`}
              </Button>
            </DialogFooter>
          </div>
        )}

        {step === "done" && (
          <div className="space-y-4">
            <p className="text-sm text-zinc-800 dark:text-zinc-200" data-testid="import-done">
              <strong>{(imported ?? 0).toLocaleString("en-US")}</strong> repositories are in scope. Nothing has been scanned or
              charged yet: create a scan policy (schedule and/or scan on push) or select repositories and choose Scan now.
            </p>
            {webhook && connection && (
              <div className="rounded-lg border border-amber-500/40 bg-amber-500/5 p-4 space-y-3">
                <p className="text-sm font-medium">Scan on push: add this webhook (the secret is shown only now)</p>
                <p className="text-xs text-zinc-600 dark:text-zinc-400">{webhookHelp(connection.provider)}</p>
                <div className="flex flex-wrap items-center gap-2">
                  <code className="text-xs break-all bg-zinc-100 dark:bg-zinc-800 rounded px-2 py-1">{hookUrl}</code>
                  <CopyButton text={hookUrl} label="Copy URL" />
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <code className="text-xs break-all bg-zinc-100 dark:bg-zinc-800 rounded px-2 py-1" data-testid="webhook-secret">{webhook.secret}</code>
                  <CopyButton text={webhook.secret} label="Copy secret" />
                </div>
              </div>
            )}
            <DialogFooter>
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={() => close(false)}>Done</Button>
            </DialogFooter>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
