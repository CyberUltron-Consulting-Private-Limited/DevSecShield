# Brief: build CBOM Sources tabs in the DevSecShield frontend

Repo: /home/claude/devsecshield (branch ansh; DO NOT commit, stash or touch git). Frontend: /home/claude/devsecshield/frontend
(Next.js 16, React 19, Tailwind v4, shadcn new-york zinc, lucide-react 0.555, TanStack Query v5; node_modules installed).

The backend is DONE and tested; the API contract is fixed. You only write the two tab components assigned to you
(replace the stub files that exist now). Do not edit any other file. If you think another file must change, say so in
your report instead.

## Read first (in this order)
1. Reference implementation to copy style and patterns from: frontend/components/cbom/sources/ScanNodesTab.tsx
2. Shared building blocks you must reuse: frontend/components/cbom/sources/shared.tsx (StatusBadge and the status badges,
   SectionCard, StatCard, LoadingBlock, ErrorBlock, EmptyState, Field, SecretField, CopyButton, CodeSnippet, NodeSelect,
   ConfirmDialog, usePolledJob, Truncate, ChoiceCards, Checkbox2), logic.ts (splitLines, csvFirstColumn, zoneFileHostnames,
   readTextFile, ago, formatDateTime, formatDay, newRequestId, credits, pluralize, grid helpers), keys.ts (cbomSourcesKeys).
3. API client: the "CBOM Sources API Routes" section at the END of frontend/utils/backend_api.ts (types + functions).
4. Backend truth for fields/validation: backend/utilities/cbom_sources/kinds.py (per-kind `config` models, secret names,
   credential types, defaults), backend/routers/cbom_sources.py (endpoint behaviour, error texts),
   backend/utilities/cbom_sources/planning.py (what is skipped and why), templates.py (template names).
5. The approved designs for your tabs (static HTML artboards, read the text/structure):
   /tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/design/project/<Name>.dc.html
6. Plan + review amendments (binding): /tmp/claude-0/-home-claude/976896a4-2e24-5405-8100-31f07ced9160/scratchpad/cbom-sources-plan.md
   (read section "v2" fully; it overrides earlier sections).

## Component contract
`export default function XTab({ teamId, onNavigate }: { teamId: number; onNavigate: (tab: string) => void })`
Tab values for onNavigate: "scan-nodes" | "servers" | "k8s-db" | "cloud" | "network" | "evidence" | "review".
The page (app/[team_id]/cbom/sources/page.tsx) already renders the header, tabs and Refresh.

## Rules (all mandatory)
- Look and feel = existing app: `SectionCard` cards, `bg-blue-600 hover:bg-blue-700 text-white cursor-pointer` for primary
  buttons, `variant="outline"` for secondary, `variant="destructive"` for delete, Loader2 spinners, tinted outline badges,
  tables inside `<ScrollArea className="w-full border rounded-lg"><div className="min-w-max"><Table>…` with ScrollBar.
  Light + dark classes like ScanNodesTab (`text-zinc-600 dark:text-zinc-400`, etc.). Responsive: everything must work at
  390px wide (stack grids with `grid-cols-1 md:grid-cols-2`, tables scroll horizontally inside their ScrollArea).
- Forms: plain useState (no form libraries, no zod, no new dependencies). Validate on the client before submit (show
  inline `Field error`), but the server is the authority: errors toast automatically through the API functions.
- ESLint uses the React compiler rules: NEVER call setState synchronously inside useEffect. To load an existing record
  into a form, mount the form/dialog with `key={record.id}` and initialise useState from props (see NodeDialog in
  ScanNodesTab). Derive values instead of syncing them.
- Data: `useQuery({ queryKey: cbomSourcesKeys.X(teamId,...), queryFn, enabled: Number.isFinite(teamId), retry: 1 })`.
  After every mutation: `onSettled: () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) })`.
  Polling: `usePolledJob(teamId, jobId)` for test jobs; list queries may use `refetchInterval: 30000`.
- Secrets are write-only: use `SecretField`, never prefill, never display. On create send `secrets: {name: value}`; on
  edit send only non-empty secrets (blank keeps the stored one). `source.secrets_set` tells you which are stored.
  Changing where a credential is used (targets/port/host/api_url/node...) makes the server clear stored secrets unless
  re-entered; show the server's message (it toasts) and show a hint under the secret field when editing.
- Edits send `expected_version: source.row_version`; a 409 means it changed elsewhere (it toasts); close the dialog and
  let the invalidation refresh.
- Files (PEM, kubeconfig, known_hosts, CSV, zone files): read with `readTextFile(file)`; show its error inline.
- Never use navigator.clipboard directly: use CopyButton / CodeSnippet.
- Every list has an empty state with its primary action. Long names: `Truncate`. Accessible labels on icon buttons.
- Honesty (the product must not claim what is not built):
  * secrets copy: "Encrypted at rest by ZeroShield; sent only to the scan node that runs the job" (SecretField default hint).
  * NO buttons for vCenter/CMDB import, CT-log import, Kubernetes-ingress import, "Launch StackSet", email sending,
    "contradicts scan results" banners, NIST list checks. Email-style actions become "Create link" + copy.
  * Connection tests for node-based sources are run by the scan node: after "Save and test" show the queued job via
    usePolledJob with its `waiting_reason` (e.g. "Scan node X is offline") until it finishes; then the sample rows.
  * Cloud (AWS) "Validate connection" really calls AWS from the backend and returns check rows (pass/fail/skipped/error);
    Azure/GCP/IdP/CA (except AD CS) show "Validation is not available yet".
  * Run/collection of cloud, CA (except AD CS) and IdP sources is "not available yet" (they are configured but skipped).
- Use `test_after_save: true` on create/update for the "Save and test" button (the design's "test before saving").
- Data-testid attributes on key controls (e.g. data-testid="servers-save", "servers-targets") to help browser tests.

## Done = all of these pass with zero output
cd /home/claude/devsecshield/frontend && npx tsc --noEmit -p . && npx eslint components/cbom/sources/<YourFile1>.tsx components/cbom/sources/<YourFile2>.tsx
Do NOT start a dev server or browser; the lead runs browser tests afterwards. Do not edit shared.tsx/logic.ts/keys.ts; if
you need a helper, put it in your own file. Report: what you built per design section, any design element you left out
and why, and anything you think the backend or shared files should change.
