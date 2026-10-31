"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ExternalLink, Eye, Link2, Loader2, MoreVertical, Pencil, Plus, Trash2 } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  createCbomVendor,
  createCbomVendorLink,
  deleteCbomVendor,
  getCbomEvidence,
  updateCbomEvidenceArea,
  updateCbomVendor,
  type CbomConfidence,
  type CbomEvidenceArea,
  type CbomEvidenceAreaWrite,
  type CbomEvidenceQuestion,
  type CbomVendor,
} from "@/utils/backend_api";

import { cbomSourcesKeys } from "./keys";
import { formatDay, pluralize } from "./logic";
import {
  ChoiceCards,
  CONFIDENCE_LABEL,
  ConfidenceBadge,
  ConfirmDialog,
  CopyButton,
  EmptyState,
  ErrorBlock,
  Field,
  LoadingBlock,
  SectionCard,
  StatCard,
  StatusBadge,
  Truncate,
  type Tone,
} from "./shared";

const LEVELS: CbomConfidence[] = ["Q0", "Q1", "Q2", "Q3"];
const CHOICES: { value: string; label: string }[] = [
  { value: "yes", label: "Yes" },
  { value: "no", label: "No" },
  { value: "dont_know", label: "Don't know" },
];
const CHOICE_LABEL: Record<string, string> = { yes: "Yes", no: "No", dont_know: "Don't know" };
const EMAIL_RE = /^[^@\s'"<>]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$/;
const DAY_RE = /^\d{4}-\d{2}-\d{2}$/;
const MAX_ANSWER = 2000;
const EVIDENCE_MAX_AGE_DAYS = 365;
const VENDOR_AREA = "third_party_vendors";

const VENDOR_STATUS: Record<CbomVendor["status"], [Tone, string]> = {
  not_sent: ["zinc", "Not sent"],
  link_created: ["blue", "Link created"],
  overdue: ["red", "Overdue"],
  answered: ["green", "Answered"],
  expired: ["amber", "Expired"],
};

// ---------------------------------------------------------------------------- helpers
function httpStatus(err: unknown): number | undefined {
  return (err as { response?: { status?: number } } | null)?.response?.status;
}

/** Mirrors the backend check_http_url: http(s) with a host, no spaces, quotes or user info. */
function urlError(value: string): string | null {
  const text = value.trim();
  if (!text) return null;
  if (text.length > 1000) return "Use at most 1,000 characters";
  if (/[\s'"`<>\\]/.test(text)) return "The link contains characters that are not allowed";
  let parsed: URL;
  try {
    parsed = new URL(text);
  } catch {
    return "Enter a full link that starts with http:// or https://";
  }
  if ((parsed.protocol !== "http:" && parsed.protocol !== "https:") || !parsed.hostname) {
    return "The link must start with http:// or https://";
  }
  if (parsed.username || parsed.password) return "The link must not contain a user name or password";
  return null;
}

/** Only http(s) links become clickable; anything else is shown as text. */
function safeHref(url: string | null | undefined): string | null {
  if (!url || !url.trim()) return null;
  return urlError(url) === null ? url.trim() : null;
}

function isValidDay(day: string): boolean {
  if (!DAY_RE.test(day)) return false;
  const [y, m, d] = day.split("-").map(Number);
  const t = new Date(Date.UTC(y, m - 1, d));
  return t.getUTCFullYear() === y && t.getUTCMonth() === m - 1 && t.getUTCDate() === d;
}

function addDays(day: string, n: number): string {
  const [y, m, d] = day.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d + n)).toISOString().slice(0, 10);
}

function daysBetween(fromDay: string, toDay: string): number {
  const [y1, m1, d1] = fromDay.split("-").map(Number);
  const [y2, m2, d2] = toDay.split("-").map(Number);
  return Math.round((Date.UTC(y2, m2 - 1, d2) - Date.UTC(y1, m1 - 1, d1)) / 86_400_000);
}

function shortDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "—";
  return new Date(t).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}

function daysSince(iso: string | null | undefined, nowIso: string | null | undefined): number | null {
  if (!iso || !nowIso) return null;
  const then = Date.parse(iso);
  const now = Date.parse(nowIso);
  if (Number.isNaN(then) || Number.isNaN(now)) return null;
  return Math.max(0, Math.floor((now - then) / 86_400_000));
}

function answerText(question: CbomEvidenceQuestion, value: string | undefined): string {
  if (!value) return "Not answered";
  return question.type === "choice" ? CHOICE_LABEL[value] ?? value : value;
}

/** Known question ids only, trimmed, capped; choices must be yes / no / dont_know (as the backend does). */
function cleanAnswers(questions: CbomEvidenceQuestion[], answers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const q of questions) {
    const value = (answers[q.id] ?? "").trim().slice(0, MAX_ANSWER);
    if (!value) continue;
    if (q.type === "choice" && !(value in CHOICE_LABEL)) continue;
    out[q.id] = value;
  }
  return out;
}

function sameAnswers(a: Record<string, string>, b: Record<string, string>): boolean {
  const ka = Object.keys(a).sort();
  const kb = Object.keys(b).sort();
  return ka.length === kb.length && ka.every((k, i) => k === kb[i] && a[k] === b[k]);
}

function confidenceNote(area: CbomEvidenceArea, vendorCount: number): string | null {
  if (area.confidence === area.effective_confidence) return null;
  if (area.area_key === VENDOR_AREA && vendorCount > 0) {
    return `Taken from the lowest vendor answer (set here: ${area.confidence} ${CONFIDENCE_LABEL[area.confidence]})`;
  }
  return `Set as ${area.confidence} ${CONFIDENCE_LABEL[area.confidence]}, but the evidence is older than 12 months, so it counts as Q0 until renewed`;
}

function areaReminder(area: CbomEvidenceArea): string {
  const due = area.due_date ? ` by ${formatDay(area.due_date)}` : "";
  return [
    `Reminder${area.owner ? ` for ${area.owner}` : ""}: please answer the "${area.title}" questions in ZeroShield DevSecShield (CBOM Sources, Evidence tab)${due}.`,
    `Current status: ${area.effective_confidence} ${CONFIDENCE_LABEL[area.effective_confidence]}. Until it is answered it stays a visible Q0 gap.`,
  ].join("\n");
}

function vendorReminder(vendor: CbomVendor): string {
  const created = shortDate(vendor.link_created_at);
  const expires = shortDate(vendor.link_expires_at);
  const status = vendor.status === "overdue" ? "is still unanswered" : "is waiting for your answers";
  return [
    `Hello ${vendor.name},`,
    `The single-use questionnaire link we shared with you on ${created} ${status}. It expires on ${expires}.`,
    "It takes a few minutes and needs no login. Please use the link from our earlier message; if you no longer have it, reply and we will create a new one.",
  ].join("\n");
}

function vendorDates(vendor: CbomVendor, serverNow: string | undefined): string {
  switch (vendor.status) {
    case "not_sent":
      return "No link yet";
    case "answered":
      return `Answered ${shortDate(vendor.answered_at)}`;
    case "expired":
      return `Expired ${shortDate(vendor.link_expires_at)}`;
    case "overdue": {
      const days = daysSince(vendor.link_created_at, serverNow);
      return `Created ${shortDate(vendor.link_created_at)}${days != null ? ` (${days} days ago)` : ""} · expires ${shortDate(vendor.link_expires_at)}`;
    }
    default:
      return `Created ${shortDate(vendor.link_created_at)} · expires ${shortDate(vendor.link_expires_at)}`;
  }
}

function vendorLevel(vendor: CbomVendor): CbomConfidence {
  return vendor.answered_at ? vendor.confidence : "Q0";
}

// ---------------------------------------------------------------------------- tab
export default function EvidenceTab({ teamId, onNavigate }: { teamId: number; onNavigate: (tab: string) => void }) {
  const queryClient = useQueryClient();
  const [editingArea, setEditingArea] = useState<CbomEvidenceArea | null>(null);
  const [vendorForm, setVendorForm] = useState<{ vendor: CbomVendor | null } | null>(null);
  const [viewing, setViewing] = useState<CbomVendor | null>(null);
  const [deleting, setDeleting] = useState<CbomVendor | null>(null);
  const [relinking, setRelinking] = useState<CbomVendor | null>(null);
  const [createdLink, setCreatedLink] = useState<{ vendorName: string; url: string; areaKey: string } | null>(null);
  const [previewKey, setPreviewKey] = useState("");

  const evidenceQuery = useQuery({
    queryKey: cbomSourcesKeys.evidence(teamId),
    queryFn: () => getCbomEvidence(teamId),
    enabled: Number.isFinite(teamId),
    retry: 1,
  });

  const invalidate = () => queryClient.invalidateQueries({ queryKey: cbomSourcesKeys.all(teamId) });

  const linkMutation = useMutation({
    mutationFn: (vendor: CbomVendor) => createCbomVendorLink(teamId, vendor.id),
    onSuccess: (data) => {
      setCreatedLink({ vendorName: data.vendor.name, url: data.url, areaKey: data.vendor.area_key });
      setRelinking(null);
    },
    onError: (err) => {
      if (httpStatus(err) === 404) setRelinking(null);
    },
    onSettled: invalidate,
  });

  const deleteMutation = useMutation({
    mutationFn: (vendor: CbomVendor) => deleteCbomVendor(teamId, vendor.id),
    onSuccess: () => setDeleting(null),
    onError: (err) => {
      if (httpStatus(err) === 404) setDeleting(null);
    },
    onSettled: invalidate,
  });

  if (evidenceQuery.isLoading) return <LoadingBlock />;
  if (evidenceQuery.isError && !evidenceQuery.data) return <ErrorBlock onRetry={() => evidenceQuery.refetch()} />;
  const data = evidenceQuery.data;
  if (!data) return <LoadingBlock />;

  const areas = data.areas;
  const vendors = data.vendors;
  const serverNow = data.server_time;
  const today = /^\d{4}-\d{2}-\d{2}/.test(serverNow ?? "") ? serverNow.slice(0, 10) : null;
  // The backend accepts an evidence date up to one day ahead of its UTC date (time zones east of UTC).
  const maxEvidenceDate = today ? addDays(today, 1) : null;
  const counts: Record<CbomConfidence, number> = { Q0: 0, Q1: 0, Q2: 0, Q3: 0 };
  for (const area of areas) counts[area.effective_confidence] = (counts[area.effective_confidence] ?? 0) + 1;
  const answeredVendors = vendors.filter((v) => !!v.answered_at).length;
  const previewArea = areas.find((a) => a.area_key === previewKey) ?? areas[0] ?? null;
  const linkArea = createdLink ? areas.find((a) => a.area_key === createdLink.areaKey) ?? areas.find((a) => a.area_key === VENDOR_AREA) : null;
  const viewingQuestions = viewing ? (areas.find((a) => a.area_key === viewing.area_key) ?? areas.find((a) => a.area_key === VENDOR_AREA))?.questions ?? [] : [];

  const openAddVendor = () => setVendorForm({ vendor: null });

  return (
    <div className="space-y-6">
      <p className="text-sm text-zinc-600 dark:text-zinc-400 max-w-3xl">
        Some things cannot be scanned. Owners and vendors answer short questionnaires, each answer carries a confidence level,
        and a missing answer stays a visible gap. Gaps are listed on{" "}
        <button type="button" className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer" onClick={() => onNavigate("review")}>
          Review &amp; Run
        </button>
        .
      </p>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {LEVELS.map((q) => (
          <StatCard
            key={q}
            label={`${q} ${CONFIDENCE_LABEL[q]}`}
            value={pluralize(counts[q], "area")}
            tone={q === "Q0" && counts.Q0 > 0 ? "red" : q === "Q3" && counts.Q3 > 0 ? "green" : undefined}
          />
        ))}
      </div>

      <SectionCard
        title="Areas that cannot be scanned"
        description={`${pluralize(areas.length, "area")} · ${data.answered.toLocaleString()} answered`}
      >
        {areas.length === 0 ? (
          <EmptyState
            title="No evidence areas yet"
            body="The evidence areas are created with the team's first visit. Refresh to load them."
            action={
              <Button variant="outline" className="cursor-pointer" onClick={() => evidenceQuery.refetch()}>
                Refresh
              </Button>
            }
          />
        ) : (
          <ScrollArea className="w-full border rounded-lg">
            <div className="min-w-max">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Area</TableHead>
                    <TableHead>Owner</TableHead>
                    <TableHead>Confidence</TableHead>
                    <TableHead>Evidence</TableHead>
                    <TableHead>Due</TableHead>
                    <TableHead>
                      <span className="sr-only">Action</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {areas.map((area) => {
                    const note = confidenceNote(area, vendors.length);
                    const href = safeHref(area.evidence_url);
                    const answered = Object.keys(area.answers ?? {}).length > 0 || area.confidence !== "Q0";
                    return (
                      <TableRow key={area.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800" data-testid={`evidence-area-${area.area_key}`}>
                        <TableCell className="font-medium text-zinc-900 dark:text-white max-w-[240px]">
                          <Truncate text={area.title} />
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400 max-w-[180px]">
                          {area.owner ? (
                            <Truncate text={area.owner} />
                          ) : (
                            <span className="text-zinc-500" title={area.owner_hint ? `Usually: ${area.owner_hint}` : undefined}>
                              Not assigned
                            </span>
                          )}
                        </TableCell>
                        <TableCell>
                          <ConfidenceBadge level={area.effective_confidence} />
                          {note && <p className="mt-1 max-w-[240px] whitespace-normal text-xs text-amber-600 dark:text-amber-400">{note}</p>}
                        </TableCell>
                        <TableCell className="max-w-[260px]">
                          {href ? (
                            <a
                              href={href}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex max-w-full items-center gap-1 text-blue-600 dark:text-blue-400 hover:underline"
                              title={href}
                            >
                              <span className="truncate">{area.evidence_title || "Evidence document"}</span>
                              <ExternalLink className="h-3 w-3 shrink-0" />
                            </a>
                          ) : area.evidence_title ? (
                            <Truncate text={area.evidence_title} className="text-zinc-700 dark:text-zinc-300" />
                          ) : (
                            <span className="text-zinc-500">No document yet</span>
                          )}
                          {area.evidence_date && <p className="text-xs text-zinc-500">Dated {formatDay(area.evidence_date)}</p>}
                          {area.area_key === VENDOR_AREA && vendors.length > 0 && (
                            <p className="text-xs text-zinc-500">
                              {answeredVendors} of {pluralize(vendors.length, "vendor")} answered
                            </p>
                          )}
                        </TableCell>
                        <TableCell className="text-zinc-600 dark:text-zinc-400">
                          <div className="flex items-center gap-2">
                            <span>{formatDay(area.due_date)}</span>
                            {area.overdue && <StatusBadge tone="red">Overdue</StatusBadge>}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center justify-end gap-2">
                            {area.effective_confidence === "Q0" && <CopyButton text={areaReminder(area)} label="Copy reminder" />}
                            <Button
                              size="sm"
                              variant="outline"
                              className="cursor-pointer"
                              data-testid={`evidence-answer-${area.area_key}`}
                              onClick={() => setEditingArea(area)}
                            >
                              {answered ? "Update" : "Answer"}
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
            <ScrollBar orientation="horizontal" />
          </ScrollArea>
        )}
      </SectionCard>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
        <div className="xl:col-span-2 min-w-0">
          <SectionCard
            title="Vendors"
            description="Single-use links, no login, expire in 14 days. A vendor who does not answer stays Q0."
            actions={
              <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={openAddVendor} data-testid="vendor-add">
                <Plus className="h-4 w-4 mr-2" />
                Add vendor
              </Button>
            }
          >
            {vendors.length === 0 ? (
              <EmptyState
                title="No vendors yet"
                body="Add the vendors who hold or protect your keys and data. Each gets a single-use link to a short questionnaire that you send them yourself."
                action={
                  <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" onClick={openAddVendor}>
                    <Plus className="h-4 w-4 mr-2" />
                    Add your first vendor
                  </Button>
                }
              />
            ) : (
              <ScrollArea className="w-full border rounded-lg">
                <div className="min-w-max">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Vendor</TableHead>
                        <TableHead>Link status</TableHead>
                        <TableHead>Confidence</TableHead>
                        <TableHead>
                          <span className="sr-only">Action</span>
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {vendors.map((vendor) => {
                        const [tone, label] = VENDOR_STATUS[vendor.status] ?? VENDOR_STATUS.not_sent;
                        const linking = linkMutation.isPending && linkMutation.variables?.id === vendor.id;
                        return (
                          <TableRow key={vendor.id} className="hover:bg-zinc-50 dark:hover:bg-zinc-800" data-testid={`vendor-row-${vendor.id}`}>
                            <TableCell className="max-w-[220px]">
                              <Truncate text={vendor.name} className="font-medium text-zinc-900 dark:text-white" />
                              {vendor.contact_email && <Truncate text={vendor.contact_email} className="text-xs text-zinc-500" />}
                            </TableCell>
                            <TableCell>
                              <StatusBadge tone={tone}>{label}</StatusBadge>
                              <p className="text-xs text-zinc-500 mt-1">{vendorDates(vendor, serverNow)}</p>
                            </TableCell>
                            <TableCell>
                              <ConfidenceBadge level={vendorLevel(vendor)} />
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center justify-end gap-2">
                                {vendor.status === "not_sent" || vendor.status === "expired" ? (
                                  <Button
                                    size="sm"
                                    className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
                                    disabled={linkMutation.isPending}
                                    data-testid={`vendor-create-link-${vendor.id}`}
                                    onClick={() => linkMutation.mutate(vendor)}
                                  >
                                    {linking ? <Loader2 className="h-4 w-4 mr-1.5 animate-spin" /> : <Link2 className="h-4 w-4 mr-1.5" />}
                                    {vendor.status === "not_sent" ? "Create link" : "New link"}
                                  </Button>
                                ) : vendor.status === "answered" ? (
                                  <Button size="sm" variant="outline" className="cursor-pointer" data-testid={`vendor-view-${vendor.id}`} onClick={() => setViewing(vendor)}>
                                    <Eye className="h-4 w-4 mr-1.5" />
                                    View answers
                                  </Button>
                                ) : (
                                  <CopyButton text={vendorReminder(vendor)} label="Copy reminder" />
                                )}
                                <DropdownMenu>
                                  <DropdownMenuTrigger asChild>
                                    <Button variant="ghost" size="icon" className="cursor-pointer" aria-label={`Actions for ${vendor.name}`}>
                                      <MoreVertical className="h-4 w-4" />
                                    </Button>
                                  </DropdownMenuTrigger>
                                  <DropdownMenuContent align="end">
                                    {(vendor.status === "link_created" || vendor.status === "overdue" || vendor.status === "answered") && (
                                      <DropdownMenuItem className="cursor-pointer" onSelect={() => setRelinking(vendor)}>
                                        <Link2 className="h-4 w-4" />
                                        New link
                                      </DropdownMenuItem>
                                    )}
                                    <DropdownMenuItem className="cursor-pointer" onSelect={() => setVendorForm({ vendor })}>
                                      <Pencil className="h-4 w-4" />
                                      Edit
                                    </DropdownMenuItem>
                                    <DropdownMenuSeparator />
                                    <DropdownMenuItem variant="destructive" className="cursor-pointer" onSelect={() => setDeleting(vendor)}>
                                      <Trash2 className="h-4 w-4" />
                                      Delete
                                    </DropdownMenuItem>
                                  </DropdownMenuContent>
                                </DropdownMenu>
                              </div>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
                <ScrollBar orientation="horizontal" />
              </ScrollArea>
            )}
          </SectionCard>
        </div>

        <SectionCard title="Questionnaire preview" description="What an owner or a vendor is asked. Read-only.">
          {previewArea ? (
            <div className="space-y-5">
              <Field label="Area" htmlFor="evidence-preview-area">
                <Select value={previewArea.area_key} onValueChange={setPreviewKey}>
                  <SelectTrigger id="evidence-preview-area" className="w-full cursor-pointer" data-testid="evidence-preview-area">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {areas.map((a) => (
                      <SelectItem key={a.area_key} value={a.area_key} className="cursor-pointer">
                        {a.title}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </Field>
              <QuestionnairePreview area={previewArea} />
            </div>
          ) : (
            <p className="text-sm text-zinc-500">No questionnaire to preview yet.</p>
          )}
        </SectionCard>
      </div>

      {editingArea && (
        <AreaDialog
          key={editingArea.id}
          teamId={teamId}
          area={editingArea}
          vendorCount={vendors.length}
          today={today}
          maxEvidenceDate={maxEvidenceDate}
          onClose={() => setEditingArea(null)}
          onSaved={invalidate}
        />
      )}

      {vendorForm && (
        <VendorDialog
          key={vendorForm.vendor?.id ?? "new"}
          teamId={teamId}
          vendor={vendorForm.vendor}
          onClose={() => setVendorForm(null)}
          onSaved={invalidate}
        />
      )}

      {viewing && (
        <VendorAnswersDialog
          key={viewing.id}
          teamId={teamId}
          vendor={viewing}
          questions={viewingQuestions}
          onClose={() => setViewing(null)}
          onSaved={invalidate}
        />
      )}

      <Dialog open={!!createdLink} onOpenChange={(v) => !v && setCreatedLink(null)}>
        <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Questionnaire link for {createdLink?.vendorName}</DialogTitle>
            <DialogDescription>Copy this link now; it is shown only once. Send it to the vendor yourself.</DialogDescription>
          </DialogHeader>
          {createdLink && (
            <div className="space-y-4 min-w-0">
              <div className="flex items-start gap-2">
                <code
                  data-testid="vendor-link-url"
                  className="flex-1 min-w-0 break-all rounded-md border bg-zinc-50 dark:bg-zinc-950 p-2 text-xs"
                >
                  {createdLink.url}
                </code>
                <CopyButton text={createdLink.url} />
              </div>
              <p className="text-sm text-zinc-600 dark:text-zinc-400">
                Opens a page that asks the questions below; no login needed. The link works once and expires in 14 days. Creating
                another link for this vendor stops this one working.
              </p>
              {linkArea && (
                <ol className="list-decimal pl-5 space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
                  {linkArea.questions.map((q) => (
                    <li key={q.id}>{q.prompt}</li>
                  ))}
                </ol>
              )}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" className="cursor-pointer" onClick={() => setCreatedLink(null)}>
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!relinking}
        onOpenChange={(v) => !v && setRelinking(null)}
        title="Create a new link?"
        description={
          relinking
            ? relinking.status === "answered"
              ? `${relinking.name} has already answered. A new link clears their answers and puts them back to Q0 until they answer it.`
              : `The link you created on ${shortDate(relinking.link_created_at)} stops working. Send the new link to ${relinking.name} yourself.`
            : ""
        }
        confirmLabel="Create new link"
        destructive={relinking?.status === "answered"}
        pending={linkMutation.isPending}
        onConfirm={() => relinking && linkMutation.mutate(relinking)}
      />

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(v) => !v && setDeleting(null)}
        title="Delete vendor?"
        description={
          deleting
            ? `${deleting.name} is removed with any answers they gave. Their questionnaire link stops working.`
            : ""
        }
        confirmLabel="Delete"
        destructive
        pending={deleteMutation.isPending}
        onConfirm={() => deleting && deleteMutation.mutate(deleting)}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------- read-only preview
function QuestionnairePreview({ area }: { area: CbomEvidenceArea }) {
  return (
    <fieldset disabled className="space-y-5" aria-label={`Preview of ${area.title}`}>
      {area.questions.map((q) => (
        <div key={q.id} className="space-y-2">
          <Label htmlFor={`preview-${area.area_key}-${q.id}`} className="leading-snug">
            {q.prompt}
          </Label>
          {q.type === "choice" ? (
            <div role="radiogroup" aria-label={q.prompt} className="flex flex-wrap gap-4">
              {CHOICES.map((c) => (
                <label key={c.value} className="flex items-center gap-2 text-sm text-zinc-700 dark:text-zinc-300">
                  <input type="radio" name={`preview-${area.area_key}-${q.id}`} className="h-4 w-4 accent-blue-600" disabled />
                  {c.label}
                </label>
              ))}
            </div>
          ) : (
            <Textarea id={`preview-${area.area_key}-${q.id}`} disabled placeholder="Answer" className="min-h-[64px]" />
          )}
        </div>
      ))}
      <div className="space-y-2">
        <Label htmlFor={`preview-${area.area_key}-evidence`}>Link to supporting evidence (optional)</Label>
        <Input id={`preview-${area.area_key}-evidence`} disabled placeholder="https://" />
        <p className="text-xs text-zinc-500">A policy, certificate or report. Documented (Q2) and Verified (Q3) need one.</p>
      </div>
      <p className="text-xs text-zinc-500">Evidence older than 12 months drops back to Q0 until renewed.</p>
    </fieldset>
  );
}

// ---------------------------------------------------------------------------- area dialog
type AreaErrors = Partial<Record<"owner" | "confidence" | "evidence_url" | "evidence_date" | "due_date", string>>;

function AreaDialog({
  teamId,
  area,
  vendorCount,
  today,
  maxEvidenceDate,
  onClose,
  onSaved,
}: {
  teamId: number;
  area: CbomEvidenceArea;
  vendorCount: number;
  today: string | null;
  maxEvidenceDate: string | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  // Mounted with key={area.id}, so the form starts from the saved values without a sync effect.
  const [owner, setOwner] = useState(area.owner ?? "");
  const [answers, setAnswers] = useState<Record<string, string>>(() => ({ ...(area.answers ?? {}) }));
  const [confidence, setConfidence] = useState<CbomConfidence>(area.confidence);
  const [evidenceTitle, setEvidenceTitle] = useState(area.evidence_title ?? "");
  const [evidenceUrl, setEvidenceUrl] = useState(area.evidence_url ?? "");
  const [evidenceDate, setEvidenceDate] = useState(area.evidence_date ?? "");
  const [dueDate, setDueDate] = useState(area.due_date ?? "");
  const [errors, setErrors] = useState<AreaErrors>({});

  const save = useMutation({
    mutationFn: (body: CbomEvidenceAreaWrite) => updateCbomEvidenceArea(teamId, area.area_key, body),
    onSuccess: onClose,
    onError: (err) => {
      // 409: changed elsewhere (it toasts). Close and let the invalidation show the latest version.
      const status = httpStatus(err);
      if (status === 404 || status === 409) onClose();
    },
    onSettled: onSaved,
  });

  const needsDocument = confidence === "Q2" || confidence === "Q3";
  const stale =
    needsDocument && today && isValidDay(evidenceDate) && daysBetween(evidenceDate, today) > EVIDENCE_MAX_AGE_DAYS;

  const submit = () => {
    const next: AreaErrors = {};
    const urlProblem = urlError(evidenceUrl);
    if (urlProblem) next.evidence_url = urlProblem;
    if (evidenceDate && !isValidDay(evidenceDate)) next.evidence_date = "Use a date like 2026-11-07";
    else if (evidenceDate && maxEvidenceDate && evidenceDate > maxEvidenceDate) next.evidence_date = "The evidence date cannot be in the future";
    if (dueDate && !isValidDay(dueDate)) next.due_date = "Use a date like 2026-11-07";
    if (needsDocument) {
      if (!evidenceTitle.trim() && !evidenceUrl.trim()) next.confidence = "Documented and Verified need an evidence document: add its title or link";
      if (!evidenceDate && !next.evidence_date) next.evidence_date = "Enter the date of the evidence document";
    }
    if (Object.keys(next).length) {
      setErrors(next);
      return;
    }
    setErrors({});

    // Send only what changed, so the audit log names the fields that really changed.
    const body: CbomEvidenceAreaWrite = {};
    const ownerNext = owner.trim() || null;
    if (ownerNext !== (area.owner ?? null)) body.owner = ownerNext;
    if (confidence !== area.confidence) body.confidence = confidence;
    const answersNext = cleanAnswers(area.questions, answers);
    if (!sameAnswers(answersNext, cleanAnswers(area.questions, area.answers ?? {}))) body.answers = answersNext;
    const titleNext = evidenceTitle.trim() || null;
    if (titleNext !== (area.evidence_title ?? null)) body.evidence_title = titleNext;
    const urlNext = evidenceUrl.trim() || null;
    if (urlNext !== (area.evidence_url ?? null)) body.evidence_url = urlNext;
    const dateNext = evidenceDate || null;
    if (dateNext !== (area.evidence_date ?? null)) body.evidence_date = dateNext;
    const dueNext = dueDate || null;
    if (dueNext !== (area.due_date ?? null)) body.due_date = dueNext;
    if (Object.keys(body).length === 0) {
      onClose();
      return;
    }
    save.mutate({ ...body, expected_version: area.row_version });
  };

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{area.title}</DialogTitle>
          <DialogDescription>
            Currently <ConfidenceBadge level={area.effective_confidence} />. A missing answer stays Q0 and is never treated as safe.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-6 py-2 min-w-0">
          <Field label="Owner" htmlFor="evidence-owner" hint={area.owner_hint ? `Usually: ${area.owner_hint}` : undefined} error={errors.owner}>
            <Input
              id="evidence-owner"
              data-testid="evidence-owner"
              value={owner}
              maxLength={128}
              placeholder={area.owner_hint ?? "Name or role"}
              onChange={(e) => setOwner(e.target.value)}
            />
          </Field>

          <div className="space-y-4">
            <h3 className="text-sm font-medium text-zinc-900 dark:text-white">Questions</h3>
            {area.questions.map((q) =>
              q.type === "choice" ? (
                <Field
                  key={q.id}
                  label={q.prompt}
                  hint={
                    answers[q.id] ? (
                      <button
                        type="button"
                        className="text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
                        onClick={() => setAnswers({ ...answers, [q.id]: "" })}
                      >
                        Clear this answer
                      </button>
                    ) : undefined
                  }
                >
                  <ChoiceCards
                    name={`evidence-${area.area_key}-${q.id}`}
                    label={q.prompt}
                    columns={3}
                    value={answers[q.id] ?? ""}
                    onChange={(v) => setAnswers({ ...answers, [q.id]: v })}
                    options={CHOICES.map((c) => ({ value: c.value, title: c.label }))}
                  />
                </Field>
              ) : (
                <Field key={q.id} label={q.prompt} htmlFor={`evidence-${area.area_key}-${q.id}`}>
                  <Textarea
                    id={`evidence-${area.area_key}-${q.id}`}
                    data-testid={`evidence-answer-input-${q.id}`}
                    value={answers[q.id] ?? ""}
                    maxLength={MAX_ANSWER}
                    className="min-h-[72px]"
                    onChange={(e) => setAnswers({ ...answers, [q.id]: e.target.value })}
                  />
                </Field>
              ),
            )}
          </div>

          <Field
            label="Confidence"
            htmlFor="evidence-confidence"
            hint="Documented and Verified need an evidence document and its date"
            error={errors.confidence}
          >
            <Select value={confidence} onValueChange={(v) => setConfidence(v as CbomConfidence)}>
              <SelectTrigger id="evidence-confidence" className="w-full cursor-pointer" data-testid="evidence-confidence">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LEVELS.map((q) => (
                  <SelectItem key={q} value={q} className="cursor-pointer">
                    {q} {CONFIDENCE_LABEL[q]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
          {area.area_key === VENDOR_AREA && vendorCount > 0 && (
            <p className="text-xs text-zinc-500 -mt-4">
              While you have vendors, this area shows the lowest confidence among their answers.
            </p>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Field label="Evidence title" htmlFor="evidence-title" hint="For example: Key management policy v3 (PDF)">
              <Input id="evidence-title" value={evidenceTitle} maxLength={200} onChange={(e) => setEvidenceTitle(e.target.value)} />
            </Field>
            <Field label="Evidence link" htmlFor="evidence-url" hint="http:// or https:// link to the document" error={errors.evidence_url}>
              <Input
                id="evidence-url"
                data-testid="evidence-url"
                value={evidenceUrl}
                maxLength={1000}
                placeholder="https://"
                onChange={(e) => setEvidenceUrl(e.target.value)}
              />
            </Field>
            <Field
              label="Evidence date"
              htmlFor="evidence-date"
              hint={
                stale ? (
                  <span className="text-amber-600 dark:text-amber-400">Older than 12 months: it counts as Q0 until renewed</span>
                ) : (
                  "Date of the document. Evidence older than 12 months drops back to Q0 until renewed."
                )
              }
              error={errors.evidence_date}
            >
              <Input
                id="evidence-date"
                type="date"
                value={evidenceDate}
                max={maxEvidenceDate ?? undefined}
                onChange={(e) => setEvidenceDate(e.target.value)}
              />
            </Field>
            <Field label="Due date" htmlFor="evidence-due" hint="When the owner should answer by" error={errors.due_date}>
              <Input id="evidence-due" type="date" value={dueDate} onChange={(e) => setDueDate(e.target.value)} />
            </Field>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>
            Cancel
          </Button>
          <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending} onClick={submit} data-testid="evidence-save">
            {save.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------- vendor dialogs
function VendorDialog({
  teamId,
  vendor,
  onClose,
  onSaved,
}: {
  teamId: number;
  vendor: CbomVendor | null;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState(vendor?.name ?? "");
  const [email, setEmail] = useState(vendor?.contact_email ?? "");
  const [errors, setErrors] = useState<{ name?: string; email?: string }>({});

  const save = useMutation({
    mutationFn: () =>
      vendor
        ? updateCbomVendor(teamId, vendor.id, {
            name: name.trim(),
            contact_email: email.trim() || null,
            expected_version: vendor.row_version,
          })
        : createCbomVendor(teamId, { name: name.trim(), contact_email: email.trim() || null }),
    onSuccess: onClose,
    onError: (err) => {
      const status = httpStatus(err);
      if (status === 404 || status === 409) onClose();
    },
    onSettled: onSaved,
  });

  const submit = () => {
    const next: { name?: string; email?: string } = {};
    if (!name.trim()) next.name = "Enter the vendor's name";
    else if (name.trim().length > 128) next.name = "Use at most 128 characters";
    if (email.trim() && !EMAIL_RE.test(email.trim())) next.email = "Enter a valid email address";
    setErrors(next);
    if (Object.keys(next).length) return;
    save.mutate();
  };

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{vendor ? `Edit ${vendor.name}` : "Add vendor"}</DialogTitle>
          <DialogDescription>
            After saving, create a single-use link and send it to the vendor yourself. ZeroShield does not email anyone.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <Field label="Vendor name" htmlFor="vendor-name" required error={errors.name}>
            <Input
              id="vendor-name"
              data-testid="vendor-name"
              value={name}
              maxLength={128}
              placeholder="Core banking vendor"
              onChange={(e) => setName(e.target.value)}
            />
          </Field>
          <Field label="Contact email (optional)" htmlFor="vendor-email" hint="For your records only" error={errors.email}>
            <Input
              id="vendor-email"
              data-testid="vendor-email"
              type="email"
              value={email}
              maxLength={254}
              placeholder="security@vendor.example"
              onChange={(e) => setEmail(e.target.value)}
            />
          </Field>
        </div>
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>
            Cancel
          </Button>
          <Button className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer" disabled={save.isPending} onClick={submit} data-testid="vendor-save">
            {save.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            {vendor ? "Save" : "Add vendor"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function VendorAnswersDialog({
  teamId,
  vendor,
  questions,
  onClose,
  onSaved,
}: {
  teamId: number;
  vendor: CbomVendor;
  questions: CbomEvidenceQuestion[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const [confidence, setConfidence] = useState<CbomConfidence>(vendorLevel(vendor));
  const href = safeHref(vendor.evidence_url);

  const save = useMutation({
    mutationFn: () => updateCbomVendor(teamId, vendor.id, { confidence, expected_version: vendor.row_version }),
    onSuccess: onClose,
    onError: (err) => {
      const status = httpStatus(err);
      if (status === 404 || status === 409) onClose();
    },
    onSettled: onSaved,
  });

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Answers from {vendor.name}</DialogTitle>
          <DialogDescription>Answered {shortDate(vendor.answered_at)}. Shown exactly as the vendor typed them.</DialogDescription>
        </DialogHeader>
        <div className="space-y-5 py-2 min-w-0">
          <dl className="space-y-4 text-sm">
            {questions.map((q) => (
              <div key={q.id}>
                <dt className="font-medium text-zinc-900 dark:text-white">{q.prompt}</dt>
                <dd
                  className={
                    vendor.answers?.[q.id]
                      ? "mt-1 whitespace-pre-wrap break-words text-zinc-700 dark:text-zinc-300"
                      : "mt-1 text-zinc-500"
                  }
                >
                  {answerText(q, vendor.answers?.[q.id])}
                </dd>
              </div>
            ))}
            <div>
              <dt className="font-medium text-zinc-900 dark:text-white">Supporting evidence</dt>
              <dd className="mt-1 break-all">
                {href ? (
                  <a href={href} target="_blank" rel="noopener noreferrer" className="text-blue-600 dark:text-blue-400 hover:underline">
                    {href}
                  </a>
                ) : vendor.evidence_url ? (
                  <span className="text-zinc-700 dark:text-zinc-300">{vendor.evidence_url}</span>
                ) : (
                  <span className="text-zinc-500">No link given</span>
                )}
              </dd>
            </div>
          </dl>
          <Field
            label="Confidence"
            htmlFor="vendor-confidence"
            hint="Set to Q1 when answered, or Q2 when the vendor gave an evidence link. Raise it to Q3 once you have verified the evidence."
          >
            <Select value={confidence} onValueChange={(v) => setConfidence(v as CbomConfidence)}>
              <SelectTrigger id="vendor-confidence" className="w-full cursor-pointer" data-testid="vendor-confidence">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LEVELS.map((q) => (
                  <SelectItem key={q} value={q} className="cursor-pointer">
                    {q} {CONFIDENCE_LABEL[q]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>
        </div>
        <DialogFooter>
          <Button variant="outline" className="cursor-pointer" onClick={onClose}>
            Close
          </Button>
          <Button
            className="bg-blue-600 hover:bg-blue-700 text-white cursor-pointer"
            disabled={save.isPending || confidence === vendorLevel(vendor)}
            onClick={() => save.mutate()}
            data-testid="vendor-confidence-save"
          >
            {save.isPending && <Loader2 className="h-4 w-4 mr-2 animate-spin" />}
            Save confidence
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
