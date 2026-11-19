/**
 * The PDF export dialog (plan §7) rendered in jsdom against a fake API at the HTTP layer, used the way a customer
 * does: presets tick their sections, an empty severity set or a name in another script blocks Download with a reason,
 * the query sent is exactly the options that differ from the default, a 409 offers "Remove status filter" and the retry
 * works, a second click while the report is being built starts nothing, an error after the dialog was closed is one
 * toast, and a refused build never turns a real options sidebar into its error view.
 * Run (frontend/): npx --yes tsx@4.23.15 components/reports/exportPdfDialog.dom.test.ts
 */
import { FakeApi, button, click, render, run, settle, spyToasts, text, type } from "@/components/cbom/sources/fleet/testing/harness";

import assert from "node:assert/strict";
import { act, createElement, type ReactElement } from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { AppRouterContext } from "next/dist/shared/lib/app-router-context.shared-runtime";
import { PathParamsContext, PathnameContext, SearchParamsContext } from "next/dist/shared/lib/hooks-client-context.shared-runtime";

import { TooltipProvider } from "@/components/ui/tooltip";
import { AiBomOptionsSidebar } from "@/components/ai-bom-options-sidebar";
import http from "@/utils/interceptors";
import type { AIBOMConversationResponse } from "@/utils/backend_api";

import { useExportPdf, type ExportTarget } from "./ExportPdfDialog";

const PDF = () => new Blob(["%PDF-1.7 report"], { type: "application/pdf" });
const json = (detail: string) => new Blob([JSON.stringify({ detail })], { type: "application/json" }); // a blob request's error body
const EXPORT = /\/7\/(\w+)\/scan\/(\d+)\/export$/;

// every saved file, by name (the link the app clicks)
const saved: string[] = [];
HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) {
  saved.push(this.download);
};
localStorage.clear();

function Opener({ target, fileName }: { target: ExportTarget; fileName: string }) {
  const pdf = useExportPdf({ teamId: 7, target, fileName });
  return createElement("div", null,
    createElement("button", { type: "button", onClick: pdf.open, disabled: pdf.pending, "data-testid": "opener" }, pdf.pending ? "Building" : "PDF Report"),
    pdf.dialog);
}
const wrap = (el: ReactElement) => createElement(TooltipProvider, null, el);
const scanOpener = (type: "cbom" | "sast" = "cbom") =>
  wrap(createElement(Opener, { target: { family: "scan", type, scanId: 12 }, fileName: `cbom-report-12.pdf` }));

const q = <T extends HTMLElement = HTMLElement>(sel: string) => document.querySelector(sel) as T | null;
const byTest = <T extends HTMLElement = HTMLElement>(id: string) => q<T>(`[data-testid="${id}"]`);
const dialog = () => byTest("export-pdf-dialog");
const download = () => byTest<HTMLButtonElement>("export-download")!;
/** The checkbox or radio inside the <label> whose text starts with `title`. */
function choice(title: string): HTMLInputElement {
  const label = [...document.querySelectorAll("label")].find((l) => (l.textContent ?? "").trim().startsWith(title));
  const input = label?.querySelector("input");
  if (!input) throw new Error(`no choice "${title}"; labels: ${[...document.querySelectorAll("label")].map((l) => l.textContent).join(" | ")}`);
  return input;
}
const sectionsTicked = () => [...document.querySelectorAll<HTMLInputElement>('[data-testid="export-sections"] input[type=checkbox]')]
  .filter((i) => i.checked).map((i) => i.id.split("-section-")[1]);

async function openDialog() {
  await click(byTest("opener")!);
  assert.ok(dialog(), "the dialog opens");
}

function api(handler?: (url: string, params: Record<string, unknown>) => { status?: number; data: unknown; headers?: Record<string, string> }) {
  const fake = new FakeApi()
    .on("get", EXPORT, (req) => handler?.(req.url, req.params) ?? { data: PDF(), headers: { "x-report-findings": "40/40", "x-report-logo": "none" } });
  fake.install();
  return fake;
}

run([
  ["presets tick their sections (only those this scan type has)", async () => {
    api();
    await render(scanOpener("cbom"));
    await openDialog();
    assert.deepEqual(sectionsTicked(), ["summary", "catalog", "details", "remediation", "mappings", "compliance", "notes"], "Full: every CBOM section, no inventory");
    await click(choice("Executive"));
    assert.deepEqual(sectionsTicked(), ["summary", "compliance"]);
    await click(choice("Technical"));
    assert.deepEqual(sectionsTicked(), ["summary", "catalog", "details", "remediation", "mappings", "notes"]);
    // unticking a section makes the choice custom
    await click(choice("Scan notes"));
    assert.equal(choice("Custom").checked, true, "a hand-made set is Custom");
    assert.equal(choice("Technical").checked, false);
    assert.match(byTest("export-summary")!.textContent!, /^A report with the sections you chose/);
    assert.doesNotMatch(byTest("export-summary")!.textContent!, /\d/, "the summary has no numbers");
    // ticking it back finds the preset again
    await click(choice("Scan notes"));
    assert.equal(choice("Technical").checked, true);
  }],
  ["an empty severity set disables Download, with the reason", async () => {
    api();
    await render(scanOpener());
    await openDialog();
    for (const s of ["critical", "high", "medium", "low"]) await click(byTest(`export-severity-${s}`)!);
    assert.equal(download().disabled, false, "one severity left is fine");
    await click(byTest("export-severity-other")!);
    assert.equal(byTest("export-severity-other")!.getAttribute("aria-pressed"), "false");
    assert.equal(download().disabled, true, "nothing chosen: Download is disabled");
    assert.ok(text().includes("Choose at least one severity"));
    await click(byTest("export-severity-high")!);
    assert.equal(download().disabled, false);
  }],
  ["a name the PDF cannot print shows an error and blocks Download; the counter counts as the server does", async () => {
    api();
    await render(scanOpener());
    await openDialog();
    const name = byTest<HTMLInputElement>("export-prepared_for")!;
    await type(name, "東京銀行");
    assert.ok(text().includes("Prepared for can only use Latin characters for now."), text());
    assert.equal(name.getAttribute("aria-invalid"), "true");
    assert.equal(download().disabled, true);
    await type(name, "  Société Générale  ");
    assert.equal(byTest("export-prepared_for-count")!.textContent, "16/120", "trimmed, NFC");
    assert.equal(download().disabled, false);
    await type(byTest<HTMLInputElement>("export-title")!, "x".repeat(141));
    assert.ok(text().includes("Report title must be 140 characters or fewer."));
    assert.equal(download().disabled, true);
  }],
  ["the query is the options that differ from the default; the file keeps its name; one toast with N of M", async () => {
    const fake = api(() => ({ data: PDF(), headers: { "x-report-findings": "9/40", "x-report-logo": "skipped" } }));
    const toasts = spyToasts();
    await render(scanOpener());
    await openDialog();
    await click(choice("Executive"));
    for (const s of ["medium", "low", "other"]) await click(byTest(`export-severity-${s}`)!);
    await click(choice("Fixed"));
    await click(choice("Ignored"));
    await type(byTest<HTMLInputElement>("export-prepared_for")!, " Acme Bank ");
    await type(byTest<HTMLInputElement>("export-title")!, "Q4 review");
    await click(byTest("export-hide-evidence")!);
    await click(download());
    await settle(60);
    const sent = fake.calls("get", EXPORT);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].url, "/7/cbom/scan/12/export");
    assert.deepEqual(sent[0].params, {
      preset: "executive", severities: "critical,high", statuses: "not_started,in_progress",
      prepared_for: "Acme Bank", title: "Q4 review", hide_evidence: "true",
    });
    assert.deepEqual(saved.splice(0), ["cbom-report-12.pdf"], "the client-built file name");
    assert.deepEqual(toasts.map((t) => [t.kind, t.message]), [["success", "Report downloaded (9 of 40 findings; team logo skipped: it could not be read)"]]);
    assert.equal(dialog(), null, "the dialog closes on success");
    // remembered: preset, sections, label, snippets; never the name, title or filters
    const kept = JSON.parse(localStorage.getItem("zs.export.v1.7.scan")!);
    assert.deepEqual(kept, { preset: "executive", sections: ["summary", "compliance"], label: "confidential", hide_evidence: true });
    await openDialog();
    assert.equal(choice("Executive").checked, true, "the preset comes back");
    assert.equal(byTest<HTMLInputElement>("export-prepared_for")!.value, "", "the name does not");
    assert.equal(byTest("export-severity-low")!.getAttribute("aria-pressed"), "true", "filters do not");
    localStorage.clear();
  }],
  ["defaults send no parameter at all (today's report)", async () => {
    const fake = api();
    await render(scanOpener());
    await openDialog();
    await click(download());
    await settle(60);
    assert.deepEqual(fake.calls("get", EXPORT)[0].params, {});
    saved.length = 0;
    localStorage.clear();
  }],
  ["409: inline error with Remove status filter; the retry works", async () => {
    const fake = api((_url, params) => params.statuses
      ? { status: 409, data: json("Finding statuses aren't available for this scan yet") }
      : { data: PDF(), headers: { "x-report-findings": "40/40", "x-report-logo": "none" } });
    const toasts = spyToasts();
    await render(scanOpener());
    await openDialog();
    await click(choice("Fixed"));
    await click(download());
    await settle(60);
    const error = byTest("export-error")!;
    assert.ok(error, "the error is in the dialog");
    assert.equal(error.getAttribute("data-status"), "409");
    assert.ok(error.textContent!.includes("Finding statuses aren't available for this scan yet"));
    assert.equal(toasts.length, 0, "no toast: the dialog says it");
    assert.ok(dialog(), "the dialog stays open");
    await click(byTest("export-remove-status-filter")!);
    assert.equal(byTest("export-error"), null, "the error is cleared");
    assert.equal(choice("Fixed").checked, true, "every status again");
    await click(download());
    await settle(60);
    const calls = fake.calls("get", EXPORT);
    assert.equal(calls.length, 2);
    assert.equal(calls[1].params.statuses, undefined, "the retry has no status filter");
    assert.deepEqual(toasts.map((t) => t.kind), ["success"]);
    assert.equal(dialog(), null);
    saved.length = 0;
    localStorage.clear();
  }],
  ["429 shows the wait and holds Download until Retry-After; 400 and 503 show the server's words", async () => {
    let reply: { status: number; data: unknown; headers?: Record<string, string> } = { status: 429, data: json("Busy building other reports"), headers: { "retry-after": "2" } };
    api(() => reply);
    await render(scanOpener());
    await openDialog();
    await click(download());
    await settle(60);
    assert.equal(byTest("export-error")!.getAttribute("data-status"), "429");
    assert.match(byTest("export-error")!.textContent!, /Try again in [12] s\./);
    assert.equal(download().disabled, true, "Download waits for Retry-After");
    await settle(2400);
    assert.match(byTest("export-error")!.textContent!, /You can try again now\./);
    assert.equal(download().disabled, false, "then it can be retried");
    reply = { status: 400, data: json("The scan has not finished yet") };
    await click(download());
    await settle(60);
    assert.equal(byTest("export-error")!.getAttribute("data-status"), "400");
    assert.ok(byTest("export-error")!.textContent!.includes("The scan has not finished yet"));
    assert.equal(byTest("export-remove-status-filter"), null, "no status filter to remove");
    reply = { status: 503, data: json("Finding statuses are unavailable right now") };
    await click(choice("Ignored"));
    await click(download());
    await settle(60);
    assert.equal(byTest("export-error")!.getAttribute("data-status"), "503");
    assert.ok(byTest("export-remove-status-filter"), "503 (statuses) also offers to drop the filter");
    localStorage.clear();
  }],
  ["while the report is built a second click starts nothing; closing the dialog keeps the opener busy", async () => {
    const fake = api((_url, params) => (params.label ? { status: 422, data: json("label: unknown value") } : { data: PDF(), headers: {} }));
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const inner = http.defaults.adapter as (c: unknown) => Promise<unknown>;
    let requests = 0;
    http.defaults.adapter = (async (c: unknown) => { requests += 1; await gate; return inner(c); }) as typeof http.defaults.adapter;
    const toasts = spyToasts();
    await render(scanOpener());
    await openDialog();
    await act(async () => {
      download().click();
      download().click(); // a double click
    });
    await settle();
    assert.equal(requests, 1, "one request");
    assert.equal(download().disabled, true, "Download is disabled while building");
    assert.equal(byTest<HTMLButtonElement>("opener")!.disabled, true, "the opener shows it is busy");
    assert.equal(byTest("opener")!.textContent, "Building");
    // closed mid-build: the opener stays busy; the outcome is one toast
    await click(button("Close"));
    assert.equal(dialog(), null);
    assert.equal(byTest<HTMLButtonElement>("opener")!.disabled, true);
    await act(async () => { release(); });
    await settle(60);
    assert.equal(byTest<HTMLButtonElement>("opener")!.disabled, false, "done");
    assert.deepEqual(toasts.map((t) => t.kind), ["success"]);
    assert.deepEqual(saved.splice(0), ["cbom-report-12.pdf"]);
    assert.equal(fake.calls("get", EXPORT).length, 1);
    http.defaults.adapter = inner as typeof http.defaults.adapter;
    localStorage.clear();
  }],
  ["a refusal that ends after the dialog was closed is one error toast", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    api(() => ({ status: 422, data: json("sections: leave nothing this report has") }));
    const inner = http.defaults.adapter as (c: unknown) => Promise<unknown>;
    http.defaults.adapter = (async (c: unknown) => { await gate; return inner(c); }) as typeof http.defaults.adapter;
    const toasts = spyToasts();
    await render(scanOpener());
    await openDialog();
    await click(download());
    await click(button("Close"));
    await act(async () => { release(); });
    await settle(60);
    assert.deepEqual(toasts.map((t) => [t.kind, t.message]), [["error", "The PDF report was not downloaded: sections: leave nothing this report has"]]);
    http.defaults.adapter = inner as typeof http.defaults.adapter;
    localStorage.clear();
  }],
  ["a run: no status filter, no snippet switch; its route and query", async () => {
    const fake = new FakeApi().on("get", /\/runs\/5\/report\.pdf$/, { data: PDF(), headers: { "x-report-findings": "3/3" } });
    fake.install();
    await render(wrap(createElement(Opener, { target: { family: "run", runId: 5 }, fileName: "cbom-sources-run-5-report.pdf" })));
    await openDialog();
    assert.equal(byTest("export-statuses"), null);
    assert.equal(byTest("export-hide-evidence"), null);
    assert.deepEqual(sectionsTicked(), ["summary", "posture", "catalog", "provenance"]);
    await click(choice("Executive"));
    await click(download());
    await settle(60);
    assert.deepEqual(fake.calls("get", /report\.pdf$/)[0].params, { preset: "executive" });
    assert.deepEqual(saved.splice(0), ["cbom-sources-run-5-report.pdf"]);
    localStorage.clear();
  }],
  ["deliverables: Cover options sets the label (remembered) and the name (this session only)", async () => {
    new FakeApi().install();
    const { deliverableCover } = await import("@/utils/reportOptions");
    await render(wrap(createElement(Opener, { target: { family: "deliverable" }, fileName: "unused.pdf" })));
    await openDialog();
    assert.equal(byTest("export-sections"), null);
    assert.equal(byTest("export-title"), null);
    await type(byTest<HTMLInputElement>("export-prepared_for")!, "Acme Bank");
    await click(button(/Use for downloads/));
    assert.equal(dialog(), null);
    assert.equal(deliverableCover(7).prepared_for, "Acme Bank");
    assert.equal(localStorage.getItem("zs.export.v1.7.deliverable"), JSON.stringify({ label: "confidential" }), "the name is never stored");
    await openDialog();
    assert.equal(byTest<HTMLInputElement>("export-prepared_for")!.value, "Acme Bank", "this session's name comes back");
    localStorage.clear();
  }],
  ["a real options sidebar: a refused build stays in the dialog, never the sidebar's error view", async () => {
    api(() => ({ status: 503, data: json("Finding statuses are unavailable right now") }));
    const toasts = spyToasts();
    const scan = { title: "payments", scan_status: "success", scan_metadata: {}, data: [], findings: [] };
    const query = { data: scan, isLoading: false, isError: false, refetch: async () => ({}) } as unknown as UseQueryResult<AIBOMConversationResponse>;
    const noop = () => undefined;
    const router = { push: noop, replace: noop, refresh: noop, back: noop, forward: noop, prefetch: noop };
    const sidebar = createElement(AiBomOptionsSidebar, {
      query, mode: "github", setMode: noop, repo_url: "", setRepoUrl: noop, PAT: "", setPAT: noop, branch: "", setBranch: noop,
    });
    const tree = createElement(AppRouterContext.Provider, { value: router as never },
      createElement(PathnameContext.Provider, { value: "/7/ai_bom/12" },
        createElement(SearchParamsContext.Provider, { value: new URLSearchParams() as never },
          createElement(PathParamsContext.Provider, { value: { team_id: "7", scan_id: "12" } }, wrap(sidebar)))));
    await render(tree);
    await settle(60);
    assert.ok(text().includes("View Results"), "the sidebar is in its done view");
    await click(byTest("sidebar-download-report")!);
    assert.ok(dialog(), "Download Scan Report opens the dialog");
    await click(choice("Fixed"));
    await click(download());
    await settle(60);
    assert.equal(byTest("export-error")!.getAttribute("data-status"), "503", "the error is in the dialog");
    await click(button("Cancel"));
    assert.equal(dialog(), null);
    assert.ok(text().includes("View Results"), "still the done view");
    assert.equal(byTest("scan-try-again"), null, "not the error view");
    assert.ok(!text().includes("Finding statuses are unavailable"), "the sidebar never shows the export error");
    assert.equal(toasts.length, 0, "and no toast: the dialog said it");
    localStorage.clear();
  }],
], "exportPdfDialog.dom.test.ts");
