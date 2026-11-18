/**
 * The Sources-run finding dialog (results redesign F7–F10) rendered in jsdom against a fake API at the HTTP layer, used
 * the way a customer does: the header (risk ring, title, visible subtitle, solid chips), six tabs that all stay mounted
 * (the remediation request is made once, not again on a tab switch), Previous / Next with "n of N" and ←/→ (not in the
 * tab list, not while the AI panel is open), the AI panel inside the dialog (Escape closes it first, then the dialog),
 * the status control (the table's guards), the old-backend Fix & demo note, and no navigation for an asset-only subject.
 * Run (frontend/): npx --yes tsx@4.23.15 components/cbom/results/runFindingDialog.dom.test.ts
 */
import { FakeApi, button, click, press, render, run, settle, text } from "@/components/cbom/sources/fleet/testing/harness";

import assert from "node:assert/strict";
import { act, createElement, useEffect, useState } from "react";

import type { CbomFindingStatus, CbomRunAssetItem } from "@/utils/backend_api";
import { TooltipProvider } from "@/components/ui/tooltip";

import { RunFindingDialog, type DialogNav, type DialogSubject } from "./RunFindingDialog";
import { useDialogNav } from "./useDialogNav";

const kb = (code: string, title: string) => ({
  code, title, observed: `F5 profile accepts ${code}`, description: `why ${code}`, attack: `attack ${code}`, impact: "i", category: "c",
  pqc: null, cwe: [], owasp_2021: [{ id: "A02:2021", label: "A02:2021 Cryptographic Failures", basis: "b" }], owasp_2025: [], cves: [],
  standards: ["RFC 7568"], compliance: [{ framework: "RBI", id: "para 16", text: "Strong ciphers.", source: "https://rbi.org.in", note: null }],
  remediation: { summary: `fix ${code}`, steps: [] }, verify: [{ label: "probe", command: "nmap -p 443 10.0.0.1" }], references: [],
});
const row = (id: number, extra: Partial<CbomRunAssetItem> = {}) => ({
  id, type: "tls_endpoint", cdx_type: "cryptographic-asset", job_id: 7, source_id: 1, source_name: "F5 lab", target: "10.0.0.1",
  location: `10.0.0.1:443#client-ssl /Common/vip-${id}`, name: null, algorithm: null, key_size: null, protocol: "SSLv3",
  quantum_vulnerable: null, impact: "Critical", finding: "accepts SSLv3", finding_codes: ["PROTO_SSLv3", "PROTO_TLS10"], facts: { port: 443 },
  type_label: "Network appliance config", crypto_strength: "weak", risk_score: 8.7, status: "not_started", fix_class: "configurable",
  asset_key: `key-${id}`, ...extra,
}) as unknown as CbomRunAssetItem;
const detail = (id: number) => ({ asset: { ...row(id), pqc_class: "not-applicable", criticality: "medium", details: [kb("PROTO_SSLv3", "SSLv3 accepted"), kb("PROTO_TLS10", "TLS 1.0 accepted")], agility: null, standards: [] } });

function api({ ai = true, remediation = true } = {}) {
  const fake = new FakeApi()
    .on("get", /\/cbom\/sources\/assets\/(\d+)$/, (req) => ({ data: detail(Number(/assets\/(\d+)$/.exec(req.url)![1])) }))
    .on("get", /\/cbom\/ai\/status$/, { data: ai ? { available: true, provider: "bedrock", region: "ap-south-1", model: "m", egress: [{ host: "bedrock-runtime.ap-south-1.amazonaws.com", port: 443, purpose: "x" }] } : { available: false } })
    .on("get", /\/runs\/12\/assets\/\d+\/remediation$/, remediation
      ? { data: { source: "knowledge_base", status: "completed", engine: "kb", kb_version: "2026.11.15.6", code_fix: { available: false, kind: "config", rules: [], notes: [], warnings: [], commands: [], summary: "Disable SSLv3" }, diff: "", exploit_demo: null, details: [] } }
      : { status: 404, data: { detail: "Not Found" } });
  fake.install();
  return fake;
}

const items = [row(1), row(2), row(3)];

function Host({ initial, withNav = true, onSetStatus, onClose }: {
  initial: number; withNav?: boolean; onSetStatus?: (keys: string[], s: CbomFindingStatus) => void; onClose?: () => void;
}) {
  const [subject, setSubject] = useState<DialogSubject | null>({ assetId: initial });
  const ids = items.map((i) => i.id);
  const index = subject ? ids.indexOf(subject.assetId) + 50 : -1; // page 2 of 50 rows
  const nav: DialogNav | undefined = withNav && subject ? {
    ids, index, total: 120, onGo: (i) => setSubject({ assetId: ids[i - 50] }), pageEdge: null,
  } : undefined;
  return createElement(TooltipProvider, null, createElement(RunFindingDialog, {
    teamId: 1, runId: 12, subject, jobs: [{ id: 7, runner: "node", node_name: "lab-node" }] as never, pageItems: items, nav,
    onSetStatus, statusPending: false, priorityOf: (id: number) => (id === 1 ? 10 : null),
    onClose: () => { onClose?.(); setSubject(null); },
  }));
}

const dialog = () => document.querySelector('[data-testid="run-finding-dialog"]') as HTMLElement | null;
const q = (id: string) => document.querySelector(`[data-testid="${id}"]`) as HTMLElement | null;

run([
  ["header, chips, six mounted tabs, overview facts and location", async () => {
    api();
    await render(createElement(Host, { initial: 1 }));
    await settle(90);
    assert.ok(dialog(), "the dialog is open");
    assert.equal(dialog()!.getAttribute("data-severity"), "critical");
    assert.match(dialog()!.className, /border-t-4\b.*border-t-red-500/, "severity-tinted top edge");
    assert.ok(text().includes("Explanation, fix and provenance of this asset"), "visible subtitle");
    assert.equal(q("run-finding-chip-impact")!.textContent, "Critical");
    assert.ok(q("run-finding-chip-priority")!.textContent!.includes("Priority 10"));
    assert.equal(q("run-finding-chip-status")!.textContent, "not started");
    assert.equal(q("run-finding-ring")!.getAttribute("aria-label"), "Risk score 8.7 of 10");
    const tabs = [...document.querySelectorAll('[data-testid^="run-finding-tab-"]')].map((t) => t.textContent);
    assert.deepEqual(tabs, ["Overview", "Issues 2", "Quantum & effort", "Standards", "Fix & demo", "AI"]);
    for (const t of ["overview", "issues-tab", "quantum-tab", "standards-tab", "fix-tab", "ai-tab"]) assert.ok(q(`run-finding-${t}`), `${t} mounted`);
    assert.ok(q("run-finding-location")!.textContent!.includes("10.0.0.1:443#client-ssl /Common/vip-1"), "the stored string");
    assert.ok(q("run-finding-location-table")!.textContent!.includes("Port443"), "the location table");
    assert.equal(q("run-finding-suggested-fix")!.querySelectorAll("li").length, 2, "one step per issue");
    assert.ok(q("run-finding-provenance")!.textContent!.includes("scan node lab-node · job #7 · PROTO_SSLv3, PROTO_TLS10"));
    assert.equal(document.querySelectorAll('[data-testid="kb-standards"]').length, 1, "Standards and regulations once");
  }],
  ["tab switch keeps every panel (one remediation request)", async () => {
    const fake = api();
    await render(createElement(Host, { initial: 1 }));
    await settle(90);
    assert.equal(fake.calls("get", /\/remediation$/).length, 1);
    for (const t of ["fix", "issues", "ai", "overview", "fix"]) {
      await act(async () => {
        q(`run-finding-tab-${t}`)!.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, button: 0 }));
      });
      await settle();
    }
    assert.equal(q("run-finding-tab-fix")!.getAttribute("data-state"), "active", "the Fix & demo tab is active");
    assert.equal(fake.calls("get", /\/remediation$/).length, 1, "no new request on a tab switch");
    assert.ok(q("cbom-status-cards"), "Fix & demo as status cards");
    assert.ok(q("cbom-diff-status")!.textContent!.startsWith("Not available"), "a disabled Diff says why");
  }],
  ["Previous / Next, n of N, arrow keys and the kept tab", async () => {
    const fake = api();
    await render(createElement(Host, { initial: 2 }));
    await settle(90);
    assert.ok(q("run-finding-position")!.textContent!.startsWith("52 of 120"));
    await act(async () => {
      q("run-finding-tab-quantum")!.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, button: 0 }));
    });
    await click(q("run-finding-next")!);
    await settle(60);
    assert.ok(q("run-finding-position")!.textContent!.startsWith("53 of 120"), "Next");
    assert.ok(text().includes("vip-3"), "the next asset's row");
    assert.equal(q("run-finding-tab-quantum")!.getAttribute("data-state"), "active", "the tab is kept");
    assert.equal(fake.calls("get", /\/remediation$/).length, 2, "the new asset's remediation is loaded");
    // ←: focus in the body
    q("run-finding-scroll")!.focus();
    await press("ArrowLeft");
    assert.ok(q("run-finding-position")!.textContent!.startsWith("52 of 120"), "← moves back");
    // in the tab list the arrows move between tabs, not findings
    q("run-finding-tab-quantum")!.focus();
    await press("ArrowLeft");
    assert.ok(q("run-finding-position")!.textContent!.startsWith("52 of 120"), "← in the tab list does not move");
  }],
  ["AI panel inside the dialog: Escape closes it first, then the dialog", async () => {
    api();
    let closed = 0;
    await render(createElement(Host, { initial: 1, onClose: () => { closed += 1; } }));
    await settle(90);
    const sheet = () => q("run-finding-ai-sheet");
    assert.ok(sheet() && sheet()!.hidden, "mounted and hidden");
    await click(q("run-finding-ai-open")!);
    assert.equal(sheet()!.hidden, false, "open");
    assert.ok(sheet()!.contains(document.activeElement), "focus moves into the panel");
    assert.ok(sheet()!.querySelector('[data-testid="cbom-ai-panel"]'), "the AI assistant");
    assert.ok(sheet()!.textContent!.includes("Collected facts"), "and the facts it is given");
    q("run-finding-scroll")!.focus();
    await press("ArrowRight");
    assert.ok(q("run-finding-position")!.textContent!.startsWith("51 of 120"), "no move while the AI panel is open");
    await press("Escape");
    assert.ok(dialog(), "the dialog stays open");
    assert.ok(sheet()!.hidden, "Escape closed the AI panel");
    assert.equal(closed, 0);
    await press("Escape");
    assert.equal(closed, 1, "the next Escape closes the dialog");
  }],
  ["Explanations drawer inside the dialog follows the tab; Escape closes it, not the dialog", async () => {
    api();
    let closed = 0;
    await render(createElement(Host, { initial: 1, onClose: () => { closed += 1; } }));
    await settle(90);
    await act(async () => {
      q("run-finding-tab-standards")!.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, button: 0 }));
    });
    await click(q("run-finding-explanations")!);
    await settle(90);
    const drawer = dialog()!.querySelector('aside[data-testid="infotip-drawer"]') as HTMLElement;
    assert.ok(drawer && !drawer.hidden, "the drawer opens inside the dialog");
    assert.equal(drawer.querySelector("[data-infotip-entry]")!.getAttribute("data-infotip-entry"), "cbom.run.f.compliance", "the Standards tab's tips first");
    q("run-finding-scroll")!.focus();
    await press("Escape");
    assert.ok(dialog() && drawer.hidden && closed === 0, "Escape closed the drawer only");
  }],
  ["status control mirrors the table", async () => {
    api();
    const set: [string[], string][] = [];
    await render(createElement(Host, { initial: 1, onSetStatus: (k, s) => set.push([k, s]) }));
    await settle(90);
    const trigger = q("run-finding-status-action") as HTMLButtonElement;
    assert.equal(trigger.disabled, false);
    trigger.focus();
    await press("Enter");
    const item = q("run-finding-status-in_progress");
    assert.ok(item, "the status menu");
    await click(item!);
    assert.deepEqual(set, [[["key-1"], "in_progress"]]);
  }],
  ["useDialogNav: snapshot from the table, page edge waits for the new page, removed rows keep their slot", async () => {
    api();
    const pages: Record<number, CbomRunAssetItem[]> = { 1: [row(1), row(2)], 2: [row(3), row(4)] };
    const probe: {
      ctl?: { setPlaceholder: (b: boolean) => void; setItems: (i: CbomRunAssetItem[]) => void };
      nav?: DialogNav;
      openTable?: (id: number) => void;
    } = {};
    function Paged() {
      const [page, setPage] = useState(1);
      const [placeholder, setPlaceholder] = useState(false);
      const [items, setItems] = useState(pages[1]);
      const [subject, setSubject] = useState<DialogSubject | null>(null);

      const { nav, openFromTable } = useDialogNav({
        assetId: subject?.assetId ?? null, open: (id) => setSubject({ assetId: id }), items, page, pageSize: 2, total: 4, placeholder,
        goToPage: (p) => { setPage(p); setPlaceholder(true); },
      });
      useEffect(() => {
        probe.ctl = { setPlaceholder, setItems };
        probe.nav = nav;
        probe.openTable = openFromTable;
      }, [nav, openFromTable]);
      return createElement(TooltipProvider, null, createElement(RunFindingDialog, {
        teamId: 1, runId: 12, subject, jobs: [], pageItems: items, nav, onClose: () => setSubject(null),
      }));
    }
    await render(createElement(Paged));
    await act(async () => probe.openTable!(2));
    await settle(60);
    assert.ok(q("run-finding-position")!.textContent!.startsWith("2 of 4"));
    await click(q("run-finding-next")!);
    assert.equal(probe.nav!.pageEdge, "next", "page edge: waiting for page 2");
    assert.ok(q("run-finding-position")!.textContent!.startsWith("Loading the next page"));
    assert.equal((q("run-finding-next") as HTMLButtonElement).disabled, true);
    // the placeholder (page 1's rows) is not taken for page 2
    await act(async () => probe.ctl!.setItems(pages[1]));
    await settle();
    assert.equal(probe.nav!.pageEdge, "next", "still waiting while the table shows placeholder rows");
    await act(async () => { probe.ctl!.setItems(pages[2]); probe.ctl!.setPlaceholder(false); });
    await settle(60);
    assert.ok(q("run-finding-position")!.textContent!.startsWith("3 of 4"), "landed on page 2's first row");
    // the row leaves the page (a status filter): it keeps its slot and says so
    await act(async () => probe.ctl!.setItems([row(4)]));
    await settle(60);
    assert.ok(q("run-finding-removed"), "removed from view");
    assert.ok(q("run-finding-position")!.textContent!.startsWith("3 of 4"), "the position is kept");
    await click(q("run-finding-next")!);
    assert.ok(q("run-finding-position")!.textContent!.startsWith("4 of 4"), "Next still goes to the following row");
  }],
  ["no navigation for an asset-only subject; old backend Fix & demo note; AI off note", async () => {
    api({ ai: false, remediation: false });
    await render(createElement(Host, { initial: 1, withNav: false }));
    await settle(120);
    assert.equal(q("run-finding-prev"), null);
    assert.equal(q("run-finding-next"), null);
    assert.ok(button("Close"), "Close stays");
    assert.ok(q("run-finding-fix-missing"), "older backend: a one-line note");
    assert.ok(q("run-finding-ai-off"), "AI unavailable: a one-line note");
    assert.equal(q("run-finding-ai-sheet"), null);
  }],
], "run finding dialog DOM");
