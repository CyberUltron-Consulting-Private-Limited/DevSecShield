// Render tests of the Fleet tab, run with tsx (no test framework): the sections render in jsdom against a fake API
// that answers at the HTTP layer (the app's own axios instance and API client), so what a test checks is what a
// customer does (click, type, press Escape) and what the server receives.
import "./dom";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AxiosError, type AxiosResponse, type InternalAxiosRequestConfig } from "axios";
import { act, createElement, type ReactElement } from "react";
import { createRoot, type Root } from "react-dom/client";

import http from "@/utils/interceptors";
import { toast } from "@/utils/toast";

export interface Sent {
  method: string;
  url: string;
  params: Record<string, unknown>;
  body: unknown;
}
export interface Reply {
  status?: number;
  data: unknown;
}
type Handler = Reply | ((req: Sent) => Reply);

/** Routes by method and URL pattern (the last matching route wins, so a test can override a default); every request
 * is kept in ``sent``. */
export class FakeApi {
  sent: Sent[] = [];
  private routes: { method: string; pattern: RegExp; handler: Handler }[] = [];

  on(method: string, pattern: RegExp, handler: Handler): this {
    this.routes.push({ method: method.toLowerCase(), pattern, handler });
    return this;
  }

  calls(method: string, pattern: RegExp): Sent[] {
    return this.sent.filter((s) => s.method === method.toLowerCase() && pattern.test(s.url));
  }

  install(): void {
    http.defaults.adapter = async (config: InternalAxiosRequestConfig): Promise<AxiosResponse> => {
      const method = (config.method ?? "get").toLowerCase();
      const url = config.url ?? "";
      let body: unknown = config.data;
      if (typeof body === "string" && body !== "") {
        try {
          body = JSON.parse(body);
        } catch {
          // not JSON: kept as sent
        }
      }
      const req: Sent = { method, url, params: { ...(config.params ?? {}) }, body };
      this.sent.push(req);
      const route = [...this.routes].reverse().find((r) => r.method === method && r.pattern.test(url));
      const reply: Reply = route ? (typeof route.handler === "function" ? route.handler(req) : route.handler) : { status: 404, data: { detail: "Not Found" } };
      const response: AxiosResponse = { data: reply.data, status: reply.status ?? 200, statusText: "", headers: {}, config, request: {} };
      if (response.status >= 400) {
        throw new AxiosError(`Request failed with status code ${response.status}`, "ERR_BAD_REQUEST", config, {}, response);
      }
      return response;
    };
  }
}

let root: Root | null = null;

/** Render an element the way the page does (inside a React Query provider); returns the query client. */
export async function render(element: ReactElement): Promise<QueryClient> {
  const host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root?.render(createElement(QueryClientProvider, { client }, element));
  });
  await settle();
  return client;
}

/** Let effects, queries and timers run (React Query answers on the next ticks). */
export async function settle(ms = 30): Promise<void> {
  for (let i = 0; i < 3; i++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, ms / 3));
    });
  }
}

function accessibleName(el: Element): string {
  return (el.getAttribute("aria-label") ?? el.textContent ?? "").trim();
}

/** The button whose accessible name (aria-label, else its text) matches; fails the test when there is none. */
export function button(name: string | RegExp): HTMLButtonElement {
  const all = [...document.querySelectorAll("button")];
  const hit = all.find((b) => (typeof name === "string" ? accessibleName(b) === name : name.test(accessibleName(b))));
  if (!hit) throw new Error(`no button ${String(name)}; buttons: ${all.map(accessibleName).filter(Boolean).join(" | ")}`);
  return hit;
}

export function maybeButton(name: string | RegExp): HTMLButtonElement | undefined {
  try {
    return button(name);
  } catch {
    return undefined;
  }
}

export function byId<T extends HTMLElement = HTMLInputElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no element #${id}`);
  return el as T;
}

export function byLabel<T extends HTMLElement = HTMLInputElement>(label: string, index = 0): T {
  const all = [...document.querySelectorAll<T>(`[aria-label="${label}"]`)];
  if (!all[index]) throw new Error(`no element labelled ${label} (#${index})`);
  return all[index];
}

export async function click(el: HTMLElement): Promise<void> {
  el.focus();
  await act(async () => {
    el.click();
  });
  await settle();
}

/** Type into an input or textarea as a person does (React listens to the native input event). */
export async function type(el: HTMLInputElement | HTMLTextAreaElement, value: string): Promise<void> {
  const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  await act(async () => {
    Object.getOwnPropertyDescriptor(proto, "value")?.set?.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await settle();
}

/** Press a key on whatever has the focus (Escape closes a dialog). */
export async function press(key: string): Promise<void> {
  const target = document.activeElement ?? document.body;
  await act(async () => {
    target.dispatchEvent(new KeyboardEvent("keydown", { key, bubbles: true, cancelable: true }));
  });
  await settle(60);
}

/** Record the toasts the components raise ({kind, message}), instead of showing them. */
export function spyToasts(): { kind: string; message: string }[] {
  const seen: { kind: string; message: string }[] = [];
  const t = toast as unknown as Record<string, unknown>;
  for (const kind of ["success", "error", "info", "warning", "message"]) {
    t[kind] = (message: unknown) => {
      seen.push({ kind, message: String(message) });
      return 0;
    };
  }
  return seen;
}

export function text(): string {
  return document.body.textContent ?? "";
}

export async function cleanup(): Promise<void> {
  if (root) {
    const r = root;
    await act(async () => r.unmount());
    root = null;
  }
  document.body.innerHTML = "";
}

/** A tiny sequential runner: each case gets a clean document; the process exits 1 if one failed. */
export async function run(cases: [string, () => Promise<void>][], label: string): Promise<never> {
  let failed = 0;
  const only = process.env.ONLY; // run the cases whose name contains this text
  for (const [name, fn] of cases) {
    if (only && !name.includes(only)) continue;
    try {
      await fn();
      console.log(`  ok   ${name}`);
    } catch (err) {
      failed += 1;
      console.log(`  FAIL ${name}\n       ${(err as Error).stack?.split("\n").slice(0, 6).join("\n       ")}`);
    } finally {
      await cleanup();
    }
  }
  console.log(failed ? `${label}: ${failed} of ${cases.length} failed` : `${label}: ${cases.length} passed`);
  process.exit(failed ? 1 : 0);
}
