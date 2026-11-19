/**
 * Loads the text of an (i) tip area on demand and keeps it for the rest of the session (issue #145). Each area is one
 * literal `import()`, so the bundler emits one small chunk per area and a page downloads only the areas whose tips
 * it renders (content/infotipsBundle.test.ts checks that no page bundles tip text statically).
 *
 * A tiny external store for useSyncExternalStore: tipAreaState() returns the same object until the area's state
 * changes. A failed load (a chunk that could not be fetched, e.g. offline or after a deploy) is not cached: the next
 * loadTipArea() call, on the next hover, focus or tap, tries again.
 */
import type { TipArea } from "./areas";
import type { TipAreaText } from "./types";

type Loader = () => Promise<{ default: TipAreaText }>;

const LOADERS: Record<TipArea, Loader> = {
  scan: () => import("./text/scan"),
  results: () => import("./text/results"),
  sast: () => import("./text/sast"),
  sbom: () => import("./text/sbom"),
  iac: () => import("./text/iac"),
  dast: () => import("./text/dast"),
  aibom: () => import("./text/aibom"),
  mcp: () => import("./text/mcp"),
  llm: () => import("./text/llm"),
  team: () => import("./text/team"),
  settings: () => import("./text/settings"),
  integrations: () => import("./text/integrations"),
  "cbom-scans": () => import("./text/cbom-scans"),
  "cbom-results": () => import("./text/cbom-results"),
  "cbom-grade": () => import("./text/cbom-grade"),
  "cbom-run": () => import("./text/cbom-run"),
  "cbsrc-common": () => import("./text/cbsrc-common"),
  "cbsrc-nodes": () => import("./text/cbsrc-nodes"),
  "cbsrc-servers": () => import("./text/cbsrc-servers"),
  "cbsrc-workloads": () => import("./text/cbsrc-workloads"),
  "cbsrc-cloud": () => import("./text/cbsrc-cloud"),
  "cbsrc-network": () => import("./text/cbsrc-network"),
  "cbsrc-evidence": () => import("./text/cbsrc-evidence"),
  "cbsrc-run": () => import("./text/cbsrc-run"),
  "cbsrc-ssh-ca": () => import("./text/cbsrc-ssh-ca"),
  fleet: () => import("./text/fleet"),
  repos: () => import("./text/repos"),
  export: () => import("./text/export"),
};

export type TipAreaState = { status: "loading" } | { status: "ready"; text: TipAreaText } | { status: "error" };

const states = new Map<TipArea, TipAreaState>();
const inFlight = new Map<TipArea, Promise<TipAreaText>>();
const listeners = new Set<() => void>();
const overrides = new Map<TipArea, Loader>();

function set(area: TipArea, state: TipAreaState) {
  states.set(area, state);
  for (const l of [...listeners]) l();
}

/** The area's state; undefined until something asks for it. The same object until it changes. */
export function tipAreaState(area: TipArea): TipAreaState | undefined {
  return states.get(area);
}

export function subscribeTipAreas(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/** Loads the area once; concurrent callers share the request. Rejects (and forgets the failure) if the chunk fails. */
export function loadTipArea(area: TipArea): Promise<TipAreaText> {
  const state = states.get(area);
  if (state?.status === "ready") return Promise.resolve(state.text);
  const pending = inFlight.get(area);
  if (pending) return pending;
  const loader = overrides.get(area) ?? LOADERS[area];
  const p = loader().then(
    (mod) => {
      inFlight.delete(area);
      set(area, { status: "ready", text: mod.default });
      return mod.default;
    },
    (err: unknown) => {
      inFlight.delete(area);
      set(area, { status: "error" });
      throw err;
    },
  );
  inFlight.set(area, p);
  set(area, { status: "loading" });
  return p;
}

/** Tests only: replace an area's loader (null restores it) and forget what was loaded for it. */
export function setTipAreaLoaderForTests(area: TipArea, loader: Loader | null) {
  if (loader) overrides.set(area, loader);
  else overrides.delete(area);
  states.delete(area);
  inFlight.delete(area);
}
