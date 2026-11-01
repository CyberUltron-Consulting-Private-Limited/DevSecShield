/**
 * Deterministic layout helpers for BOM dependency graphs.
 * Connected subgraph → dagre; orphan/cluster rail sits to the right.
 */

import dagre from "@dagrejs/dagre";
import type { CSSProperties } from "react";
import type { Edge, Node } from "@xyflow/react";
import type { BomGraph, BomGraphEdge, BomGraphNode, BomLane } from "./types";
import { isClusterNode } from "./types";

const NODE_W = 168;
const NODE_H = 36;

const CBOM_COLS = [
  "certificate",
  "protocol",
  "related-crypto-material",
  "algorithm",
  "library",
  "other",
] as const;

export const AIBOM_KIND_COLOR: Record<string, string> = {
  model: "#6366f1",
  dataset: "#06b6d4",
  framework: "#8b5cf6",
  prompt: "#f59e0b",
  service: "#10b981",
  cloud_service: "#14b8a6",
  endpoint: "#0ea5e9",
  secret: "#ef4444",
  embedding_model: "#a855f7",
};

export const CBOM_ASSET_COLOR: Record<string, string> = {
  algorithm: "#6366f1",
  certificate: "#10b981",
  protocol: "#0ea5e9",
  "related-crypto-material": "#f59e0b",
  library: "#8b5cf6",
  family: "#0f766e",
  location: "#475569",
  other: "#71717a",
};

export const REL_LABEL_AIBOM: Record<string, string> = {
  trained_on: "trained on",
  depends_on: "depends on",
  served_by: "served by",
  deployed_at: "deployed at",
};

export const REL_LABEL_CBOM: Record<string, string> = {
  signatureAlgorithm: "signed with",
  subjectPublicKey: "public key",
  algorithmRef: "produced by",
  cryptoRefArray: "uses",
  algorithms: "uses",
  signed_by: "signed by",
  used_by: "used by",
  provides: "provides",
  contains: "contains",
  declares: "declares",
  is_a: "is a",
};

function assetKey(n: BomGraphNode): string {
  if (n.asset_type) return String(n.asset_type);
  if (n.kind === "framework") return "library";
  return "other";
}

export function nodeStyleFor(
  lane: BomLane,
  n: BomGraphNode
): CSSProperties {
  const bg =
    lane === "cbom"
      ? CBOM_ASSET_COLOR[assetKey(n)] ?? CBOM_ASSET_COLOR.other
      : AIBOM_KIND_COLOR[n.kind] ?? "#71717a";
  const ring =
    lane === "cbom"
      ? n.weak
        ? "#dc2626"
        : n.quantum_vulnerable
          ? "#f97316"
          : "transparent"
      : "transparent";
  const clustered = isClusterNode(n);
  return {
    background: bg,
    color: "white",
    border: `2px solid ${ring === "transparent" && clustered ? "#a1a1aa" : ring}`,
    borderRadius: 8,
    fontSize: 11,
    fontWeight: 600,
    padding: "6px 10px",
    width: NODE_W,
    height: NODE_H,
    opacity: clustered ? 0.92 : 1,
  };
}

function connectedIds(edges: BomGraphEdge[]): Set<string> {
  const s = new Set<string>();
  for (const e of edges) {
    s.add(e.source);
    s.add(e.target);
  }
  return s;
}

export const BOARD_RELS = new Set(["contains", "provides", "declares", "is_a"]);

/** True when a CBOM graph is laid out as a family board (it has algorithm-family nodes). */
export function isFamilyBoard(graph: BomGraph, lane: BomLane): boolean {
  return lane === "cbom" && (graph.nodes ?? []).some((n) => n.kind === "family");
}

/**
 * CBOM "family board": one column per algorithm family (family node on top, its assets stacked below, wrapping
 * after 12 rows), folders in a band above and libraries in a band below.  A dagre layout of the same graph puts
 * every asset in one rank, which renders as a single very tall column once a repository has more than ~20 assets.
 * Returns null when the graph has no family nodes (older scans), so the dagre layout is used.
 */
function cbomFamilyBoard(gn: BomGraphNode[], ge: BomGraphEdge[]): Map<string, { x: number; y: number }> | null {
  const families = gn.filter((n) => n.kind === "family");
  if (families.length === 0) return null;
  const COLW = NODE_W + 36;
  const ROWH = NODE_H + 14;
  const MAX_ROWS = 12;
  const famOf = new Map<string, string>();
  for (const e of ge) if (e.rel === "is_a") famOf.set(e.source, e.target);
  const members = new Map<string, BomGraphNode[]>(families.map((f) => [f.id, []]));
  for (const n of gn) {
    const f = famOf.get(n.id);
    if (f && members.has(f) && n.kind !== "family") members.get(f)!.push(n);
  }
  const placed = new Set<string>();
  const pos = new Map<string, { x: number; y: number }>();
  // widths first, so the folder and library bands can wrap at the board width
  const cols = families.map((f) => Math.max(1, Math.ceil((members.get(f.id)?.length ?? 0) / MAX_ROWS)));
  const boardCols = Math.max(4, cols.reduce((a, b) => a + b, 0));
  const band = (nodes: BomGraphNode[], top: number): number => {
    nodes.forEach((n, i) => {
      pos.set(n.id, { x: 24 + (i % boardCols) * COLW, y: top + Math.floor(i / boardCols) * ROWH });
      placed.add(n.id);
    });
    return nodes.length ? Math.ceil(nodes.length / boardCols) * ROWH : 0;
  };
  const folders = gn.filter((n) => n.kind === "location");
  const libraries = gn.filter((n) => n.kind === "framework" || n.asset_type === "library");
  let y = 24;
  y += band(folders, y);
  if (folders.length) y += ROWH;
  const famTop = y;
  let x = 24;
  let tallest = 0;
  families.forEach((f, k) => {
    pos.set(f.id, { x, y: famTop });
    placed.add(f.id);
    const list = members.get(f.id) ?? [];
    list.forEach((m, i) => {
      if (placed.has(m.id)) return;
      pos.set(m.id, { x: x + Math.floor(i / MAX_ROWS) * COLW, y: famTop + Math.round(ROWH * 1.4) + (i % MAX_ROWS) * ROWH });
      placed.add(m.id);
    });
    tallest = Math.max(tallest, Math.min(list.length, MAX_ROWS));
    x += cols[k] * COLW + 24;
  });
  y = famTop + Math.round(ROWH * 1.4) + tallest * ROWH + ROWH;
  y += band(libraries.filter((n) => !placed.has(n.id)), y);
  // anything else (certificate/key lineage without a family): one more band at the bottom
  band(gn.filter((n) => !placed.has(n.id)), y + (libraries.length ? ROWH : 0));
  return pos;
}

/** Dagre LR on the connected component; orphan rail on the right (CBOM detailed graphs: family board). */
export function layoutBomGraph(
  graph: BomGraph,
  lane: BomLane,
  relLabels: Record<string, string>
): { nodes: Node[]; edges: Edge[] } {
  const gn = graph.nodes ?? [];
  const ge = graph.edges ?? [];
  if (gn.length === 0) return { nodes: [], edges: [] };

  const touched = connectedIds(ge);
  const connected = gn.filter((n) => touched.has(n.id));
  const orphans = gn.filter((n) => !touched.has(n.id));

  const board = lane === "cbom" ? cbomFamilyBoard(gn, ge) : null;
  const positions = board ?? new Map<string, { x: number; y: number }>();

  if (board) {
    // family board placed every node
  } else if (connected.length > 0) {
    const g = new dagre.graphlib.Graph();
    g.setDefaultEdgeLabel(() => ({}));
    g.setGraph({ rankdir: "LR", nodesep: 28, ranksep: 72, marginx: 24, marginy: 24 });
    for (const n of connected) {
      g.setNode(n.id, { width: NODE_W, height: NODE_H });
    }
    for (const e of ge) {
      if (touched.has(e.source) && touched.has(e.target) && e.source !== e.target) {
        g.setEdge(e.source, e.target);
      }
    }
    dagre.layout(g);
    for (const n of connected) {
      const p = g.node(n.id);
      if (p) {
        positions.set(n.id, {
          x: p.x - NODE_W / 2,
          y: p.y - NODE_H / 2,
        });
      }
    }
  } else if (lane === "cbom") {
    // No edges — fall back to compact columns for orphan rail only.
    const perCol: Record<number, number> = {};
    for (const n of gn) {
      const col = Math.max(0, CBOM_COLS.indexOf(assetKey(n) as (typeof CBOM_COLS)[number]));
      const idx = col === -1 ? CBOM_COLS.length - 1 : col;
      const row = perCol[idx] ?? 0;
      perCol[idx] = row + 1;
      positions.set(n.id, { x: 40 + idx * 200, y: 24 + row * 56 });
    }
  } else {
    // AIBOM empty-edge fallback: stack by kind.
    gn.forEach((n, i) => {
      positions.set(n.id, { x: 40, y: 24 + i * 56 });
    });
  }

  // Orphan / cluster rail to the right of the connected dagre box.
  let maxX = 0;
  for (const p of positions.values()) {
    maxX = Math.max(maxX, p.x + NODE_W);
  }
  const railX = connected.length > 0 ? maxX + 80 : 40;
  if (!board) {
    orphans.forEach((n, i) => {
      positions.set(n.id, { x: railX, y: 24 + i * 56 });
    });
  }

  // Explicit width/height are REQUIRED for MiniMap: xyflow gates
  // `.react-flow__minimap-node` on nodeHasDimensions(userNode), which reads
  // width/height/measured/initial* — NOT style.width. Style-only nodes yield
  // an empty MiniMap (solid dark inset under the viewport mask).
  const nodes: Node[] = gn.map((n) => ({
    id: n.id,
    position: positions.get(n.id) ?? { x: 0, y: 0 },
    data: { label: n.label },
    width: NODE_W,
    height: NODE_H,
    style: nodeStyleFor(lane, n),
  }));

  const edges: Edge[] = ge.map((e, i) => ({
    id: `e${i}-${e.source}-${e.target}`,
    source: e.source,
    target: e.target,
    // on the family board the structure is the layout itself; the legend explains it, so no edge labels
    label: board && BOARD_RELS.has(e.rel) ? undefined : relLabels[e.rel] ?? e.rel,
    animated: e.rel === "deployed_at",
    style: board && BOARD_RELS.has(e.rel) ? { stroke: "#a1a1aa", strokeOpacity: 0.45 } : { stroke: "#a1a1aa" },
    labelStyle: { fontSize: 10, fill: "#71717a" },
  }));

  return { nodes, edges };
}

/** Prefer pruned compact/expanded from metadata; fall back to full graph. */
export function pickBomGraph(opts: {
  full?: BomGraph | null;
  compact?: BomGraph | null;
  expanded?: BomGraph | null;
  view?: BomGraph | null;
  mode: "compact" | "expanded";
}): BomGraph {
  const { full, compact, expanded, view, mode } = opts;
  const empty: BomGraph = { nodes: [], edges: [] };
  if (mode === "compact") {
    return compact ?? view ?? full ?? empty;
  }
  return expanded ?? compact ?? view ?? full ?? empty;
}
