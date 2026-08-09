"use client";

/**
 * Shared React Flow canvas for AIBOM + CBOM dependency graphs.
 * Compact Card and fullscreen Dialog both embed this component.
 */

import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type RefObject,
} from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  MarkerType,
  useReactFlow,
  ReactFlowProvider,
  type ColorMode,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { BomGraph, BomGraphNode, BomLane } from "./types";
import { layoutBomGraph, REL_LABEL_AIBOM, REL_LABEL_CBOM } from "./layout";

/** Sync React Flow colorMode to the app's class-based dark theme. */
function useAppColorMode(): ColorMode {
  const [mode, setMode] = useState<ColorMode>("light");
  useEffect(() => {
    const root = document.documentElement;
    const sync = () =>
      setMode(root.classList.contains("dark") ? "dark" : "light");
    sync();
    const mo = new MutationObserver(sync);
    mo.observe(root, { attributes: true, attributeFilter: ["class"] });
    return () => mo.disconnect();
  }, []);
  return mode;
}

/**
 * Theme-aware Controls chrome.
 * Default xyflow light mode uses `color: inherit` — under app `.dark` that
 * yields near-white icons on #fefefe buttons (invisible on the dotted grid).
 */
const CONTROLS_CLASS =
  "!overflow-hidden !rounded-md !border !shadow-md " +
  "!border-zinc-300 !bg-zinc-100 " +
  "dark:!border-zinc-600/80 dark:!bg-zinc-900 " +
  "[&_.react-flow__controls-button]:!h-7 [&_.react-flow__controls-button]:!w-7 " +
  "[&_.react-flow__controls-button]:!bg-zinc-100 [&_.react-flow__controls-button]:!text-zinc-800 " +
  "[&_.react-flow__controls-button]:!border-zinc-300 " +
  "dark:[&_.react-flow__controls-button]:!bg-zinc-900 dark:[&_.react-flow__controls-button]:!text-zinc-100 " +
  "dark:[&_.react-flow__controls-button]:!border-zinc-700 " +
  "[&_.react-flow__controls-button:hover]:!bg-zinc-200 [&_.react-flow__controls-button:hover]:!text-zinc-950 " +
  "dark:[&_.react-flow__controls-button:hover]:!bg-zinc-800 dark:[&_.react-flow__controls-button:hover]:!text-white " +
  "[&_.react-flow__controls-button]:!outline-none " +
  "[&_.react-flow__controls-button:focus-visible]:!ring-2 " +
  "[&_.react-flow__controls-button:focus-visible]:!ring-zinc-400 " +
  "[&_.react-flow__controls-button:focus-visible]:!ring-offset-1 " +
  "[&_.react-flow__controls-button:focus-visible]:!ring-offset-zinc-50 " +
  "dark:[&_.react-flow__controls-button:focus-visible]:!ring-offset-zinc-950 " +
  "[&_.react-flow__controls-button_svg]:!fill-current";

const MINIMAP_CLASS =
  "!overflow-hidden !rounded-md !border !shadow-md " +
  "!border-zinc-300 !bg-zinc-50 " +
  "dark:!border-zinc-600/80 dark:!bg-zinc-800";

/** MiniMap node fill from lane colors already on node.style.background. */
function minimapNodeColor(node: Node): string {
  const bg = node.style?.background;
  return typeof bg === "string" && bg.length > 0 ? bg : "#71717a";
}

function FitOnOpen({ enabled }: { enabled: boolean }) {
  const { fitView } = useReactFlow();
  useEffect(() => {
    if (!enabled) return;
    const run = () => fitView({ padding: 0.15, duration: 200 });
    // Dialog open animates size; fit once after paint and again shortly after.
    const raf = window.requestAnimationFrame(run);
    const t = window.setTimeout(run, 120);
    return () => {
      window.cancelAnimationFrame(raf);
      window.clearTimeout(t);
    };
  }, [enabled, fitView]);
  return null;
}

/** Re-fit when THIS canvas shell gains a real size (Dialog flex layout). */
function FitOnResize({
  enabled,
  target,
}: {
  enabled: boolean;
  target: RefObject<HTMLDivElement | null>;
}) {
  const { fitView } = useReactFlow();
  useEffect(() => {
    if (!enabled) return;
    const el = target.current;
    if (!el || typeof ResizeObserver === "undefined") return;
    let lastH = 0;
    const ro = new ResizeObserver((entries) => {
      const h = entries[0]?.contentRect.height ?? 0;
      if (h < 40) return;
      if (Math.abs(h - lastH) < 8) return;
      lastH = h;
      fitView({ padding: 0.15, duration: 160 });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [enabled, fitView, target]);
  return null;
}

function CanvasInner({
  graph,
  lane,
  styleFor,
  relLabel,
  interactive,
  showMiniMap,
  fitOnMount,
  className,
  minZoom,
}: {
  graph: BomGraph;
  lane: BomLane;
  styleFor?: (n: BomGraphNode) => CSSProperties;
  relLabel?: (rel: string) => string;
  interactive: boolean;
  showMiniMap: boolean;
  fitOnMount: boolean;
  className?: string;
  minZoom: number;
}) {
  const shellRef = useRef<HTMLDivElement>(null);
  const colorMode = useAppColorMode();
  const defaultRel = lane === "cbom" ? REL_LABEL_CBOM : REL_LABEL_AIBOM;
  const { nodes, edges } = useMemo(() => {
    const laid = layoutBomGraph(graph, lane, defaultRel);
    // Re-apply caller styles when provided (kind/asset colors from wrappers).
    const byId = new Map((graph.nodes ?? []).map((n) => [n.id, n]));
    const nodes: Node[] = laid.nodes.map((rn) => {
      const src = byId.get(rn.id);
      if (!(src && styleFor)) return rn;
      // Keep explicit width/height — MiniMap requires them on the user node.
      return {
        ...rn,
        width: rn.width,
        height: rn.height,
        style: { ...styleFor(src), width: rn.width, height: rn.height },
      };
    });
    const edges: Edge[] = laid.edges.map((e) => ({
      ...e,
      label: relLabel ? relLabel(String(e.label ?? "")) : e.label,
      // relLabel above receives the already-humanized label; prefer raw rel:
      markerEnd: { type: MarkerType.ArrowClosed },
    }));
    // Fix labels from raw edge rels
    const rawEdges = graph.edges ?? [];
    const labeled: Edge[] = rawEdges.map((e, i) => ({
      id: `e${i}-${e.source}-${e.target}`,
      source: e.source,
      target: e.target,
      label: (relLabel ? relLabel(e.rel) : defaultRel[e.rel]) ?? e.rel,
      animated: e.rel === "deployed_at",
      markerEnd: { type: MarkerType.ArrowClosed },
      style: { stroke: "#a1a1aa" },
      labelStyle: { fontSize: 10, fill: "#71717a" },
    }));
    return { nodes, edges: labeled.length ? labeled : edges };
  }, [graph, lane, defaultRel, styleFor, relLabel]);

  if (nodes.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-sm text-zinc-500">
        No graph nodes to display
      </div>
    );
  }

  return (
    <div ref={shellRef} className={className ?? "h-full w-full"}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        minZoom={minZoom}
        maxZoom={1.75}
        colorMode={colorMode}
        proOptions={{ hideAttribution: true }}
        nodesDraggable={interactive}
        nodesConnectable={false}
        elementsSelectable={interactive}
      >
        <Background gap={16} className="text-zinc-200 dark:text-zinc-800" />
        <Controls
          showInteractive={interactive}
          className={CONTROLS_CLASS}
          aria-label="Graph viewport controls"
        />
        {showMiniMap && (
          <MiniMap
            pannable
            zoomable
            className={MINIMAP_CLASS}
            bgColor={colorMode === "dark" ? "#27272a" : "#fafafa"}
            maskColor={
              colorMode === "dark"
                ? "rgb(9 9 11 / 0.45)"
                : "rgb(244 244 245 / 0.55)"
            }
            maskStrokeColor={colorMode === "dark" ? "#a1a1aa" : "#71717a"}
            maskStrokeWidth={1}
            nodeStrokeColor={colorMode === "dark" ? "#e4e4e7" : "#3f3f46"}
            nodeStrokeWidth={1}
            nodeColor={minimapNodeColor}
            ariaLabel="Graph overview minimap"
          />
        )}
        <FitOnOpen enabled={fitOnMount} />
        <FitOnResize enabled={fitOnMount} target={shellRef} />
      </ReactFlow>
    </div>
  );
}

export function BomGraphCanvas({
  graph,
  lane = "aibom",
  styleFor,
  relLabel,
  interactive = false,
  showMiniMap = false,
  fitOnMount = false,
  heightClass,
  className,
  minZoom = 0.15,
}: {
  graph: BomGraph;
  lane?: BomLane;
  mode?: "compact" | "expanded";
  styleFor?: (n: BomGraphNode) => CSSProperties;
  relLabel?: (rel: string) => string;
  interactive?: boolean;
  showMiniMap?: boolean;
  fitOnMount?: boolean;
  heightClass?: string;
  className?: string;
  /** Compact cards use a higher floor so labels stay readable under fitView. */
  minZoom?: number;
}) {
  const shell =
    className ??
    (heightClass
      ? `${heightClass} w-full rounded-lg border border-zinc-200 bg-zinc-50/50 dark:border-zinc-800 dark:bg-zinc-900/40`
      : "h-full w-full");
  return (
    <ReactFlowProvider>
      <CanvasInner
        graph={graph}
        lane={lane}
        styleFor={styleFor}
        relLabel={relLabel}
        interactive={interactive}
        showMiniMap={showMiniMap}
        fitOnMount={fitOnMount}
        className={shell}
        minZoom={minZoom}
      />
    </ReactFlowProvider>
  );
}

export default BomGraphCanvas;
