"use client";

/**
 * GitHub-diagram style fullscreen Dialog for BOM dependency graphs.
 */

import { useState, type CSSProperties, type ReactNode } from "react";
import { Maximize2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { BomGraphCanvas } from "./BomGraphCanvas";
import type { BomGraph, BomGraphNode, BomLane } from "./types";

export function BomGraphFullscreen({
  graph,
  lane = "aibom",
  title,
  description,
  styleFor,
  relLabel,
  legend,
  triggerClassName,
}: {
  graph: BomGraph;
  lane?: BomLane;
  title: string;
  description?: string;
  styleFor?: (n: BomGraphNode) => CSSProperties;
  relLabel?: (rel: string) => string;
  legend?: ReactNode;
  triggerClassName?: string;
}) {
  const [open, setOpen] = useState(false);
  const n = graph.nodes?.length ?? 0;
  const e = graph.edges?.length ?? 0;
  const raw = graph.meta?.raw_node_count;

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className={triggerClassName ?? "h-8 gap-1.5 text-xs shrink-0"}
          aria-label="Expand dependency graph"
        >
          <Maximize2 className="size-3.5" />
          Expand
        </Button>
      </DialogTrigger>
      <DialogContent
        showCloseButton
        // Explicit height is required: max-h alone lets the flex column
        // shrink-wrap to the header (~75px) and the canvas collapses to 0.
        className="flex h-[90vh] max-h-[92vh] w-[96vw] max-w-[96vw] flex-col gap-0 overflow-hidden p-0 sm:max-w-[96vw]"
      >
        <DialogHeader className="shrink-0 space-y-1 border-b border-zinc-200 px-5 py-3.5 pr-12 dark:border-zinc-800">
          <DialogTitle className="text-base font-semibold tracking-tight text-zinc-900 dark:text-zinc-50">
            {title}
          </DialogTitle>
          <DialogDescription className="text-xs text-zinc-600 dark:text-zinc-400">
            <span className="font-medium text-zinc-700 dark:text-zinc-300">
              {n} nodes · {e} edges
              {raw != null && raw > n ? ` · clustered from ${raw}` : ""}
            </span>
            {description ? (
              <span className="mt-0.5 block text-zinc-500 dark:text-zinc-500">
                {description}
              </span>
            ) : null}
            <span className="mt-1 block text-[11px] text-zinc-500 dark:text-zinc-500">
              Use zoom controls (bottom-left) or scroll to navigate. Lock toggles
              pan/drag.
            </span>
          </DialogDescription>
        </DialogHeader>
        <div className="min-h-0 flex-1 bg-zinc-50/60 p-1 dark:bg-zinc-950/40">
          {open && (
            <BomGraphCanvas
              graph={graph}
              lane={lane}
              mode="expanded"
              styleFor={styleFor}
              relLabel={relLabel}
              interactive
              showMiniMap
              fitOnMount
              className="h-full w-full"
            />
          )}
        </div>
        {legend ? (
          <div className="shrink-0 border-t border-zinc-200 px-5 py-2 dark:border-zinc-800">
            {legend}
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

export default BomGraphFullscreen;
