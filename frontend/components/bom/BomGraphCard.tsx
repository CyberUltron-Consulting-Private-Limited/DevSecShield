"use client";

/**
 * Card chrome + compact canvas + Expand Dialog for BOM dependency graphs.
 */

import type { ReactNode } from "react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { BomGraphCanvas } from "./BomGraphCanvas";
import { BomGraphFullscreen } from "./BomGraphFullscreen";
import type { BomGraph, BomLane } from "./types";
import { AIBOM_KIND_COLOR, CBOM_ASSET_COLOR } from "./layout";

export function BomGraphCard({
  graph,
  expandedGraph,
  lane,
  title,
  description,
  icon,
  heightClass = "h-[360px]",
}: {
  graph: BomGraph;
  /** Fuller projection for the Dialog (falls back to ``graph``). */
  expandedGraph?: BomGraph | null;
  lane: BomLane;
  title: string;
  description: string;
  icon?: ReactNode;
  heightClass?: string;
}) {
  const overlay = expandedGraph ?? graph;
  const n = graph.nodes?.length ?? 0;
  const raw = graph.meta?.raw_node_count;
  const simplified = raw != null && raw > n;

  return (
    <Card className="col-span-full border-zinc-200 dark:border-zinc-800">
      <CardHeader className="flex flex-row items-start justify-between gap-3 space-y-0">
        <div className="space-y-1.5">
          <CardTitle className="flex items-center gap-2 text-base">
            {icon}
            {title}
          </CardTitle>
          <CardDescription>
            {description}
            {simplified ? (
              <span className="mt-1 block text-[11px] text-zinc-500">
                Showing {n} clustered nodes of {raw}. Open fullscreen for more
                detail.
              </span>
            ) : null}
          </CardDescription>
        </div>
        <BomGraphFullscreen
          graph={overlay}
          lane={lane}
          title={title}
          description={description}
        />
      </CardHeader>
      <CardContent>
        {n === 0 ? (
          <div className="flex h-[200px] items-center justify-center text-sm text-zinc-500">
            No assets to graph
          </div>
        ) : (
          <>
            <div
              className={`${heightClass} w-full rounded-lg border border-zinc-200 bg-zinc-50/50 dark:border-zinc-800 dark:bg-zinc-900/40`}
            >
              <BomGraphCanvas graph={graph} lane={lane} minZoom={0.55} fitOnMount />
            </div>
            <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1.5 text-xs text-zinc-600 dark:text-zinc-400">
              {lane === "aibom"
                ? Object.entries(AIBOM_KIND_COLOR).map(([k, c]) => (
                    <span key={k} className="flex items-center gap-1.5">
                      <span
                        className="size-2.5 rounded-full"
                        style={{ background: c }}
                      />
                      {k}
                    </span>
                  ))
                : (
                  <>
                    {["algorithm", "certificate", "protocol", "related-crypto-material", "library"].map(
                      (k) => (
                        <span key={k} className="flex items-center gap-1.5">
                          <span
                            className="size-2.5 rounded-full"
                            style={{ background: CBOM_ASSET_COLOR[k] }}
                          />
                          {k}
                        </span>
                      )
                    )}
                    <span className="flex items-center gap-1.5">
                      <span
                        className="size-2.5 rounded-sm border-2"
                        style={{ borderColor: "#dc2626" }}
                      />{" "}
                      weak
                    </span>
                    <span className="flex items-center gap-1.5">
                      <span
                        className="size-2.5 rounded-sm border-2"
                        style={{ borderColor: "#f97316" }}
                      />{" "}
                      quantum-vulnerable
                    </span>
                  </>
                )}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

export default BomGraphCard;
