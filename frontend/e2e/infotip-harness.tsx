/**
 * Browser harness for e2e/infotip.e2e.mjs: the real <InfoTip> and <FieldLabel> with the app's CSS, the longest tips of
 * the registry placed at every edge and corner of the viewport, a form field, and a page that scrolls. Not part of the
 * app (nothing imports it); the e2e script bundles it with esbuild.
 */
import type { CSSProperties } from "react";
import { createRoot } from "react-dom/client";

import { FieldLabel, InfoTip } from "@/components/ui/info-tip";
import { INFO_TIPS, type InfoTipId } from "@/content/infotips";

const longest = (Object.keys(INFO_TIPS) as InfoTipId[])
  .map((id) => ({ id, length: INFO_TIPS[id].what.length + INFO_TIPS[id].example.length }))
  .sort((a, b) => b.length - a.length)
  .map((t) => t.id);

const SPOTS: { name: string; style: CSSProperties }[] = [
  { name: "top-left", style: { top: 0, left: 0 } },
  { name: "top-center", style: { top: 0, left: "50%" } },
  { name: "top-right", style: { top: 0, right: 0 } },
  { name: "middle-left", style: { top: "50%", left: 0 } },
  { name: "middle-right", style: { top: "50%", right: 0 } },
  { name: "bottom-left", style: { bottom: 0, left: 0 } },
  { name: "bottom-center", style: { bottom: 0, left: "50%" } },
  { name: "bottom-right", style: { bottom: 0, right: 0 } },
];

function Harness() {
  return (
    <div className="dark min-h-screen bg-zinc-950 text-zinc-100">
      {SPOTS.map((spot, i) => (
        <span key={spot.name} data-spot={spot.name} className="fixed inline-flex items-center gap-1 text-xs" style={spot.style}>
          <InfoTip id={longest[i % longest.length]} />
        </span>
      ))}
      <main className="mx-auto max-w-md space-y-4 p-16">
        <h1 className="text-lg font-semibold">InfoTip harness</h1>
        <div>
          <FieldLabel htmlFor="scan-title" infoId="scan.new.title">
            Scan title
          </FieldLabel>
          <input id="scan-title" className="mt-1 w-full rounded border border-zinc-700 bg-zinc-900 px-2 py-1" />
        </div>
        <p className="flex items-center gap-1 text-sm">
          Credits <InfoTip id="scan.table.credits" />
        </p>
        <button type="button" data-outside className="rounded border border-zinc-700 px-2 py-1 text-sm">
          Somewhere else
        </button>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<Harness />);
