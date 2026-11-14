"use client";

// A small (i) button: the text of one GRADE_TIPS entry, opened by click or tap (not hover only), shown in the flow
// below the button so it never overflows a narrow screen. Replaced by F2's <InfoTip id="…" /> once PR #38 merges.
import { Info } from "lucide-react";
import { useId, useState } from "react";

import { GRADE_TIPS, type GradeTipId } from "./tips";

export function Tip({ id }: { id: GradeTipId }) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const tip = GRADE_TIPS[id];
  return (
    <>
      <button
        type="button"
        className="inline-flex items-center text-zinc-400 hover:text-zinc-700 dark:hover:text-zinc-200 cursor-pointer align-middle"
        aria-label={`About ${tip.label}`}
        aria-expanded={open}
        aria-controls={panelId}
        title={tip.what}
        data-testid={`tip-${id}`}
        onClick={(e) => {
          e.stopPropagation();
          setOpen((o) => !o);
        }}
      >
        <Info className="h-3.5 w-3.5" />
      </button>
      {open && (
        <span
          id={panelId}
          role="note"
          className="basis-full block w-full max-w-prose rounded-md border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 p-2 text-xs font-normal text-zinc-700 dark:text-zinc-300 whitespace-normal"
          data-testid={`tip-text-${id}`}
        >
          <span className="block">{tip.what}</span>
          <span className="block mt-1 text-zinc-500">Example: {tip.example}</span>
        </span>
      )}
    </>
  );
}
