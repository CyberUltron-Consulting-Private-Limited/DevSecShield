"use client";

import { Info } from "lucide-react";
import { useRef, useState, type ReactNode } from "react";

import { Label } from "@/components/ui/label";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { INFO_TIPS, type InfoTipId } from "@/content/infotips";
import { cn } from "@/lib/utils";

import { openAfterClick, pressPointer, type PressPointer } from "./info-tip-logic";

/**
 * A small (i) button that explains the field, metric or setting next to it: what it is and an example.
 * Text comes from the registry (content/infotips.ts) by a stable id; the id is typed, so an unknown id fails tsc.
 *
 * Hover (mouse), keyboard focus and tap (touch) open it; Esc, blur, a tap outside and a second tap close it. The
 * button is named "About <label>" and, while open, described by the tip's text (Radix aria-describedby). See
 * info-tip-logic.ts for why the open state is controlled here.
 */
export function InfoTip({ id, side = "top", className }: { id: InfoTipId; side?: "top" | "right" | "bottom" | "left"; className?: string }) {
  const tip = INFO_TIPS[id];
  const [open, setOpen] = useState(false);
  const press = useRef<{ wasOpen: boolean; pointer: PressPointer } | null>(null);
  return (
    <Tooltip open={open} onOpenChange={setOpen} delayDuration={150}>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={`About ${tip.label}`}
          data-infotip={id}
          className={cn(
            "inline-flex size-6 -my-1 shrink-0 cursor-help items-center justify-center rounded-full align-middle",
            "text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500",
            className,
          )}
          onPointerDown={(e) => {
            press.current = { wasOpen: open, pointer: pressPointer(e.pointerType) };
          }}
          onClick={(e) => {
            // Radix closes the tooltip on click; preventDefault skips that, and the press decides instead.
            e.preventDefault();
            e.stopPropagation();
            const p = press.current ?? { wasOpen: open, pointer: "keyboard" as const };
            press.current = null;
            setOpen(openAfterClick(p.wasOpen, p.pointer));
          }}
        >
          <Info className="size-3.5" aria-hidden="true" />
        </button>
      </TooltipTrigger>
      <TooltipContent
        side={side}
        sideOffset={4}
        collisionPadding={12}
        className="w-auto max-w-[min(20rem,calc(100vw-2rem))] text-left text-pretty px-3 py-2 leading-relaxed"
      >
        <InfoTipBody id={id} />
      </TooltipContent>
    </Tooltip>
  );
}

/** Text only: tooltip content cannot take focus (WAI-ARIA tooltip pattern), so it never holds a link or a button. */
function InfoTipBody({ id }: { id: InfoTipId }) {
  const tip = INFO_TIPS[id];
  return (
    <span className="block space-y-1.5">
      <span className="block">{tip.what}</span>
      <span className="block opacity-80">
        <span className="font-semibold">Example: </span>
        {tip.example}
      </span>
    </span>
  );
}

/**
 * A form label with its (i) tip. The tip sits beside the <label>, not inside it: a button inside a label would be
 * read as part of the input's accessible name. `infoId` is required, so a field cannot be added without a tip.
 */
export function FieldLabel({
  infoId,
  htmlFor,
  children,
  className,
  labelClassName,
  required,
}: {
  infoId: InfoTipId;
  htmlFor?: string;
  children: ReactNode;
  className?: string;
  labelClassName?: string;
  required?: boolean;
}) {
  return (
    <div className={cn("flex items-center gap-1 min-w-0", className)}>
      <Label htmlFor={htmlFor} className={labelClassName}>
        {children}
        {required && <span className="text-red-500">*</span>}
      </Label>
      <InfoTip id={infoId} />
    </div>
  );
}
