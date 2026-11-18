"use client";

import { Info } from "lucide-react";
import { useEffect, useId, useRef, useState, useSyncExternalStore, type ReactNode } from "react";

import { Label } from "@/components/ui/label";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  INFO_TIP_LABELS,
  areaOf,
  loadTipArea,
  subscribeTipAreas,
  tipAreaState,
  type InfoTipId,
  type InfoTipText,
} from "@/content/infotips";
import { cn } from "@/lib/utils";

import { useInfoTipDrawer } from "./info-tip-drawer-context";
import { acceptRadixClose, focusOpensTip, openAfterClick, pressPointer, type PressPointer } from "./info-tip-logic";

/** One tip open at a time: each shadcn Tooltip has its own provider, so focusing one tip and hovering another would
 * otherwise show both. Opening a tip closes the one that was open. */
let closeOpenTip: (() => void) | null = null;

/** Whether the last key pressed was Tab (a pointer press resets it): tells a Tab focus from a programmatic one. The
 * listeners are added once, by the first tip that renders (never on the server). */
let lastKeyWasTab = false;
let listening = false;
function listenForTab() {
  if (listening || typeof document === "undefined") return;
  listening = true;
  document.addEventListener("keydown", (e) => { lastKeyWasTab = e.key === "Tab"; }, true);
  document.addEventListener("pointerdown", () => { lastKeyWasTab = false; }, true);
}

/** Asks for the text of a tip's area (once per session; a failed load is tried again on the next call). */
function requestText(id: InfoTipId) {
  const area = areaOf(id);
  if (area) loadTipArea(area).catch(() => {});
}

/**
 * The text of a tip, or why there is none yet. The label is eager (INFO_TIP_LABELS); the text arrives with its area
 * (content/infotips/load.ts, issue #145). The server and the first client render have no text, so hydration matches.
 */
function useTipText(id: InfoTipId): { text?: InfoTipText; failed: boolean } {
  const area = areaOf(id);
  const state = useSyncExternalStore(
    subscribeTipAreas,
    () => (area ? tipAreaState(area) : undefined),
    () => undefined,
  );
  // the area loads when its first tip renders, so the text (and the screen reader's description) is usually there
  // before anyone hovers, focuses or taps; those ask again in case this load failed
  useEffect(() => requestText(id), [id]);
  return { text: state?.status === "ready" ? state.text[id] : undefined, failed: !area || state?.status === "error" };
}

/**
 * A small (i) button that explains the field, metric or setting next to it: what it is and an example.
 * Text comes from the registry (content/infotips) by a stable id: what it is, why it matters, an example; the id is
 * typed, so an unknown id fails tsc. The label is there at once; the text is loaded with its area when the first tip
 * of that area renders (a tip opened before it arrives shows its label and "Loading…").
 *
 * Hover (mouse), focus reached with Tab, and tap (touch) open it (a programmatic focus, such as a dialog focusing its
 * first button, does not); Esc, blur, a tap outside and a second tap close it. The button is named "About <label>"
 * and is always described by the tip's text (aria-describedby on a hidden copy), so a screen reader reads the text
 * when it reaches the button, whether or not the tip is open. See info-tip-logic.ts for why the open state is
 * controlled here.
 */
export function InfoTip({ id, side = "top", className }: { id: InfoTipId; side?: "top" | "right" | "bottom" | "left"; className?: string }) {
  const label = INFO_TIP_LABELS[id];
  const { text, failed } = useTipText(id);
  // below an <InfoTipDrawerProvider> only: the tip gains "More in Explanations ›" (no provider: unchanged)
  const drawer = useInfoTipDrawer();
  const descriptionId = useId();
  const [open, setOpenState] = useState(false);
  const press = useRef<{ wasOpen: boolean; pointer: PressPointer } | null>(null);
  const closeThis = useRef(() => setOpenState(false));
  const setOpen = (next: boolean) => {
    if (next && closeOpenTip && closeOpenTip !== closeThis.current) closeOpenTip();
    if (next) {
      closeOpenTip = closeThis.current;
      requestText(id);
    }
    else if (closeOpenTip === closeThis.current) closeOpenTip = null;
    setOpenState(next);
  };
  // keyboard focus: set on a focus that no pointer press started, cleared on blur (see acceptRadixClose)
  const keyboardFocus = useRef(false);
  const pointerPressing = useRef(false);
  const byEscape = useRef(false);
  // set by onFocus just before Radix's own focus handler asks to open; cleared by that request
  const focusing = useRef(false);
  useEffect(listenForTab, []);
  const endFocus = () => {
    focusing.current = false;
  };
  const onRadixOpenChange = (next: boolean) => {
    const fromFocus = focusing.current;
    focusing.current = false;
    if (next && fromFocus && !keyboardFocus.current) return;
    if (!next && !acceptRadixClose(keyboardFocus.current, byEscape.current)) return;
    byEscape.current = false;
    setOpen(next);
  };
  return (
    <>
    <Tooltip open={open} onOpenChange={onRadixOpenChange} delayDuration={150}>
      <TooltipTrigger asChild>
        <button
          type="button"
          aria-label={`About ${label}`}
          // always described by the hidden copy below (the child's prop wins over Radix's open-only one)
          aria-describedby={descriptionId}
          data-infotip={id}
          className={cn(
            "inline-flex size-6 -my-1 shrink-0 cursor-help items-center justify-center rounded-full align-middle",
            "text-zinc-500 hover:text-zinc-900 dark:text-zinc-400 dark:hover:text-white",
            "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500",
            className,
          )}
          onPointerEnter={() => requestText(id)}
          onPointerDown={(e) => {
            pointerPressing.current = true;
            press.current = { wasOpen: open, pointer: pressPointer(e.pointerType) };
          }}
          onFocus={() => {
            requestText(id);
            // a pointer press focuses the button too: that is not keyboard focus, and the click decides
            keyboardFocus.current = !pointerPressing.current && focusOpensTip(lastKeyWasTab);
            focusing.current = !pointerPressing.current;
            pointerPressing.current = false;
            // Radix's own focus handler runs right after this one, in the same event: a flag it did not consume (the
            // tip was already open, so Radix asked nothing) must not block a later hover
            queueMicrotask(endFocus);
          }}
          onPointerLeave={endFocus}
          onBlur={() => {
            keyboardFocus.current = false;
            focusing.current = false;
            pointerPressing.current = false;
          }}
          onClick={(e) => {
            // Radix closes the tooltip on click; preventDefault skips that, and the press decides instead.
            e.preventDefault();
            e.stopPropagation();
            const p = press.current ?? { wasOpen: open, pointer: "keyboard" as const };
            press.current = null;
            pointerPressing.current = false;
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
        onEscapeKeyDown={() => {
          byEscape.current = true;
        }}
        className="w-auto max-w-[min(20rem,calc(100vw-2rem))] text-left text-pretty px-3 py-2 leading-relaxed"
      >
        <InfoTipBody label={label} text={text} failed={failed} />
        {drawer && (
          // a pointer shortcut (tooltip content takes no focus, WAI-ARIA tooltip pattern); keyboard users reach the
          // same drawer with the page's or dialog's "Explanations" button
          <button type="button" tabIndex={-1} data-testid="infotip-more"
                  className="mt-1.5 block cursor-pointer text-left font-semibold underline-offset-2 hover:underline"
                  onClick={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    setOpen(false);
                    drawer.open(id);
                  }}>
            More in Explanations ›
          </button>
        )}
      </TooltipContent>
    </Tooltip>
    {/* the description screen readers read on the button; `hidden` keeps it off screen and out of the reading order */}
    <span id={descriptionId} hidden>
      {text && (
        <>
          {text.what}
          {text.why ? ` Why it matters: ${text.why}` : ""} Example: {text.example}
        </>
      )}
    </span>
    </>
  );
}

/** Text only: tooltip content cannot take focus (WAI-ARIA tooltip pattern). The one exception, below a drawer
 * provider, is the pointer-only "More in Explanations ›" shortcut next to this body (the drawer has its own button). */
function InfoTipBody({ label, text: tip, failed }: { label: string; text?: InfoTipText; failed: boolean }) {
  if (!tip) {
    return (
      <span className="block space-y-1.5">
        <span className="block font-semibold">{label}</span>
        <span className="block opacity-80" data-infotip-loading={failed ? undefined : ""}>
          {failed ? "This tip could not be loaded. Close it and open it again to retry." : "Loading…"}
        </span>
      </span>
    );
  }
  return (
    <span className="block space-y-1.5">
      <span className="block">{tip.what}</span>
      {tip.why && (
        <span className="block">
          <span className="font-semibold">Why it matters: </span>
          {tip.why}
        </span>
      )}
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
  /** Optional only for files the coverage test lists in NOT_YET_COVERED; every covered file must pass one. */
  infoId?: InfoTipId;
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
      {infoId && <InfoTip id={infoId} />}
    </div>
  );
}
