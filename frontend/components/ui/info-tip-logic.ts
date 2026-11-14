/**
 * The open/close rules of <InfoTip> (components/ui/info-tip.tsx), kept free of React so a unit test can check them.
 *
 * <InfoTip> is a Radix tooltip used as a "toggletip". Radix opens a tooltip on mouse hover and on keyboard focus and
 * closes it on Esc, blur, scroll and a pointer press outside. It never opens one on touch: its trigger ignores touch
 * pointer moves, and both its pointerdown and click handlers close the tooltip. So <InfoTip> controls `open` itself:
 * it notes at pointerdown whether the tip was open and which pointer pressed, and on click it cancels Radix's close
 * (preventDefault) and applies `openAfterClick`.
 */
export type PressPointer = "mouse" | "touch" | "pen" | "keyboard";

/** The state after a click (or Enter/Space, which browsers deliver as a click with no pointerdown). */
export function openAfterClick(wasOpen: boolean, pointer: PressPointer): boolean {
  // A mouse user has usually opened the tip by hovering before clicking; a click must not close what they are reading.
  if (pointer === "mouse") return true;
  // Touch, pen and keyboard toggle: tap to open, tap again to close.
  return !wasOpen;
}

/** The pointer type of a pointerdown event, normalised ("" or unknown types count as touch: no hover to rely on). */
export function pressPointer(pointerType: string | undefined | null): PressPointer {
  if (pointerType === "mouse" || pointerType === "pen" || pointerType === "touch") return pointerType;
  return "touch";
}

/**
 * Whether <InfoTip> accepts a close request from Radix. While the (i) button has keyboard focus, only Esc (or the
 * blur that ends the focus) closes it: Radix also closes a tooltip when a scroll contains its trigger, and the browser
 * scrolls the page to bring a button reached by Tab into view right after focus opened its tip (review of #135, QA M1).
 */
export function acceptRadixClose(keyboardFocused: boolean, byEscape: boolean): boolean {
  return !keyboardFocused || byEscape;
}
