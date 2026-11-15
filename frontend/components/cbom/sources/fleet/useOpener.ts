// Keyboard focus back to what opened a dialog (PR #81 UX review 4550301291). The fleet dialogs are opened by plain
// buttons, not a <DialogTrigger>, so Radix has no trigger to return the focus to and leaves it on <body>: a keyboard
// user who closes the dialog starts again from the top of the page. Remember the opener, and focus it on close.
import { useCallback, useRef, type RefObject, type SyntheticEvent } from "react";

/** ``fallback``: what gets the focus when the opener left the page (a Delete confirmed: its row is gone), usually the
 * section's "Add ..." button. */
export function useOpener(fallback?: RefObject<HTMLElement | null>) {
  const opener = useRef<HTMLElement | null>(null);
  /** Call from the opener's onClick (a table row passes the row: its first button is remembered). */
  const remember = useCallback((event: SyntheticEvent<HTMLElement>) => {
    const el = event.currentTarget;
    opener.current = el instanceof HTMLButtonElement ? el : el.querySelector("button") ?? el;
  }, []);
  /** DialogContent's onCloseAutoFocus. An opener that left the page (a deleted row) gives the focus to ``fallback``;
   * without one (or a disabled one), Radix's default. */
  const onCloseAutoFocus = useCallback((event: Event) => {
    const usable = (el: HTMLElement | null | undefined): el is HTMLElement =>
      !!el && el.isConnected && !(el as HTMLButtonElement).disabled;
    const el = usable(opener.current) ? opener.current : usable(fallback?.current) ? fallback.current : null;
    if (el) {
      event.preventDefault();
      el.focus();
    }
  }, [fallback]);
  return { remember, onCloseAutoFocus };
}
