// Keyboard focus back to what opened a dialog (PR #81 UX review 4550301291). The fleet dialogs are opened by plain
// buttons, not a <DialogTrigger>, so Radix has no trigger to return the focus to and leaves it on <body>: a keyboard
// user who closes the dialog starts again from the top of the page. Remember the opener, and focus it on close.
import { useCallback, useRef, type SyntheticEvent } from "react";

export function useOpener() {
  const opener = useRef<HTMLElement | null>(null);
  /** Call from the opener's onClick (a table row passes the row: its first button is remembered). */
  const remember = useCallback((event: SyntheticEvent<HTMLElement>) => {
    const el = event.currentTarget;
    opener.current = el instanceof HTMLButtonElement ? el : el.querySelector("button") ?? el;
  }, []);
  /** DialogContent's onCloseAutoFocus. An opener that left the page (a deleted row) keeps Radix's default. */
  const onCloseAutoFocus = useCallback((event: Event) => {
    const el = opener.current;
    if (el && el.isConnected) {
      event.preventDefault();
      el.focus();
    }
  }, []);
  return { remember, onCloseAutoFocus };
}
