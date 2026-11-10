// Taking the user from a table row's "..." menu to a form further down the page (Edit, Test results, a new
// registration token).
//
// Radix returns focus to the menu trigger when a DropdownMenu closes. That happens about 150 ms after the item is
// chosen (FocusScope's unmount handler runs after the exit animation), and the trigger's focus() scrolls the page back
// to the table, cancelling a smooth scroll the item started: Edit from the Servers / Databases table left the page at
// the table (lab UI r1 F1; a setTimeout(0) before the scroll does not help, the focus comes later). So the item only
// records where to go, and the menu's onCloseAutoFocus skips the focus return and reveals that section instead: its
// first field gets focus without scrolling, then the section scrolls into view. Items that stay on the table (Run
// connection test, Disable) keep the default, focus back on the trigger.

/** The part of a DOM element revealSection uses (keeps it testable without a browser). */
export interface Focusable {
  focus(options?: FocusOptions): void;
}
export interface Revealable {
  scrollIntoView(options?: ScrollIntoViewOptions): void;
  querySelector(selectors: string): Focusable | null;
}

/** The first field a user would type into; buttons in the card header (the locked server-type switch) are skipped. */
export const FIRST_FIELD = [
  'input:not([type="hidden"]):not([disabled])',
  "textarea:not([disabled])",
  "select:not([disabled])",
  'button[role="combobox"]:not([disabled])',
].join(", ");
/** Fallback when every field is read-only (the "Register again" wizard): the first thing keyboard focus can land on. */
export const FIRST_FOCUSABLE = "button:not([disabled]), a[href], [tabindex]:not([tabindex='-1'])";

/** Focus the section's first field without scrolling, then scroll the section into view. False if it is not there. */
export function revealSection(section: Revealable | null | undefined): boolean {
  if (!section) return false;
  // Focus first: focus() with preventScroll never moves the page, and the smooth scroll that follows is not cancelled.
  (section.querySelector(FIRST_FIELD) ?? section.querySelector(FIRST_FOCUSABLE))?.focus({ preventScroll: true });
  section.scrollIntoView({ behavior: "smooth", block: "start" });
  return true;
}

export interface MenuReveal {
  /** Called by a menu item: reveal this section once the menu has closed. */
  request(id: string): void;
  /** The DropdownMenuContent's onCloseAutoFocus. */
  onCloseAutoFocus(event: { preventDefault(): void }): void;
}

export function menuReveal(lookup: (id: string) => Revealable | null): MenuReveal {
  let pending: string | null = null;
  return {
    request(id) {
      pending = id;
    },
    onCloseAutoFocus(event) {
      const id = pending;
      pending = null;
      if (id === null) return; // an item that stays on the table: focus goes back to the trigger
      event.preventDefault();
      // The section may not be there yet (a registration token still being issued): its own success handler reveals it.
      revealSection(lookup(id));
    },
  };
}

/** Reveal a section by id in the page (also used outside menus, e.g. after a save). */
export function revealById(id: string): boolean {
  return revealSection(document.getElementById(id));
}
