/**
 * <InfoTip> open/close rules (components/ui/info-tip-logic.ts): hover and focus are Radix's; a click decides here.
 * Run: npx --yes tsx components/ui/info-tip-logic.test.ts
 */
import assert from "node:assert/strict";

import { openAfterClick, pressPointer } from "./info-tip-logic";

// touch: Radix never opens on touch, so a tap toggles
assert.equal(openAfterClick(false, "touch"), true, "a tap opens a closed tip");
assert.equal(openAfterClick(true, "touch"), false, "a second tap closes it");
assert.equal(openAfterClick(false, "pen"), true);
assert.equal(openAfterClick(true, "pen"), false);
// mouse: hovering opened it already; the click must not close what the user is reading
assert.equal(openAfterClick(true, "mouse"), true);
assert.equal(openAfterClick(false, "mouse"), true);
// keyboard: focus opened it; Enter/Space toggles
assert.equal(openAfterClick(true, "keyboard"), false);
assert.equal(openAfterClick(false, "keyboard"), true);
// pointer types
assert.equal(pressPointer("mouse"), "mouse");
assert.equal(pressPointer("touch"), "touch");
assert.equal(pressPointer("pen"), "pen");
assert.equal(pressPointer(""), "touch", "an unknown pointer has no hover: treat as touch");
assert.equal(pressPointer(undefined), "touch");

console.log("info-tip logic: tests passed");
