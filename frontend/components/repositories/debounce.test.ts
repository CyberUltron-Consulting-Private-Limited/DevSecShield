// Run: npx --yes tsx components/repositories/debounce.test.ts
// Review of #66, minor 4: the inventory and findings searches ask the server once the typing pauses (300 ms).
import assert from "node:assert/strict"
import fs from "node:fs"
import path from "node:path"

import { Debouncer, SEARCH_DEBOUNCE_MS, type Timers } from "./debounce"

/** Fake timers: a clock moved by hand. */
function fakeTimers() {
  let now = 0
  let next = 1
  const pending = new Map<number, { at: number; fn: () => void }>()
  const timers: Timers = {
    set: (fn, ms) => { const id = next++; pending.set(id, { at: now + ms, fn }); return id },
    clear: (id) => { pending.delete(id as number) },
  }
  const advance = (ms: number) => {
    now += ms
    for (const [id, t] of [...pending].sort((a, b) => a[1].at - b[1].at)) {
      if (t.at <= now) { pending.delete(id); t.fn() }
    }
  }
  return { timers, advance }
}

assert.equal(SEARCH_DEBOUNCE_MS, 300)
{
  const { timers, advance } = fakeTimers()
  const fired: string[] = []
  const d = new Debouncer<string>(SEARCH_DEBOUNCE_MS, (v) => fired.push(v), timers)
  for (const text of ["p", "pa", "pay", "paym", "payme", "paymen", "payments"]) { d.push(text); advance(80) } // typing
  assert.deepEqual(fired, [], "nothing is asked while typing")
  advance(SEARCH_DEBOUNCE_MS)
  assert.deepEqual(fired, ["payments"], "one request, with the whole word")
  d.push("x")
  advance(299)
  assert.deepEqual(fired, ["payments"])
  advance(1)
  assert.deepEqual(fired, ["payments", "x"])
  d.push("y")
  d.cancel() // the component unmounted or the value changed again
  advance(1000)
  assert.deepEqual(fired, ["payments", "x"])
}

// both search boxes query with the settled value, never the raw keystrokes
for (const file of ["InventoryTab.tsx", "FindingsTab.tsx"]) {
  const src = fs.readFileSync(path.join(__dirname, file), "utf8")
  assert.match(src, /useDebouncedValue\(search\.trim\(\)\)/, `${file} debounces its search`)
  assert.doesNotMatch(src, /q: search\.trim\(\)/, `${file} must not send the raw search`)
}

console.log("repositories debounce: ok")
