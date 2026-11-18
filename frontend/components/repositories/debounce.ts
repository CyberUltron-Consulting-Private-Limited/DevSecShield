"use client";

// Debounced values for the search boxes of the Repositories pages: the server is asked once the typing pauses, not
// once per character (a 50,000-repository inventory is filtered on the server).

import { useEffect, useState } from "react";

export const SEARCH_DEBOUNCE_MS = 300;

export interface Timers {
  set: (fn: () => void, ms: number) => unknown;
  clear: (handle: unknown) => void;
}

const REAL_TIMERS: Timers = {
  set: (fn, ms) => setTimeout(fn, ms),
  clear: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
};

/** Calls ``fire`` with the last value pushed, ``ms`` after the last push; a new push restarts the wait. */
export class Debouncer<T> {
  private handle: unknown = undefined;

  constructor(private readonly ms: number, private readonly fire: (value: T) => void,
              private readonly timers: Timers = REAL_TIMERS) {}

  push(value: T): void {
    this.cancel();
    this.handle = this.timers.set(() => {
      this.handle = undefined;
      this.fire(value);
    }, this.ms);
  }

  cancel(): void {
    if (this.handle !== undefined) this.timers.clear(this.handle);
    this.handle = undefined;
  }
}

/** ``value``, updated ``ms`` after it last changed. */
export function useDebouncedValue<T>(value: T, ms: number = SEARCH_DEBOUNCE_MS): T {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const d = new Debouncer<T>(ms, setSettled);
    d.push(value);
    return () => d.cancel();
  }, [value, ms]);
  return settled;
}
