// One call at a time (issue #99 review): the create form can be submitted by Enter in the title field and by the
// Create button. React's isPending flips only after a render, so two quick submits (a double Enter ~100 ms apart)
// could both start a create; the first integration's one-time key was then never shown. A call made while the
// previous one is still running is dropped; the gate opens again when it settles (success or error).

export function singleFlight<A extends unknown[]>(fn: (...args: A) => Promise<unknown>): (...args: A) => boolean {
  let inFlight = false;
  return (...args: A) => {
    if (inFlight) return false;
    inFlight = true;
    let pending: Promise<unknown>;
    try {
      pending = fn(...args);
    } catch {
      inFlight = false;
      return true;
    }
    // errors are reported by the caller's own handlers (the mutation's onError); never an unhandled rejection here
    pending.then(
      () => { inFlight = false; },
      () => { inFlight = false; },
    );
    return true;
  };
}
