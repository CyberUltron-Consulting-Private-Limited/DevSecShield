/**
 * Lets a submit handler start one request at a time. A double-click (or Enter pressed twice) delivers both events
 * before React re-renders the button as disabled: useMutation's isPending is still false for the second one, so a
 * disabled prop alone sent two POSTs (two scan nodes, two scans with the same title).
 * Use: const [guard] = useState(singleFlight); if (!guard.tryStart()) return; m.mutate(v, { onSettled: guard.done })
 */
export function singleFlight() {
  let busy = false
  return {
    tryStart(): boolean {
      if (busy) return false
      busy = true
      return true
    },
    done(): void {
      busy = false
    },
  }
}
