// #150: "Accept new host key" / "Forget remembered key" on a host_key_changed result (trust on first use only).
// The scan node writes "host key changed (pinned SHA256:<old>, now SHA256:<new>)" when a server presents a different
// key of a remembered type, and "the server no longer offers the pinned host key type" when it stopped offering it:
// only the first can be accepted (the exact key shown), both can be forgotten.

import type { CbomHostKeyReset } from "@/utils/backend_api";

const FP = "SHA256:[A-Za-z0-9+/]{43}";
const CHANGED = new RegExp(`pinned (${FP}), now (${FP})`);
const PINNED = new RegExp(`pinned (${FP})`);

export interface HostKeyChange {
  pinned: string | null;
  presented: string | null;
}

/** The fingerprints a host_key_changed note names (null for a note that is not one). */
export function hostKeyChange(status: string, note: string | undefined | null): HostKeyChange | null {
  if (status !== "host_key_changed") return null;
  const text = note ?? "";
  const changed = CHANGED.exec(text);
  if (changed) return { pinned: changed[1], presented: changed[2] };
  const pinned = PINNED.exec(text);
  return { pinned: pinned ? pinned[1] : null, presented: null };
}

/** Decisions exist only for keys remembered on first use; a pinned known_hosts source is fixed in its known_hosts. */
export function decisionsAllowed(hostKeyPolicy: unknown): boolean {
  return hostKeyPolicy !== "pinned";
}

export const ACCEPT_WARNING =
  "Accept only if you know this server was rebuilt or its host keys were regenerated. A host key that changes without " +
  "a reason can mean someone is intercepting the connection. The scan node will trust exactly this key; any other key " +
  "still fails.";

export const FORGET_WARNING =
  "The scan node will trust whatever key the server presents on its next connection and remember it. Use this only " +
  "when the server no longer offers the remembered key type and you have checked the change is expected.";

/** The newest pending decision for a target, if any (the list comes newest first). */
export function pendingFor(resets: CbomHostKeyReset[] | undefined, target: string): CbomHostKeyReset | null {
  return (resets ?? []).find((r) => r.target === target && r.status === "pending") ?? null;
}

export function pendingLabel(reset: CbomHostKeyReset): string {
  return reset.action === "accept"
    ? `New key ${reset.fingerprint} accepted: the scan node applies it on its next job for this source.`
    : "Remembered keys forgotten: the scan node applies this on its next job for this source.";
}
