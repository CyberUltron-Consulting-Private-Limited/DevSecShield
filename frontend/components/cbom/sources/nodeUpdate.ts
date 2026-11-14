import type { CbomNodeUpdate } from "@/utils/backend_api";

/**
 * Staging QA B6-1: every node said "1.0.0" while the lab node ran old code. The API now compares each node with the
 * node build this server ships (backend node_release.node_update); this turns its answer into what the Scan nodes tab
 * shows. Nothing is shown when there is nothing to compare (no node downloads on this server, or the node never
 * reported) or when the node is current.
 */
export type NodeUpdateBadge = { tone: "amber" | "zinc"; label: string; short: string; message: string };

const SHORT: Record<string, string> = {
  no_build_id: "No build id: older than the server's node build",
  older_version: "Older than the server's node build",
  different_version: "Not the server's node build",
  different_build: "Not the server's node build",
  newer_version: "Newer than the server's node build",
};

export function nodeUpdateBadge(update: CbomNodeUpdate | null | undefined): NodeUpdateBadge | null {
  if (!update || !update.message) return null;
  if (update.state === "update_available") {
    return { tone: "amber", label: "Update available", short: SHORT[update.reason ?? ""] ?? "Not the server's node build", message: update.message };
  }
  if (update.state === "newer") {
    return { tone: "zinc", label: "Newer than server", short: SHORT.newer_version, message: update.message };
  }
  return null;
}

/** How a node is updated in place: it keeps its registration (node token and keys live in its state volume). */
export const NODE_UPDATE_STEPS =
  "Load this server's scan node image (Add scan node > Download scan node image, or the docker pull it shows), then " +
  "recreate the container with the same name, settings and state volume and no registration token: it keeps its " +
  "registration. Helm: helm upgrade the release with the new chart. OVA/AMI: rebuild from the new kit, or load the new " +
  "image on the appliance and restart its service.";

export function nodesNeedingUpdate(nodes: { update?: CbomNodeUpdate | null }[]): number {
  return nodes.filter((n) => n.update?.state === "update_available").length;
}
