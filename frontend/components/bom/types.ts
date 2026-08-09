/** Shared BOM dependency-graph types (AIBOM + CBOM). */

export type BomLane = "aibom" | "cbom";

export interface BomGraphNode {
  id: string;
  label: string;
  kind: string;
  type?: string | null;
  asset_type?: string | null;
  primitive?: string | null;
  impact?: string | null;
  quantum_vulnerable?: boolean;
  weak?: boolean;
  cluster?: boolean;
  is_cluster?: boolean;
  cluster_count?: number;
  clustered_count?: number;
  member_ids?: string[];
}

export interface BomGraphEdge {
  source: string;
  target: string;
  rel: string;
}

export interface BomGraphMeta {
  lane?: BomLane | string;
  raw_node_count?: number;
  raw_edge_count?: number;
  view_node_count?: number;
  view_edge_count?: number;
  clustered_members?: number;
  max_nodes?: number;
}

export interface BomGraph {
  nodes: BomGraphNode[];
  edges: BomGraphEdge[];
  meta?: BomGraphMeta;
}

export const COMPACT_MAX_NODES = 40;
export const EXPANDED_MAX_NODES = 120;

export function isClusterNode(n: BomGraphNode): boolean {
  return Boolean(n.is_cluster || n.cluster);
}

export function clusterCount(n: BomGraphNode): number {
  return Number(n.clustered_count ?? n.cluster_count ?? 1);
}
