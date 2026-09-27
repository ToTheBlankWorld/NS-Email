"use client";

import {
  type Edge,
  type Node,
} from "@xyflow/react";

import type { GraphEdge, GraphNode } from "@/lib/api";

/**
 * Deterministic layered layout for the evidence graph. The same graph
 * always produces the same positions: nodes are assigned to layers via
 * BFS depth from the capture root, ties broken by node id.
 */

export const NODE_CATEGORY_ORDER = [
  "capture",
  "host",
  "endpoint",
  "session",
  "protocol",
  "tls_handshake",
  "tls_configuration",
  "certificate",
  "finding",
  "anomaly",
  "posture_factor",
  "timeline_event",
] as const;

export type NodeCategory = (typeof NODE_CATEGORY_ORDER)[number];

export const CATEGORY_LABEL: Record<NodeCategory, string> = {
  capture: "Capture",
  host: "Host",
  endpoint: "Endpoint",
  session: "Session",
  protocol: "Protocol",
  tls_handshake: "TLS handshake",
  tls_configuration: "TLS configuration",
  certificate: "Certificate",
  finding: "Finding",
  anomaly: "Anomaly",
  posture_factor: "Posture factor",
  timeline_event: "Timeline event",
};

export const CATEGORY_COLOR: Record<NodeCategory, string> = {
  capture: "#1a365d",
  host: "#2c5282",
  endpoint: "#4a6fa5",
  session: "#2b6cb0",
  protocol: "#6b7fa3",
  tls_handshake: "#805ad5",
  tls_configuration: "#9f7aea",
  certificate: "#dd6b20",
  finding: "#c53030",
  anomaly: "#b7791f",
  posture_factor: "#319795",
  timeline_event: "#a0aec0",
};

const LAYER_WIDTH = 280;
const ROW_HEIGHT = 92;
const CATEGORY_MAX_ROWS = 8;

type Positioned = { node: GraphNode; depth: number };

/** BFS depth from the capture node; unreachable nodes go after all layers. */
function computeDepths(nodes: GraphNode[], edges: GraphEdge[]): Map<string, number> {
  const depths = new Map<string, number>();
  const adjacency = new Map<string, string[]>();
  for (const edge of edges) {
    const list = adjacency.get(edge.source_node_id) ?? [];
    list.push(edge.target_node_id);
    adjacency.set(edge.source_node_id, list);
  }

  const captureNode = nodes.find((n) => n.node_type === "capture");
  const queue: string[] = [];
  if (captureNode) {
    depths.set(captureNode.node_id, 0);
    queue.push(captureNode.node_id);
  }
  let head = 0;
  while (head < queue.length) {
    const current = queue[head++];
    const depth = depths.get(current) ?? 0;
    for (const next of adjacency.get(current) ?? []) {
      if (!depths.has(next)) {
        depths.set(next, depth + 1);
        queue.push(next);
      }
    }
  }
  const reachable = [...depths.values()];
  const maxDepth = reachable.length > 0 ? Math.max(...reachable) : 0;
  for (const node of nodes) {
    if (!depths.has(node.node_id)) {
      depths.set(node.node_id, maxDepth + 1);
    }
  }
  return depths;
}

/** Convert API graph to positioned React Flow nodes and edges. */
export function toFlowElements(
  graph: { nodes: GraphNode[]; edges: GraphEdge[] },
): { nodes: Node[]; edges: Edge[] } {
  const byId = new Map(graph.nodes.map((n) => [n.node_id, n]));
  const depths = computeDepths(graph.nodes, graph.edges);

  // Layer assignment: depth first, then category order, then node id — stable.
  const layers = new Map<number, Positioned[]>();
  for (const node of graph.nodes) {
    const depth = depths.get(node.node_id) ?? 0;
    const list = layers.get(depth) ?? [];
    list.push({ node, depth });
    layers.set(depth, list);
  }

  const flowNodes: Node[] = [];
  for (const [depth, entries] of [...layers.entries()].sort((a, b) => a[0] - b[0])) {
    entries.sort((a, b) => {
      const catA = NODE_CATEGORY_ORDER.indexOf(a.node.node_type as NodeCategory);
      const catB = NODE_CATEGORY_ORDER.indexOf(b.node.node_type as NodeCategory);
      const catDiff = (catA === -1 ? 99 : catA) - (catB === -1 ? 99 : catB);
      return catDiff !== 0 ? catDiff : a.node.node_id.localeCompare(b.node.node_id);
    });
    entries.forEach((entry, index) => {
      const category = (entry.node.node_type as NodeCategory) ?? "session";
      flowNodes.push({
        id: entry.node.node_id,
        position: {
          x: depth * LAYER_WIDTH,
          // Column fold keeps deep captures from becoming one endless strip.
          y: (index % CATEGORY_MAX_ROWS) * ROW_HEIGHT,
        },
        data: {
          label: entry.node.label,
          nodeType: entry.node.node_type,
          sourceId: entry.node.source_id ?? "",
        },
        type: "evidence",
        zIndex: category === "timeline_event" ? 0 : 1,
      });
    });
  }

  const flowEdges: Edge[] = graph.edges
    .filter((e) => byId.has(e.source_node_id) && byId.has(e.target_node_id))
    .map((edge, index) => ({
      id: `edge-${index}-${edge.source_node_id}-${edge.target_node_id}`,
      source: edge.source_node_id,
      target: edge.target_node_id,
      label: edge.edge_type.replace(/_/g, " "),
      data: { edgeType: edge.edge_type, basis: edge.basis ?? "" },
      type: "smoothstep",
      animated: false,
    }));

  return { nodes: flowNodes, edges: flowEdges };
}

/** Sub-graph around one node: the node plus its direct neighbors. */
export function neighborhood(
  graph: { nodes: GraphNode[]; edges: GraphEdge[] },
  nodeId: string,
): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const keep = new Set([nodeId]);
  for (const edge of graph.edges) {
    if (edge.source_node_id === nodeId) keep.add(edge.target_node_id);
    if (edge.target_node_id === nodeId) keep.add(edge.source_node_id);
  }
  return {
    nodes: graph.nodes.filter((n) => keep.has(n.node_id)),
    edges: graph.edges.filter(
      (e) => keep.has(e.source_node_id) && keep.has(e.target_node_id),
    ),
  };
}

/** Find the graph node backing a domain id (session/finding/anomaly id). */
export function findNodeBySourceId(
  graph: { nodes: GraphNode[] },
  sourceId: string,
): GraphNode | null {
  return graph.nodes.find((n) => n.source_id === sourceId) ?? null;
}
