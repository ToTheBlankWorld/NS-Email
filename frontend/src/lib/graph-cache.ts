"use client";

/**
 * Module-level graph cache: the full evidence graph for a capture is
 * downloaded once per page session and reused across components
 * (graph page, session workspace neighborhood views).
 */

const cache = new Map<
  string,
  { nodes: import("@/lib/api").GraphNode[]; edges: import("@/lib/api").GraphEdge[] }
>();

export function cacheGraph(
  captureId: string,
  graph: { nodes: import("@/lib/api").GraphNode[]; edges: import("@/lib/api").GraphEdge[] },
): void {
  cache.set(captureId, graph);
}

export function getCachedGraph(captureId: string): {
  nodes: import("@/lib/api").GraphNode[];
  edges: import("@/lib/api").GraphEdge[];
} | null {
  return cache.get(captureId) ?? null;
}
