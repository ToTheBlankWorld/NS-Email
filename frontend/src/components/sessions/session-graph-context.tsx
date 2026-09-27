"use client";

import "@xyflow/react/dist/style.css";

import {
  Background,
  ReactFlow,
  ReactFlowProvider,
  type EdgeMouseHandler,
  type NodeMouseHandler,
} from "@xyflow/react";
import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { LoaderCircle, Network } from "lucide-react";

import { EvidenceNode } from "@/components/graph/evidence-node";
import { EmptyState } from "@/components/empty-state";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { getGraph, type GraphEdge, type GraphNode } from "@/lib/api";
import { toFlowElements, neighborhood } from "@/lib/graph-layout";
import { getCachedGraph } from "@/lib/graph-cache";

const nodeTypes = { evidence: EvidenceNode };

type GraphState =
  | { status: "loading" }
  | { status: "loaded"; graph: { nodes: GraphNode[]; edges: GraphEdge[] } }
  | { status: "unavailable" };

/**
 * Focused evidence graph around one session: the session node plus its
 * direct neighborhood (host, endpoints, TLS handshake, certificates,
 * findings, anomaly).
 */
export function SessionGraphContext({
  captureId,
  sessionId,
}: {
  captureId: string;
  sessionId: string;
}) {
  const [state, setState] = useState<GraphState>(() => {
    const cached = getCachedGraph(captureId);
    return cached ? { status: "loaded", graph: cached } : { status: "loading" };
  });
  const [focus, setFocus] = useState<{ type: string; label: string } | null>(null);

  useEffect(() => {
    if (getCachedGraph(captureId)) return;
    const controller = new AbortController();
    getGraph(captureId, controller.signal)
      .then((payload) => setState({ status: "loaded", graph: payload }))
      .catch(() => setState({ status: "unavailable" }));
    return () => controller.abort();
  }, [captureId]);

  const { nodes, edges } = useMemo(() => {
    if (state.status !== "loaded") return { nodes: [], edges: [] };
    const sessionNode = state.graph.nodes.find(
      (n) => n.node_type === "session" && n.source_id === sessionId,
    );
    if (!sessionNode) return { nodes: [], edges: [] };
    const sub = neighborhood(state.graph, sessionNode.node_id);
    return toFlowElements(sub);
  }, [state, sessionId]);

  const onNodeClick: NodeMouseHandler = useCallback((_, node) => {
    setFocus({
      type: (node.data as { nodeType: string }).nodeType.replace(/_/g, " "),
      label: (node.data as { label: string }).label,
    });
  }, []);

  const onEdgeClick: EdgeMouseHandler = useCallback((_, edge) => {
    setFocus({
      type: (edge.data as { edgeType: string }).edgeType.replace(/_/g, " "),
      label: (edge.data as { basis: string }).basis,
    });
  }, []);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Network className="size-4 text-muted-foreground" aria-hidden />
          Evidence graph context
        </CardTitle>
        <CardDescription>
          Direct neighborhood of this session in the capture evidence graph.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {state.status === "loading" ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading graph…
          </p>
        ) : state.status === "unavailable" ? (
          <p className="text-xs text-muted-foreground">
            Evidence graph is not available for this capture.
          </p>
        ) : nodes.length === 0 ? (
          <EmptyState
            icon={Network}
            title="Session not present in graph"
            description="The graph for this capture does not reference this session."
          />
        ) : (
          <>
            <div className="h-72 w-full overflow-hidden rounded-md border border-border/60">
              <ReactFlowProvider>
                <ReactFlow
                  nodes={nodes}
                  edges={edges}
                  nodeTypes={nodeTypes}
                  onNodeClick={onNodeClick}
                  onEdgeClick={onEdgeClick}
                  onPaneClick={() => setFocus(null)}
                  fitView
                  fitViewOptions={{ padding: 0.2 }}
                  minZoom={0.2}
                  proOptions={{ hideAttribution: true }}
                  nodesConnectable={false}
                  zoomOnScroll={false}
                  preventScrolling={false}
                >
                  <Background gap={22} />
                </ReactFlow>
              </ReactFlowProvider>
            </div>
            <div className="mt-2 flex items-center justify-between gap-3">
              <p className="min-w-0 truncate text-xs text-muted-foreground" aria-live="polite">
                {focus ? (
                  <>
                    <span className="font-medium uppercase">{focus.type}</span> · {focus.label}
                  </>
                ) : (
                  `${nodes.length} nodes · ${edges.length} relationships — select an element to inspect`
                )}
              </p>
              <Link
                href={`/graph?capture=${captureId}`}
                className="shrink-0 text-xs font-medium text-primary underline-offset-2 hover:underline"
              >
                Full graph →
              </Link>
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}
