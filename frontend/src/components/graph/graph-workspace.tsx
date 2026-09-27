"use client";

import "@xyflow/react/dist/style.css";

import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type NodeMouseHandler,
  type EdgeMouseHandler,
} from "@xyflow/react";
import { Crosshair, Maximize, RotateCcw } from "lucide-react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";

import { CaptureSelector } from "@/components/captures/capture-selector";
import { EvidenceNode } from "@/components/graph/evidence-node";
import { EmptyState } from "@/components/empty-state";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { getGraph, type GraphEdge, type GraphNode } from "@/lib/api";
import {
  CATEGORY_COLOR,
  CATEGORY_LABEL,
  NODE_CATEGORY_ORDER,
  toFlowElements,
  type NodeCategory,
} from "@/lib/graph-layout";
import { cacheGraph } from "@/lib/graph-cache";
import { LoaderCircle } from "lucide-react";
import { defaultCaptureId, useCaptures } from "@/lib/use-captures";

const nodeTypes = { evidence: EvidenceNode };

type DetailSelection =
  | { kind: "node"; node: GraphNode }
  | { kind: "edge"; edge: GraphEdge }
  | null;

function detailLinkFor(node: GraphNode): { href: string; label: string } | null {
  if (!node.source_id) return null;
  switch (node.node_type) {
    case "session":
      return { href: `/sessions/${node.source_id}`, label: "Open session workspace" };
    case "finding":
      return { href: `/findings/${node.source_id}`, label: "Open finding detail" };
    case "anomaly":
      return { href: `/anomalies/${node.source_id}`, label: "Open anomaly detail" };
    default:
      return null;
  }
}

function MetadataTable({ metadata }: { metadata: Record<string, unknown> }) {
  const entries = Object.entries(metadata).filter(([, v]) => v !== "" && v != null);
  if (entries.length === 0) return null;
  return (
    <dl className="mt-2 grid grid-cols-[130px_1fr] gap-x-3 gap-y-1 text-xs">
      {entries.map(([key, value]) => (
        <div key={key} className="contents">
          <dt className="text-muted-foreground">{key.replace(/_/g, " ")}</dt>
          <dd className="break-all font-mono">{String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function SelectionDetails({ selection }: { selection: DetailSelection }) {
  if (!selection) {
    return (
      <p className="text-xs text-muted-foreground">
        Select a node or edge to inspect its evidence.
      </p>
    );
  }
  if (selection.kind === "edge") {
    const edge = selection.edge;
    return (
      <div>
        <h3 className="text-sm font-medium">{edge.edge_type.replace(/_/g, " ")}</h3>
        <p className="mt-1 text-xs text-muted-foreground">
          {edge.source_node_id} → {edge.target_node_id}
        </p>
        {edge.basis ? (
          <p className="mt-2 text-xs">
            <span className="font-medium">Basis:</span> {edge.basis}
          </p>
        ) : null}
      </div>
    );
  }
  const node = selection.node;
  const link = detailLinkFor(node);
  return (
    <div>
      <p
        className="text-[10px] font-semibold uppercase tracking-wider"
        style={{ color: CATEGORY_COLOR[node.node_type as NodeCategory] ?? "#4a5568" }}
      >
        {node.node_type.replace(/_/g, " ")}
      </p>
      <h3 className="mt-0.5 break-words text-sm font-medium">{node.label}</h3>
      <p className="mt-1 break-all font-mono text-[10px] text-muted-foreground">
        {node.node_id}
      </p>
      <MetadataTable metadata={node.metadata} />
      {link ? (
        <Link
          href={link.href}
          className="mt-3 inline-block text-xs font-medium text-primary underline-offset-2 hover:underline"
        >
          {link.label} →
        </Link>
      ) : null}
    </div>
  );
}

interface GraphCanvasProps {
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  hiddenNodeTypes: Set<string>;
  hiddenEdgeTypes: Set<string>;
  focusNodeId: string | null;
  onSelectionChange: (selection: DetailSelection) => void;
  selected: DetailSelection;
}

function GraphCanvas({
  graph,
  hiddenNodeTypes,
  hiddenEdgeTypes,
  focusNodeId,
  onSelectionChange,
  selected,
}: GraphCanvasProps) {
  const { fitView, setCenter } = useReactFlow();

  const { nodes, edges } = useMemo(() => {
    const elements = toFlowElements(graph);
    const visibleNodes = elements.nodes.filter(
      (n) => !hiddenNodeTypes.has((n.data as { nodeType: string }).nodeType),
    );
    const visibleIds = new Set(visibleNodes.map((n) => n.id));
    const visibleEdges = elements.edges
      .filter(
        (e) =>
          !hiddenEdgeTypes.has((e.data as { edgeType: string }).edgeType) &&
          visibleIds.has(e.source) &&
          visibleIds.has(e.target),
      )
      .map((e) => ({
        ...e,
        style: {
          stroke:
            selected?.kind === "edge" &&
            e.source === selected.edge.source_node_id &&
            e.target === selected.edge.target_node_id
              ? "#c53030"
              : "#94a3b8",
          strokeWidth: 1,
        },
        labelStyle: { fontSize: 9, fill: "#64748b" },
        labelBgStyle: { fillOpacity: 0.7 },
      }));
    return { nodes: visibleNodes, edges: visibleEdges };
  }, [graph, hiddenNodeTypes, hiddenEdgeTypes, selected]);

  const onNodeClick: NodeMouseHandler = useCallback(
    (_, node) => {
      const graphNode = graph.nodes.find((n) => n.node_id === node.id);
      if (graphNode) onSelectionChange({ kind: "node", node: graphNode });
    },
    [graph, onSelectionChange],
  );

  const onEdgeClick: EdgeMouseHandler = useCallback(
    (_, edge) => {
      const graphEdge = graph.edges.find(
        (e) => e.source_node_id === edge.source && e.target_node_id === edge.target,
      );
      if (graphEdge) onSelectionChange({ kind: "edge", edge: graphEdge });
    },
    [graph, onSelectionChange],
  );

  const focusSelected = useCallback(() => {
    const target = selected?.kind === "node" ? selected.node.node_id : focusNodeId;
    if (!target) return;
    const node = nodes.find((n) => n.id === target);
    if (!node) return;
    setCenter(node.position.x + 100, node.position.y + 30, { zoom: 1.4, duration: 400 });
  }, [nodes, selected, focusNodeId, setCenter]);

  return (
    <div className="relative h-[560px] w-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        onPaneClick={() => onSelectionChange(null)}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.1}
        proOptions={{ hideAttribution: true }}
        nodesDraggable
        nodesConnectable={false}
        elementsSelectable
      >
        <Background gap={22} />
        <Controls showInteractive={false} />
        <MiniMap pannable zoomable className="!bg-muted" />
      </ReactFlow>
      <div className="absolute right-3 top-3 z-10 flex gap-1.5">
        <Button
          size="sm"
          variant="outline"
          onClick={focusSelected}
          aria-label="Focus selected node"
          title="Focus selected node"
        >
          <Crosshair className="size-3.5" aria-hidden /> Focus
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={() => fitView({ padding: 0.15, duration: 400 })}
          aria-label="Fit graph to screen"
          title="Fit to screen"
        >
          <Maximize className="size-3.5" aria-hidden /> Fit
        </Button>
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            onSelectionChange(null);
            fitView({ padding: 0.15, duration: 400 });
          }}
          aria-label="Reset graph view"
          title="Reset view"
        >
          <RotateCcw className="size-3.5" aria-hidden /> Reset
        </Button>
      </div>
    </div>
  );
}

/** Evidence graph workspace: interactive forensic graph for one capture. */
export function GraphWorkspace() {
  const captures = useCaptures();
  const router = useRouter();
  const searchParams = useSearchParams();

  const captureId =
    searchParams.get("capture") ?? defaultCaptureId(captures.status === "loaded" ? captures.captures : []);
  const [graph, setGraph] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hiddenNodeTypes, setHiddenNodeTypes] = useState<Set<string>>(new Set());
  const [hiddenEdgeTypes, setHiddenEdgeTypes] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<DetailSelection>(null);
  const [prevCaptureId, setPrevCaptureId] = useState(captureId);
  if (prevCaptureId !== captureId) {
    setPrevCaptureId(captureId);
    setSelected(null);
    setError(null);
    setGraph(null);
  }

  const load = useCallback(
    (id: string, signal: AbortSignal) => {
      getGraph(id, signal)
        .then((payload) => {
          cacheGraph(id, { nodes: payload.nodes, edges: payload.edges });
          setGraph({ nodes: payload.nodes, edges: payload.edges });
        })
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError("Evidence graph could not be loaded.");
        });
    },
    [],
  );

  useEffect(() => {
    if (!captureId) return;
    const controller = new AbortController();
    load(captureId, controller.signal);
    return () => controller.abort();
  }, [captureId, load]);

  const presentTypes = useMemo(() => {
    if (!graph) return [];
    return NODE_CATEGORY_ORDER.filter((t) => graph.nodes.some((n) => n.node_type === t));
  }, [graph]);

  const presentEdgeTypes = useMemo(() => {
    if (!graph) return [];
    return [...new Set(graph.edges.map((e) => e.edge_type))].sort();
  }, [graph]);

  const toggle = (set: Set<string>, value: string, apply: (s: Set<string>) => void) => {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    apply(next);
  };

  if (captures.status !== "loaded") {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={LoaderCircle} title="Loading captures…" />
        </CardContent>
      </Card>
    );
  }

  if (captures.captures.length === 0 || !captureId) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={LoaderCircle}
            title="No captures available"
            description="Upload and analyze a capture to build its evidence graph."
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <CaptureSelector
          captures={captures.captures}
          value={captureId}
          onChange={(id) => router.replace(`/graph?capture=${id}`, { scroll: false })}
          analyzedOnly
        />
        <p className="text-[11px] text-muted-foreground">
          {graph ? `${graph.nodes.length} nodes · ${graph.edges.length} relationships` : ""}
        </p>
      </div>

      {error ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState icon={LoaderCircle} title="Graph unavailable" description={error} />
          </CardContent>
        </Card>
      ) : !graph ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState icon={LoaderCircle} title="Loading evidence graph…" />
          </CardContent>
        </Card>
      ) : graph.nodes.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState
              icon={LoaderCircle}
              title="Empty evidence graph"
              description="This capture produced no graph nodes."
            />
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[1fr_280px]">
          <Card className="overflow-hidden">
            <CardContent className="p-0">
              <ReactFlowProvider>
                <GraphCanvas
                  graph={graph}
                  hiddenNodeTypes={hiddenNodeTypes}
                  hiddenEdgeTypes={hiddenEdgeTypes}
                  focusNodeId={selected?.kind === "node" ? selected.node.node_id : null}
                  onSelectionChange={setSelected}
                  selected={selected}
                />
              </ReactFlowProvider>
            </CardContent>
          </Card>

          <div className="space-y-4">
            <Card>
              <CardContent className="space-y-3 py-3">
                <h3 className="text-sm font-medium">Investigation panel</h3>
                <SelectionDetails selection={selected} />
              </CardContent>
            </Card>

            <Card>
              <CardContent className="space-y-2 py-3">
                <h3 className="text-sm font-medium">Node filters</h3>
                <ul className="space-y-1">
                  {presentTypes.map((type) => (
                    <li key={type}>
                      <label className="flex items-center gap-2 text-xs">
                        <input
                          type="checkbox"
                          checked={!hiddenNodeTypes.has(type)}
                          onChange={() =>
                            toggle(hiddenNodeTypes, type, setHiddenNodeTypes)
                          }
                          className="size-3.5 accent-primary"
                        />
                        <span
                          className="size-2.5 shrink-0 rounded-sm"
                          style={{ background: CATEGORY_COLOR[type as NodeCategory] }}
                          aria-hidden
                        />
                        {CATEGORY_LABEL[type as NodeCategory]}
                      </label>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="space-y-2 py-3">
                <h3 className="text-sm font-medium">Relationships</h3>
                <ul className="max-h-44 space-y-1 overflow-y-auto">
                  {presentEdgeTypes.map((type) => (
                    <li key={type}>
                      <label className="flex items-center gap-2 text-[11px]">
                        <input
                          type="checkbox"
                          checked={!hiddenEdgeTypes.has(type)}
                          onChange={() =>
                            toggle(hiddenEdgeTypes, type, setHiddenEdgeTypes)
                          }
                          className="size-3.5 accent-primary"
                        />
                        {type.replace(/_/g, " ")}
                      </label>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
}
