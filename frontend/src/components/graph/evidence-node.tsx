"use client";

import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";

import { CATEGORY_COLOR, type NodeCategory } from "@/lib/graph-layout";
import { cn } from "@/lib/utils";

type EvidenceNodeData = {
  label: string;
  nodeType: string;
  sourceId: string;
};

function EvidenceNodeInner({ data, selected }: NodeProps) {
  const nodeData = data as unknown as EvidenceNodeData;
  const category = (nodeData.nodeType as NodeCategory) ?? "session";
  const color = CATEGORY_COLOR[category] ?? "#4a5568";
  return (
    <div
      className={cn(
        "min-w-36 max-w-56 rounded-md border bg-card px-2.5 py-1.5 shadow-sm transition-shadow",
        selected ? "ring-2 ring-ring/70 shadow-md" : "",
      )}
      style={{ borderLeft: `3px solid ${color}` }}
    >
      <Handle type="target" position={Position.Left} className="!size-1.5" />
      <p
        className="truncate text-[9px] font-medium uppercase tracking-wider"
        style={{ color }}
      >
        {nodeData.nodeType.replace(/_/g, " ")}
      </p>
      <p className="truncate text-xs text-foreground" title={nodeData.label}>
        {nodeData.label}
      </p>
      <Handle type="source" position={Position.Right} className="!size-1.5" />
    </div>
  );
}

export const EvidenceNode = memo(EvidenceNodeInner);
