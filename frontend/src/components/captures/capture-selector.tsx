"use client";

import { ListFilter } from "lucide-react";

import type { CaptureRecord } from "@/lib/api";
import { cn } from "@/lib/utils";

interface CaptureSelectorProps {
  captures: CaptureRecord[];
  value: string | null;
  onChange: (captureId: string) => void;
  /** Only offer captures whose analysis completed (findings/graph pages). */
  analyzedOnly?: boolean;
  className?: string;
}

/** Capture context selector — native select for full keyboard accessibility. */
export function CaptureSelector({
  captures,
  value,
  onChange,
  analyzedOnly = false,
  className,
}: CaptureSelectorProps) {
  const eligible = analyzedOnly
    ? captures.filter((c) => c.analysis?.status === "completed")
    : captures;

  return (
    <label className={cn("flex items-center gap-2 text-sm", className)}>
      <ListFilter className="size-4 shrink-0 text-muted-foreground" aria-hidden />
      <span className="sr-only">Capture</span>
      <select
        value={value ?? ""}
        onChange={(e) => onChange(e.target.value)}
        disabled={eligible.length === 0}
        className="max-w-64 truncate rounded-md border border-border/70 bg-background px-2 py-1.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/60 disabled:opacity-50"
      >
        {eligible.length === 0 ? (
          <option value="">No analyzed captures</option>
        ) : (
          eligible.map((capture) => (
            <option key={capture.id} value={capture.id}>
              {capture.filename} ({capture.id})
            </option>
          ))
        )}
      </select>
    </label>
  );
}
