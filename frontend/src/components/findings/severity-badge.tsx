"use client";

import { Badge } from "@/components/ui/badge";
import type { FindingSeverity } from "@/lib/api";
import { cn } from "@/lib/utils";

const SEVERITY_BADGE: Record<FindingSeverity, string> = {
  critical: "bg-destructive/15 text-destructive",
  high: "bg-destructive/10 text-destructive",
  medium: "bg-warning/15 text-warning",
  low: "bg-primary/10 text-primary",
  info: "bg-muted text-muted-foreground",
};

/**
 * Severity indicator. The label text carries the meaning — color is
 * reinforcement only, never the sole signal.
 */
export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <Badge className={cn("capitalize", SEVERITY_BADGE[severity])}>{severity}</Badge>
  );
}

export const SEVERITY_ORDER: FindingSeverity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];
