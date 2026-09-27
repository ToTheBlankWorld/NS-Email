"use client";

import { RefreshCw } from "lucide-react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { API_BASE_URL } from "@/lib/api";
import { useBackendHealth } from "@/lib/backend-health";
import { cn } from "@/lib/utils";

const STATUS_META = {
  checking: { label: "Checking API", dot: "bg-warning", pulse: true },
  online: { label: "API online", dot: "bg-success", pulse: true },
  offline: { label: "API offline", dot: "bg-destructive", pulse: false },
} as const;

/** Live backend availability pill shown in the top bar. */
export function BackendStatus() {
  const { status, service, refresh } = useBackendHealth();
  const meta = STATUS_META[status];

  return (
    <Tooltip>
      <TooltipTrigger
        onClick={(event) => {
          event.preventDefault();
          refresh();
        }}
        aria-label={`Backend status: ${meta.label}. Select to re-check.`}
        className={cn(
          "group inline-flex h-7 items-center gap-2 rounded-full border border-border/70 px-2.5",
          "text-xs text-muted-foreground transition-colors outline-none",
          "hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/60",
        )}
      >
        <span
          className={cn("size-1.5 rounded-full", meta.dot, meta.pulse && "animate-pulse")}
          aria-hidden
        />
        <span className="whitespace-nowrap">
          {meta.label}
          {status === "online" && service ? (
            <span className="font-mono text-[11px] text-muted-foreground/80"> · {service}</span>
          ) : null}
        </span>
        <RefreshCw
          className="size-3 opacity-0 transition-opacity group-hover:opacity-60"
          aria-hidden
        />
      </TooltipTrigger>
      <TooltipContent side="bottom">
        {status === "offline"
          ? `Cannot reach ${API_BASE_URL} — is the backend running?`
          : `Connected to ${API_BASE_URL}`}
      </TooltipContent>
    </Tooltip>
  );
}
