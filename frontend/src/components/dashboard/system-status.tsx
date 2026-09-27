"use client";

import { Cpu, PlugZap, Server } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { API_BASE_URL } from "@/lib/api";
import { useBackendHealth } from "@/lib/backend-health";
import { cn } from "@/lib/utils";

function apiHost(): string {
  try {
    return new URL(API_BASE_URL).host;
  } catch {
    return API_BASE_URL;
  }
}

function StatusValue({ tone, children }: { tone: "ok" | "warn" | "off"; children: string }) {
  return (
    <p
      className={cn(
        "mt-1 flex items-center gap-1.5 text-sm font-medium",
        tone === "ok" && "text-success",
        tone === "warn" && "text-warning",
        tone === "off" && "text-muted-foreground",
      )}
    >
      <span
        className={cn(
          "size-1.5 rounded-full",
          tone === "ok" && "bg-success",
          tone === "warn" && "bg-warning",
          tone === "off" && "bg-muted-foreground/50",
        )}
        aria-hidden
      />
      {children}
    </p>
  );
}

/**
 * Ground truth about what this build can do right now. Deliberately free
 * of statistics or findings — no analysis capabilities are wired yet.
 */
export function SystemStatus() {
  const { status } = useBackendHealth();

  const backendValue =
    status === "online" ? "Online" : status === "checking" ? "Checking…" : "Offline";
  const backendTone = status === "online" ? "ok" : status === "checking" ? "warn" : "off";

  return (
    <div className="grid gap-3 sm:grid-cols-3">
      <Card size="sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-[13px] font-medium text-muted-foreground">
            <Server className="size-3.5" aria-hidden />
            Backend API
          </CardTitle>
        </CardHeader>
        <CardContent>
          <StatusValue tone={backendTone}>{backendValue}</StatusValue>
          <p className="mt-1 font-mono text-[11px] text-muted-foreground/80">{apiHost()}</p>
        </CardContent>
      </Card>

      <Card size="sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-[13px] font-medium text-muted-foreground">
            <Cpu className="size-3.5" aria-hidden />
            Analysis engine
          </CardTitle>
        </CardHeader>
        <CardContent>
          <StatusValue tone="off">Not connected</StatusValue>
          <p className="mt-1 text-[11px] text-muted-foreground/80">
            Engine modules attach in a later stage.
          </p>
        </CardContent>
      </Card>

      <Card size="sm">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-[13px] font-medium text-muted-foreground">
            <PlugZap className="size-3.5" aria-hidden />
            Capture ingestion
          </CardTitle>
        </CardHeader>
        <CardContent>
          <StatusValue tone="ok">Available</StatusValue>
          <p className="mt-1 text-[11px] text-muted-foreground/80">
            Upload PCAP/PCAPNG evidence from the capture panel.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
