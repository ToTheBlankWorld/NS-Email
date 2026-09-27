"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { FileArchive, RefreshCw } from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ApiError, listCaptures, type CaptureRecord } from "@/lib/api";
import { formatBytes, formatCount, formatTimestamp } from "@/lib/format";

type ListState =
  | { status: "loading" }
  | { status: "loaded"; captures: CaptureRecord[] }
  | { status: "error"; error: ApiError };

function StatusBadge({ capture }: { capture: CaptureRecord }) {
  if (capture.status === "ready") {
    return <Badge className="bg-success/15 text-success">Ready</Badge>;
  }
  return (
    <Badge variant="outline" className="text-muted-foreground">
      Registered
    </Badge>
  );
}

/** Registered captures list — empty state until the first ingest. */
export function CaptureList() {
  const [state, setState] = useState<ListState>({ status: "loading" });

  const load = useCallback((signal?: AbortSignal) => {
    listCaptures(signal)
      .then((captures) => setState({ status: "loaded", captures }))
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setState({
          status: "error",
          error:
            err instanceof ApiError ? err : new ApiError("network_error", "Request failed", 0),
        });
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  if (state.status === "error") {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={RefreshCw}
            title="Captures could not be loaded"
            description={state.error.message}
          >
            <Button variant="outline" size="sm" onClick={() => load()}>
              Retry
            </Button>
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  if (state.status === "loading") {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={FileArchive} title="Loading captures…" />
        </CardContent>
      </Card>
    );
  }

  if (state.captures.length === 0) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={FileArchive}
            title="No captures yet"
            description="Upload a PCAP from the dashboard to register forensic evidence."
          >
            <Button render={<Link href="/" />} size="sm">
              Go to dashboard
            </Button>
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border/60 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
              <th className="px-4 py-2.5 font-medium">Capture</th>
              <th className="px-4 py-2.5 font-medium">Format</th>
              <th className="px-4 py-2.5 font-medium">Size</th>
              <th className="px-4 py-2.5 font-medium">Packets</th>
              <th className="px-4 py-2.5 font-medium">Status</th>
              <th className="px-4 py-2.5 font-medium">Ingested</th>
            </tr>
          </thead>
          <tbody>
            {state.captures.map((capture) => (
              <tr
                key={capture.id}
                className="border-b border-border/40 transition-colors last:border-0 hover:bg-muted/40"
              >
                <td className="max-w-[220px] px-4 py-2.5">
                  <Link
                    href={`/captures/${capture.id}`}
                    className="block truncate font-mono text-xs text-foreground hover:text-primary"
                    title={capture.filename}
                  >
                    {capture.filename}
                  </Link>
                </td>
                <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                  {capture.format}
                </td>
                <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                  {formatBytes(capture.size_bytes)}
                </td>
                <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                  {formatCount(capture.packet_count)}
                </td>
                <td className="px-4 py-2.5">
                  <StatusBadge capture={capture} />
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">
                  {formatTimestamp(capture.ingested_at)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}
