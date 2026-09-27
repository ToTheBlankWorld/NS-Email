"use client";

import Link from "next/link";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  ArrowLeft,
  Check,
  Copy,
  FileArchive,
  FileScan,
  LoaderCircle,
  RefreshCw,
} from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ApiError, getCapture, type CaptureRecord } from "@/lib/api";
import { formatBytes, formatCount, formatDuration, formatTimestamp } from "@/lib/format";

type DetailState =
  | { status: "loading" }
  | { status: "loaded"; capture: CaptureRecord }
  | { status: "error"; error: ApiError };

function MetaRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-6 border-b border-border/30 py-2 last:border-0">
      <dt className="shrink-0 text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all text-right text-sm">{children}</dd>
    </div>
  );
}

function HashRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    navigator.clipboard.writeText(value).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      },
      () => setCopied(false),
    );
  }, [value]);

  return (
    <div className="flex items-baseline justify-between gap-6 border-b border-border/30 py-2 last:border-0">
      <dt className="shrink-0 text-xs text-muted-foreground">{label}</dt>
      <dd className="flex min-w-0 items-center gap-1.5">
        <code className="min-w-0 break-all text-right font-mono text-xs">{value}</code>
        <button
          type="button"
          onClick={copy}
          aria-label={`Copy ${label}`}
          className="shrink-0 rounded-sm p-1 text-muted-foreground transition-colors hover:text-foreground"
        >
          {copied ? (
            <Check className="size-3.5 text-success" aria-hidden />
          ) : (
            <Copy className="size-3.5" aria-hidden />
          )}
        </button>
      </dd>
    </div>
  );
}

/** Full capture detail: acquisition metadata plus the next-stage placeholder. */
export function CaptureDetail({ captureId }: { captureId: string }) {
  const [state, setState] = useState<DetailState>({ status: "loading" });

  const load = useCallback(
    (signal?: AbortSignal) => {
      getCapture(captureId, signal)
        .then((capture) => setState({ status: "loaded", capture }))
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setState({
            status: "error",
            error:
              err instanceof ApiError ? err : new ApiError("network_error", "Request failed", 0),
          });
        });
    },
    [captureId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  if (state.status === "loading") {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={LoaderCircle} title="Loading capture…" />
        </CardContent>
      </Card>
    );
  }

  if (state.status === "error") {
    const notFound = state.error.code === "capture_not_found";
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={notFound ? FileArchive : RefreshCw}
            title={notFound ? "Capture not found" : "Capture could not be loaded"}
            description={state.error.message}
          >
            <div className="flex items-center gap-2">
              <Button render={<Link href="/captures" />} variant="outline" size="sm">
                <ArrowLeft aria-hidden /> All captures
              </Button>
              {notFound ? null : (
                <Button
                  size="sm"
                  onClick={() => {
                    setState({ status: "loading" });
                    load();
                  }}
                >
                  Retry
                </Button>
              )}
            </div>
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const capture = state.capture;

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Capture</CardTitle>
          <CardDescription className="truncate font-mono text-xs">
            {capture.filename}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <dl>
            <HashRow label="Evidence ID" value={capture.id} />
            <HashRow label="SHA-256" value={capture.sha256} />
            <MetaRow label="Filename">{capture.filename}</MetaRow>
            <MetaRow label="Format">
              <Badge variant="outline" className="font-mono text-[11px]">
                {capture.format}
              </Badge>
            </MetaRow>
            <MetaRow label="Size">{formatBytes(capture.size_bytes)}</MetaRow>
            <MetaRow label="Status">
              {capture.status === "ready" ? (
                <Badge className="bg-success/15 text-success">Ready</Badge>
              ) : (
                <Badge variant="outline" className="text-muted-foreground">
                  Registered
                </Badge>
              )}
            </MetaRow>
            <MetaRow label="Packets">{formatCount(capture.packet_count)}</MetaRow>
            <MetaRow label="Capture start">{formatTimestamp(capture.started_at)}</MetaRow>
            <MetaRow label="Capture end">{formatTimestamp(capture.ended_at)}</MetaRow>
            <MetaRow label="Duration">{formatDuration(capture.duration_seconds)}</MetaRow>
            <MetaRow label="Link type">{capture.link_type ?? "—"}</MetaRow>
            <MetaRow label="Ingested">{formatTimestamp(capture.ingested_at)}</MetaRow>
            <MetaRow label="Inspection">
              {capture.inspection.status === "inspected" ? (
                <span className="font-mono text-xs">
                  {capture.inspection.tool}
                  {capture.inspection.tool_version
                    ? ` · v${capture.inspection.tool_version}`
                    : ""}
                </span>
              ) : (
                <span className="text-xs text-muted-foreground">
                  {capture.inspection.message ?? "not available"}
                </span>
              )}
            </MetaRow>
          </dl>
          {capture.inspection.warnings.length > 0 ? (
            <ul className="mt-3 space-y-1 rounded-md border border-warning/30 bg-warning/5 px-3 py-2">
              {capture.inspection.warnings.map((warning) => (
                <li key={warning} className="text-[11px] text-warning/90">
                  {warning}
                </li>
              ))}
            </ul>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <FileScan className="size-4 text-muted-foreground" aria-hidden />
            Forensic analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Protocol analysis will become available in the next analysis stage.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
