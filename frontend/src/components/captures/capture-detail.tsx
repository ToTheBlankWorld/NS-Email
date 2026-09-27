"use client";

import Link from "next/link";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  ArrowLeft,
  ArrowRight,
  FileArchive,
  FileScan,
  LoaderCircle,
  RefreshCw,
  TriangleAlert,
} from "lucide-react";

import { AnomaliesSection } from "@/components/anomalies/anomalies-section";
import { FindingsSection } from "@/components/findings/findings-section";
import { PostureSection } from "@/components/posture/posture-section";
import { CaptureSecurityOverview } from "@/components/captures/capture-overview";
import { HashRow } from "@/components/hash-row";
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
import {
  ApiError,
  analyzeCapture,
  getCapture,
  listSessions,
  type CaptureRecord,
  type SessionRecord,
} from "@/lib/api";
import { formatBytes, formatCount, formatDuration, formatTimestamp } from "@/lib/format";

type DetailState =
  | { status: "loading" }
  | { status: "loaded"; capture: CaptureRecord }
  | { status: "error"; error: ApiError };

type AnalysisState = "idle" | "analyzing";

function MetaRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-6 border-b border-border/30 py-2 last:border-0">
      <dt className="shrink-0 text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all text-right text-sm">{children}</dd>
    </div>
  );
}

function protocolCounts(sessions: SessionRecord[]): { protocol: string; count: number }[] {
  const counts = new Map<string, number>();
  for (const session of sessions) {
    const key = session.protocol ?? "unknown";
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([protocol, count]) => ({ protocol, count }))
    .sort((a, b) => b.count - a.count || a.protocol.localeCompare(b.protocol));
}

function AnalysisCard({
  capture,
  sessions,
  onAnalyzed,
}: {
  capture: CaptureRecord;
  sessions: SessionRecord[] | null;
  onAnalyzed: () => void;
}) {
  const [phase, setPhase] = useState<AnalysisState>("idle");
  const [error, setError] = useState<ApiError | null>(null);
  const analysis = capture.analysis;

  const runAnalysis = useCallback(() => {
    setPhase("analyzing");
    setError(null);
    analyzeCapture(capture.id)
      .then(onAnalyzed)
      .catch((err: unknown) => {
        setError(
          err instanceof ApiError ? err : new ApiError("network_error", "Request failed", 0),
        );
      })
      .finally(() => setPhase("idle"));
  }, [capture.id, onAnalyzed]);

  const notAnalyzed = !analysis || analysis.status === "not_analyzed";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <FileScan className="size-4 text-muted-foreground" aria-hidden />
          Forensic analysis
        </CardTitle>
        <CardDescription>
          Reconstruct TCP sessions and email protocol evidence from this capture.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {phase === "analyzing" ? (
          <div className="flex items-center gap-3 rounded-md border border-border/60 bg-muted/30 px-4 py-3">
            <LoaderCircle className="size-4 animate-spin text-muted-foreground" aria-hidden />
            <p className="text-sm">Analyzing capture…</p>
          </div>
        ) : notAnalyzed ? (
          <div className="flex items-center justify-between gap-4">
            <p className="text-sm text-muted-foreground">Not analyzed</p>
            <Button size="sm" onClick={runAnalysis}>
              Analyze capture
            </Button>
          </div>
        ) : analysis?.status === "failed" ? (
          <div className="flex items-center justify-between gap-4">
            <div className="min-w-0">
              <p className="flex items-center gap-1.5 text-sm text-destructive">
                <TriangleAlert className="size-3.5" aria-hidden /> Analysis failed
              </p>
              <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                {analysis.error_code}
                {analysis.error_message ? ` · ${analysis.error_message}` : ""}
              </p>
            </div>
            <Button variant="outline" size="sm" onClick={runAnalysis}>
              Retry
            </Button>
          </div>
        ) : (
          <div className="space-y-3">
            <div className="flex items-center justify-between gap-4">
              <p className="text-sm">
                Analysis complete ·{" "}
                <span className="font-medium">
                  Sessions discovered: {analysis?.session_count ?? 0}
                </span>
              </p>
              <Button variant="outline" size="sm" onClick={runAnalysis}>
                <RefreshCw aria-hidden /> Re-analyze
              </Button>
            </div>
            {sessions !== null && sessions.length > 0 ? (
              <div className="flex flex-wrap gap-2" aria-label="Protocol breakdown">
                {protocolCounts(sessions).map(({ protocol, count }) => (
                  <Badge key={protocol} variant="outline" className="font-mono text-[11px]">
                    {protocol.toUpperCase()} {count}
                  </Badge>
                ))}
              </div>
            ) : null}
            {analysis?.warnings.length ? (
              <ul className="space-y-1 rounded-md border border-warning/30 bg-warning/5 px-3 py-2">
                {analysis.warnings.map((warning) => (
                  <li key={warning} className="text-[11px] text-warning/90">
                    {warning}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        )}
        {error ? (
          <p role="alert" className="mt-3 text-xs text-destructive">
            {error.message}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function SessionsTable({ captureId }: { captureId: string }) {
  const [sessions, setSessions] = useState<SessionRecord[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  const load = useCallback(
    (signal?: AbortSignal) => {
      listSessions(captureId, signal)
        .then(setSessions)
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(
            err instanceof ApiError ? err : new ApiError("network_error", "Request failed", 0),
          );
        });
    },
    [captureId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  if (error) {
    return <p className="text-xs text-destructive">{error.message}</p>;
  }
  if (sessions === null || sessions.length === 0) {
    return null;
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Sessions</CardTitle>
      </CardHeader>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border/60 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
              <th className="px-4 py-2.5 font-medium">Protocol</th>
              <th className="px-4 py-2.5 font-medium">Client</th>
              <th className="px-4 py-2.5 font-medium">Server</th>
              <th className="px-4 py-2.5 font-medium">Start</th>
              <th className="px-4 py-2.5 font-medium">Duration</th>
              <th className="px-4 py-2.5 font-medium">Packets</th>
              <th className="px-4 py-2.5 font-medium">Bytes</th>
              <th className="px-4 py-2.5 font-medium">Complete</th>
              <th className="px-4 py-2.5 font-medium">Confidence</th>
              <th className="px-4 py-2.5" aria-label="Open" />
            </tr>
          </thead>
          <tbody>
            {sessions.map((session) => (
              <tr
                key={session.id}
                className="border-b border-border/40 transition-colors last:border-0 hover:bg-muted/40"
              >
                <td className="px-4 py-2.5">
                  <Badge variant="outline" className="font-mono text-[11px]">
                    {(session.protocol ?? "unknown").toUpperCase()}
                  </Badge>
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">
                  {session.client_ip}:{session.client_port}
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">
                  {session.server_ip}:{session.server_port}
                </td>
                <td className="px-4 py-2.5 text-xs text-muted-foreground">
                  {formatTimestamp(session.started_at)}
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">
                  {formatDuration(session.duration_seconds)}
                </td>
                <td className="px-4 py-2.5 font-mono text-xs">{formatCount(session.packet_count)}</td>
                <td className="px-4 py-2.5 font-mono text-xs">
                  {formatBytes(session.bytes_client_to_server + session.bytes_server_to_client)}
                </td>
                <td className="px-4 py-2.5">
                  {session.complete ? (
                    <Badge className="bg-success/15 text-success">Complete</Badge>
                  ) : (
                    <Badge variant="outline" className="text-warning">
                      Incomplete
                    </Badge>
                  )}
                </td>
                <td className="px-4 py-2.5 text-xs capitalize text-muted-foreground">
                  {session.confidence}
                </td>
                <td className="px-4 py-2.5 text-right">
                  <Link
                    href={`/sessions/${session.id}`}
                    aria-label={`Open session ${session.id}`}
                    className="inline-flex text-muted-foreground transition-colors hover:text-foreground"
                  >
                    <ArrowRight className="size-4" aria-hidden />
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

/** Full capture detail: acquisition metadata, analysis, and sessions. */
export function CaptureDetail({ captureId }: { captureId: string }) {
  const [state, setState] = useState<DetailState>({ status: "loading" });
  const [sessions, setSessions] = useState<SessionRecord[] | null>(null);

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

  const loadSessions = useCallback(
    (signal?: AbortSignal) => {
      listSessions(captureId, signal)
        .then(setSessions)
        .catch(() => setSessions(null));
    },
    [captureId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    loadSessions(controller.signal);
    return () => controller.abort();
  }, [load, loadSessions]);

  const onAnalyzed = useCallback(() => {
    const controller = new AbortController();
    load(controller.signal);
    loadSessions(controller.signal);
  }, [load, loadSessions]);

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
            <MetaRow label="Packets">{formatCount(capture.packet_count)}</MetaRow>
            <MetaRow label="Ingested">{formatTimestamp(capture.ingested_at)}</MetaRow>
          </dl>
        </CardContent>
      </Card>

      <AnalysisCard capture={capture} sessions={sessions} onAnalyzed={onAnalyzed} />

      {capture.analysis?.status === "completed" ? (
        <CaptureSecurityOverview captureId={capture.id} sessions={sessions} />
      ) : null}

      <SessionsTable captureId={capture.id} />

      <FindingsSection captureId={capture.id} />

      <AnomaliesSection captureId={capture.id} />

      <PostureSection captureId={capture.id} />
    </div>
  );
}
