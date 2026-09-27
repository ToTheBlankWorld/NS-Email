"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { LoaderCircle, Waypoints } from "lucide-react";

import { CaptureSelector } from "@/components/captures/capture-selector";
import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { listSessions, type SessionRecord } from "@/lib/api";
import { formatDuration } from "@/lib/format";
import { defaultCaptureId, useCaptures } from "@/lib/use-captures";

/** Sessions workspace: reconstructed sessions across captures. */
export function SessionsWorkspace() {
  const captures = useCaptures();
  const router = useRouter();
  const searchParams = useSearchParams();

  const captureId =
    searchParams.get("capture") ?? defaultCaptureId(captures.status === "loaded" ? captures.captures : []);
  const [sessions, setSessions] = useState<SessionRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [prevCaptureId, setPrevCaptureId] = useState(captureId);
  if (prevCaptureId !== captureId) {
    setPrevCaptureId(captureId);
    setSessions(null);
    setError(null);
  }

  useEffect(() => {
    if (!captureId) return;
    const controller = new AbortController();
    listSessions(captureId, controller.signal)
      .then(setSessions)
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError("Sessions could not be loaded.");
      });
    return () => controller.abort();
  }, [captureId]);

  const onCaptureChange = useCallback(
    (id: string) => {
      router.replace(`/sessions?capture=${id}`, { scroll: false });
    },
    [router],
  );

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
            icon={Waypoints}
            title="No captures registered"
            description="Upload a PCAP from the dashboard to reconstruct sessions."
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
          onChange={onCaptureChange}
        />
        <p className="text-[11px] text-muted-foreground" aria-live="polite">
          {sessions ? `${sessions.length} session(s)` : ""}
        </p>
      </div>

      <Card>
        <CardContent className="px-0 py-2">
          {error ? (
            <p className="px-4 text-xs text-destructive">{error}</p>
          ) : sessions === null ? (
            <p className="flex items-center gap-2 px-4 py-3 text-sm text-muted-foreground">
              <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading sessions…
            </p>
          ) : sessions.length > 0 ? (
            <table className="w-full text-sm">
              <caption className="sr-only">Reconstructed sessions for capture {captureId}</caption>
              <thead>
                <tr className="border-b border-border/60 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th scope="col" className="px-4 py-2 font-medium">Session</th>
                  <th scope="col" className="hidden px-2 py-2 font-medium sm:table-cell">Protocol</th>
                  <th scope="col" className="px-2 py-2 font-medium">Client → Server</th>
                  <th scope="col" className="hidden px-2 py-2 text-right font-medium md:table-cell">
                    Duration
                  </th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">Stream</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((session) => (
                  <tr
                    key={session.id}
                    className="border-b border-border/30 transition-colors last:border-0 hover:bg-muted/40"
                  >
                    <td className="px-4 py-2">
                      <Link
                        href={`/sessions/${session.id}`}
                        className="font-mono text-xs hover:underline"
                      >
                        {session.id}
                      </Link>
                    </td>
                    <td className="hidden px-2 py-2 sm:table-cell">
                      <Badge variant="outline" className="font-mono text-[10px] uppercase">
                        {(session.protocol ?? "unknown").toUpperCase()}
                      </Badge>
                    </td>
                    <td className="px-2 py-2 font-mono text-[11px] text-muted-foreground">
                      {session.client_ip}:{session.client_port} → {session.server_ip}:
                      {session.server_port}
                    </td>
                    <td className="hidden px-2 py-2 text-right text-[11px] text-muted-foreground md:table-cell">
                      {formatDuration(session.duration_seconds)}
                    </td>
                    <td className="px-4 py-2 text-right">
                      {session.complete ? (
                        <Badge className="bg-success/15 text-success">complete</Badge>
                      ) : (
                        <Badge variant="outline" className="text-warning">incomplete</Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="px-4 py-4">
              <EmptyState
                icon={Waypoints}
                title="No sessions reconstructed"
                description="Run analysis on this capture to reconstruct email sessions."
              />
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
