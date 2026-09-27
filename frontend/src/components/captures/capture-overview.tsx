"use client";

import { useEffect, useState } from "react";
import { LoaderCircle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  getAnomalySummary,
  getPosture,
  type AnomalySummary,
  type SessionRecord,
  type SecurityPosture,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

const SEVERITY_TEXT: Record<(typeof SEVERITIES)[number], string> = {
  critical: "text-destructive",
  high: "text-destructive",
  medium: "text-warning",
  low: "text-primary",
  info: "text-muted-foreground",
};

const BANDS = ["highly_anomalous", "anomalous", "unusual", "normal", "insufficient_evidence"] as const;

const POSTURE_BADGE: Record<string, string> = {
  good: "bg-success/15 text-success",
  fair: "bg-warning/15 text-warning",
  poor: "bg-destructive/10 text-destructive",
  critical: "bg-destructive/15 text-destructive",
};

type OverviewState =
  | { status: "loading" }
  | { status: "loaded"; posture: SecurityPosture | null; anomalies: AnomalySummary | null };

function Stat({
  label,
  value,
  sub,
}: {
  label: string;
  value: string | number;
  sub?: string;
}) {
  return (
    <div className="rounded-md border border-border/50 bg-muted/20 px-3 py-2">
      <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </p>
      <p className="mt-0.5 text-lg font-semibold leading-tight">{value}</p>
      {sub ? <p className="text-[11px] text-muted-foreground">{sub}</p> : null}
    </div>
  );
}

/**
 * Capture security overview. Every figure comes from a persisted
 * Stage 4-6 document; nothing is estimated client-side except TLS
 * coverage, which is derived from the reconstructed session list.
 */
export function CaptureSecurityOverview({
  captureId,
  sessions,
}: {
  captureId: string;
  sessions: SessionRecord[] | null;
}) {
  const [state, setState] = useState<OverviewState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      getPosture(captureId, controller.signal).catch(() => null),
      getAnomalySummary(captureId, controller.signal).catch(() => null),
    ]).then(([posture, anomalies]) =>
      setState({ status: "loaded", posture, anomalies }),
    );
    return () => controller.abort();
  }, [captureId]);

  if (state.status === "loading") {
    return (
      <Card>
        <CardContent className="py-3">
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading security
            overview…
          </p>
        </CardContent>
      </Card>
    );
  }

  const posture = state.posture;
  const anomalies = state.anomalies;
  const withHandshake = (sessions ?? []).filter((s) => s.handshake).length;
  const completeHandshakes = (sessions ?? []).filter(
    (s) => s.handshake?.handshake_complete,
  ).length;

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Security overview</CardTitle>
        <CardDescription>
          Persisted posture, findings, and anomaly figures for this capture.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <div className="rounded-md border border-border/50 bg-muted/20 px-3 py-2">
            <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              Posture
            </p>
            {posture ? (
              <>
                <p className="mt-0.5 text-lg font-semibold leading-tight">
                  {posture.overall_score}
                </p>
                <Badge
                  className={cn(
                    "capitalize",
                    POSTURE_BADGE[posture.posture_state] ?? "bg-muted text-muted-foreground",
                  )}
                >
                  {posture.posture_state}
                </Badge>
              </>
            ) : (
              <p className="mt-0.5 text-sm text-muted-foreground">unavailable</p>
            )}
          </div>
          <Stat
            label="Affected sessions"
            value={posture ? `${posture.affected_sessions}/${posture.total_sessions}` : "—"}
          />
          <Stat
            label="Affected hosts"
            value={posture ? `${posture.affected_hosts}/${posture.total_hosts}` : "—"}
          />
          <Stat
            label="TLS coverage"
            value={
              sessions && sessions.length > 0
                ? `${withHandshake}/${sessions.length}`
                : "—"
            }
            sub={`${completeHandshakes} handshakes complete`}
          />
          <Stat
            label="Anomalies evaluated"
            value={anomalies ? anomalies.total_evaluated : "—"}
          />
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded-md border border-border/50 bg-muted/20 px-3 py-2.5">
            <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              Findings by severity
            </p>
            {posture ? (
              <ul className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1">
                {SEVERITIES.map((severity) => (
                  <li key={severity} className="flex items-baseline gap-1.5">
                    <span
                      className={cn(
                        "text-sm font-semibold",
                        SEVERITY_TEXT[severity],
                      )}
                    >
                      {posture.finding_counts_by_severity?.[severity] ?? 0}
                    </span>
                    <span className="text-[11px] capitalize text-muted-foreground">
                      {severity}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="mt-1 text-sm text-muted-foreground">unavailable</p>
            )}
          </div>
          <div className="rounded-md border border-border/50 bg-muted/20 px-3 py-2.5">
            <p className="text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
              Anomaly distribution
            </p>
            {anomalies ? (
              <ul className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1">
                {BANDS.map((band) => {
                  const count = anomalies[band];
                  if (!count) return null;
                  return (
                    <li key={band} className="flex items-baseline gap-1.5">
                      <span className="text-sm font-semibold">{count}</span>
                      <span className="text-[11px] capitalize text-muted-foreground">
                        {band.replace(/_/g, " ")}
                      </span>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="mt-1 text-sm text-muted-foreground">unavailable</p>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
