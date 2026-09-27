"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { LoaderCircle, ShieldAlert, ShieldQuestion } from "lucide-react";

import { SeverityBadge } from "@/components/findings/severity-badge";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  getSessionAnomaly,
  listSessionFindings,
  type AnomalyRecord,
  type FindingRecord,
  type FindingSeverity,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const BAND_BADGE: Record<string, string> = {
  highly_anomalous: "bg-destructive/15 text-destructive",
  anomalous: "bg-destructive/10 text-destructive",
  unusual: "bg-warning/15 text-warning",
  normal: "bg-primary/10 text-primary",
  insufficient_evidence: "bg-muted text-muted-foreground",
};

type SummaryState =
  | { status: "loading" }
  | { status: "loaded"; findings: FindingRecord[]; anomaly: AnomalyRecord | null }
  | { status: "error"; message: string };

/** Security summary for one session: findings and anomaly state (Stage 4/6). */
export function SessionSecuritySummary({ sessionId }: { sessionId: string }) {
  const [state, setState] = useState<SummaryState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      listSessionFindings(sessionId, controller.signal).catch(() => []),
      getSessionAnomaly(sessionId, controller.signal).catch(() => null),
    ])
      .then(([findings, anomaly]) =>
        setState({ status: "loaded", findings, anomaly }),
      )
      .catch(() => setState({ status: "error", message: "Security data unavailable." }));
    return () => controller.abort();
  }, [sessionId]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Security summary</CardTitle>
        <CardDescription>
          Deterministic findings and the behavioral anomaly state for this session.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {state.status === "loading" ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading…
          </p>
        ) : state.status === "error" ? (
          <p className="text-xs text-destructive">{state.message}</p>
        ) : (
          <div className="space-y-3">
            {state.findings.length === 0 ? (
              <p className="text-sm text-muted-foreground">No findings for this session.</p>
            ) : (
              <ul className="space-y-1.5">
                {state.findings.map((finding) => (
                  <li key={finding.id} className="flex items-center gap-2.5">
                    <SeverityBadge severity={finding.severity as FindingSeverity} />
                    <Link
                      href={`/findings/${finding.id}`}
                      className="min-w-0 flex-1 truncate text-sm hover:underline"
                    >
                      {finding.title}
                    </Link>
                    <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                      {finding.rule_id}
                    </span>
                  </li>
                ))}
              </ul>
            )}
            {state.anomaly ? (
              <div className="flex items-center gap-2.5 border-t border-border/40 pt-2.5">
                <Badge
                  className={cn(
                    "capitalize",
                    BAND_BADGE[state.anomaly.band ?? state.anomaly.status] ??
                      "bg-muted text-muted-foreground",
                  )}
                >
                  {(state.anomaly.band ?? state.anomaly.status).replace(/_/g, " ")}
                </Badge>
                <span className="text-xs text-muted-foreground">
                  behavioral anomaly band (not an indicator of compromise)
                </span>
                <Link
                  href={`/anomalies/${state.anomaly.anomaly_id}`}
                  className="ml-auto shrink-0 text-xs font-medium text-primary underline-offset-2 hover:underline"
                >
                  Details →
                </Link>
              </div>
            ) : (
              <p className="flex items-center gap-2 border-t border-border/40 pt-2.5 text-xs text-muted-foreground">
                <ShieldQuestion className="size-3.5" aria-hidden /> No behavioral anomaly
                evaluation for this session.
              </p>
            )}
            {state.findings.length === 0 && !state.anomaly ? (
              <p className="flex items-center gap-2 text-[11px] text-muted-foreground">
                <ShieldAlert className="size-3.5" aria-hidden /> Absence of findings is not
                proof of security.
              </p>
            ) : null}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
