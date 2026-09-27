"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Activity, LoaderCircle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  listAnomalies,
  type AnomalyRecord,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const BAND_BADGE: Record<string, string> = {
  normal: "bg-success/10 text-success",
  unusual: "bg-warning/15 text-warning",
  anomalous: "bg-warning/20 text-warning",
  highly_anomalous: "bg-destructive/15 text-destructive",
  insufficient_evidence: "bg-muted text-muted-foreground",
  model_error: "bg-destructive/10 text-destructive",
};

/** Behavioral anomaly section for one capture. */
export function AnomaliesSection({ captureId }: { captureId: string }) {
  const [anomalies, setAnomalies] = useState<AnomalyRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    (signal?: AbortSignal) => {
      listAnomalies(captureId, signal)
        .then(setAnomalies)
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError("Anomaly results could not be loaded.");
        });
    },
    [captureId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Activity className="size-4 text-muted-foreground" aria-hidden />
          Behavioral anomalies
        </CardTitle>
        <CardDescription>
          IsolationForest over session features — behavioral, not attack attribution.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {error ? (
          <p className="text-xs text-destructive">{error}</p>
        ) : anomalies === null ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading anomalies…
          </p>
        ) : anomalies.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No anomaly results — run analysis to generate the baseline.
          </p>
        ) : (
          <ul className="divide-y divide-border/40">
            {anomalies.map((anomaly) => (
              <li key={anomaly.anomaly_id}>
                <Link
                  href={`/anomalies/${anomaly.anomaly_id}`}
                  className="flex items-center gap-3 px-1 py-2.5 transition-colors hover:bg-muted/40"
                >
                  <Badge
                    className={cn(
                      "capitalize",
                      BAND_BADGE[anomaly.band ?? anomaly.status],
                    )}
                  >
                    {anomaly.band?.replace("_", " ") ?? anomaly.status.replace("_", " ")}
                  </Badge>
                  {anomaly.score !== null ? (
                    <span className="w-10 shrink-0 font-mono text-sm font-medium">
                      {anomaly.score}
                    </span>
                  ) : (
                    <span className="w-10 shrink-0 text-center text-xs text-muted-foreground">
                      —
                    </span>
                  )}
                  <span className="hidden shrink-0 font-mono text-[11px] uppercase text-muted-foreground sm:inline">
                    {anomaly.protocol ?? "—"}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">
                    {anomaly.session_id}
                  </span>
                  {anomaly.top_deviations.length > 0 ? (
                    <span className="hidden max-w-[200px] shrink-0 truncate text-[11px] text-muted-foreground lg:inline">
                      {anomaly.top_deviations[0].feature}: {anomaly.top_deviations[0].observed}
                    </span>
                  ) : null}
                </Link>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
