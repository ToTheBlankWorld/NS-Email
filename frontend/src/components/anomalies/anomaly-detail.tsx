"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, LoaderCircle, RefreshCw, ShieldQuestion } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ApiError, getAnomaly, type AnomalyRecord } from "@/lib/api";
import { formatTimestamp } from "@/lib/format";

type DetailState =
  | { status: "loading" }
  | { status: "loaded"; anomaly: AnomalyRecord }
  | { status: "error"; error: string };

function DeviationRow({
  feature,
  observed,
  baseline,
  deviation,
}: {
  feature: string;
  observed: string;
  baseline: string;
  deviation: string;
}) {
  return (
    <div className="grid grid-cols-[1fr_1fr_1fr_80px] gap-2 border-b border-border/30 py-2 text-xs last:border-0">
      <span className="font-mono font-medium">{feature}</span>
      <span className="text-right font-mono">{observed}</span>
      <span className="text-right font-mono text-muted-foreground">{baseline}</span>
      <span
        className={
          deviation === "high"
            ? "text-right font-medium text-destructive"
            : deviation === "moderate"
              ? "text-right font-medium text-warning"
              : "text-right text-muted-foreground"
        }
      >
        {deviation}
      </span>
    </div>
  );
}

/** Behavioral anomaly detail — deviations from baseline, not attack attribution. */
export function AnomalyDetail({ anomalyId }: { anomalyId: string }) {
  const [state, setState] = useState<DetailState>({ status: "loading" });

  const load = useCallback(
    (signal?: AbortSignal) => {
      getAnomaly(anomalyId, signal)
        .then((anomaly) => setState({ status: "loaded", anomaly }))
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setState({
            status: "error",
            error: err instanceof Error ? err.message : "Request failed",
          });
        });
    },
    [anomalyId],
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
          <div className="flex items-center justify-center gap-2 px-6 py-12 text-sm text-muted-foreground">
            <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading…
          </div>
        </CardContent>
      </Card>
    );
  }

  if (state.status === "error") {
    return (
      <Card>
        <CardContent className="p-0">
          <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
            <p className="text-sm">{state.error}</p>
            <Button render={<Link href="/captures" />} variant="outline" size="sm">
              <ArrowLeft aria-hidden /> Captures
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  const anomaly = state.anomaly;

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Anomaly assessment</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="space-y-1 text-sm">
            <div className="flex items-baseline justify-between gap-4 border-b border-border/30 py-2">
              <dt className="shrink-0 text-xs text-muted-foreground">Anomaly score</dt>
              <dd className="font-mono text-xl font-semibold">
                {anomaly.score !== null ? anomaly.score : "—"}
                <span className="text-xs font-normal text-muted-foreground">/100</span>
              </dd>
            </div>
            {anomaly.band ? (
              <div className="flex items-baseline justify-between gap-4 border-b border-border/30 py-2">
                <dt className="shrink-0 text-xs text-muted-foreground">Band</dt>
                <dd>
                  <Badge className="capitalize">{anomaly.band.replace("_", " ")}</Badge>
                </dd>
              </div>
            ) : null}
            <div className="flex items-baseline justify-between gap-4 border-b border-border/30 py-2">
              <dt className="shrink-0 text-xs text-muted-foreground">Model</dt>
              <dd className="font-mono text-xs">{anomaly.model_id ?? "—"}</dd>
            </div>
            <div className="flex items-baseline justify-between gap-4 border-b border-border/30 py-2">
              <dt className="shrink-0 text-xs text-muted-foreground">Model version</dt>
              <dd className="font-mono text-xs">{anomaly.model_version}</dd>
            </div>
            <div className="flex items-baseline justify-between gap-4 py-2">
              <dt className="shrink-0 text-xs text-muted-foreground">Feature schema</dt>
              <dd className="font-mono text-xs">{anomaly.feature_schema_version}</dd>
            </div>
          </dl>
        </CardContent>
      </Card>

      {anomaly.top_deviations.length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Top deviations</CardTitle>
            <CardDescription>
              Features ranked by deviation from the capture-local baseline.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-[1fr_1fr_1fr_80px] gap-2 pb-1 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              <span>Feature</span>
              <span className="text-right">Observed</span>
              <span className="text-right">Baseline</span>
              <span className="text-right">Deviation</span>
            </div>
            {anomaly.top_deviations.map((d) => (
              <DeviationRow
                key={d.feature}
                feature={d.feature}
                observed={d.observed}
                baseline={d.baseline}
                deviation={d.deviation}
              />
            ))}
          </CardContent>
        </Card>
      ) : null}

      {Object.keys(anomaly.baseline_summary).length > 0 ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Baseline comparison</CardTitle>
            <CardDescription>
              Session values vs capture-local baseline distribution.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="space-y-1 text-xs">
              {Object.entries(anomaly.baseline_summary).map(([feature, summary]) => (
                <div
                  key={feature}
                  className="flex items-baseline justify-between gap-4 border-b border-border/30 py-1.5 last:border-0"
                >
                  <dt className="shrink-0 font-mono text-muted-foreground">{feature}</dt>
                  <dd className="min-w-0 break-all text-right font-mono">{summary}</dd>
                </div>
              ))}
            </dl>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Evidence</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="space-y-2">
            {anomaly.evidence_refs.map((ref, index) => (
              <li
                key={`${ref.source}-${index}`}
                className="rounded-md border border-border/60 bg-muted/20 px-3 py-2"
              >
                <div className="flex items-center justify-between gap-3">
                  <span className="font-mono text-xs">{ref.source}</span>
                  <Link
                    href={`/sessions/${anomaly.session_id}`}
                    className="shrink-0 text-[11px] text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
                  >
                    open session
                  </Link>
                </div>
                {ref.packet_numbers.length > 0 ? (
                  <p className="mt-1 font-mono text-[11px] text-muted-foreground">
                    packets {ref.packet_numbers.join(", ")}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
          <div className="mt-3 space-y-1 text-xs text-muted-foreground">
            <div className="flex justify-between gap-4">
              <dt>Capture</dt>
              <dd className="font-mono">{anomaly.capture_id}</dd>
            </div>
            <div className="flex justify-between gap-4">
              <dt>Generated</dt>
              <dd className="font-mono">{formatTimestamp(anomaly.generated_at)}</dd>
            </div>
          </div>
          <p className="mt-3 rounded-md border border-border/50 bg-muted/20 px-3 py-2 text-[11px] text-muted-foreground">
            This is behavioral anomaly detection relative to the capture-local baseline —
            not attack attribution. A rare but legitimate configuration can be anomalous.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
