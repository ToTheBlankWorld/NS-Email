"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { LoaderCircle, ShieldQuestion } from "lucide-react";

import { CaptureSelector } from "@/components/captures/capture-selector";
import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { listAnomalies, type AnomalyRecord } from "@/lib/api";
import { cn } from "@/lib/utils";
import { defaultCaptureId, useCaptures } from "@/lib/use-captures";

const BANDS = ["highly_anomalous", "anomalous", "unusual", "normal", "insufficient_evidence"] as const;

const BAND_BADGE: Record<string, string> = {
  highly_anomalous: "bg-destructive/15 text-destructive",
  anomalous: "bg-destructive/10 text-destructive",
  unusual: "bg-warning/15 text-warning",
  normal: "bg-primary/10 text-primary",
  insufficient_evidence: "bg-muted text-muted-foreground",
};

/** Band label carries the meaning; color is reinforcement only. */
function BandBadge({ band }: { band: string }) {
  return (
    <Badge className={cn("capitalize", BAND_BADGE[band] ?? "bg-muted text-muted-foreground")}>
      {band.replace(/_/g, " ")}
    </Badge>
  );
}

function FilterRow({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
      {label}
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-md border border-border/70 bg-background px-1.5 py-1 font-mono text-[11px] text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
      >
        <option value="">all</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Anomaly workspace: Stage 6 results with filtering, sorting, navigation. */
export function AnomaliesWorkspace() {
  const captures = useCaptures();
  const router = useRouter();
  const searchParams = useSearchParams();

  const captureId =
    searchParams.get("capture") ?? defaultCaptureId(captures.status === "loaded" ? captures.captures : []);
  const [anomalies, setAnomalies] = useState<AnomalyRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [band, setBand] = useState("");
  const [protocol, setProtocol] = useState("");
  const [sort, setSort] = useState<"band" | "score_desc" | "session">("band");
  const [prevCaptureId, setPrevCaptureId] = useState(captureId);
  if (prevCaptureId !== captureId) {
    setPrevCaptureId(captureId);
    setAnomalies(null);
    setError(null);
  }

  useEffect(() => {
    if (!captureId) return;
    const controller = new AbortController();
    listAnomalies(captureId, controller.signal)
      .then(setAnomalies)
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError("Anomalies could not be loaded.");
      });
    return () => controller.abort();
  }, [captureId]);

  const onCaptureChange = useCallback(
    (id: string) => {
      router.replace(`/anomalies?capture=${id}`, { scroll: false });
    },
    [router],
  );

  const filtered = useMemo(() => {
    if (!anomalies) return null;
    const result = anomalies.filter(
      (a) =>
        (!band || (a.band ?? a.status) === band) &&
        (!protocol || a.protocol === protocol),
    );
    result.sort((a, b) => {
      if (sort === "score_desc") {
        return (b.score ?? -1) - (a.score ?? -1);
      }
      if (sort === "session") {
        return a.session_id.localeCompare(b.session_id);
      }
      const bandA = BANDS.indexOf((a.band ?? a.status) as (typeof BANDS)[number]);
      const bandB = BANDS.indexOf((b.band ?? b.status) as (typeof BANDS)[number]);
      return (bandA === -1 ? 99 : bandA) - (bandB === -1 ? 99 : bandB);
    });
    return result;
  }, [anomalies, band, protocol, sort]);

  const distinct = useCallback(
    (values: (string | null)[]) =>
      [...new Set(values.filter((value): value is string => Boolean(value)))].sort(),
    [],
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

  if (captures.captures.length === 0) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={ShieldQuestion}
            title="No captures registered"
            description="Upload a PCAP from the dashboard to begin."
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <CaptureSelector captures={captures.captures} value={captureId} onChange={onCaptureChange} analyzedOnly />
        <div className="flex flex-wrap items-center gap-3">
          <FilterRow
            label="Band"
            value={band}
            options={[...BANDS]}
            onChange={setBand}
          />
          <FilterRow
            label="Protocol"
            value={protocol}
            options={anomalies ? distinct(anomalies.map((a) => a.protocol)) : []}
            onChange={setProtocol}
          />
          <FilterRow
            label="Sort"
            value={sort}
            options={["band", "score_desc", "session"]}
            onChange={(value) => setSort(value as typeof sort)}
          />
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        Anomaly bands describe statistical deviation from the capture-local baseline. They are
        not indicators of compromise, attack, or maliciousness.
      </p>

      <Card>
        <CardContent className="px-0 py-2">
          {error ? (
            <p className="px-4 text-xs text-destructive">{error}</p>
          ) : anomalies === null ? (
            <p className="flex items-center gap-2 px-4 py-3 text-sm text-muted-foreground">
              <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading anomalies…
            </p>
          ) : filtered && filtered.length > 0 ? (
            <table className="w-full text-sm">
              <caption className="sr-only">Behavioral anomalies for capture {captureId}</caption>
              <thead>
                <tr className="border-b border-border/60 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th scope="col" className="px-4 py-2 font-medium">Band</th>
                  <th scope="col" className="px-2 py-2 font-medium">Session</th>
                  <th scope="col" className="hidden px-2 py-2 font-medium sm:table-cell">Protocol</th>
                  <th scope="col" className="hidden px-2 py-2 font-medium md:table-cell">Score</th>
                  <th scope="col" className="px-4 py-2 font-medium">Top deviations</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((anomaly) => (
                  <tr
                    key={anomaly.anomaly_id}
                    className="border-b border-border/30 transition-colors last:border-0 hover:bg-muted/40"
                  >
                    <td className="px-4 py-2">
                      <BandBadge band={anomaly.band ?? anomaly.status} />
                    </td>
                    <td className="px-2 py-2">
                      <Link
                        href={`/anomalies/${anomaly.anomaly_id}`}
                        className="font-mono text-xs hover:underline"
                      >
                        {anomaly.session_id}
                      </Link>
                    </td>
                    <td className="hidden px-2 py-2 sm:table-cell">
                      <Badge variant="outline" className="font-mono text-[10px] uppercase">
                        {anomaly.protocol ?? "unknown"}
                      </Badge>
                    </td>
                    <td className="hidden px-2 py-2 font-mono text-xs md:table-cell">
                      {anomaly.score ?? "—"}
                    </td>
                    <td className="max-w-72 truncate px-4 py-2 text-[11px] text-muted-foreground">
                      {anomaly.top_deviations
                        .slice(0, 3)
                        .map((d) => d.feature)
                        .join(", ") || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="px-4 py-4">
              <EmptyState
                icon={ShieldQuestion}
                title="No anomalies match the active filters"
                description={
                  anomalies.length === 0
                    ? "No behavioral anomalies were evaluated for this capture."
                    : undefined
                }
              />
            </div>
          )}
        </CardContent>
      </Card>
      {anomalies ? (
        <p className="text-[11px] text-muted-foreground" aria-live="polite">
          {filtered?.length ?? 0} of {anomalies.length} anomaly result(s) shown
        </p>
      ) : null}
    </div>
  );
}
