"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { GitCompare, RefreshCw } from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  clearBaseline,
  comparePair,
  getBaseline,
  getDrift,
  getDriftSummary,
  getRemediationDrift,
  listComparisons,
  listDrift,
  listObservations,
  setBaseline,
  type ComparisonResult,
  type DriftObservation,
  type DriftRecord,
  type DriftSummary,
  type RemediationDriftView,
} from "@/lib/cases";
import { formatTimestamp } from "@/lib/format";

const DRIFT_TYPES = [
  "posture_change",
  "finding_introduced",
  "finding_resolved",
  "finding_recurred",
  "tls_configuration_changed",
  "certificate_changed",
  "certificate_validity_changed",
  "protocol_behavior_changed",
  "anomaly_state_changed",
  "correlation_pattern_changed",
];

const LIFECYCLE_BADGE: Record<string, "default" | "outline" | "destructive"> = {
  new: "default",
  persistent: "outline",
  resolved: "outline",
  recurred: "destructive",
  not_comparable: "outline",
};

/** Longitudinal drift: observations, baseline, comparisons, and drift records. */
export function DriftTab({
  caseId,
  captureIds,
}: {
  caseId: string;
  captureIds: string[];
}) {
  const [observations, setObservations] = useState<DriftObservation[]>([]);
  const [baseline, setBaselineId] = useState<string | null>(null);
  const [summary, setSummary] = useState<DriftSummary | null>(null);
  const [comparisons, setComparisons] = useState<ComparisonResult[]>([]);
  const [drift, setDrift] = useState<DriftRecord[]>([]);
  const [driftTotal, setDriftTotal] = useState(0);
  const [typeFilter, setTypeFilter] = useState("");
  const [appliedType, setAppliedType] = useState("");
  const [selectedPair, setSelectedPair] = useState<string | null>(null);
  const [pairDetail, setPairDetail] = useState<ComparisonResult | null>(null);
  const [selectedDrift, setSelectedDrift] = useState<string | null>(null);
  const [driftDetail, setDriftDetail] = useState<DriftRecord | null>(null);
  const [remediationView, setRemediationView] = useState<RemediationDriftView | null>(null);
  const [baselinePick, setBaselinePick] = useState("");
  const [pairBase, setPairBase] = useState("");
  const [pairCmp, setPairCmp] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const load = useCallback(
    (signal?: AbortSignal) => {
      Promise.all([
        listObservations(caseId, signal),
        getBaseline(caseId, signal),
        getDriftSummary(caseId, signal),
        listComparisons(caseId, signal),
        listDrift(caseId, appliedType ? { type: appliedType, limit: 200 } : { limit: 200 }, signal),
      ])
        .then(([obs, base, summ, comps, driftList]) => {
          setObservations(obs.observations);
          setBaselineId(base.baseline_capture_id);
          setSummary(summ);
          setComparisons(comps.comparisons);
          setDrift(driftList.drift);
          setDriftTotal(driftList.total);
          if (comps.comparisons.length > 0 && !selectedPair) {
            const first = comps.comparisons[comps.comparisons.length - 1];
            setSelectedPair(`${first.previous_capture_id}→${first.comparison_capture_id}`);
            setPairDetail(first);
          }
        })
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(err instanceof Error ? err.message : "Request failed");
        })
        .finally(() => setLoading(false));
    },
    [caseId, appliedType, selectedPair],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  function refresh() {
    setActionError(null);
    setError(null);
    setLoading(true);
    setDriftDetail(null);
    setRemediationView(null);
    load();
  }

  async function runBaseline(action: () => Promise<unknown>) {
    setActionError(null);
    try {
      await action();
      refresh();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Request failed");
    }
  }

  function openPair(previousId: string, comparisonId: string, record?: ComparisonResult) {
    setSelectedPair(`${previousId}→${comparisonId}`);
    setPairDetail(record ?? null);
    if (!record) {
      comparePair(caseId, { baseline_capture_id: previousId, comparison_capture_id: comparisonId })
        .then(setPairDetail)
        .catch((err: unknown) => {
          setActionError(err instanceof Error ? err.message : "Request failed");
        });
    }
  }

  function openDrift(driftId: string) {
    setSelectedDrift(driftId);
    setRemediationView(null);
    getDrift(caseId, driftId)
      .then(setDriftDetail)
      .catch((err: unknown) => {
        setActionError(err instanceof Error ? err.message : "Request failed");
      });
  }

  function openRemediationView(remediationId: string) {
    getRemediationDrift(caseId, remediationId)
      .then(setRemediationView)
      .catch((err: unknown) => {
        setActionError(err instanceof Error ? err.message : "Request failed");
      });
  }

  if (loading) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={GitCompare} title="Loading longitudinal drift…" />
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={RefreshCw} title="Drift could not be loaded" description={error}>
            <Button variant="outline" size="sm" onClick={refresh}>
              Retry
            </Button>
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const regressions = drift.filter((d) => d.drift_type === "finding_recurred");
  const configChanges = drift.filter((d) =>
    [
      "tls_configuration_changed",
      "certificate_changed",
      "certificate_validity_changed",
      "protocol_behavior_changed",
    ].includes(d.drift_type),
  );

  return (
    <div className="space-y-5">
      {actionError ? (
        <Card>
          <CardContent className="py-3">
            <p className="text-sm text-destructive">{actionError}</p>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Longitudinal summary
            {summary ? ` — ${summary.drift_count} drift records across ${summary.observations} observations` : ""}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p className="text-xs text-muted-foreground">
            Drift is derived from observed captures; it does not prove causality, and repeated
            findings do not prove malicious activity. The analyst explicitly selects the baseline —
            nothing is selected automatically.
          </p>
          {summary ? (
            <dl className="grid grid-cols-2 gap-2 md:grid-cols-4">
              {(
                [
                  ["Posture changes", summary.posture_changes],
                  ["New findings", summary.new_findings],
                  ["Resolved", summary.resolved_findings],
                  ["Recurring", summary.recurring_findings],
                  ["Configuration", summary.configuration_changes],
                  ["Anomaly", summary.anomaly_changes],
                ] as [string, number][]
              ).map(([label, value]) => (
                <div key={label} className="rounded-md border border-border px-3 py-2">
                  <dt className="text-xs text-muted-foreground">{label}</dt>
                  <dd className="text-lg font-semibold">{value}</dd>
                </div>
              ))}
            </dl>
          ) : null}
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted-foreground">
              Baseline: <span className="font-mono">{baseline ?? "none selected"}</span>
            </span>
            <select
              value={baselinePick}
              onChange={(e) => setBaselinePick(e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Baseline capture"
            >
              <option value="">Select baseline capture…</option>
              {captureIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
            <Button
              size="sm"
              variant="outline"
              disabled={!baselinePick}
              onClick={() => void runBaseline(() => setBaseline(caseId, baselinePick))}
            >
              Set baseline
            </Button>
            {baseline ? (
              <Button size="sm" variant="outline" onClick={() => void runBaseline(() => clearBaseline(caseId))}>
                Clear
              </Button>
            ) : null}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Posture trend</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-xs text-muted-foreground">
            Authoritative per-capture Stage 5 scores, quoted in attachment order. Score changes are
            arithmetic differences — they do not attribute cause.
          </p>
          {observations.length === 0 ? <p>No observations recorded.</p> : null}
          {observations.map((o, index) => {
            const prev = index > 0 ? observations[index - 1].posture_score : null;
            const delta =
              o.posture_score !== null && prev !== null ? o.posture_score - prev : null;
            return (
              <div
                key={o.capture_id}
                className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
              >
                <Link
                  href={`/captures/${encodeURIComponent(o.capture_id)}`}
                  className="font-mono text-xs hover:underline"
                >
                  {o.capture_id}
                </Link>
                <Badge variant="outline">{o.posture_state ?? o.analysis_status}</Badge>
                {o.posture_score !== null ? (
                  <span className="text-xs">score {o.posture_score}</span>
                ) : (
                  <span className="text-xs text-muted-foreground">score unavailable</span>
                )}
                {delta !== null ? (
                  <span className="text-xs text-muted-foreground">
                    change {delta >= 0 ? "+" : ""}
                    {delta} points
                  </span>
                ) : null}
                {o.capture_id === baseline ? <Badge>baseline</Badge> : null}
              </div>
            );
          })}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Finding lifecycle</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted-foreground">Comparison:</span>
            {comparisons.map((c) => {
              const key = `${c.previous_capture_id}→${c.comparison_capture_id}`;
              return (
                <Button
                  key={key}
                  size="sm"
                  variant={selectedPair === key ? "default" : "outline"}
                  onClick={() => openPair(c.previous_capture_id, c.comparison_capture_id, c)}
                >
                  {c.comparison_capture_id.slice(-6)}
                </Button>
              );
            })}
            <select
              value={pairBase}
              onChange={(e) => setPairBase(e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Pair baseline"
            >
              <option value="">Baseline…</option>
              {captureIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
            <select
              value={pairCmp}
              onChange={(e) => setPairCmp(e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Pair comparison"
            >
              <option value="">Comparison…</option>
              {captureIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
            <Button
              size="sm"
              variant="outline"
              disabled={!pairBase || !pairCmp}
              onClick={() => openPair(pairBase, pairCmp)}
            >
              Compare
            </Button>
          </div>
          {pairDetail ? (
            <>
              <p className="text-xs text-muted-foreground">{pairDetail.posture_statement}</p>
              {pairDetail.finding_lifecycle.length === 0 ? (
                <p>No finding rules in either observation.</p>
              ) : (
                pairDetail.finding_lifecycle.map((row) => (
                  <div
                    key={row.rule_id}
                    className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
                  >
                    <span className="font-mono text-xs">{row.rule_id}</span>
                    <Badge variant={LIFECYCLE_BADGE[row.lifecycle] ?? "outline"}>
                      {row.lifecycle}
                    </Badge>
                    {!row.comparable ? (
                      <span className="text-xs text-muted-foreground">insufficient comparable evidence</span>
                    ) : null}
                    {row.baseline_finding_id ? (
                      <Button
                        render={
                          <Link href={`/findings/${encodeURIComponent(row.baseline_finding_id)}`} />
                        }
                        variant="outline"
                        size="sm"
                      >
                        Baseline finding
                      </Button>
                    ) : null}
                    {row.latest_finding_id ? (
                      <Button
                        render={
                          <Link href={`/findings/${encodeURIComponent(row.latest_finding_id)}`} />
                        }
                        variant="outline"
                        size="sm"
                      >
                        Latest finding
                      </Button>
                    ) : null}
                  </div>
                ))
              )}
            </>
          ) : (
            <p className="text-xs text-muted-foreground">
              Select two observations to compare. Absence in one capture does not prove global
              remediation.
            </p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Configuration changes ({configChanges.length})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {configChanges.length === 0 ? <p>No configuration drift observed.</p> : null}
          {configChanges.slice(0, 20).map((d) => (
            <div
              key={d.drift_id}
              className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
            >
              <Badge variant="outline">{d.drift_type}</Badge>
              <span className="break-all font-mono text-xs text-muted-foreground">{d.evidence_key}</span>
              <Button variant="outline" size="sm" onClick={() => openDrift(d.drift_id)}>
                Detail
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Regressions ({regressions.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-xs text-muted-foreground">
            A regression means a previously observed condition was observed again. It does not mean
            an attack occurred.
          </p>
          {regressions.length === 0 ? <p>No recurring findings observed.</p> : null}
          {regressions.map((d) => (
            <div
              key={d.drift_id}
              className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
            >
              <span className="break-all font-mono text-xs">{d.evidence_key}</span>
              {d.regression_after_verification ? (
                <Badge variant="destructive">regression after verification</Badge>
              ) : (
                <Badge variant="outline">recurred</Badge>
              )}
              <Button variant="outline" size="sm" onClick={() => openDrift(d.drift_id)}>
                Detail
              </Button>
              {d.related_remediation_ids.map((rid) => (
                <Button key={rid} variant="outline" size="sm" onClick={() => openRemediationView(rid)}>
                  Review remediation
                </Button>
              ))}
            </div>
          ))}
          {remediationView ? (
            <div className="rounded-md border border-border px-3 py-2">
              <p className="font-medium">Remediation {remediationView.remediation_id}</p>
              <p className="font-mono text-xs text-muted-foreground">
                rule {remediationView.rule_id} · status {remediationView.status} · verification{" "}
                {remediationView.verification_status} · current lifecycle{" "}
                {remediationView.current_lifecycle}
              </p>
              {remediationView.regression_detected ? (
                <p className="text-xs text-destructive">
                  Regression detected after previous verification. Existing remediation may require
                  review.
                </p>
              ) : null}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Drift records ({driftTotal})
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Drift type filter"
            >
              <option value="">All types</option>
              {DRIFT_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                setAppliedType(typeFilter);
              }}
            >
              Apply
            </Button>
          </div>
          {drift.length === 0 ? <p>No drift records for this filter.</p> : null}
          {drift.map((d) => (
            <div
              key={d.drift_id}
              className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
            >
              <Badge variant="outline">{d.drift_type}</Badge>
              <span className="break-all font-mono text-xs text-muted-foreground">
                {d.baseline_capture_id} → {d.comparison_capture_id}
              </span>
              <Button
                variant={selectedDrift === d.drift_id ? "default" : "outline"}
                size="sm"
                onClick={() => openDrift(d.drift_id)}
              >
                Detail
              </Button>
            </div>
          ))}
          {driftDetail ? (
            <div className="space-y-1 rounded-md border border-border px-3 py-2">
              <p className="font-mono text-xs">{driftDetail.drift_id}</p>
              <p className="text-xs text-muted-foreground">
                {driftDetail.drift_type} · evidence key{" "}
                <span className="font-mono">{driftDetail.evidence_key}</span>
              </p>
              <p>{driftDetail.statement}</p>
              <p className="font-mono text-xs text-muted-foreground">
                before: {JSON.stringify(driftDetail.before)} · after:{" "}
                {JSON.stringify(driftDetail.after)}
              </p>
              {driftDetail.related_finding_ids.length > 0 ? (
                <p className="text-xs">
                  Related findings:{" "}
                  {driftDetail.related_finding_ids.map((fid) => (
                    <Link
                      key={fid}
                      href={`/findings/${encodeURIComponent(fid)}`}
                      className="mr-2 font-mono hover:underline"
                    >
                      {fid}
                    </Link>
                  ))}
                </p>
              ) : null}
              {driftDetail.related_remediation_ids.length > 0 ? (
                <p className="text-xs">
                  Related remediations: {driftDetail.related_remediation_ids.join(", ")}
                </p>
              ) : null}
              {driftDetail.related_correlations.length > 0 ? (
                <p className="text-xs text-muted-foreground">
                  Related correlations:{" "}
                  {driftDetail.related_correlations.map((c) => c.correlation_id).join(", ")}
                </p>
              ) : null}
            </div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Observations ({observations.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {observations.map((o) => (
            <div
              key={o.capture_id}
              className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
            >
              <Link
                href={`/captures/${encodeURIComponent(o.capture_id)}`}
                className="font-mono text-xs hover:underline"
              >
                {o.capture_id}
              </Link>
              <span className="text-xs text-muted-foreground">
                {o.session_count} sessions · {o.finding_rules.length} rules ·{" "}
                {formatTimestamp(o.analyzed_at)}
              </span>
              {o.capture_id === baseline ? <Badge>baseline</Badge> : null}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
