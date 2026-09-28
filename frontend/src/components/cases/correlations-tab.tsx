"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { Network, RefreshCw } from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError } from "@/lib/api";
import {
  getCorrelationContext,
  getCorrelationSummary,
  getInvestigationGraph,
  getSessionRelated,
  listCorrelations,
  queryCorrelationAI,
  type CorrelationAIResult,
  type CorrelationContext,
  type CorrelationRecord,
  type CorrelationSummary,
  type InvestigationGraph,
  type SessionRelated,
} from "@/lib/cases";
import { formatTimestamp } from "@/lib/format";

const CORRELATION_TYPES = [
  "shared_endpoint",
  "shared_host",
  "shared_certificate",
  "shared_certificate_subject",
  "shared_tls_configuration",
  "shared_protocol",
  "shared_finding",
  "shared_anomaly_pattern",
  "repeated_session_pattern",
  "shared_evidence",
];

const SORTS = ["occurrences", "type", "first_observed", "last_observed"];

/** Neutral one-line explanation of why the records are related. */
function whyRelated(correlation: CorrelationRecord): string {
  const captures = correlation.capture_count;
  const what: Record<string, string> = {
    shared_endpoint: "This endpoint was observed",
    shared_host: "This host was observed",
    shared_certificate: "This certificate fingerprint was observed",
    shared_certificate_subject: "This certificate subject was observed",
    shared_tls_configuration: "This TLS configuration was observed",
    shared_protocol: "This email protocol was observed",
    shared_finding: "This finding rule was observed",
    shared_anomaly_pattern: "This anomaly band was observed",
    repeated_session_pattern: "This session pattern was observed",
    shared_evidence: "This evidence value was observed",
  };
  const prefix = what[correlation.correlation_type] ?? "This evidence was observed";
  return `${prefix} in ${correlation.occurrence_count} observation(s) across ${captures} capture(s).`;
}

type Filters = {
  type: string;
  capture_id: string;
  protocol: string;
  endpoint: string;
  certificate: string;
  finding: string;
  search: string;
  sort: string;
};

const EMPTY_FILTERS: Filters = {
  type: "",
  capture_id: "",
  protocol: "",
  endpoint: "",
  certificate: "",
  finding: "",
  search: "",
  sort: "occurrences",
};

/** Case correlations: dense analyst table with filters, search, and detail. */
export function CorrelationsTab({
  caseId,
  captureIds,
}: {
  caseId: string;
  captureIds: string[];
}) {
  const [summary, setSummary] = useState<CorrelationSummary | null>(null);
  const [records, setRecords] = useState<CorrelationRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [applied, setApplied] = useState<Filters>(EMPTY_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [context, setContext] = useState<CorrelationContext | null>(null);
  const [graph, setGraph] = useState<InvestigationGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    (active: Filters, signal?: AbortSignal) => {
      const params: Record<string, string | number> = { sort: active.sort, limit: 100 };
      for (const key of [
        "type",
        "capture_id",
        "protocol",
        "endpoint",
        "certificate",
        "finding",
        "search",
      ] as const) {
        if (active[key]) params[key] = active[key];
      }
      Promise.all([
        listCorrelations(caseId, params, signal),
        getCorrelationSummary(caseId, signal),
        getInvestigationGraph(caseId, signal).catch(() => null),
      ])
        .then(([list, corrSummary, invGraph]) => {
          setRecords(list.correlations);
          setTotal(list.total);
          setSummary(corrSummary);
          setGraph(invGraph);
        })
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(err instanceof Error ? err.message : "Request failed");
        })
        .finally(() => setLoading(false));
    },
    [caseId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(applied, controller.signal);
    return () => controller.abort();
  }, [load, applied]);

  const loadContext = useCallback(
    (id: string, signal?: AbortSignal) => {
      getCorrelationContext(caseId, id, signal)
        .then(setContext)
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(err instanceof Error ? err.message : "Request failed");
        });
    },
    [caseId],
  );

  useEffect(() => {
    if (!selectedId) return;
    const controller = new AbortController();
    loadContext(selectedId, controller.signal);
    return () => controller.abort();
  }, [selectedId, loadContext]);

  function update<K extends keyof Filters>(key: K, value: Filters[K]) {
    const next = { ...filters, [key]: value };
    setFilters(next);
    if (key === "type" || key === "capture_id" || key === "sort") {
      setLoading(true);
      setError(null);
      setApplied(next);
    }
  }

  function applyFilters(event: React.FormEvent) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setApplied(filters);
  }

  if (loading && !summary) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={Network} title="Loading correlations…" />
        </CardContent>
      </Card>
    );
  }

  if (error && !summary) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={RefreshCw} title="Correlations could not be loaded" description={error}>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setLoading(true);
                setError(null);
                load(applied);
              }}
            >
              Retry
            </Button>
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const selected = records.find((r) => r.correlation_id === selectedId) ?? null;

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Correlation summary — {summary?.correlation_count ?? 0} relationship(s) across{" "}
            {summary?.capture_count ?? 0} capture(s)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-xs text-muted-foreground">
            Counts only — never a score. Repeated evidence does not establish intent, ownership,
            or compromise.
          </p>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(summary?.by_type ?? {}).map(([type, count]) => (
              <Badge key={type} variant="outline">
                {type}: {count}
              </Badge>
            ))}
          </div>
          {graph ? (
            <p className="text-xs text-muted-foreground">
              Investigation graph: {graph.node_count} nodes / {graph.edge_count} edges across
              forensic + correlation layers
              {graph.sessions_truncated ? " (sessions truncated — counts unaffected)" : ""}.
            </p>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Filters &amp; search</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-2 md:grid-cols-4"
            onSubmit={applyFilters}
          >
            <select
              value={filters.type}
              onChange={(e) => update("type", e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Correlation type"
            >
              <option value="">All types</option>
              {CORRELATION_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
            <select
              value={filters.capture_id}
              onChange={(e) => update("capture_id", e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Capture"
            >
              <option value="">All captures</option>
              {captureIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
            <select
              value={filters.sort}
              onChange={(e) => update("sort", e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Sort"
            >
              {SORTS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <input
              value={filters.search}
              onChange={(e) => setFilters({ ...filters, search: e.target.value })}
              placeholder="Search evidence key…"
              maxLength={128}
              className="rounded-md border border-input bg-background px-3 py-1 text-sm"
            />
            <input
              value={filters.protocol}
              onChange={(e) => setFilters({ ...filters, protocol: e.target.value })}
              placeholder="protocol (e.g. smtp)"
              maxLength={32}
              className="rounded-md border border-input bg-background px-3 py-1 text-sm"
            />
            <input
              value={filters.endpoint}
              onChange={(e) => setFilters({ ...filters, endpoint: e.target.value })}
              placeholder="endpoint (e.g. 198.51.100.20)"
              maxLength={64}
              className="rounded-md border border-input bg-background px-3 py-1 text-sm"
            />
            <input
              value={filters.certificate}
              onChange={(e) => setFilters({ ...filters, certificate: e.target.value })}
              placeholder="certificate (fingerprint)"
              maxLength={128}
              className="rounded-md border border-input bg-background px-3 py-1 text-sm"
            />
            <div className="flex gap-2">
              <input
                value={filters.finding}
                onChange={(e) => setFilters({ ...filters, finding: e.target.value })}
                placeholder="finding (rule id)"
                maxLength={64}
                className="w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
              />
              <Button type="submit" size="sm">
                Apply
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Correlations ({total}){loading ? " — refreshing…" : ""}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {records.length === 0 ? (
            <p>
              No correlations match. Attach two or more captures with shared structured
              evidence (endpoints, certificates, TLS configurations, findings).
            </p>
          ) : null}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-muted-foreground">
                  <th className="py-1 pr-2 font-medium">Type</th>
                  <th className="py-1 pr-2 font-medium">Strength</th>
                  <th className="py-1 pr-2 font-medium">Occurrences</th>
                  <th className="py-1 pr-2 font-medium">Captures</th>
                  <th className="py-1 pr-2 font-medium">Evidence key</th>
                  <th className="py-1 font-medium">First observed</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr
                    key={r.correlation_id}
                    onClick={() => {
                      setSelectedId(r.correlation_id);
                      setContext(null);
                    }}
                    className={`cursor-pointer border-b border-border/60 hover:bg-muted/50 ${
                      r.correlation_id === selectedId ? "bg-muted" : ""
                    }`}
                  >
                    <td className="py-1.5 pr-2 font-mono text-xs">{r.correlation_type}</td>
                    <td className="py-1.5 pr-2">
                      <Badge variant="outline">{r.strength}</Badge>
                    </td>
                    <td className="py-1.5 pr-2">{r.occurrence_count}</td>
                    <td className="py-1.5 pr-2">{r.capture_count}</td>
                    <td className="max-w-64 truncate py-1.5 pr-2 font-mono text-xs">
                      {r.evidence_key}
                    </td>
                    <td className="py-1.5 font-mono text-xs">
                      {formatTimestamp(r.first_observed_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {selected ? (
        <CorrelationDetail
          caseId={caseId}
          correlation={selected}
          context={context}
          onSelectCorrelation={setSelectedId}
        />
      ) : null}
    </div>
  );
}

function CorrelationDetail({
  caseId,
  correlation,
  context,
  onSelectCorrelation,
}: {
  caseId: string;
  correlation: CorrelationRecord;
  context: CorrelationContext | null;
  onSelectCorrelation: (id: string) => void;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">
          {correlation.correlation_type} · {correlation.evidence_key}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-xs text-muted-foreground">{whyRelated(correlation)}</p>
        <dl className="grid gap-1 font-mono text-xs">
          <div className="flex gap-2">
            <dt className="text-muted-foreground">id</dt>
            <dd className="break-all">{correlation.correlation_id}</dd>
          </div>
          <div className="flex gap-2">
            <dt className="text-muted-foreground">strength</dt>
            <dd>{correlation.strength}</dd>
          </div>
          {Object.entries(correlation.evidence).map(([key, value]) => (
            <div key={key} className="flex gap-2">
              <dt className="text-muted-foreground">{key}</dt>
              <dd className="break-all">{String(value)}</dd>
            </div>
          ))}
        </dl>

        <section aria-label="Affected captures">
          <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Affected captures ({correlation.source_capture_ids.length})
          </h4>
          <div className="mt-1 flex flex-wrap gap-1.5">
            {correlation.source_capture_ids.map((id) => (
              <Button key={id} render={<Link href={`/captures/${encodeURIComponent(id)}`} />} variant="outline" size="sm">
                <span className="font-mono text-xs">{id}</span>
              </Button>
            ))}
          </div>
        </section>

        <section aria-label="Affected sessions">
          <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Affected sessions ({correlation.source_session_ids.length})
          </h4>
          <ul className="mt-1 space-y-1">
            {correlation.source_session_ids.slice(0, 8).map((id) => (
              <li key={id} className="flex flex-wrap items-center gap-2">
                <Button render={<Link href={`/sessions/${encodeURIComponent(id)}`} />} variant="outline" size="sm">
                  <span className="font-mono text-xs">{id}</span>
                </Button>
                <SessionRelatedView caseId={caseId} sessionId={id} onSelect={onSelectCorrelation} />
              </li>
            ))}
            {correlation.source_session_ids.length > 8 ? (
              <li className="text-xs text-muted-foreground">
                …and {correlation.source_session_ids.length - 8} more (see occurrences in export).
              </li>
            ) : null}
          </ul>
        </section>

        {context ? (
          <>
            {context.related_finding_ids.length > 0 ? (
              <section aria-label="Related findings">
                <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Related findings ({context.related_finding_ids.length})
                </h4>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {context.related_finding_ids.slice(0, 12).map((id) => (
                    <Button key={id} render={<Link href={`/findings/${encodeURIComponent(id)}`} />} variant="outline" size="sm">
                      <span className="font-mono text-xs">{id}</span>
                    </Button>
                  ))}
                </div>
              </section>
            ) : null}
            {context.related_anomaly_ids.length > 0 ? (
              <section aria-label="Related anomalies">
                <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Related anomalies ({context.related_anomaly_ids.length})
                </h4>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {context.related_anomaly_ids.slice(0, 12).map((id) => (
                    <Button key={id} render={<Link href={`/anomalies/${encodeURIComponent(id)}`} />} variant="outline" size="sm">
                      <span className="font-mono text-xs">{id}</span>
                    </Button>
                  ))}
                </div>
              </section>
            ) : null}
            {context.graph_nodes.length > 0 ? (
              <section aria-label="Graph context">
                <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Graph context ({context.graph_nodes.length} nodes)
                </h4>
                <ul className="mt-1 space-y-0.5 font-mono text-xs text-muted-foreground">
                  {context.graph_nodes.slice(0, 12).map((n) => (
                    <li key={n.node_id}>
                      {n.node_type} · {n.node_id}
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
            {context.timeline_refs.length > 0 ? (
              <section aria-label="Timeline references">
                <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
                  Case timeline references ({context.timeline_refs.length})
                </h4>
                <ul className="mt-1 space-y-0.5 font-mono text-xs text-muted-foreground">
                  {context.timeline_refs.slice(0, 12).map((t) => (
                    <li key={t.entry_id}>
                      {t.event_type} · {formatTimestamp(t.created_at)}
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}
          </>
        ) : (
          <p className="text-xs text-muted-foreground">Loading context…</p>
        )}

        <CorrelationAIPanel
          caseId={caseId}
          correlationId={correlation.correlation_id}
          evidenceKey={correlation.evidence_key}
        />
      </CardContent>
    </Card>
  );
}

/** Related observations for one session, loaded on demand. */
function SessionRelatedView({
  caseId,
  sessionId,
  onSelect,
}: {
  caseId: string;
  sessionId: string;
  onSelect: (id: string) => void;
}) {
  const [related, setRelated] = useState<SessionRelated | null>(null);
  const [open, setOpen] = useState(false);

  const loadRelated = useCallback(
    (signal?: AbortSignal) => {
      getSessionRelated(caseId, sessionId, signal)
        .then(setRelated)
        .catch(() => {});
    },
    [caseId, sessionId],
  );

  useEffect(() => {
    if (!open || related) return;
    const controller = new AbortController();
    loadRelated(controller.signal);
    return () => controller.abort();
  }, [open, related, loadRelated]);

  if (!open) {
    return (
      <Button variant="ghost" size="sm" onClick={() => setOpen(true)}>
        Related observations
      </Button>
    );
  }
  if (!related) return <span className="text-xs text-muted-foreground">Loading…</span>;
  if (related.related.length === 0)
    return <span className="text-xs text-muted-foreground">No related observations.</span>;
  return (
    <ul className="w-full space-y-0.5 text-xs text-muted-foreground">
      {related.related.slice(0, 5).map((r) => (
        <li key={r.correlation_id}>
          {r.correlation_type} · {r.other_session_count} other session(s) in{" "}
          {r.other_capture_ids.length} other capture(s) ·{" "}
          <button
            type="button"
            className="underline hover:text-foreground"
            onClick={() => onSelect(r.correlation_id)}
          >
            view
          </button>
        </li>
      ))}
    </ul>
  );
}

/** Explicit, ephemeral AI question about one correlation. */
function CorrelationAIPanel({
  caseId,
  correlationId,
  evidenceKey,
}: {
  caseId: string;
  correlationId: string;
  evidenceKey: string;
}) {
  const [question, setQuestion] = useState("Explain the repeated observations in this case.");
  const [state, setState] = useState<
    { status: "idle" } | { status: "loading" } | { status: "loaded"; result: CorrelationAIResult } | { status: "error"; message: string }
  >({ status: "idle" });

  return (
    <section aria-label="Ask AI about this correlation" className="rounded-md border border-border p-3">
      <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        Ask AI (minimized context, never persisted)
      </h4>
      <form
        className="mt-2 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (!question.trim()) return;
          setState({ status: "loading" });
          queryCorrelationAI(caseId, correlationId, question)
            .then((result) => setState({ status: "loaded", result }))
            .catch((err: unknown) => {
              setState({
                status: "error",
                message: err instanceof ApiError ? err.message : "Request failed",
              });
            });
        }}
      >
        <input
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          maxLength={2000}
          placeholder="e.g. Explain the repeated certificate observations"
          className="w-full rounded-md border border-input bg-background px-3 py-1 text-sm"
        />
        <Button type="submit" size="sm" disabled={state.status === "loading" || !question.trim()}>
          Ask
        </Button>
      </form>
      {state.status === "loading" ? (
        <p className="mt-2 text-xs text-muted-foreground">Asking…</p>
      ) : null}
      {state.status === "error" ? <p className="mt-2 text-sm text-destructive">{state.message}</p> : null}
      {state.status === "loaded" ? (
        <div className="mt-2 text-sm">
          {state.result.status !== "completed" ? (
            <p className="text-destructive">
              {state.result.error ?? `AI returned ${state.result.status}`} (evidence key:{" "}
              {evidenceKey})
            </p>
          ) : (
            <>
              <p className="whitespace-pre-wrap">{state.result.answer}</p>
              {(state.result.interpretations ?? []).length > 0 ? (
                <p className="mt-1 text-xs text-muted-foreground">
                  Interpretive assistance only — not evidence.
                </p>
              ) : null}
            </>
          )}
        </div>
      ) : null}
    </section>
  );
}
