"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ClipboardCheck, RefreshCw } from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError } from "@/lib/api";
import {
  completeVerification,
  deleteRemediation,
  getRemediation,
  listRemediationTimeline,
  listRemediations,
  listVerifications,
  requestVerification,
  updateRemediation,
  type RemediationRecord,
  type RemediationTimelineEntry,
  type VerificationRecord,
} from "@/lib/cases";
import { formatTimestamp } from "@/lib/format";

const STATUSES = ["OPEN", "PLANNED", "IN_PROGRESS", "BLOCKED", "COMPLETED", "CANCELLED"];
const PRIORITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const VERIFICATION_STATUSES = ["NOT_VERIFIED", "PENDING", "VERIFIED", "FAILED", "INCONCLUSIVE"];
const SORTS = ["updated", "priority", "due_date", "status"];

/** Valid next states per remediation (mirrors the backend state machine). */
const NEXT_STATES: Record<string, string[]> = {
  OPEN: ["PLANNED", "CANCELLED"],
  PLANNED: ["IN_PROGRESS", "CANCELLED"],
  IN_PROGRESS: ["BLOCKED", "COMPLETED", "CANCELLED"],
  BLOCKED: ["IN_PROGRESS", "CANCELLED"],
  COMPLETED: [],
  CANCELLED: [],
};

type Filters = {
  status: string;
  priority: string;
  owner: string;
  verification: string;
  rule: string;
  search: string;
  sort: string;
};

const EMPTY_FILTERS: Filters = {
  status: "",
  priority: "",
  owner: "",
  verification: "",
  rule: "",
  search: "",
  sort: "updated",
};

/** Case remediations: dense workflow table with filters and detail. */
export function RemediationsTab({
  caseId,
  captureIds,
}: {
  caseId: string;
  captureIds: string[];
}) {
  const [records, setRecords] = useState<RemediationRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [applied, setApplied] = useState<Filters>(EMPTY_FILTERS);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(
    (active: Filters, signal?: AbortSignal) => {
      const params: Record<string, string | number> = { sort: active.sort, limit: 100 };
      for (const key of ["status", "priority", "owner", "verification", "rule", "search"] as const) {
        if (active[key]) params[key] = active[key];
      }
      listRemediations(caseId, params, signal)
        .then((list) => {
          setRecords(list.remediations);
          setTotal(list.total);
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

  function refresh() {
    setLoading(true);
    setError(null);
    load(applied);
  }

  function update<K extends keyof Filters>(key: K, value: Filters[K]) {
    const next = { ...filters, [key]: value };
    setFilters(next);
    if (key === "status" || key === "priority" || key === "verification" || key === "sort") {
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

  if (loading && records.length === 0 && !error) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={ClipboardCheck} title="Loading remediations…" />
        </CardContent>
      </Card>
    );
  }

  if (error && records.length === 0) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={RefreshCw} title="Remediations could not be loaded" description={error}>
            <Button variant="outline" size="sm" onClick={refresh}>
              Retry
            </Button>
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const selected = records.find((r) => r.remediation_id === selectedId) ?? null;

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Filters &amp; search</CardTitle>
        </CardHeader>
        <CardContent>
          <form className="grid gap-2 md:grid-cols-4" onSubmit={applyFilters}>
            <select
              value={filters.status}
              onChange={(e) => update("status", e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Status"
            >
              <option value="">All statuses</option>
              {STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <select
              value={filters.priority}
              onChange={(e) => update("priority", e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Priority"
            >
              <option value="">All priorities</option>
              {PRIORITIES.map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
            <select
              value={filters.verification}
              onChange={(e) => update("verification", e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Verification status"
            >
              <option value="">Any verification</option>
              {VERIFICATION_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {s}
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
              value={filters.owner}
              onChange={(e) => setFilters({ ...filters, owner: e.target.value })}
              placeholder="owner"
              maxLength={128}
              className="rounded-md border border-input bg-background px-3 py-1 text-sm"
            />
            <input
              value={filters.rule}
              onChange={(e) => setFilters({ ...filters, rule: e.target.value })}
              placeholder="rule (e.g. TLS-VERSION-001)"
              maxLength={64}
              className="rounded-md border border-input bg-background px-3 py-1 text-sm"
            />
            <input
              value={filters.search}
              onChange={(e) => setFilters({ ...filters, search: e.target.value })}
              placeholder="Search title, owner, target…"
              maxLength={128}
              className="rounded-md border border-input bg-background px-3 py-1 text-sm"
            />
            <Button type="submit" size="sm">
              Apply
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Remediations ({total}){loading ? " — refreshing…" : ""}
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {error ? <p className="text-sm text-destructive">{error}</p> : null}
          {records.length === 0 ? (
            <p>
              No remediations match. Create one from a finding in the Findings tab, or track a
              session, host, certificate, or case-level action here.
            </p>
          ) : null}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-muted-foreground">
                  <th className="py-1 pr-2 font-medium">Title</th>
                  <th className="py-1 pr-2 font-medium">Status</th>
                  <th className="py-1 pr-2 font-medium">Priority</th>
                  <th className="py-1 pr-2 font-medium">Owner</th>
                  <th className="py-1 pr-2 font-medium">Rule</th>
                  <th className="py-1 pr-2 font-medium">Verification</th>
                  <th className="py-1 font-medium">Due</th>
                </tr>
              </thead>
              <tbody>
                {records.map((r) => (
                  <tr
                    key={r.remediation_id}
                    onClick={() => setSelectedId(r.remediation_id)}
                    className={`cursor-pointer border-b border-border/60 hover:bg-muted/50 ${
                      r.remediation_id === selectedId ? "bg-muted" : ""
                    }`}
                  >
                    <td className="max-w-56 truncate py-1.5 pr-2 font-medium">{r.title}</td>
                    <td className="py-1.5 pr-2">
                      <Badge variant="outline">{r.status}</Badge>
                    </td>
                    <td className="py-1.5 pr-2">
                      <Badge variant="outline">{r.priority}</Badge>
                    </td>
                    <td className="max-w-32 truncate py-1.5 pr-2">{r.owner || "—"}</td>
                    <td className="py-1.5 pr-2 font-mono text-xs">{r.rule_id ?? "—"}</td>
                    <td className="py-1.5 pr-2">
                      <Badge variant="outline">{r.verification_status}</Badge>
                    </td>
                    <td className="py-1.5 font-mono text-xs">{r.due_at ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {selected ? (
        <RemediationDetail
          key={selected.remediation_id}
          caseId={caseId}
          remediationId={selected.remediation_id}
          captureIds={captureIds}
          onChanged={refresh}
          onDeleted={() => {
            setSelectedId(null);
            refresh();
          }}
        />
      ) : null}
    </div>
  );
}

function RemediationDetail({
  caseId,
  remediationId,
  captureIds,
  onChanged,
  onDeleted,
}: {
  caseId: string;
  remediationId: string;
  captureIds: string[];
  onChanged: () => void;
  onDeleted: () => void;
}) {
  const [record, setRecord] = useState<RemediationRecord | null>(null);
  const [timeline, setTimeline] = useState<RemediationTimelineEntry[]>([]);
  const [verifications, setVerifications] = useState<VerificationRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [owner, setOwner] = useState("");
  const [dueAt, setDueAt] = useState("");
  const [verifyMode, setVerifyMode] = useState("evidence");
  const [verifyCapture, setVerifyCapture] = useState("");
  const [verifyNotes, setVerifyNotes] = useState("");
  const [completeNotes, setCompleteNotes] = useState<Record<string, string>>({});

  const load = useCallback(
    (signal?: AbortSignal) => {
      Promise.all([
        getRemediation(caseId, remediationId, signal),
        listRemediationTimeline(caseId, remediationId, signal),
        listVerifications(caseId, remediationId, signal),
      ])
        .then(([rec, tl, vers]) => {
          setRecord(rec);
          setOwner(rec.owner);
          setDueAt(rec.due_at ?? "");
          setTimeline(tl.timeline);
          setVerifications(vers.verifications);
        })
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError(err instanceof ApiError ? err.message : "Request failed");
        });
    },
    [caseId, remediationId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await action();
      await Promise.resolve();
      load();
      onChanged();
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  if (!record) {
    return (
      <Card>
        <CardContent className="py-4">
          <p className="text-sm text-muted-foreground">{error ?? "Loading remediation…"}</p>
        </CardContent>
      </Card>
    );
  }

  const nextStates = NEXT_STATES[record.status] ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">
          {record.title} · <span className="font-mono text-xs">{record.remediation_id}</span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {error ? <p className="text-sm text-destructive">{error}</p> : null}
        <dl className="grid gap-1 text-sm">
          <div className="flex gap-2">
            <dt className="w-28 shrink-0 text-xs text-muted-foreground">Target</dt>
            <dd className="font-mono text-xs">
              {record.target_type}: {record.target_id}
            </dd>
          </div>
          {record.rule_id ? (
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-xs text-muted-foreground">Rule</dt>
              <dd className="font-mono text-xs">{record.rule_id}</dd>
            </div>
          ) : null}
          {record.description ? (
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-xs text-muted-foreground">Description</dt>
              <dd>{record.description}</dd>
            </div>
          ) : null}
          {record.recommended_action ? (
            <div className="flex gap-2">
              <dt className="w-28 shrink-0 text-xs text-muted-foreground">Recommended</dt>
              <dd className="whitespace-pre-wrap">
                {record.recommended_action}
                <span className="mt-1 block text-xs text-muted-foreground">
                  Source:{" "}
                  {record.recommended_action_source === "policy"
                    ? "SecureMailScope policy baseline (guidance, not the only correct fix)"
                    : "analyst"}
                </span>
              </dd>
            </div>
          ) : null}
          <div className="flex gap-2">
            <dt className="w-28 shrink-0 text-xs text-muted-foreground">Created / updated</dt>
            <dd className="font-mono text-xs">
              {formatTimestamp(record.created_at)} / {formatTimestamp(record.updated_at)}
            </dd>
          </div>
        </dl>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground">Status: {record.status}</span>
          {nextStates.map((s) => (
            <Button
              key={s}
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => void run(() => updateRemediation(caseId, record.remediation_id, { status: s }))}
            >
              → {s}
            </Button>
          ))}
        </div>

        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(() => updateRemediation(caseId, record.remediation_id, { owner, due_at: dueAt || undefined }));
          }}
        >
          <label className="text-xs text-muted-foreground">
            Owner
            <input
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
              maxLength={128}
              placeholder="team or display name"
              className="ml-2 rounded-md border border-input bg-background px-2 py-1 text-sm"
            />
          </label>
          <label className="text-xs text-muted-foreground">
            Due
            <input
              value={dueAt}
              onChange={(e) => setDueAt(e.target.value)}
              placeholder="YYYY-MM-DD"
              maxLength={32}
              className="ml-2 rounded-md border border-input bg-background px-2 py-1 text-sm"
            />
          </label>
          <Button type="submit" size="sm" variant="outline" disabled={busy}>
            Save
          </Button>
          <Button
            size="sm"
            variant="destructive"
            disabled={busy}
            onClick={() => {
              if (window.confirm("Delete this remediation and its history? Findings are kept.")) {
                void run(() => deleteRemediation(caseId, record.remediation_id)).then(() =>
                  onDeleted(),
                );
              }
            }}
          >
            Delete
          </Button>
        </form>

        <section aria-label="Verification">
          <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Verification — {record.verification_status}
            {record.verification_method ? ` (${record.verification_method})` : ""}
          </h4>
          <form
            className="mt-2 grid gap-2 md:grid-cols-[160px_1fr]"
            onSubmit={(e) => {
              e.preventDefault();
              void run(() =>
                requestVerification(caseId, record.remediation_id, {
                  mode: verifyMode,
                  verification_capture_id: verifyCapture || undefined,
                  notes: verifyNotes || undefined,
                }),
              );
            }}
          >
            <select
              value={verifyMode}
              onChange={(e) => setVerifyMode(e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Verification mode"
            >
              <option value="evidence">evidence-based</option>
              <option value="manual">manual (analyst note)</option>
            </select>
            <select
              value={verifyCapture}
              onChange={(e) => setVerifyCapture(e.target.value)}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Verification capture"
            >
              <option value="">Select verification capture…</option>
              {captureIds.map((id) => (
                <option key={id} value={id}>
                  {id}
                </option>
              ))}
            </select>
            <textarea
              value={verifyNotes}
              onChange={(e) => setVerifyNotes(e.target.value)}
              placeholder={
                verifyMode === "manual"
                  ? "Verification note (required to complete immediately)"
                  : "Optional analyst note attached to the result"
              }
              maxLength={10000}
              rows={2}
              className="rounded-md border border-input bg-background px-3 py-1 text-sm md:col-span-2"
            />
            <div className="md:col-span-2">
              <Button type="submit" size="sm" disabled={busy}>
                Run verification
              </Button>
            </div>
          </form>

          {verifications.length === 0 ? (
            <p className="mt-2 text-xs text-muted-foreground">No verification records yet.</p>
          ) : null}
          <ul className="mt-2 space-y-2">
            {verifications.map((v) => (
              <li key={v.verification_id} className="rounded-md border border-border px-3 py-2">
                <p className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline">{v.result}</Badge>
                  <Badge variant="outline">{v.method}</Badge>
                  <span className="font-mono text-xs text-muted-foreground">
                    {v.verification_id} · {formatTimestamp(v.created_at)}
                  </span>
                </p>
                <VerificationComparisonView comparison={v.comparison} />
                {v.notes ? <p className="mt-1 text-xs">{v.notes}</p> : null}
                {v.result === "PENDING" ? (
                  <form
                    className="mt-2 flex gap-2"
                    onSubmit={(e) => {
                      e.preventDefault();
                      const notes = completeNotes[v.verification_id] ?? "";
                      if (!notes.trim()) return;
                      void run(() =>
                        completeVerification(caseId, record.remediation_id, v.verification_id, notes),
                      );
                    }}
                  >
                    <input
                      value={completeNotes[v.verification_id] ?? ""}
                      onChange={(e) =>
                        setCompleteNotes({ ...completeNotes, [v.verification_id]: e.target.value })
                      }
                      placeholder="Completion note (required)"
                      maxLength={10000}
                      className="w-full rounded-md border border-input bg-background px-2 py-1 text-sm"
                    />
                    <Button type="submit" size="sm" disabled={busy}>
                      Complete
                    </Button>
                  </form>
                ) : null}
              </li>
            ))}
          </ul>
        </section>

        <section aria-label="Remediation timeline">
          <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            Timeline ({timeline.length})
          </h4>
          <ul className="mt-1 space-y-0.5 font-mono text-xs text-muted-foreground">
            {timeline.map((e) => (
              <li key={e.entry_id}>
                {e.event_type} · {formatTimestamp(e.created_at)}
                {Object.keys(e.detail).length > 0 ? ` · ${JSON.stringify(e.detail)}` : ""}
              </li>
            ))}
          </ul>
        </section>

        {record.target_type === "finding" ? (
          <Button render={<Link href={`/findings/${encodeURIComponent(record.target_id)}`} />} variant="outline" size="sm">
            Open finding (unchanged by this workflow)
          </Button>
        ) : null}
      </CardContent>
    </Card>
  );
}

/** Before/after comparison with neutral posture wording. */
function VerificationComparisonView({ comparison }: { comparison: Record<string, unknown> }) {
  const statement = typeof comparison.statement === "string" ? comparison.statement : "";
  const before = (comparison.posture_before ?? {}) as Record<string, unknown>;
  const after = (comparison.posture_after ?? {}) as Record<string, unknown>;
  const delta = comparison.posture_delta_points;
  const baselineEvidence = (comparison.baseline_evidence ?? {}) as Record<string, unknown>;
  const verificationEvidence = (comparison.verification_evidence ?? {}) as Record<string, unknown>;
  const method = comparison.method;

  if (!statement && Object.keys(comparison).length === 0) return null;
  return (
    <div className="mt-2 space-y-1 text-xs">
      {method === "analyst_asserted" ? (
        <p className="text-muted-foreground">
          Analyst-asserted verification — an analyst recorded this outcome. Not evidence-based.
        </p>
      ) : null}
      {statement ? <p>{statement}</p> : null}
      {Object.keys(baselineEvidence).length > 0 || Object.keys(verificationEvidence).length > 0 ? (
        <dl className="grid gap-0.5 font-mono text-[11px]">
          {["tls_version", "cipher_suite", "key_exchange", "certificate_fingerprint", "certificate_valid"].map(
            (key) =>
              baselineEvidence[key] !== undefined || verificationEvidence[key] !== undefined ? (
                <div key={key} className="flex gap-2">
                  <dt className="w-44 shrink-0 text-muted-foreground">{key}</dt>
                  <dd className="break-all">
                    {String(baselineEvidence[key] ?? "—")} →{" "}
                    {String(verificationEvidence[key] ?? "—")}
                  </dd>
                </div>
              ) : null,
          )}
        </dl>
      ) : null}
      {before.available || after.available ? (
        <p className="font-mono text-[11px] text-muted-foreground">
          Posture: {String(before.posture_state ?? "—")} ({String(before.overall_score ?? "—")}) →{" "}
          {String(after.posture_state ?? "—")} ({String(after.overall_score ?? "—")})
          {typeof delta === "number" ? (
            <>
              {" "}
              — the verification capture produced a score {Math.abs(delta)} point
              {Math.abs(delta) === 1 ? "" : "s"} {delta >= 0 ? "higher" : "lower"} (quoted
              values; causation is not established).
            </>
          ) : null}
        </p>
      ) : null}
    </div>
  );
}
