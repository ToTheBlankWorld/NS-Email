"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { FolderOpen, RefreshCw } from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CorrelationsTab } from "@/components/cases/correlations-tab";
import { RemediationsTab } from "@/components/cases/remediations-tab";
import {
  getGraph,
  listAnomalies,
  listCaptureFindings,
  listCaptures,
  type AnomalyRecord,
  type CaptureRecord,
  type FindingRecord,
} from "@/lib/api";
import { ApiError } from "@/lib/api";
import {
  addTag,
  attachCapture,
  bookmarkHref,
  caseBundleUrl,
  caseExportUrl,
  caseReportUrl,
  createBookmark,
  createNote,
  createRemediationFromFinding,
  deleteBookmark,
  deleteCase,
  deleteNote,
  detachCapture,
  getCase,
  getCaseSummary,
  listBookmarks,
  listNotes,
  listTags,
  listTimeline,
  removeTag,
  updateCase,
  updateNote,
  type CaseBookmark,
  type CaseNote,
  type CaseRecord as WorkspaceCase,
  type CaseSummary,
  type CaseTimelineEntry,
} from "@/lib/cases";
import { formatTimestamp } from "@/lib/format";

const TABS = [
  "overview",
  "evidence",
  "findings",
  "anomalies",
  "graph",
  "correlations",
  "remediations",
  "notes",
  "bookmarks",
  "timeline",
  "reports",
] as const;

type Tab = (typeof TABS)[number];

type WorkspaceState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | {
      status: "loaded";
      case: WorkspaceCase;
      summary: CaseSummary;
      notes: CaseNote[];
      bookmarks: CaseBookmark[];
      tags: string[];
      timeline: CaseTimelineEntry[];
      captures: CaptureRecord[];
    };

type EvidenceCache = {
  findings: FindingRecord[];
  anomalies: AnomalyRecord[];
  graphs: { capture_id: string; nodes: number; edges: number }[];
  anomalyNote: string | null;
};

/** Case workspace: orchestration layer around existing evidence views. */
export function CaseWorkspace({ caseId, initialTab }: { caseId: string; initialTab?: string }) {
  const [tab, setTab] = useState<Tab>(
    TABS.includes(initialTab as Tab) ? (initialTab as Tab) : "overview",
  );
  const [state, setState] = useState<WorkspaceState>({ status: "loading" });
  const [evidence, setEvidence] = useState<EvidenceCache | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionBusy, setActionBusy] = useState(false);

  const load = useCallback(
    (signal?: AbortSignal) => {
      Promise.all([
        getCase(caseId, signal),
        getCaseSummary(caseId, signal),
        listNotes(caseId, signal),
        listBookmarks(caseId, signal),
        listTags(caseId, signal),
        listTimeline(caseId, signal),
        listCaptures(signal),
      ])
        .then(([record, summary, notes, bookmarks, tagsResponse, timeline, captures]) => {
          setState({
            status: "loaded",
            case: record,
            summary,
            notes,
            bookmarks,
            tags: tagsResponse.tags,
            timeline,
            captures,
          });
        })
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setState({
            status: "error",
            message: err instanceof Error ? err.message : "Request failed",
          });
        });
    },
    [caseId],
  );

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const loadEvidence = useCallback(() => {
    if (state.status !== "loaded" || evidence) return;
    const ids = state.summary.captures.filter((c) => c.available).map((c) => c.capture_id);
    let anomalyMissing = false;
    const findingsCall = Promise.all(
      ids.map((id) => listCaptureFindings(id).catch(() => [] as FindingRecord[])),
    );
    const anomaliesCall = Promise.all(
      ids.map((id) =>
        listAnomalies(id).catch((err: unknown) => {
          if (err instanceof ApiError && err.status === 404) anomalyMissing = true;
          return [] as AnomalyRecord[];
        }),
      ),
    );
    const graphsCall = Promise.all(
      ids.map((id) =>
        getGraph(id)
          .then((graph) => ({
            capture_id: id,
            nodes: graph.nodes.length,
            edges: graph.edges.length,
          }))
          .catch(() => null),
      ),
    );
    findingsCall
      .then((nested) =>
        Promise.all([nested, anomaliesCall, graphsCall]).then(
          ([nestedFindings, nestedAnomalies, graphResults]) => {
            setEvidence({
              findings: nestedFindings.flat(),
              anomalies: nestedAnomalies.flat(),
              graphs: graphResults.filter((g) => g !== null),
              anomalyNote: anomalyMissing
                ? "Anomaly analysis is not available for one or more captures."
                : null,
            });
          },
        ),
      )
      .catch(() => {
        setEvidence({ findings: [], anomalies: [], graphs: [], anomalyNote: null });
      });
  }, [state, evidence]);

  useEffect(() => {
    if (tab === "findings" || tab === "anomalies" || tab === "graph") loadEvidence();
  }, [tab, loadEvidence]);

  async function runAction(action: () => Promise<unknown>) {
    setActionBusy(true);
    setActionError(null);
    try {
      await action();
      setEvidence(null);
      await load();
    } catch (err: unknown) {
      setActionError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setActionBusy(false);
    }
  }

  if (state.status === "loading") {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={FolderOpen} title="Loading case…" />
        </CardContent>
      </Card>
    );
  }

  if (state.status === "error") {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={RefreshCw} title="Case could not be loaded" description={state.message}>
            <Button variant="outline" size="sm" onClick={() => load()}>
              Retry
            </Button>
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const attachedIds = new Set(state.summary.captures.map((c) => c.capture_id));
  const unattached = state.captures.filter((c) => !attachedIds.has(c.id));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Case sections">
        {TABS.map((t) => (
          <Button
            key={t}
            variant={tab === t ? "default" : "outline"}
            size="sm"
            role="tab"
            aria-selected={tab === t}
            onClick={() => setTab(t)}
          >
            {t[0].toUpperCase() + t.slice(1)}
          </Button>
        ))}
      </div>

      {actionError ? (
        <Card>
          <CardContent className="py-3">
            <p className="text-sm text-destructive">{actionError}</p>
          </CardContent>
        </Card>
      ) : null}

      {tab === "overview" ? (
        <OverviewTab
          caseRecord={state.case}
          summary={state.summary}
          busy={actionBusy}
          onUpdate={(input) => runAction(() => updateCase(caseId, input))}
          onDelete={() => runAction(() => deleteCase(caseId))}
        />
      ) : null}

      {tab === "evidence" ? (
        <EvidenceTab
          summary={state.summary}
          unattached={unattached}
          busy={actionBusy}
          onAttach={(captureId) => runAction(() => attachCapture(caseId, captureId))}
          onDetach={(captureId) => runAction(() => detachCapture(caseId, captureId))}
        />
      ) : null}

      {tab === "findings" ? (
        <FindingsTab
          evidence={evidence}
          onBookmark={(findingId) =>
            runAction(() =>
              createBookmark(caseId, { target_type: "finding", target_id: findingId }),
            )
          }
          onRemediate={(findingId) =>
            runAction(() => createRemediationFromFinding(caseId, { finding_id: findingId }))
          }
        />
      ) : null}

      {tab === "anomalies" ? (
        <AnomaliesTab
          evidence={evidence}
          onBookmark={(anomalyId) =>
            runAction(() =>
              createBookmark(caseId, { target_type: "anomaly", target_id: anomalyId }),
            )
          }
        />
      ) : null}

      {tab === "graph" ? <GraphTab evidence={evidence} /> : null}

      {tab === "correlations" ? (
        <CorrelationsTab
          caseId={caseId}
          captureIds={state.summary.captures
            .filter((c) => c.available)
            .map((c) => c.capture_id)}
        />
      ) : null}

      {tab === "remediations" ? (
        <RemediationsTab
          caseId={caseId}
          captureIds={state.summary.captures
            .filter((c) => c.available)
            .map((c) => c.capture_id)}
        />
      ) : null}

      {tab === "notes" ? (
        <NotesTab
          caseId={caseId}
          notes={state.notes}
          busy={actionBusy}
          onCreate={(input) => runAction(() => createNote(caseId, input))}
          onUpdate={(noteId, content) => runAction(() => updateNote(caseId, noteId, content))}
          onDelete={(noteId) => runAction(() => deleteNote(caseId, noteId))}
        />
      ) : null}

      {tab === "bookmarks" ? (
        <BookmarksTab
          bookmarks={state.bookmarks}
          busy={actionBusy}
          onDelete={(bookmarkId) => runAction(() => deleteBookmark(caseId, bookmarkId))}
        />
      ) : null}

      {tab === "timeline" ? <TimelineTab timeline={state.timeline} /> : null}

      {tab === "reports" ? (
        <ReportsTab caseId={caseId} summary={state.summary} tags={state.tags} />
      ) : null}

      {(tab === "notes" || tab === "bookmarks") && state.tags.length > 0 ? (
        <TagRow tags={state.tags} />
      ) : null}

      {tab !== "reports" ? (
        <Card>
          <CardContent className="py-3">
            <TagsEditor
              tags={state.tags}
              busy={actionBusy}
              onAdd={(tag) => runAction(() => addTag(caseId, tag))}
              onRemove={(tag) => runAction(() => removeTag(caseId, tag))}
            />
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}

function OverviewTab({
  caseRecord,
  summary,
  busy,
  onUpdate,
  onDelete,
}: {
  caseRecord: WorkspaceCase;
  summary: CaseSummary;
  busy: boolean;
  onUpdate: (input: { status?: string; priority?: string }) => Promise<void>;
  onDelete: () => Promise<void>;
}) {
  const router = useRouter();
  const [status, setStatus] = useState<"OPEN" | "IN_REVIEW" | "CLOSED" | "ARCHIVED">(
    (["OPEN", "IN_REVIEW", "CLOSED", "ARCHIVED"] as const).includes(
      caseRecord.status as "OPEN" | "IN_REVIEW" | "CLOSED" | "ARCHIVED",
    )
      ? (caseRecord.status as "OPEN" | "IN_REVIEW" | "CLOSED" | "ARCHIVED")
      : "OPEN",
  );
  const [priority, setPriority] = useState<"LOW" | "MEDIUM" | "HIGH" | "CRITICAL">(
    (["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const).includes(
      caseRecord.priority as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
    )
      ? (caseRecord.priority as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL")
      : "MEDIUM",
  );
  const counts = summary.counts;
  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Case detail</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="font-mono text-xs text-muted-foreground">
            {caseRecord.case_number} · {caseRecord.case_id}
          </p>
          {caseRecord.description ? <p>{caseRecord.description}</p> : null}
          <p className="text-xs text-muted-foreground">
            Created {formatTimestamp(caseRecord.created_at)} · Updated{" "}
            {formatTimestamp(caseRecord.updated_at)}
            {caseRecord.closed_at ? ` · Closed ${formatTimestamp(caseRecord.closed_at)}` : ""}
          </p>
          <div className="flex flex-wrap items-center gap-2 pt-1">
            <select
              value={status}
              onChange={(e) =>
                setStatus(e.target.value as "OPEN" | "IN_REVIEW" | "CLOSED" | "ARCHIVED")
              }
              disabled={busy}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Status"
            >
              {["OPEN", "IN_REVIEW", "CLOSED", "ARCHIVED"].map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
            <select
              value={priority}
              onChange={(e) =>
                setPriority(e.target.value as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL")
              }
              disabled={busy}
              className="rounded-md border border-input bg-background px-2 py-1 text-sm"
              aria-label="Priority"
            >
              {["LOW", "MEDIUM", "HIGH", "CRITICAL"].map((p) => (
                <option key={p} value={p}>
                  {p}
                </option>
              ))}
            </select>
            <Button
              size="sm"
              variant="outline"
              disabled={busy}
              onClick={() => void onUpdate({ status, priority })}
            >
              Save
            </Button>
            <Button
              size="sm"
              variant="destructive"
              disabled={busy}
              onClick={() => {
                if (window.confirm("Delete this case and all of its metadata? Evidence is kept.")) {
                  void onDelete().then(() => {
                    router.push("/cases");
                  });
                }
              }}
            >
              Delete case
            </Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Evidence summary</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-2 text-sm md:grid-cols-4">
            {(
              [
                ["Captures", counts.captures],
                ["Sessions", counts.sessions],
                ["Findings", counts.findings],
                ["Anomalies", counts.anomalies],
                ["Bookmarks", counts.bookmarks],
                ["Notes", counts.notes],
                ["Tags", counts.tags],
                ["Reports", counts.reports],
              ] as [string, number][]
            ).map(([label, value]) => (
              <div key={label} className="rounded-md border border-border px-3 py-2">
                <dt className="text-xs text-muted-foreground">{label}</dt>
                <dd className="text-lg font-semibold">{value}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-xs text-muted-foreground">
            Remediation workflow (counts, not scores): open {counts.remediations.open} ·
            in progress {counts.remediations.in_progress} · blocked {counts.remediations.blocked}{" "}
            · completed {counts.remediations.completed} · verification pending{" "}
            {counts.remediations.verification_pending} · verified {counts.remediations.verified}{" "}
            · failed {counts.remediations.failed} · inconclusive{" "}
            {counts.remediations.inconclusive}.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            Security overview — per-capture posture (authoritative)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-xs text-muted-foreground">
            No case-level score is computed. Each row quotes the capture&apos;s own posture.
          </p>
          {summary.captures.length === 0 ? <p>No captures attached.</p> : null}
          {summary.captures.map((c) => (
            <div
              key={c.capture_id}
              className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
            >
              <Link
                href={`/captures/${encodeURIComponent(c.capture_id)}`}
                className="font-mono text-xs hover:underline"
              >
                {c.capture_id}
              </Link>
              <Badge variant="outline">{c.posture_state ?? c.analysis_status ?? "unknown"}</Badge>
              {typeof c.posture_score === "number" ? (
                <span className="text-xs text-muted-foreground">score {c.posture_score}</span>
              ) : null}
              <span className="text-xs text-muted-foreground">
                {c.findings_count ?? 0} findings · {c.anomalies_count ?? 0} anomalies
              </span>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function EvidenceTab({
  summary,
  unattached,
  busy,
  onAttach,
  onDetach,
}: {
  summary: CaseSummary;
  unattached: CaptureRecord[];
  busy: boolean;
  onAttach: (captureId: string) => Promise<void>;
  onDetach: (captureId: string) => Promise<void>;
}) {
  const [selected, setSelected] = useState("");
  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Attach capture</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <select
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
            className="min-w-0 flex-1 rounded-md border border-input bg-background px-2 py-1 text-sm"
            aria-label="Capture to attach"
          >
            <option value="">Select a registered capture…</option>
            {unattached.map((c) => (
              <option key={c.id} value={c.id}>
                {c.filename} · {c.id}
              </option>
            ))}
          </select>
          <Button size="sm" disabled={busy || !selected} onClick={() => void onAttach(selected)}>
            Attach
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Attached evidence</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {summary.captures.length === 0 ? <p>No captures attached.</p> : null}
          {summary.captures.map((c) => (
            <div
              key={c.capture_id}
              className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
            >
              <div className="min-w-0 flex-1">
                <p className="truncate font-medium">{c.filename ?? c.capture_id}</p>
                <p className="break-all font-mono text-xs text-muted-foreground">
                  {c.capture_id} · sha256 {c.sha256 ?? "unavailable"}
                </p>
              </div>
              <Badge variant="outline">{c.analysis_status ?? "unknown"}</Badge>
              <Button render={<Link href={`/captures/${encodeURIComponent(c.capture_id)}`} />} variant="outline" size="sm">
                Open capture
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={busy}
                onClick={() => void onDetach(c.capture_id)}
              >
                Detach
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function FindingsTab({
  evidence,
  onBookmark,
  onRemediate,
}: {
  evidence: EvidenceCache | null;
  onBookmark: (findingId: string) => Promise<void>;
  onRemediate: (findingId: string) => Promise<void>;
}) {
  if (!evidence) return <p className="text-sm text-muted-foreground">Loading findings…</p>;
  if (evidence.findings.length === 0) return <p className="text-sm">No findings recorded.</p>;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">
          Findings across attached captures ({evidence.findings.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p className="text-xs text-muted-foreground">
          Bookmarking is workflow metadata — severity and confidence never change.
        </p>
        {evidence.findings.map((f) => (
          <div
            key={f.id}
            className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
          >
            <div className="min-w-0 flex-1">
              <p className="truncate font-medium">{f.title}</p>
              <p className="font-mono text-xs text-muted-foreground">
                {f.rule_id} · {f.capture_id}
              </p>
            </div>
            <Badge variant="outline">{f.severity}</Badge>
            <Button render={<Link href={`/findings/${encodeURIComponent(f.id)}`} />} variant="outline" size="sm">
              Open
            </Button>
            <Button variant="outline" size="sm" onClick={() => void onBookmark(f.id)}>
              Bookmark
            </Button>
            <Button variant="outline" size="sm" onClick={() => void onRemediate(f.id)}>
              Remediate
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function AnomaliesTab({
  evidence,
  onBookmark,
}: {
  evidence: EvidenceCache | null;
  onBookmark: (anomalyId: string) => Promise<void>;
}) {
  if (!evidence) return <p className="text-sm text-muted-foreground">Loading anomalies…</p>;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">
          Anomalies across attached captures ({evidence.anomalies.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        {evidence.anomalyNote ? (
          <p className="text-xs text-muted-foreground">{evidence.anomalyNote}</p>
        ) : null}
        <p className="text-xs text-muted-foreground">
          Bands describe statistical deviation from the capture-local baseline — never compromise
          verdicts. Scores never change.
        </p>
        {evidence.anomalies.length === 0 ? <p>No anomalies recorded.</p> : null}
        {evidence.anomalies.map((a) => (
          <div
            key={a.anomaly_id}
            className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
          >
            <div className="min-w-0 flex-1">
              <p className="truncate font-medium">{a.session_id}</p>
              <p className="font-mono text-xs text-muted-foreground">
                {a.band ?? a.status} · score {a.score ?? "—"}
              </p>
            </div>
            <Badge variant="outline">{a.band ?? a.status}</Badge>
            <Button
              render={<Link href={`/anomalies/${encodeURIComponent(a.anomaly_id)}`} />}
              variant="outline"
              size="sm"
            >
              Open
            </Button>
            <Button variant="outline" size="sm" onClick={() => void onBookmark(a.anomaly_id)}>
              Bookmark
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function GraphTab({ evidence }: { evidence: EvidenceCache | null }) {
  if (!evidence) return <p className="text-sm text-muted-foreground">Loading graph…</p>;
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Evidence graph per capture</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p className="text-xs text-muted-foreground">
          The forensic graph is unchanged by case metadata. Open the full interactive graph to
          bookmark nodes or pivot to evidence.
        </p>
        {evidence.graphs.length === 0 ? <p>No graph data available.</p> : null}
        {evidence.graphs.map((g) => (
          <div
            key={g.capture_id}
            className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
          >
            <span className="font-mono text-xs">{g.capture_id}</span>
            <span className="text-xs text-muted-foreground">
              {g.nodes} nodes · {g.edges} edges
            </span>
            <Button render={<Link href="/graph" />} variant="outline" size="sm">
              Open graph
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function NotesTab({
  caseId,
  notes,
  busy,
  onCreate,
  onUpdate,
  onDelete,
}: {
  caseId: string;
  notes: CaseNote[];
  busy: boolean;
  onCreate: (input: { target_type: string; target_id: string; content: string }) => Promise<void>;
  onUpdate: (noteId: string, content: string) => Promise<void>;
  onDelete: (noteId: string) => Promise<void>;
}) {
  const [targetType, setTargetType] = useState("case");
  const [targetId, setTargetId] = useState(caseId);
  const [content, setContent] = useState("");
  const [editing, setEditing] = useState<string | null>(null);
  const [editContent, setEditContent] = useState("");

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">New analyst note</CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-2"
            onSubmit={(e) => {
              e.preventDefault();
              void onCreate({ target_type: targetType, target_id: targetId.trim(), content }).then(
                () => {
                  setContent("");
                },
              );
            }}
          >
            <div className="grid gap-2 md:grid-cols-[180px_1fr]">
              <select
                value={targetType}
                onChange={(e) => {
                  setTargetType(e.target.value);
                  if (e.target.value === "case") setTargetId(caseId);
                }}
                className="rounded-md border border-input bg-background px-2 py-1 text-sm"
                aria-label="Note target type"
              >
                {["case", "capture", "session", "finding", "anomaly", "graph_node"].map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
              <input
                value={targetId}
                onChange={(e) => setTargetId(e.target.value)}
                placeholder="Target ID"
                maxLength={256}
                required
                className="rounded-md border border-input bg-background px-3 py-1 text-sm"
              />
            </div>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Analyst note — treated as untrusted input, never evidence, never sent to AI."
              maxLength={10000}
              rows={3}
              required
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            />
            <Button type="submit" size="sm" disabled={busy || !content.trim()}>
              Add note
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Notes ({notes.length})</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          {notes.length === 0 ? <p>No notes recorded.</p> : null}
          {notes.map((n) => (
            <div key={n.note_id} className="rounded-md border border-border px-3 py-2">
              <p className="font-mono text-xs text-muted-foreground">
                {n.target_type} · {n.target_id}
              </p>
              {editing === n.note_id ? (
                <div className="mt-2 space-y-2">
                  <textarea
                    value={editContent}
                    onChange={(e) => setEditContent(e.target.value)}
                    rows={3}
                    maxLength={10000}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  />
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      disabled={busy}
                      onClick={() =>
                        void onUpdate(n.note_id, editContent).then(() => setEditing(null))
                      }
                    >
                      Save
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setEditing(null)}>
                      Cancel
                    </Button>
                  </div>
                </div>
              ) : (
                <>
                  <p className="mt-1 whitespace-pre-wrap">{n.content}</p>
                  <div className="mt-2 flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setEditing(n.note_id);
                        setEditContent(n.content);
                      }}
                    >
                      Edit
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => void onDelete(n.note_id)}
                    >
                      Delete
                    </Button>
                  </div>
                </>
              )}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}

function BookmarksTab({
  bookmarks,
  busy,
  onDelete,
}: {
  bookmarks: CaseBookmark[];
  busy: boolean;
  onDelete: (bookmarkId: string) => Promise<void>;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Bookmarks ({bookmarks.length})</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p className="text-xs text-muted-foreground">
          Bookmarks are references — the evidence stays where it was recorded.
        </p>
        {bookmarks.length === 0 ? <p>No bookmarks recorded.</p> : null}
        {bookmarks.map((b) => (
          <div
            key={b.bookmark_id}
            className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2"
          >
            <div className="min-w-0 flex-1">
              <p className="truncate font-medium">{b.label || b.target_type}</p>
              <p className="break-all font-mono text-xs text-muted-foreground">
                {b.target_type} · {b.target_id}
              </p>
              {b.note ? <p className="mt-0.5 text-xs">{b.note}</p> : null}
            </div>
            <Button render={<Link href={bookmarkHref(b)} />} variant="outline" size="sm">
              Open evidence
            </Button>
            <Button
              variant="outline"
              size="sm"
              disabled={busy}
              onClick={() => void onDelete(b.bookmark_id)}
            >
              Remove
            </Button>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function TimelineTab({ timeline }: { timeline: CaseTimelineEntry[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Case timeline ({timeline.length})</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm">
        <p className="text-xs text-muted-foreground">
          Investigation events — what the analyst did. This is not the forensic timeline
          reconstructed from captured packets.
        </p>
        {timeline.length === 0 ? <p>No events recorded.</p> : null}
        {timeline.map((e) => (
          <div key={e.entry_id} className="rounded-md border border-border px-3 py-2">
            <p className="font-medium">{e.event_type}</p>
            <p className="font-mono text-xs text-muted-foreground">
              {formatTimestamp(e.created_at)}
              {Object.keys(e.detail).length > 0 ? ` · ${JSON.stringify(e.detail)}` : ""}
            </p>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function ReportsTab({
  caseId,
  summary,
  tags,
}: {
  caseId: string;
  summary: CaseSummary;
  tags: string[];
}) {
  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Case reports</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-xs text-muted-foreground">
            Reports quote authoritative per-capture evidence, include the derived correlation
            section (shared evidence across captures — not attribution), the remediation
            workflow and verification evidence sections, and clearly separate
            analyst notes from AI interpretation. Tags on this case: {tags.join(", ") || "none"}.
          </p>
          <div className="flex flex-wrap gap-2">
            {(["json", "html", "pdf"] as const).map((format) => (
              <a key={format} href={caseReportUrl(caseId, format)}>
                <Button variant="outline" size="sm">
                  Report (.{format})
                </Button>
              </a>
            ))}
          </div>
          {summary.reports.length > 0 ? (
            <ul className="space-y-1 font-mono text-xs text-muted-foreground">
              {summary.reports.map((r) => (
                <li key={r.report_id}>
                  {r.format} · {formatTimestamp(r.generated_at)}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-muted-foreground">No reports generated yet.</p>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Export &amp; bundle</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p className="text-xs text-muted-foreground">
            The versioned JSON export and reproducible bundle exclude raw evidence payloads,
            credentials, and unvalidated AI output. Raw PCAP bytes are included only on explicit
            request.
          </p>
          <div className="flex flex-wrap gap-2">
            <a href={caseExportUrl(caseId)}>
              <Button variant="outline" size="sm">
                Export JSON
              </Button>
            </a>
            <a href={caseBundleUrl(caseId)}>
              <Button variant="outline" size="sm">
                Bundle (.zip)
              </Button>
            </a>
            <a href={caseBundleUrl(caseId, true)}>
              <Button variant="outline" size="sm">
                Bundle with evidence
              </Button>
            </a>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function TagsEditor({
  tags,
  busy,
  onAdd,
  onRemove,
}: {
  tags: string[];
  busy: boolean;
  onAdd: (tag: string) => Promise<void>;
  onRemove: (tag: string) => Promise<void>;
}) {
  const [value, setValue] = useState("");
  return (
    <form
      className="flex flex-wrap items-center gap-2"
      onSubmit={(e) => {
        e.preventDefault();
        if (value.trim()) void onAdd(value).then(() => setValue(""));
      }}
    >
      <span className="text-sm font-medium">Tags:</span>
      {tags.map((t) => (
        <Badge key={t} variant="outline" className="gap-1">
          {t}
          <button
            type="button"
            aria-label={`Remove tag ${t}`}
            disabled={busy}
            onClick={() => void onRemove(t)}
            className="ml-1 hover:text-destructive"
          >
            ×
          </button>
        </Badge>
      ))}
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="add tag…"
        maxLength={64}
        className="w-32 rounded-md border border-input bg-background px-2 py-1 text-sm"
      />
      <Button type="submit" size="sm" variant="outline" disabled={busy || !value.trim()}>
        Add
      </Button>
    </form>
  );
}

function TagRow({ tags }: { tags: string[] }) {
  return (
    <Card>
      <CardContent className="flex flex-wrap gap-1.5 py-3">
        {tags.map((t) => (
          <Badge key={t} variant="outline">
            {t}
          </Badge>
        ))}
      </CardContent>
    </Card>
  );
}
