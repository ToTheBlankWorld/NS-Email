/** Forensic case management API access (Stage 11). */

import { API_BASE_URL, ApiError } from "./api";

export type CaseStatus = "OPEN" | "IN_REVIEW" | "CLOSED" | "ARCHIVED";
export type CasePriority = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type CaseRecord = {
  case_id: string;
  case_number: string;
  title: string;
  description: string;
  status: CaseStatus;
  priority: CasePriority;
  created_at: string | null;
  updated_at: string | null;
  closed_at: string | null;
  schema_version: string;
};

export type CaseNote = {
  note_id: string;
  case_id: string;
  target_type: string;
  target_id: string;
  content: string;
  created_at: string | null;
  updated_at: string | null;
};

export type CaseBookmark = {
  bookmark_id: string;
  case_id: string;
  target_type: string;
  target_id: string;
  label: string;
  note: string;
  created_at: string | null;
};

export type CaseTimelineEntry = {
  entry_id: string;
  case_id: string;
  event_type: string;
  detail: Record<string, string>;
  created_at: string | null;
};

export type CaseCaptureCard = {
  capture_id: string;
  available: boolean;
  filename?: string;
  sha256?: string;
  analysis_status?: string;
  session_count?: number;
  findings_count?: number;
  anomalies_count?: number;
  posture_state?: string | null;
  posture_score?: number | null;
};

export type CaseSummary = {
  case: CaseRecord;
  counts: {
    captures: number;
    sessions: number;
    findings: number;
    anomalies: number;
    bookmarks: number;
    notes: number;
    tags: number;
    timeline_events: number;
    reports: number;
    remediations: {
      open: number;
      in_progress: number;
      blocked: number;
      completed: number;
      verification_pending: number;
      verified: number;
      failed: number;
      inconclusive: number;
    };
  };
  captures: CaseCaptureCard[];
  reports: { report_id: string; format: string; generated_at: string }[];
};

async function parseCaseError(response: Response): Promise<ApiError> {
  try {
    const body = (await response.json()) as { error?: { code?: string; message?: string } };
    return new ApiError(
      body.error?.code ?? `http_${response.status}`,
      body.error?.message ?? `Request failed with HTTP ${response.status}`,
      response.status,
    );
  } catch {
    return new ApiError(
      `http_${response.status}`,
      `Request failed with HTTP ${response.status}`,
      response.status,
    );
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  if (!response.ok) throw await parseCaseError(response);
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** List cases, optionally filtered by status. */
export function listCases(signal?: AbortSignal, status?: string): Promise<CaseRecord[]> {
  const query = status ? `?status=${encodeURIComponent(status)}` : "";
  return request<CaseRecord[]>(`/api/cases${query}`, { signal, cache: "no-store" });
}

export function getCase(caseId: string, signal?: AbortSignal): Promise<CaseRecord> {
  return request<CaseRecord>(`/api/cases/${encodeURIComponent(caseId)}`, {
    signal,
    cache: "no-store",
  });
}

export function createCase(input: {
  title: string;
  description?: string;
  priority?: string;
}): Promise<CaseRecord> {
  return request<CaseRecord>("/api/cases", {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function updateCase(
  caseId: string,
  input: { title?: string; description?: string; status?: string; priority?: string },
): Promise<CaseRecord> {
  return request<CaseRecord>(`/api/cases/${encodeURIComponent(caseId)}`, {
    method: "PATCH",
    body: JSON.stringify(input),
  });
}

export function deleteCase(caseId: string): Promise<void> {
  return request<void>(`/api/cases/${encodeURIComponent(caseId)}`, { method: "DELETE" });
}

export function attachCapture(caseId: string, captureId: string): Promise<unknown> {
  return request(`/api/cases/${encodeURIComponent(caseId)}/captures`, {
    method: "POST",
    body: JSON.stringify({ capture_id: captureId }),
  });
}

export function detachCapture(caseId: string, captureId: string): Promise<void> {
  return request<void>(
    `/api/cases/${encodeURIComponent(caseId)}/captures/${encodeURIComponent(captureId)}`,
    { method: "DELETE" },
  );
}

export function listNotes(caseId: string, signal?: AbortSignal): Promise<CaseNote[]> {
  return request<CaseNote[]>(`/api/cases/${encodeURIComponent(caseId)}/notes`, {
    signal,
    cache: "no-store",
  });
}

export function createNote(
  caseId: string,
  input: { target_type: string; target_id: string; content: string },
): Promise<CaseNote> {
  return request<CaseNote>(`/api/cases/${encodeURIComponent(caseId)}/notes`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function updateNote(caseId: string, noteId: string, content: string): Promise<CaseNote> {
  return request<CaseNote>(
    `/api/cases/${encodeURIComponent(caseId)}/notes/${encodeURIComponent(noteId)}`,
    { method: "PATCH", body: JSON.stringify({ content }) },
  );
}

export function deleteNote(caseId: string, noteId: string): Promise<void> {
  return request<void>(
    `/api/cases/${encodeURIComponent(caseId)}/notes/${encodeURIComponent(noteId)}`,
    { method: "DELETE" },
  );
}

export function listTags(caseId: string, signal?: AbortSignal): Promise<{ tags: string[] }> {
  return request<{ tags: string[] }>(`/api/cases/${encodeURIComponent(caseId)}/tags`, {
    signal,
    cache: "no-store",
  });
}

export function addTag(caseId: string, tag: string): Promise<{ tag: string }> {
  return request(`/api/cases/${encodeURIComponent(caseId)}/tags`, {
    method: "POST",
    body: JSON.stringify({ tag }),
  });
}

export function removeTag(caseId: string, tag: string): Promise<void> {
  return request<void>(
    `/api/cases/${encodeURIComponent(caseId)}/tags/${encodeURIComponent(tag)}`,
    { method: "DELETE" },
  );
}

export function listBookmarks(caseId: string, signal?: AbortSignal): Promise<CaseBookmark[]> {
  return request<CaseBookmark[]>(`/api/cases/${encodeURIComponent(caseId)}/bookmarks`, {
    signal,
    cache: "no-store",
  });
}

export function createBookmark(
  caseId: string,
  input: { target_type: string; target_id: string; label?: string; note?: string },
): Promise<CaseBookmark> {
  return request<CaseBookmark>(`/api/cases/${encodeURIComponent(caseId)}/bookmarks`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function deleteBookmark(caseId: string, bookmarkId: string): Promise<void> {
  return request<void>(
    `/api/cases/${encodeURIComponent(caseId)}/bookmarks/${encodeURIComponent(bookmarkId)}`,
    { method: "DELETE" },
  );
}

export function listTimeline(caseId: string, signal?: AbortSignal): Promise<CaseTimelineEntry[]> {
  return request<CaseTimelineEntry[]>(`/api/cases/${encodeURIComponent(caseId)}/timeline`, {
    signal,
    cache: "no-store",
  });
}

export function getCaseSummary(caseId: string, signal?: AbortSignal): Promise<CaseSummary> {
  return request<CaseSummary>(`/api/cases/${encodeURIComponent(caseId)}/summary`, {
    signal,
    cache: "no-store",
  });
}

export function importCaseBundle(document: unknown): Promise<CaseRecord> {
  return request<CaseRecord>("/api/cases/import", {
    method: "POST",
    body: JSON.stringify(document),
  });
}

/** Download URLs for case reports, export, and bundle. */
export function caseReportUrl(caseId: string, format: "json" | "html" | "pdf"): string {
  return `${API_BASE_URL}/api/cases/${encodeURIComponent(caseId)}/report.${format}`;
}

export function caseExportUrl(caseId: string): string {
  return `${API_BASE_URL}/api/cases/${encodeURIComponent(caseId)}/export`;
}

export function caseBundleUrl(caseId: string, includeEvidence = false): string {
  const query = includeEvidence ? "?include_evidence=true" : "";
  return `${API_BASE_URL}/api/cases/${encodeURIComponent(caseId)}/bundle${query}`;
}

// ---------------------------------------------------------------------------
// Multi-capture correlation (Stage 12)
// ---------------------------------------------------------------------------

export type CorrelationOccurrence = {
  capture_id: string;
  session_id: string;
  finding_id: string | null;
  anomaly_id: string | null;
  observed_at: string | null;
};

export type CorrelationRecord = {
  correlation_id: string;
  case_id: string;
  correlation_type: string;
  strength: "direct" | "derived";
  evidence_key: string;
  evidence: Record<string, unknown>;
  occurrence_count: number;
  capture_count: number;
  session_count: number;
  source_capture_ids: string[];
  source_session_ids: string[];
  occurrences: CorrelationOccurrence[];
  first_observed_at: string | null;
  last_observed_at: string | null;
};

export type CorrelationSummary = {
  case_id: string;
  capture_count: number;
  correlation_count: number;
  sessions_scanned: number;
  index_keys: number;
  by_type: Record<string, number>;
};

export type CorrelationListParams = {
  type?: string;
  capture_id?: string;
  protocol?: string;
  endpoint?: string;
  certificate?: string;
  finding?: string;
  search?: string;
  sort?: string;
  limit?: number;
  offset?: number;
};

export type CorrelationList = {
  case_id: string;
  total: number;
  limit: number;
  offset: number;
  correlations: CorrelationRecord[];
};

export type GraphRefNode = {
  node_id: string;
  node_type: string;
  label: string;
};

export type CorrelationContext = {
  correlation: CorrelationRecord;
  related_finding_ids: string[];
  related_anomaly_ids: string[];
  graph_nodes: GraphRefNode[];
  timeline_refs: { entry_id: string; event_type: string; created_at: string | null }[];
};

export type SessionRelatedEntry = {
  correlation_id: string;
  correlation_type: string;
  evidence_key: string;
  other_session_count: number;
  other_session_ids: string[];
  other_capture_ids: string[];
};

export type SessionRelated = {
  case_id: string;
  session_id: string;
  capture_id: string;
  related: SessionRelatedEntry[];
};

export type InvestigationGraph = {
  case_id: string;
  nodes: { node_id: string; node_type: string; label: string; layer: string }[];
  edges: {
    source_node_id: string;
    target_node_id: string;
    edge_type: string;
    layer: string;
    basis: string;
  }[];
  node_count: number;
  edge_count: number;
  sessions_truncated: boolean;
  correlation_count: number;
};

export type CorrelationAIResult = {
  status: string;
  answer?: string;
  error?: string;
  query?: string;
  key_observations?: string[];
  interpretations?: string[];
  uncertainties?: string[];
  model?: string;
  provider?: string;
  validation_status?: string;
};

/** List correlations with analyst filters, search, and sorting. */
export function listCorrelations(
  caseId: string,
  params: CorrelationListParams = {},
  signal?: AbortSignal,
): Promise<CorrelationList> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const suffix = query.size > 0 ? `?${query.toString()}` : "";
  return request<CorrelationList>(`/api/cases/${encodeURIComponent(caseId)}/correlations${suffix}`, {
    signal,
    cache: "no-store",
  });
}

export function getCorrelationSummary(
  caseId: string,
  signal?: AbortSignal,
): Promise<CorrelationSummary> {
  return request<CorrelationSummary>(
    `/api/cases/${encodeURIComponent(caseId)}/correlations/summary`,
    { signal, cache: "no-store" },
  );
}

export function getCorrelationContext(
  caseId: string,
  correlationId: string,
  signal?: AbortSignal,
): Promise<CorrelationContext> {
  return request<CorrelationContext>(
    `/api/cases/${encodeURIComponent(caseId)}/correlations/${encodeURIComponent(correlationId)}/context`,
    { signal, cache: "no-store" },
  );
}

export function getSessionRelated(
  caseId: string,
  sessionId: string,
  signal?: AbortSignal,
): Promise<SessionRelated> {
  return request<SessionRelated>(
    `/api/cases/${encodeURIComponent(caseId)}/sessions/${encodeURIComponent(sessionId)}/related`,
    { signal, cache: "no-store" },
  );
}

export function getInvestigationGraph(
  caseId: string,
  signal?: AbortSignal,
): Promise<InvestigationGraph> {
  return request<InvestigationGraph>(`/api/cases/${encodeURIComponent(caseId)}/graph`, {
    signal,
    cache: "no-store",
  });
}

/** Ask the AI about one correlation (minimized context, never persisted). */
export async function queryCorrelationAI(
  caseId: string,
  correlationId: string,
  question: string,
): Promise<CorrelationAIResult> {
  const response = await fetch(`${API_BASE_URL}/api/ai/query-correlation`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, case_id: caseId, correlation_id: correlationId }),
  });
  if (!response.ok) throw await parseCaseError(response);
  return (await response.json()) as CorrelationAIResult;
}

// ---------------------------------------------------------------------------
// Remediation workflow (Stage 13)
// ---------------------------------------------------------------------------

export type RemediationRecord = {
  remediation_id: string;
  case_id: string;
  target_type: string;
  target_id: string;
  rule_id: string | null;
  title: string;
  description: string;
  recommended_action: string;
  recommended_action_source: "policy" | "analyst";
  status: string;
  priority: string;
  owner: string;
  due_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  completed_at: string | null;
  verification_status: string;
  verification_capture_id: string | null;
  verification_method: string | null;
};

export type RemediationTimelineEntry = {
  entry_id: string;
  remediation_id: string;
  case_id: string;
  event_type: string;
  detail: Record<string, string>;
  created_at: string | null;
};

export type VerificationRecord = {
  verification_id: string;
  remediation_id: string;
  case_id: string;
  method: string;
  baseline_capture_id: string;
  baseline_session_id: string | null;
  rule_id: string;
  verification_capture_id: string | null;
  result: string;
  comparison: Record<string, unknown>;
  notes: string;
  created_at: string | null;
  completed_at: string | null;
};

export type RemediationListParams = {
  status?: string;
  priority?: string;
  owner?: string;
  verification?: string;
  rule?: string;
  target?: string;
  search?: string;
  sort?: string;
  limit?: number;
  offset?: number;
};

export type RemediationList = {
  case_id: string;
  total: number;
  limit: number;
  offset: number;
  remediations: RemediationRecord[];
};

/** List remediations with workflow filters and sorting. */
export function listRemediations(
  caseId: string,
  params: RemediationListParams = {},
  signal?: AbortSignal,
): Promise<RemediationList> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") query.set(key, String(value));
  }
  const suffix = query.size > 0 ? `?${query.toString()}` : "";
  return request<RemediationList>(
    `/api/cases/${encodeURIComponent(caseId)}/remediations${suffix}`,
    { signal, cache: "no-store" },
  );
}

export function getRemediation(
  caseId: string,
  remediationId: string,
  signal?: AbortSignal,
): Promise<RemediationRecord> {
  return request<RemediationRecord>(
    `/api/cases/${encodeURIComponent(caseId)}/remediations/${encodeURIComponent(remediationId)}`,
    { signal, cache: "no-store" },
  );
}

export function createRemediationFromFinding(
  caseId: string,
  input: { finding_id: string; title?: string; description?: string; priority?: string; owner?: string; due_at?: string },
): Promise<RemediationRecord> {
  return request<RemediationRecord>(`/api/cases/${encodeURIComponent(caseId)}/remediations/from-finding`, {
    method: "POST",
    body: JSON.stringify(input),
  });
}

export function updateRemediation(
  caseId: string,
  remediationId: string,
  input: { title?: string; description?: string; recommended_action?: string; priority?: string; owner?: string; due_at?: string; status?: string },
): Promise<RemediationRecord> {
  return request<RemediationRecord>(
    `/api/cases/${encodeURIComponent(caseId)}/remediations/${encodeURIComponent(remediationId)}`,
    { method: "PATCH", body: JSON.stringify(input) },
  );
}

export function deleteRemediation(caseId: string, remediationId: string): Promise<void> {
  return request<void>(
    `/api/cases/${encodeURIComponent(caseId)}/remediations/${encodeURIComponent(remediationId)}`,
    { method: "DELETE" },
  );
}

export function listRemediationTimeline(
  caseId: string,
  remediationId: string,
  signal?: AbortSignal,
): Promise<{ timeline: RemediationTimelineEntry[] }> {
  return request<{ timeline: RemediationTimelineEntry[] }>(
    `/api/cases/${encodeURIComponent(caseId)}/remediations/${encodeURIComponent(remediationId)}/timeline`,
    { signal, cache: "no-store" },
  );
}

export function requestVerification(
  caseId: string,
  remediationId: string,
  input: { mode: string; verification_capture_id?: string; notes?: string },
): Promise<VerificationRecord> {
  return request<VerificationRecord>(
    `/api/cases/${encodeURIComponent(caseId)}/remediations/${encodeURIComponent(remediationId)}/verify`,
    { method: "POST", body: JSON.stringify(input) },
  );
}

export function listVerifications(
  caseId: string,
  remediationId: string,
  signal?: AbortSignal,
): Promise<{ verifications: VerificationRecord[] }> {
  return request<{ verifications: VerificationRecord[] }>(
    `/api/cases/${encodeURIComponent(caseId)}/remediations/${encodeURIComponent(remediationId)}/verification`,
    { signal, cache: "no-store" },
  );
}

export function completeVerification(
  caseId: string,
  remediationId: string,
  verificationId: string,
  notes: string,
): Promise<VerificationRecord> {
  return request<VerificationRecord>(
    `/api/cases/${encodeURIComponent(caseId)}/remediations/${encodeURIComponent(remediationId)}/verifications/${encodeURIComponent(verificationId)}`,
    { method: "PATCH", body: JSON.stringify({ notes }) },
  );
}

export function listFindingRemediations(
  caseId: string,
  findingId: string,
  signal?: AbortSignal,
): Promise<{ remediations: RemediationRecord[] }> {
  return request<{ remediations: RemediationRecord[] }>(
    `/api/cases/${encodeURIComponent(caseId)}/findings/${encodeURIComponent(findingId)}/remediations`,
    { signal, cache: "no-store" },
  );
}

/** Deep-link a bookmark target back to its evidence view. */
export function bookmarkHref(bookmark: CaseBookmark): string {
  switch (bookmark.target_type) {
    case "finding":
      return `/findings/${encodeURIComponent(bookmark.target_id)}`;
    case "anomaly":
      return `/anomalies/${encodeURIComponent(bookmark.target_id)}`;
    case "session":
      return `/sessions/${encodeURIComponent(bookmark.target_id)}`;
    case "capture":
      return `/captures/${encodeURIComponent(bookmark.target_id)}`;
    case "certificate":
    case "tls_handshake":
    case "graph_node":
      return "/graph";
    case "timeline_event":
      return `/cases/${encodeURIComponent(bookmark.case_id)}?tab=timeline`;
    default:
      return `/cases/${encodeURIComponent(bookmark.case_id)}`;
  }
}
