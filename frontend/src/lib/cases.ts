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
