/** Backend API access for the browser client. */

/**
 * Base URL of the NS-Email backend. Configure per environment with
 * NEXT_PUBLIC_API_BASE_URL (see docs/development/SETUP.md).
 */
export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8000";

export type HealthResponse = {
  status: string;
  service: string;
};

/** Query the backend health endpoint. Caller decides how to surface failures. */
export async function fetchBackendHealth(
  signal?: AbortSignal,
): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`, {
    signal,
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Backend responded with HTTP ${response.status}`);
  }
  return (await response.json()) as HealthResponse;
}

// ---------------------------------------------------------------------------
// Captures
// ---------------------------------------------------------------------------

export type InspectionStatus = "inspected" | "unavailable" | "error";

export type InspectionInfo = {
  status: InspectionStatus;
  tool: string | null;
  tool_version: string | null;
  message: string | null;
  warnings: string[];
};

export type AnalysisStatus = "not_analyzed" | "completed" | "failed";

export type AnalysisInfo = {
  status: AnalysisStatus;
  analyzed_at: string | null;
  session_count: number;
  error_code: string | null;
  error_message: string | null;
  warnings: string[];
};

export type CaptureRecord = {
  id: string;
  filename: string;
  format: string;
  size_bytes: number;
  sha256: string;
  status: string;
  duplicate: boolean;
  packet_count: number | null;
  started_at: string | null;
  ended_at: string | null;
  duration_seconds: number | null;
  link_type: string | null;
  ingested_at: string;
  inspection: InspectionInfo;
  analysis: AnalysisInfo | null;
};

export type AnalysisResult = {
  capture_id: string;
  status: "completed" | "failed";
  sessions_found: number;
  error_code: string | null;
  error_message: string | null;
};

export type StarttlsObservation = {
  advertised: boolean;
  requested: boolean;
  response_seen: boolean;
  packet_number: number | null;
  timestamp: string | null;
};

export type TlsExtension = {
  type_code: number;
  name: string;
  length: number;
  value: string | null;
};

export type TlsHandshake = {
  id: string;
  session_id: string;
  tls_version: string;
  cipher_suite: string | null;
  cipher_suite_code: number | null;
  key_exchange: string;
  cipher_suites_offered: string[];
  extensions: TlsExtension[];
  sni_server_name: string | null;
  started_at: string | null;
  handshake_complete: boolean | null;
  completeness_reason: string | null;
  certificate_ids: string[];
  warnings: string[];
};

export type TlsCertificate = {
  id: string;
  session_id: string;
  subject: string;
  issuer: string;
  serial_number: string;
  not_before: string;
  not_after: string;
  signature_algorithm: string;
  public_key_algorithm: string | null;
  public_key_size_bits: number | null;
  subject_alternative_names: string[];
  fingerprint_sha256: string | null;
  position_in_chain: number | null;
};

export type SessionEvent = {
  seq: number;
  type: string;
  direction: string;
  timestamp: string | null;
  packet_numbers: number[];
  detail: Record<string, string>;
};

export type SessionRecord = {
  id: string;
  capture_id: string;
  protocol: string | null;
  confidence: string;
  orientation: string;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  implicit_tls: boolean | null;
  started_at: string | null;
  ended_at: string | null;
  duration_seconds: number | null;
  packet_count: number;
  bytes_client_to_server: number;
  bytes_server_to_client: number;
  complete: boolean;
  completeness_reason: string | null;
  retransmissions: number;
  gap_count: number;
  gap_bytes: number;
  starttls: StarttlsObservation | null;
  handshake: TlsHandshake | null;
  certificates?: TlsCertificate[];
  warnings: string[];
  events?: SessionEvent[];
};

/** Structured API error: {"error": {"code", "message"}} plus transport codes. */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

async function parseError(response: Response): Promise<ApiError> {
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

/**
 * Upload a capture with honest progress reporting via XHR: `onProgress`
 * receives the real byte fraction while uploading, then 1 when the server
 * is processing. No synthetic percentages are ever produced.
 */
export function uploadCapture(
  file: File,
  onProgress: (fraction: number) => void,
): Promise<CaptureRecord> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE_URL}/api/captures`);
    xhr.responseType = "json";

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable && event.total > 0) {
        onProgress(Math.min(1, event.loaded / event.total));
      }
    };
    xhr.upload.onload = () => onProgress(1);

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response as CaptureRecord);
      } else if (xhr.response && typeof xhr.response === "object") {
        const body = xhr.response as { error?: { code?: string; message?: string } };
        reject(
          new ApiError(
            body.error?.code ?? `http_${xhr.status}`,
            body.error?.message ?? `Upload failed with HTTP ${xhr.status}`,
            xhr.status,
          ),
        );
      } else {
        reject(new ApiError(`http_${xhr.status}`, `Upload failed with HTTP ${xhr.status}`, xhr.status));
      }
    };
    xhr.onerror = () =>
      reject(
        new ApiError("network_error", "Cannot reach the backend — is it running?", 0),
      );
    xhr.onabort = () => reject(new ApiError("upload_aborted", "Upload aborted", 0));

    const form = new FormData();
    form.append("file", file);
    xhr.send(form);
  });
}

/** List registered captures. */
export async function listCaptures(signal?: AbortSignal): Promise<CaptureRecord[]> {
  const response = await fetch(`${API_BASE_URL}/api/captures`, {
    signal,
    cache: "no-store",
  });
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as CaptureRecord[];
}

/** Fetch one capture by its hash-derived id. */
export async function getCapture(
  captureId: string,
  signal?: AbortSignal,
): Promise<CaptureRecord> {
  const response = await fetch(`${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}`, {
    signal,
    cache: "no-store",
  });
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as CaptureRecord;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export type FindingEvidenceRef = {
  source: string;
  packet_numbers: number[];
  detail: string | null;
};

export type FindingRemediation = {
  action: string;
  target: string | null;
  rationale: string | null;
  priority: string | null;
};

export type FindingStandardReference = {
  name: string;
  url: string | null;
};

export type FindingRecord = {
  id: string;
  capture_id: string | null;
  session_id: string | null;
  protocol: string | null;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: string;
  category: string;
  rule_id: string;
  evidence_refs: FindingEvidenceRef[];
  observed_value: string | null;
  expected_value: string | null;
  remediation: FindingRemediation | null;
  standard_reference: FindingStandardReference | null;
  first_packet: number | null;
  last_packet: number | null;
};

/** List security findings for a capture. */
export async function listCaptureFindings(
  captureId: string,
  signal?: AbortSignal,
): Promise<FindingRecord[]> {
  const response = await fetch(
    `${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}/findings`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as FindingRecord[];
}

/** List security findings for one session. */
export async function listSessionFindings(
  sessionId: string,
  signal?: AbortSignal,
): Promise<FindingRecord[]> {
  const response = await fetch(
    `${API_BASE_URL}/api/sessions/${encodeURIComponent(sessionId)}/findings`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as FindingRecord[];
}

/** Fetch one finding with full evidence references. */
export async function getFinding(
  findingId: string,
  signal?: AbortSignal,
): Promise<FindingRecord> {
  const response = await fetch(`${API_BASE_URL}/api/findings/${encodeURIComponent(findingId)}`, {
    signal,
    cache: "no-store",
  });
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as FindingRecord;
}

// ---------------------------------------------------------------------------
// Posture
// ---------------------------------------------------------------------------

export type PostureState =
  | "healthy"
  | "acceptable"
  | "degraded"
  | "high_exposure"
  | "critical_exposure"
  | "insufficient_evidence";

export type PostureFactor = {
  factor: string;
  label: string;
  status: string;
  score_contribution: number;
  affected_sessions: number;
  affected_hosts: number;
  contributing_finding_ids: string[];
  explanation: string;
};

export type HostPosture = {
  host_id: string;
  ip: string;
  sessions: number;
  protocols: string[];
  findings_count: number;
  highest_severity: string | null;
  affected: boolean;
  tls_versions: string[];
};

export type ProtocolPostureRecord = {
  protocol: string;
  sessions: number;
  findings: number;
  affected_sessions: number;
  status: string;
};

export type PriorityItemRecord = {
  priority_score: number;
  rule_id: string;
  title: string;
  severity: FindingSeverity;
  confidence: string;
  affected_sessions: number;
  total_sessions: number;
  prevalence: number;
  affected_hosts: number;
  evidence_count: number;
  finding_ids: string[];
  explanation: string;
};

export type SecurityPosture = {
  capture_id: string;
  analysis_version: string;
  policy_id: string;
  policy_version: string;
  posture_state: PostureState;
  overall_score: number | null;
  confidence: string;
  total_sessions: number;
  affected_sessions: number;
  affected_hosts: number;
  total_hosts: number;
  finding_counts_by_severity: Record<string, number>;
  category_breakdown: Record<string, number>;
  factors: PostureFactor[];
  hosts: HostPosture[];
  protocols: ProtocolPostureRecord[];
  priorities: PriorityItemRecord[];
  explanation: string[];
  generated_at: string;
};

/** Fetch the explainable posture snapshot for one capture. */
export async function getPosture(
  captureId: string,
  signal?: AbortSignal,
): Promise<SecurityPosture> {
  const response = await fetch(
    `${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}/posture`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as SecurityPosture;
}

/** Observed hosts with posture context. */
export async function listPostureHosts(
  captureId: string,
  signal?: AbortSignal,
): Promise<HostPosture[]> {
  const response = await fetch(
    `${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}/hosts`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as HostPosture[];
}

/** Posture aggregated per email protocol. */
export async function getProtocolPosture(
  captureId: string,
  signal?: AbortSignal,
): Promise<ProtocolPostureRecord[]> {
  const response = await fetch(
    `${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}/posture/protocols`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as ProtocolPostureRecord[];
}

/** Findings ordered by the deterministic priority model. */
export async function getPriorities(
  captureId: string,
  signal?: AbortSignal,
): Promise<PriorityItemRecord[]> {
  const response = await fetch(
    `${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}/priorities`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as PriorityItemRecord[];
}

// ---------------------------------------------------------------------------
// Anomalies
// ---------------------------------------------------------------------------

export type AnomalyDeviation = {
  feature: string;
  observed: string;
  baseline: string;
  deviation: string;
};

export type AnomalyEvidenceRef = {
  source: string;
  packet_numbers: number[];
  detail: string | null;
};

export type AnomalyRecord = {
  anomaly_id: string;
  capture_id: string;
  session_id: string;
  protocol: string | null;
  status: string;
  score: number | null;
  band: string | null;
  model_id: string | null;
  model_version: string;
  feature_schema_version: string;
  top_deviations: AnomalyDeviation[];
  baseline_summary: Record<string, string>;
  evidence_refs: AnomalyEvidenceRef[];
  generated_at: string;
};

export type AnomalySummary = {
  normal: number;
  unusual: number;
  anomalous: number;
  highly_anomalous: number;
  insufficient_evidence: number;
  model_error: number;
  total_evaluated: number;
  total_sessions: number;
};

/** Behavioral anomaly results for all evaluated sessions in a capture. */
export async function listAnomalies(
  captureId: string,
  signal?: AbortSignal,
): Promise<AnomalyRecord[]> {
  const response = await fetch(
    `${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}/anomalies`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as AnomalyRecord[];
}

/** Behavioral anomaly result for one session. */
export async function getSessionAnomaly(
  sessionId: string,
  signal?: AbortSignal,
): Promise<AnomalyRecord> {
  const response = await fetch(
    `${API_BASE_URL}/api/sessions/${encodeURIComponent(sessionId)}/anomaly`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as AnomalyRecord;
}

/** Anomaly band summary counts for a capture. */
export async function getAnomalySummary(
  captureId: string,
  signal?: AbortSignal,
): Promise<AnomalySummary> {
  const response = await fetch(
    `${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}/anomaly-summary`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as AnomalySummary;
}

/** One anomaly result with deviations and evidence. */
export async function getAnomaly(
  anomalyId: string,
  signal?: AbortSignal,
): Promise<AnomalyRecord> {
  const response = await fetch(
    `${API_BASE_URL}/api/anomalies/${encodeURIComponent(anomalyId)}`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as AnomalyRecord;
}

// ---------------------------------------------------------------------------
// Analysis & sessions
// ---------------------------------------------------------------------------

/** Run session analysis for one capture (synchronous on the backend). */
export async function analyzeCapture(captureId: string): Promise<AnalysisResult> {
  const response = await fetch(
    `${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}/analyze`,
    { method: "POST", headers: { "Content-Type": "application/json" } },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as AnalysisResult;
}

/** List reconstructed sessions for a capture (summaries, no timeline). */
export async function listSessions(
  captureId: string,
  signal?: AbortSignal,
): Promise<SessionRecord[]> {
  const response = await fetch(
    `${API_BASE_URL}/api/captures/${encodeURIComponent(captureId)}/sessions`,
    { signal, cache: "no-store" },
  );
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as SessionRecord[];
}

/** Fetch one reconstructed session including its event timeline. */
export async function getSession(
  sessionId: string,
  signal?: AbortSignal,
): Promise<SessionRecord> {
  const response = await fetch(`${API_BASE_URL}/api/sessions/${encodeURIComponent(sessionId)}`, {
    signal,
    cache: "no-store",
  });
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as SessionRecord;
}


// ---------------------------------------------------------------------------
// AI Analyst
// ---------------------------------------------------------------------------

export type AIStatus = {
  configured: boolean;
  provider: string;
  model: string;
  local: boolean;
};

export type AIQueryResult = {
  status: string;
  answer?: string;
  error?: string;
  query?: string;
  session_id?: string;
  key_observations?: string[];
  interpretations?: string[];
  uncertainties?: string[];
  model?: string;
  provider?: string;
  validation_status?: string;
};

export async function getAIStatus(signal?: AbortSignal): Promise<AIStatus> {
  const response = await fetch(`${API_BASE_URL}/api/ai/status`, {
    signal,
    cache: "no-store",
  });
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as AIStatus;
}

export async function queryAI(
  sessionId: string,
  question: string,
): Promise<AIQueryResult> {
  const response = await fetch(`${API_BASE_URL}/api/ai/query`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ question, session_id: sessionId }),
  });
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as AIQueryResult;
}

// ---------------------------------------------------------------------------
// Evidence graph (Stage 7)
// ---------------------------------------------------------------------------

export type GraphNode = {
  node_id: string;
  capture_id: string;
  node_type: string;
  label: string;
  source_id: string | null;
  metadata: Record<string, unknown>;
};

export type GraphEdge = {
  source_node_id: string;
  target_node_id: string;
  edge_type: string;
  basis: string | null;
};

export type EvidenceGraphPayload = {
  capture_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
};

export async function getGraph(
  captureId: string,
  signal?: AbortSignal,
): Promise<EvidenceGraphPayload> {
  const response = await fetch(`${API_BASE_URL}/api/captures/${captureId}/graph`, {
    signal,
    cache: "no-store",
  });
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as EvidenceGraphPayload;
}

export type SessionContext = {
  capture_id: string;
  session_id: string;
  hosts: string[];
  endpoints: string[];
  protocol: string | null;
  tls_version: string | null;
  cipher_suite: string | null;
  key_exchange: string | null;
  certificate_ids: string[];
  finding_ids: string[];
  anomaly_id: string | null;
  anomaly_score: number | null;
  posture_factors: string[];
  related_session_ids: string[];
  related_certificate_ids: string[];
  related_tls_config_ids: string[];
  timeline_events: { type: string; timestamp: string; packet_numbers: string }[];
  evidence_refs: { source: string; packet_numbers: number[]; detail: string | null }[];
};

export async function getSessionContext(
  sessionId: string,
  signal?: AbortSignal,
): Promise<SessionContext> {
  const response = await fetch(`${API_BASE_URL}/api/sessions/${sessionId}/context`, {
    signal,
    cache: "no-store",
  });
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as SessionContext;
}

// ---------------------------------------------------------------------------
// Forensic reports (Stage 9)
// ---------------------------------------------------------------------------

export function reportUrl(captureId: string, format: "json" | "html" | "pdf"): string {
  return `${API_BASE_URL}/api/captures/${captureId}/report.${format}`;
}

export type AIHistoryEntry = {
  response_id: string;
  capture_id: string;
  session_id: string | null;
  query: string;
  answer: string;
  provider: string;
  model: string;
  prompt_version: string;
  context_version: string;
  validation_status: string;
  generated_at: string | null;
};

export async function listAIHistory(
  captureId: string,
  signal?: AbortSignal,
): Promise<AIHistoryEntry[]> {
  const response = await fetch(`${API_BASE_URL}/api/ai/history/${captureId}`, {
    signal,
    cache: "no-store",
  });
  if (!response.ok) throw await parseError(response);
  return (await response.json()) as AIHistoryEntry[];
}
