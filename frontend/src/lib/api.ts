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
