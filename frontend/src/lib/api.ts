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
