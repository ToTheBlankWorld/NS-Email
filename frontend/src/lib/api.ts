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
