"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";

import { fetchBackendHealth } from "@/lib/api";

export type BackendStatus = "checking" | "online" | "offline";

type BackendHealth = {
  status: BackendStatus;
  service: string | null;
  /** Re-query the backend immediately. */
  refresh: () => void;
};

const BackendHealthContext = createContext<BackendHealth | null>(null);

const POLL_INTERVAL_MS = 30_000;

/**
 * Shares live backend availability across the shell (status pill, system
 * status card) with a single polling loop.
 */
export function BackendHealthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<BackendStatus>("checking");
  const [service, setService] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    fetchBackendHealth(controller.signal)
      .then((health) => {
        setStatus("online");
        setService(health.service);
      })
      .catch((error: unknown) => {
        if (error instanceof DOMException && error.name === "AbortError") return;
        setStatus("offline");
        setService(null);
      });
    return () => controller.abort();
  }, [attempt]);

  useEffect(() => {
    const interval = setInterval(() => setAttempt((n) => n + 1), POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, []);

  const refresh = useCallback(() => setAttempt((n) => n + 1), []);

  return (
    <BackendHealthContext.Provider value={{ status, service, refresh }}>
      {children}
    </BackendHealthContext.Provider>
  );
}

export function useBackendHealth(): BackendHealth {
  const context = useContext(BackendHealthContext);
  if (!context) {
    throw new Error("useBackendHealth must be used within BackendHealthProvider");
  }
  return context;
}
