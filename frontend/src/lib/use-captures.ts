"use client";

import { useEffect, useState } from "react";

import { listCaptures, type CaptureRecord } from "@/lib/api";

type CapturesState =
  | { status: "loading" }
  | { status: "loaded"; captures: CaptureRecord[] }
  | { status: "error"; message: string };

/** Shared capture-list loading state for capture-scoped workspace pages. */
export function useCaptures(): CapturesState {
  const [state, setState] = useState<CapturesState>({ status: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    listCaptures(controller.signal)
      .then((captures) => setState({ status: "loaded", captures }))
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setState({
          status: "error",
          message: err instanceof Error ? err.message : "Request failed",
        });
      });
    return () => controller.abort();
  }, []);

  return state;
}

/** Pick the default capture: the most recently analyzed, else the first. */
export function defaultCaptureId(captures: CaptureRecord[]): string | null {
  if (captures.length === 0) return null;
  const analyzed = captures.filter((c) => c.analysis?.status === "completed");
  if (analyzed.length > 0) {
    return analyzed[0].id;
  }
  return captures[0].id;
}
