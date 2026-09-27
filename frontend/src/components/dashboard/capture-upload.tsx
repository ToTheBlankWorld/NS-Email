"use client";

import Link from "next/link";
import { useCallback, useRef, useState, type DragEvent } from "react";
import {
  ArrowRight,
  CheckCircle2,
  FileUp,
  LoaderCircle,
  TriangleAlert,
  X,
} from "lucide-react";

import { Button } from "@/components/ui/button";import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError, uploadCapture, type CaptureRecord } from "@/lib/api";
import { formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";

const ACCEPTED_EXTENSIONS = [".pcap", ".pcapng"] as const;
/** Mirrors the backend's default limit; the API enforces the real one. */
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024;

type Phase = "idle" | "uploading" | "processing" | "success" | "error";

function validateFile(file: File): string | null {
  const lowercaseName = file.name.toLowerCase();
  const hasValidExtension = ACCEPTED_EXTENSIONS.some((extension) =>
    lowercaseName.endsWith(extension),
  );
  if (!hasValidExtension) {
    return "Unsupported format — only .pcap and .pcapng captures are accepted.";
  }
  if (file.size === 0) {
    return "The selected file is empty.";
  }
  if (file.size > MAX_UPLOAD_BYTES) {
    return "Capture exceeds the 2 GiB size limit.";
  }
  return null;
}

const PHASE_LABELS: Record<"uploading" | "processing", string> = {
  uploading: "Uploading capture…",
  processing: "Validating and registering evidence…",
};

/**
 * Capture ingestion panel: honest upload/processing/success/error states
 * wired to POST /api/captures. Progress reflects real transferred bytes.
 */
export function CaptureUpload() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [selected, setSelected] = useState<File | null>(null);
  const [rejection, setRejection] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<CaptureRecord | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const acceptFile = useCallback(
    (file: File) => {
      const invalidReason = validateFile(file);
      if (invalidReason) {
        setRejection(invalidReason);
        return;
      }
      setRejection(null);
      setError(null);
      setResult(null);
      setSelected(file);
      setPhase("uploading");
      setProgress(0);
      uploadCapture(file, (fraction) => {
        if (fraction < 1) {
          setProgress(fraction);
        } else {
          setPhase("processing");
        }
      })
        .then((record) => {
          setResult(record);
          setPhase("success");
        })
        .catch((err: unknown) => {
          setError(
            err instanceof ApiError
              ? err
              : new ApiError("network_error", "Cannot reach the backend — is it running?", 0),
          );
          setPhase("error");
        });
    },
    [],
  );

  const onDrop = useCallback(
    (event: DragEvent<HTMLLabelElement>) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files[0];
      if (file) acceptFile(file);
    },
    [acceptFile],
  );

  const reset = useCallback(() => {
    setSelected(null);
    setRejection(null);
    setResult(null);
    setError(null);
    setProgress(0);
    setPhase("idle");
    if (inputRef.current) inputRef.current.value = "";
  }, []);

  const busy = phase === "uploading" || phase === "processing";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Capture</CardTitle>
      </CardHeader>
      <CardContent>
        <input
          ref={inputRef}
          id="capture-file-input"
          type="file"
          accept={ACCEPTED_EXTENSIONS.join(",")}
          className="sr-only"
          disabled={busy}
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) acceptFile(file);
          }}
        />

        {phase === "idle" || rejection ? (
          <label
            htmlFor="capture-file-input"
            onDragOver={(event) => {
              event.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            className={cn(
              "flex cursor-pointer flex-col items-center justify-center rounded-lg border border-dashed px-6 py-10 text-center transition-colors outline-none",
              "border-border/80 hover:border-muted-foreground/40 focus-visible:ring-2 focus-visible:ring-ring/60",
              dragging && "border-primary/70 bg-primary/5",
            )}
          >
            <div className="flex flex-col items-center">
              <div className="mb-3 flex size-11 items-center justify-center rounded-lg border border-border/70 bg-muted/40 text-muted-foreground">
                <FileUp className="size-5" aria-hidden />
              </div>
              <p className="text-sm font-medium">No capture analyzed</p>
              <p className="mt-1 max-w-sm text-sm text-muted-foreground">
                Upload a PCAP to begin forensic analysis.
              </p>
              <p className="mt-2 font-mono text-[11px] text-muted-foreground/70">
                .pcap · .pcapng — max 2 GiB
              </p>
              <Button type="button" size="sm" className="mt-4" tabIndex={-1}>
                Select capture file
              </Button>
            </div>
          </label>
        ) : null}

        {rejection ? (
          <p role="alert" className="mt-3 text-xs text-destructive">
            {rejection}
          </p>
        ) : null}

        {busy && selected ? (
          <div className="flex flex-col items-center gap-4 rounded-lg border border-border/60 px-6 py-10">
            <LoaderCircle className="size-5 animate-spin text-muted-foreground" aria-hidden />
            <p className="text-sm font-medium">{PHASE_LABELS[phase]}</p>
            <p className="font-mono text-xs text-muted-foreground">
              {selected.name} · {formatBytes(selected.size)}
            </p>
            <div
              className="h-1 w-full max-w-sm overflow-hidden rounded-full bg-muted"
              role="progressbar"
              aria-label="Upload progress"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={phase === "uploading" ? Math.round(progress * 100) : undefined}
            >
              <div
                className="h-full rounded-full bg-primary transition-[width] duration-300"
                style={{ width: `${phase === "uploading" ? Math.max(2, progress * 100) : 100}%` }}
              />
            </div>
            {phase === "uploading" ? (
              <p className="font-mono text-[11px] text-muted-foreground">
                {Math.round(progress * 100)}%
              </p>
            ) : null}
          </div>
        ) : null}

        {phase === "success" && result ? (
          <div className="flex flex-col gap-4 rounded-lg border border-border/60 px-6 py-8">
            <div className="flex flex-col items-center text-center">
              <CheckCircle2 className="mb-2 size-6 text-success" aria-hidden />
              <p className="text-sm font-medium">
                {result.duplicate ? "Duplicate evidence — existing capture reused" : "Capture registered"}
              </p>
              <p className="mt-1 font-mono text-xs text-muted-foreground">
                {result.filename} · {formatBytes(result.size_bytes)}
              </p>
            </div>
            <dl className="mx-auto w-full max-w-md space-y-1.5 text-xs">
              <div className="flex items-baseline justify-between gap-4">
                <dt className="shrink-0 text-muted-foreground">Evidence ID</dt>
                <dd className="min-w-0 truncate font-mono">{result.id}</dd>
              </div>
              <div className="flex items-baseline justify-between gap-4">
                <dt className="shrink-0 text-muted-foreground">SHA-256</dt>
                <dd className="min-w-0 break-all text-right font-mono">{result.sha256}</dd>
              </div>
              <div className="flex items-baseline justify-between gap-4">
                <dt className="shrink-0 text-muted-foreground">Packets</dt>
                <dd className="font-mono">
                  {result.packet_count ?? "not available"}
                </dd>
              </div>
            </dl>
            {result.inspection.status !== "inspected" ? (
              <p className="mx-auto max-w-md text-center text-[11px] text-warning/90">
                {result.inspection.message}
              </p>
            ) : null}
            <div className="flex items-center justify-center gap-2">
              <Button render={<Link href={`/captures/${result.id}`} />} size="sm">
                Open capture <ArrowRight aria-hidden />
              </Button>
              <Button variant="outline" size="sm" onClick={reset}>
                Upload another
              </Button>
            </div>
          </div>
        ) : null}

        {phase === "error" && error ? (
          <div className="flex flex-col items-center gap-3 rounded-lg border border-destructive/40 bg-destructive/5 px-6 py-8 text-center">
            <TriangleAlert className="size-5 text-destructive" aria-hidden />
            <p className="text-sm font-medium">Ingestion failed</p>
            <p className="max-w-md text-xs text-muted-foreground">{error.message}</p>
            <p className="font-mono text-[11px] text-muted-foreground/70">{error.code}</p>
            <div className="flex items-center gap-2">
              {selected ? (
                <Button size="sm" onClick={() => acceptFile(selected)}>
                  Retry upload
                </Button>
              ) : null}
              <Button variant="outline" size="sm" onClick={reset}>
                <X aria-hidden /> Dismiss
              </Button>
            </div>
          </div>
        ) : null}

        {phase === "idle" ? (
          <p className="mt-3 text-[11px] text-muted-foreground/70">
            Evidence is hashed (SHA-256) and stored under a content-derived id; identical
            evidence is deduplicated automatically.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
