"use client";

import { Download, FileJson, FileText, FileType2, LoaderCircle } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { CaptureSelector } from "@/components/captures/capture-selector";
import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  listAIHistory,
  reportUrl,
  type AIHistoryEntry,
  type CaptureRecord,
} from "@/lib/api";
import { formatTimestamp } from "@/lib/format";
import { defaultCaptureId, useCaptures } from "@/lib/use-captures";

const REPORT_FORMATS = [
  {
    format: "json" as const,
    title: "JSON report",
    description: "Machine-readable, versioned schema. Deterministic per evidence state.",
    icon: FileJson,
    mediaType: "application/json · schema 1.0",
  },
  {
    format: "html" as const,
    title: "HTML report",
    description: "Standalone printable document — usable without the application running.",
    icon: FileText,
    mediaType: "text/html · self-contained",
  },
  {
    format: "pdf" as const,
    title: "PDF report",
    description: "Structured, print-ready PDF for case files and distribution.",
    icon: FileType2,
    mediaType: "application/pdf · structured",
  },
];

/** Report center: generate and download deterministic forensic reports. */
export function ReportCenter() {
  const captures = useCaptures();
  const router = useRouter();
  const searchParams = useSearchParams();

  const captureId =
    searchParams.get("capture") ?? defaultCaptureId(captures.status === "loaded" ? captures.captures : []);
  const [history, setHistory] = useState<AIHistoryEntry[] | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  useEffect(() => {
    if (!captureId) return;
    const controller = new AbortController();
    listAIHistory(captureId, controller.signal)
      .then(setHistory)
      .catch(() => setHistory([]));
    return () => controller.abort();
  }, [captureId]);

  const onDownload = useCallback((format: string) => {
    setDownloading(format);
    // Clear the transient status once the browser takes over the download.
    window.setTimeout(() => setDownloading(null), 2500);
  }, []);

  if (captures.status !== "loaded") {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={LoaderCircle} title="Loading captures…" />
        </CardContent>
      </Card>
    );
  }

  if (captures.captures.length === 0 || !captureId) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={FileText}
            title="No captures available"
            description="Upload and analyze a capture to generate reports."
          />
        </CardContent>
      </Card>
    );
  }

  const capture: CaptureRecord | undefined = captures.captures.find((c) => c.id === captureId);
  const analyzed = capture?.analysis?.status === "completed";

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <CaptureSelector
          captures={captures.captures}
          value={captureId}
          onChange={(id) => router.replace(`/reports?capture=${id}`, { scroll: false })}
          analyzedOnly
        />
        {capture ? (
          <p className="text-[11px] text-muted-foreground">
            Capture: <span className="font-mono">{capture.id}</span> · ingested{" "}
            {formatTimestamp(capture.ingested_at)}
          </p>
        ) : null}
      </div>

      {!analyzed ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState
              icon={FileText}
              title="Capture not analyzed"
              description="Reports are generated from completed analysis evidence. Analyze this capture first."
            />
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            {REPORT_FORMATS.map(({ format, title, description, icon: Icon, mediaType }) => (
              <Card key={format} className="flex flex-col">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-sm font-medium">
                    <Icon className="size-4 text-muted-foreground" aria-hidden />
                    {title}
                  </CardTitle>
                  <CardDescription>{description}</CardDescription>
                </CardHeader>
                <CardContent className="mt-auto">
                  <p className="mb-3 text-[11px] text-muted-foreground">{mediaType}</p>
                  <a
                    href={reportUrl(captureId, format)}
                    download
                    onClick={() => onDownload(format)}
                    className="inline-flex h-8 items-center justify-center gap-1.5 rounded-md bg-primary px-3 text-xs font-medium text-primary-foreground transition-colors hover:bg-primary/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
                  >
                    <Download className="size-3.5" aria-hidden />
                    {downloading === format ? "Preparing…" : "Download"}
                  </a>
                </CardContent>
              </Card>
            ))}
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">AI analyst history</CardTitle>
              <CardDescription>
                Validated AI observations included in reports. Interpretive assistance only —
                never a source of security truth.
              </CardDescription>
            </CardHeader>
            <CardContent>
              {history === null ? (
                <p className="text-sm text-muted-foreground">Loading history…</p>
              ) : history.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No validated AI observations recorded for this capture. Reports will note
                  their absence.
                </p>
              ) : (
                <ul className="space-y-2">
                  {history.map((entry) => (
                    <li
                      key={entry.response_id}
                      className="rounded-md border border-border/50 bg-muted/20 px-3 py-2"
                    >
                      <div className="flex flex-wrap items-baseline justify-between gap-2">
                        <p className="min-w-0 truncate text-sm font-medium">{entry.query}</p>
                        <Badge variant="outline" className="font-mono text-[10px]">
                          {entry.validation_status}
                        </Badge>
                      </div>
                      <p className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">
                        {entry.answer}
                      </p>
                      <p className="mt-1 text-[10px] text-muted-foreground">
                        {entry.provider} · {entry.model} · session{" "}
                        <span className="font-mono">{entry.session_id ?? "—"}</span>
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <p className="text-[11px] text-muted-foreground">
            Reports are generated on demand from persisted evidence — never stored as blobs.
            Identical evidence always produces identical JSON and PDF bytes.
          </p>
        </>
      )}
    </div>
  );
}
