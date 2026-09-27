"use client";

import { useCallback, useRef, useState, type DragEvent } from "react";
import { FileArchive, FileUp, X } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";

const ACCEPTED_EXTENSIONS = [".pcap", ".pcapng"] as const;
/** Mirrors the engine's MAX_CAPTURE_SIZE_BYTES. */
const MAX_UPLOAD_BYTES = 2 * 1024 * 1024 * 1024;

type SelectedFile = {
  name: string;
  size: number;
};

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

/**
 * Capture upload empty state. Client-side validation only — this build has
 * no ingestion pipeline, so nothing is transmitted, read, or stored.
 */
export function CaptureUpload() {
  const [selected, setSelected] = useState<SelectedFile | null>(null);
  const [rejection, setRejection] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const acceptFile = useCallback((file: File) => {
    const error = validateFile(file);
    if (error) {
      setRejection(error);
      setSelected(null);
      return;
    }
    setRejection(null);
    setSelected({ name: file.name, size: file.size });
  }, []);

  const onDrop = useCallback(
    (event: DragEvent<HTMLLabelElement>) => {
      event.preventDefault();
      setDragging(false);
      const file = event.dataTransfer.files[0];
      if (file) acceptFile(file);
    },
    [acceptFile],
  );

  const clearSelection = useCallback(() => {
    setSelected(null);
    setRejection(null);
    if (inputRef.current) inputRef.current.value = "";
  }, []);

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Capture</CardTitle>
      </CardHeader>
      <CardContent>
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
          <input
            ref={inputRef}
            id="capture-file-input"
            type="file"
            accept={ACCEPTED_EXTENSIONS.join(",")}
            className="sr-only"
            onChange={(event) => {
              const file = event.target.files?.[0];
              if (file) acceptFile(file);
            }}
          />
          {selected ? (
            <div className="flex w-full max-w-sm flex-col items-center gap-3" onClick={(event) => event.preventDefault()}>
              <div className="flex w-full items-center gap-2.5 rounded-md border border-border/70 bg-muted/40 px-3 py-2 text-left">
                <FileArchive className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                <span className="min-w-0 flex-1 truncate font-mono text-xs" title={selected.name}>
                  {selected.name}
                </span>
                <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                  {formatBytes(selected.size)}
                </span>
                <button
                  type="button"
                  onClick={clearSelection}
                  aria-label="Remove selected file"
                  className="shrink-0 rounded-sm p-0.5 text-muted-foreground transition-colors hover:text-foreground"
                >
                  <X className="size-3.5" aria-hidden />
                </button>
              </div>
              <p className="max-w-md text-xs text-muted-foreground">
                Capture ingestion is not wired in this build — the file stays local and is
                not read, transmitted, or stored.
              </p>
            </div>
          ) : (
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
          )}
        </label>
        {rejection ? (
          <p role="alert" className="mt-3 text-xs text-destructive">
            {rejection}
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}
