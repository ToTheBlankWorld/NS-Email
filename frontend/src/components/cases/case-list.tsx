"use client";

import Link from "next/link";
import { useCallback, useEffect, useRef, useState } from "react";
import { Briefcase, RefreshCw, Upload } from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ApiError } from "@/lib/api";
import {
  createCase,
  importCaseBundle,
  listCases,
  type CasePriority,
  type CaseRecord,
} from "@/lib/cases";

type ListState =
  | { status: "loading" }
  | { status: "loaded"; cases: CaseRecord[] }
  | { status: "error"; error: ApiError };

const PRIORITIES: CasePriority[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

/** Case list with creation and bundle import. */
export function CaseList() {
  const [state, setState] = useState<ListState>({ status: "loading" });
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState<CasePriority>("MEDIUM");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = useCallback((signal?: AbortSignal) => {
    listCases(signal)
      .then((cases) => setState({ status: "loaded", cases }))
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setState({
          status: "error",
          error: err instanceof ApiError ? err : new ApiError("network_error", "Request failed", 0),
        });
      });
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  async function handleCreate(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      await createCase({ title: title.trim(), description: description.trim(), priority });
      setTitle("");
      setDescription("");
      setPriority("MEDIUM");
      load();
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "Case creation failed");
    } finally {
      setBusy(false);
    }
  }

  async function handleImportFile(file: File) {
    setBusy(true);
    setFormError(null);
    try {
      const document = JSON.parse(await file.text()) as unknown;
      await importCaseBundle(document);
      load();
    } catch (err: unknown) {
      setFormError(err instanceof Error ? err.message : "Case import failed");
    } finally {
      setBusy(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">New case</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleCreate} className="space-y-3">
            <div className="grid gap-3 md:grid-cols-[1fr_160px]">
              <input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Case title (e.g. Mixed TLS Security Investigation)"
                maxLength={200}
                required
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
              />
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value as CasePriority)}
                className="rounded-md border border-input bg-background px-3 py-2 text-sm"
                aria-label="Priority"
              >
                {PRIORITIES.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </div>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Description (optional)"
              maxLength={5000}
              rows={2}
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
            />
            {formError ? <p className="text-sm text-destructive">{formError}</p> : null}
            <div className="flex flex-wrap gap-2">
              <Button type="submit" size="sm" disabled={busy || !title.trim()}>
                Create case
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={busy}
                onClick={() => fileRef.current?.click()}
              >
                <Upload className="mr-1 h-3.5 w-3.5" />
                Import bundle
              </Button>
              <input
                ref={fileRef}
                type="file"
                accept="application/json"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) void handleImportFile(file);
                }}
              />
            </div>
          </form>
        </CardContent>
      </Card>

      {state.status === "error" ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState
              icon={RefreshCw}
              title="Cases could not be loaded"
              description={state.error.message}
            >
              <Button variant="outline" size="sm" onClick={() => load()}>
                Retry
              </Button>
            </EmptyState>
          </CardContent>
        </Card>
      ) : null}

      {state.status === "loading" ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState icon={Briefcase} title="Loading cases…" />
          </CardContent>
        </Card>
      ) : null}

      {state.status === "loaded" && state.cases.length === 0 ? (
        <Card>
          <CardContent className="p-0">
            <EmptyState
              icon={Briefcase}
              title="No cases yet"
              description="Create a case to organize captures into a forensic investigation."
            />
          </CardContent>
        </Card>
      ) : null}

      {state.status === "loaded" && state.cases.length > 0 ? (
        <div className="grid gap-3">
          {state.cases.map((c) => (
            <Card key={c.case_id}>
              <CardContent className="flex flex-wrap items-center gap-3 py-4">
                <div className="min-w-0 flex-1">
                  <Link
                    href={`/cases/${encodeURIComponent(c.case_id)}`}
                    className="truncate text-sm font-medium hover:underline"
                  >
                    {c.title}
                  </Link>
                  <p className="mt-0.5 font-mono text-xs text-muted-foreground">
                    {c.case_number} · {c.case_id}
                  </p>
                </div>
                <Badge variant="outline">{c.status}</Badge>
                <Badge variant="outline">{c.priority}</Badge>
                <Button render={<Link href={`/cases/${encodeURIComponent(c.case_id)}`} />} variant="outline" size="sm">
                  Open
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      ) : null}
    </div>
  );
}
