"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useMemo, useState } from "react";
import { LoaderCircle, Search, ShieldAlert } from "lucide-react";

import { CaptureSelector } from "@/components/captures/capture-selector";
import {
  SEVERITY_ORDER,
  SeverityBadge,
} from "@/components/findings/severity-badge";
import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import {
  listCaptureFindings,
  type FindingRecord,
  type FindingSeverity,
} from "@/lib/api";
import { defaultCaptureId, useCaptures } from "@/lib/use-captures";

type ConfidenceFilter = "" | "high" | "medium" | "low";
type SortKey = "severity" | "rule_id" | "session_id";

function FilterRow({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
      {label}
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="rounded-md border border-border/70 bg-background px-1.5 py-1 font-mono text-[11px] text-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
      >
        <option value="">all</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

/** Findings workspace: filterable, sortable, deep-linkable across captures. */
export function FindingsWorkspace() {
  const captures = useCaptures();
  const router = useRouter();
  const searchParams = useSearchParams();

  const captureId = searchParams.get("capture") ?? defaultCaptureId(captures.status === "loaded" ? captures.captures : []);
  const [findings, setFindings] = useState<FindingRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [confidence, setConfidence] = useState<ConfidenceFilter>("");
  const [protocol, setProtocol] = useState("");
  const [rule, setRule] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("severity");
  const [prevCaptureId, setPrevCaptureId] = useState(captureId);
  if (prevCaptureId !== captureId) {
    setPrevCaptureId(captureId);
    setFindings(null);
    setError(null);
  }

  useEffect(() => {
    if (!captureId) return;
    const controller = new AbortController();
    listCaptureFindings(captureId, controller.signal)
      .then(setFindings)
      .catch((err: unknown) => {
        if (err instanceof DOMException && err.name === "AbortError") return;
        setError("Findings could not be loaded.");
      });
    return () => controller.abort();
  }, [captureId]);

  const onCaptureChange = useCallback(
    (id: string) => {
      router.replace(`/findings?capture=${id}`, { scroll: false });
    },
    [router],
  );

  const distinct = useCallback(
    (values: (string | null)[]) =>
      [...new Set(values.filter((value): value is string => Boolean(value)))].sort(),
    [],
  );

  const filtered = useMemo(() => {
    if (!findings) return null;
    const needle = search.trim().toLowerCase();
    const result = findings.filter(
      (finding) =>
        (!severity || finding.severity === severity) &&
        (!confidence || finding.confidence === confidence) &&
        (!protocol || finding.protocol === protocol) &&
        (!rule || finding.rule_id === rule) &&
        (!needle ||
          finding.title.toLowerCase().includes(needle) ||
          finding.rule_id.toLowerCase().includes(needle) ||
          (finding.session_id ?? "").includes(needle)),
    );
    result.sort((a, b) => {
      if (sortKey === "severity") {
        return SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity);
      }
      return String(a[sortKey] ?? "").localeCompare(String(b[sortKey] ?? ""));
    });
    return result;
  }, [findings, severity, confidence, protocol, rule, search, sortKey]);

  if (captures.status === "loading") {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={LoaderCircle} title="Loading captures…" />
        </CardContent>
      </Card>
    );
  }

  if (captures.status === "error") {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState icon={ShieldAlert} title="Captures could not be loaded" description={captures.message} />
        </CardContent>
      </Card>
    );
  }

  if (captures.captures.length === 0) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={ShieldAlert}
            title="No captures registered"
            description="Upload a PCAP from the dashboard to begin."
          />
        </CardContent>
      </Card>
    );
  }

  const analyzed = captures.captures.filter((c) => c.analysis?.status === "completed");
  if (analyzed.length === 0) {
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={ShieldAlert}
            title="No analyzed captures"
            description="Run analysis on a capture to produce findings."
          />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <CaptureSelector captures={captures.captures} value={captureId} onChange={onCaptureChange} analyzedOnly />
        <div className="flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
            <Search className="size-3.5" aria-hidden />
            <span className="sr-only">Search findings</span>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search title, rule, session…"
              className="w-56 rounded-md border border-border/70 bg-background px-2 py-1 text-xs outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
            />
          </label>
          <FilterRow label="Severity" value={severity} options={SEVERITY_ORDER} onChange={setSeverity} />
          <FilterRow
            label="Confidence"
            value={confidence}
            options={["high", "medium", "low"]}
            onChange={(value) => setConfidence(value as ConfidenceFilter)}
          />
          <FilterRow
            label="Protocol"
            value={protocol}
            options={findings ? distinct(findings.map((f) => f.protocol)) : []}
            onChange={setProtocol}
          />
          <FilterRow
            label="Rule"
            value={rule}
            options={findings ? distinct(findings.map((f) => f.rule_id)) : []}
            onChange={setRule}
          />
          <FilterRow
            label="Sort"
            value={sortKey}
            options={["severity", "rule_id", "session_id"]}
            onChange={(value) => setSortKey(value as SortKey)}
          />
        </div>
      </div>

      <Card>
        <CardContent className="px-0 py-2">
          {error ? (
            <p className="px-4 text-xs text-destructive">{error}</p>
          ) : findings === null ? (
            <p className="flex items-center gap-2 px-4 py-3 text-sm text-muted-foreground">
              <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading findings…
            </p>
          ) : filtered && filtered.length > 0 ? (
            <table className="w-full text-sm">
              <caption className="sr-only">Security findings for capture {captureId}</caption>
              <thead>
                <tr className="border-b border-border/60 text-left text-[11px] uppercase tracking-wider text-muted-foreground">
                  <th scope="col" className="px-4 py-2 font-medium">Severity</th>
                  <th scope="col" className="px-2 py-2 font-medium">Finding</th>
                  <th scope="col" className="hidden px-2 py-2 font-medium md:table-cell">Rule</th>
                  <th scope="col" className="hidden px-2 py-2 font-medium sm:table-cell">Protocol</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">Session</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((finding) => (
                  <tr
                    key={finding.id}
                    className="border-b border-border/30 transition-colors last:border-0 hover:bg-muted/40"
                  >
                    <td className="px-4 py-2">
                      <SeverityBadge severity={finding.severity as FindingSeverity} />
                    </td>
                    <td className="px-2 py-2">
                      <Link
                        href={`/findings/${finding.id}`}
                        className="block max-w-96 truncate font-medium hover:underline"
                      >
                        {finding.title}
                      </Link>
                      <span className="text-[11px] capitalize text-muted-foreground">
                        {finding.confidence} confidence · {finding.evidence_refs.length} ref(s)
                      </span>
                    </td>
                    <td className="hidden px-2 py-2 font-mono text-[11px] text-muted-foreground md:table-cell">
                      {finding.rule_id}
                    </td>
                    <td className="hidden px-2 py-2 sm:table-cell">
                      <Badge variant="outline" className="font-mono text-[10px] uppercase">
                        {finding.protocol ?? "unknown"}
                      </Badge>
                    </td>
                    <td className="px-4 py-2 text-right">
                      {finding.session_id ? (
                        <Link
                          href={`/sessions/${finding.session_id}`}
                          className="font-mono text-[11px] text-muted-foreground hover:text-foreground hover:underline"
                        >
                          {finding.session_id.slice(0, 14)}…
                        </Link>
                      ) : (
                        <span className="text-[11px] text-muted-foreground">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="px-4 py-4">
              <EmptyState
                icon={ShieldAlert}
                title="No findings match the active filters"
                description={findings.length === 0 ? "This capture produced no findings." : undefined}
              />
            </div>
          )}
        </CardContent>
      </Card>
      {findings ? (
        <p className="text-[11px] text-muted-foreground" aria-live="polite">
          {filtered?.length ?? 0} of {findings.length} finding(s) shown
        </p>
      ) : null}
    </div>
  );
}
