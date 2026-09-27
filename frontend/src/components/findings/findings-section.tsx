"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { LoaderCircle, ShieldAlert } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  listCaptureFindings,
  type FindingRecord,
  type FindingSeverity,
} from "@/lib/api";
import { cn } from "@/lib/utils";

const SEVERITY_ORDER: FindingSeverity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_BADGE: Record<FindingSeverity, string> = {
  critical: "bg-destructive/15 text-destructive",
  high: "bg-destructive/10 text-destructive",
  medium: "bg-warning/15 text-warning",
  low: "bg-primary/10 text-primary",
  info: "bg-muted text-muted-foreground",
};

function SeverityBadge({ severity }: { severity: FindingSeverity }) {
  return (
    <Badge className={cn("capitalize", SEVERITY_BADGE[severity])}>{severity}</Badge>
  );
}

type Filters = {
  severity: string;
  category: string;
  protocol: string;
  rule: string;
};

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

/** Deterministic, evidence-backed security findings for one capture. */
export function FindingsSection({ captureId }: { captureId: string }) {
  const [findings, setFindings] = useState<FindingRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<Filters>({
    severity: "",
    category: "",
    protocol: "",
    rule: "",
  });

  const load = useCallback(
    (signal?: AbortSignal) => {
      listCaptureFindings(captureId, signal)
        .then(setFindings)
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setError("Findings could not be loaded.");
        });
    },
    [captureId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const filtered = useMemo(() => {
    if (!findings) return null;
    return findings.filter(
      (finding) =>
        (!filters.severity || finding.severity === filters.severity) &&
        (!filters.category || finding.category === filters.category) &&
        (!filters.protocol || finding.protocol === filters.protocol) &&
        (!filters.rule || finding.rule_id === filters.rule),
    );
  }, [findings, filters]);

  const distinct = (values: (string | null)[]) =>
    [...new Set(values.filter((value): value is string => Boolean(value)))].sort();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Security findings</CardTitle>
        <CardDescription>
          Deterministic rule evaluation over the reconstructed evidence — no AI, no scores.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {error ? (
          <p className="text-xs text-destructive">{error}</p>
        ) : findings === null ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading findings…
          </p>
        ) : findings.length === 0 ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <ShieldAlert className="size-4" aria-hidden /> No findings for this capture.
          </p>
        ) : (
          <>
            <div className="mb-3 flex flex-wrap gap-3">
              <FilterRow
                label="Severity"
                value={filters.severity}
                options={SEVERITY_ORDER}
                onChange={(severity) => setFilters((f) => ({ ...f, severity }))}
              />
              <FilterRow
                label="Category"
                value={filters.category}
                options={distinct(findings.map((f) => f.category))}
                onChange={(category) => setFilters((f) => ({ ...f, category }))}
              />
              <FilterRow
                label="Protocol"
                value={filters.protocol}
                options={distinct(findings.map((f) => f.protocol))}
                onChange={(protocol) => setFilters((f) => ({ ...f, protocol }))}
              />
              <FilterRow
                label="Rule"
                value={filters.rule}
                options={distinct(findings.map((f) => f.rule_id))}
                onChange={(rule) => setFilters((f) => ({ ...f, rule }))}
              />
            </div>

            <ul className="divide-y divide-border/40">
              {filtered?.map((finding) => (
                <li key={finding.id}>
                  <Link
                    href={`/findings/${finding.id}`}
                    className="flex items-center gap-3 px-1 py-2.5 transition-colors hover:bg-muted/40"
                  >
                    <SeverityBadge severity={finding.severity} />
                    <span className="min-w-0 flex-1 truncate text-sm">{finding.title}</span>
                    <span className="hidden shrink-0 font-mono text-[11px] text-muted-foreground sm:inline">
                      {finding.rule_id}
                    </span>
                    <span className="hidden w-16 shrink-0 text-right text-[11px] capitalize text-muted-foreground md:inline">
                      {finding.confidence}
                    </span>
                    <span className="hidden w-20 shrink-0 text-right font-mono text-[11px] text-muted-foreground lg:inline">
                      {finding.evidence_refs.length} ref(s)
                    </span>
                  </Link>
                </li>
              ))}
              {filtered?.length === 0 ? (
                <li className="px-1 py-3 text-sm text-muted-foreground">
                  No findings match the active filters.
                </li>
              ) : null}
            </ul>
          </>
        )}
      </CardContent>
    </Card>
  );
}
