"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { ArrowLeft, LoaderCircle } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { getFinding, type FindingRecord } from "@/lib/api";

type DetailState =
  | { status: "loading" }
  | { status: "loaded"; finding: FindingRecord }
  | { status: "error"; error: string };

function EvidenceList({ finding }: { finding: FindingRecord }) {
  return (
    <ul className="space-y-2">
      {finding.evidence_refs.map((ref, index) => (
        <li
          key={`${ref.source}-${index}`}
          className="rounded-md border border-border/60 bg-muted/20 px-3 py-2"
        >
          <div className="flex items-center justify-between gap-3">
            <span className="font-mono text-xs">{ref.source}</span>
            {finding.session_id ? (
              <Link
                href={`/sessions/${finding.session_id}`}
                className="shrink-0 text-[11px] text-muted-foreground underline-offset-2 hover:text-foreground hover:underline"
              >
                open session
              </Link>
            ) : null}
          </div>
          {ref.packet_numbers.length > 0 ? (
            <p className="mt-1 font-mono text-[11px] text-muted-foreground">
              packets {ref.packet_numbers.join(", ")}
            </p>
          ) : null}
          {ref.detail ? (
            <p className="mt-1 text-xs text-muted-foreground">{ref.detail}</p>
          ) : null}
        </li>
      ))}
    </ul>
  );
}

/** Forensic finding detail: what happened, why, evidence, remediation. */
export function FindingDetail({ findingId }: { findingId: string }) {
  const [state, setState] = useState<DetailState>({ status: "loading" });

  const load = useCallback(
    (signal?: AbortSignal) => {
      getFinding(findingId, signal)
        .then((finding) => setState({ status: "loaded", finding }))
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setState({
            status: "error",
            error: err instanceof Error ? err.message : "Request failed",
          });
        });
    },
    [findingId],
  );

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal);
    return () => controller.abort();
  }, [load]);

  if (state.status === "loading") {
    return (
      <Card>
        <CardContent className="p-0">
          <div className="flex items-center justify-center gap-2 px-6 py-12 text-sm text-muted-foreground">
            <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading finding…
          </div>
        </CardContent>
      </Card>
    );
  }

  if (state.status === "error") {
    return (
      <Card>
        <CardContent className="p-0">
          <div className="flex flex-col items-center gap-3 px-6 py-12 text-center">
            <p className="text-sm">{state.error}</p>
            <Button render={<Link href="/captures" />} variant="outline" size="sm">
              <ArrowLeft aria-hidden /> Captures
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  const finding = state.finding;

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center gap-2">
            <Badge className="capitalize">{finding.severity}</Badge>
            <Badge variant="outline" className="font-mono text-[11px]">
              {finding.rule_id}
            </Badge>
            <Badge variant="outline" className="font-mono text-[11px] capitalize">
              {finding.category}
            </Badge>
            {finding.protocol ? (
              <Badge variant="outline" className="font-mono text-[11px]">
                {finding.protocol.toUpperCase()}
              </Badge>
            ) : null}
          </div>
          <CardTitle className="mt-2 text-base leading-snug">{finding.title}</CardTitle>
          <CardDescription>
            Confidence in the underlying observation:{" "}
            <span className="capitalize">{finding.confidence}</span>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <section aria-label="What happened">
            <h3 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              What happened
            </h3>
            <p className="mt-1 text-sm">{finding.description}</p>
          </section>
          <section aria-label="Observed and expected">
            <h3 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              Observed / expected
            </h3>
            <dl className="mt-1 space-y-1 text-sm">
              <div className="flex items-baseline justify-between gap-4">
                <dt className="shrink-0 text-xs text-muted-foreground">Observed</dt>
                <dd className="min-w-0 break-all text-right font-mono text-xs">
                  {finding.observed_value ?? "—"}
                </dd>
              </div>
              <div className="flex items-baseline justify-between gap-4">
                <dt className="shrink-0 text-xs text-muted-foreground">Expected</dt>
                <dd className="min-w-0 break-all text-right font-mono text-xs">
                  {finding.expected_value ?? "—"}
                </dd>
              </div>
            </dl>
          </section>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Evidence</CardTitle>
          <CardDescription>
            Every finding cites the packets it was observed in.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <EvidenceList finding={finding} />
          <dl className="mt-3 space-y-1 text-xs text-muted-foreground">
            <div className="flex justify-between gap-4">
              <dt>Capture</dt>
              <dd className="font-mono">{finding.capture_id ?? "—"}</dd>
            </div>
            {finding.first_packet !== null ? (
              <div className="flex justify-between gap-4">
                <dt>First / last packet</dt>
                <dd className="font-mono">
                  #{finding.first_packet} / #{finding.last_packet}
                </dd>
              </div>
            ) : null}
          </dl>
        </CardContent>
      </Card>

      {finding.remediation ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Remediation</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-1 text-sm">
              <div className="flex items-baseline justify-between gap-4">
                <dt className="shrink-0 text-xs text-muted-foreground">Action</dt>
                <dd className="text-right">{finding.remediation.action}</dd>
              </div>
              {finding.remediation.target ? (
                <div className="flex items-baseline justify-between gap-4">
                  <dt className="shrink-0 text-xs text-muted-foreground">Target</dt>
                  <dd className="text-right">{finding.remediation.target}</dd>
                </div>
              ) : null}
              {finding.remediation.rationale ? (
                <div className="flex items-baseline justify-between gap-4">
                  <dt className="shrink-0 text-xs text-muted-foreground">Rationale</dt>
                  <dd className="text-right">{finding.remediation.rationale}</dd>
                </div>
              ) : null}
              {finding.remediation.priority ? (
                <div className="flex items-baseline justify-between gap-4">
                  <dt className="shrink-0 text-xs text-muted-foreground">Priority</dt>
                  <dd className="capitalize">{finding.remediation.priority}</dd>
                </div>
              ) : null}
            </dl>
          </CardContent>
        </Card>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Reference</CardTitle>
        </CardHeader>
        <CardContent>
          {finding.standard_reference ? (
            <div className="text-sm">
              <p>{finding.standard_reference.name}</p>
              {finding.standard_reference.url ? (
                <a
                  href={finding.standard_reference.url}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-1 inline-block font-mono text-xs text-primary underline-offset-2 hover:underline"
                >
                  {finding.standard_reference.url}
                </a>
              ) : null}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              No standard reference established for this rule.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
