"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { LoaderCircle, ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  getPosture,
  getPriorities,
  listPostureHosts,
  type HostPosture,
  type PostureFactor,
  type PriorityItemRecord,
  type ProtocolPostureRecord,
  type SecurityPosture,
} from "@/lib/api";
import { cn } from "@/lib/utils";

type PostureLoadState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "loaded"; posture: SecurityPosture };

const STATE_BADGE: Record<string, string> = {
  healthy: "bg-success/15 text-success",
  acceptable: "bg-success/10 text-success",
  degraded: "bg-warning/15 text-warning",
  high_exposure: "bg-warning/20 text-warning",
  critical_exposure: "bg-destructive/15 text-destructive",
  insufficient_evidence: "bg-muted text-muted-foreground",
};

const FACTOR_STATUS_BADGE: Record<string, string> = {
  ok: "bg-success/10 text-success",
  informational: "bg-muted text-muted-foreground",
  acceptable: "bg-success/10 text-success",
  degraded: "bg-warning/15 text-warning",
  high_exposure: "bg-warning/20 text-warning",
  critical_exposure: "bg-destructive/15 text-destructive",
};

function factorStatusLabel(status: string): string {
  return status.replace("_", " ");
}

/** Explainable cryptographic posture dashboard for one capture. */
export function PostureSection({ captureId }: { captureId: string }) {
  const [state, setState] = useState<PostureLoadState>({ status: "loading" });
  const [hosts, setHosts] = useState<HostPosture[]>([]);
  const [priorities, setPriorities] = useState<PriorityItemRecord[]>([]);
  const [protocols] = useState<ProtocolPostureRecord[]>([]);

  const load = useCallback(
    (signal?: AbortSignal) => {
      getPosture(captureId, signal)
        .then((posture) => {
          setState({ status: "loaded", posture });
          return Promise.all([
            listPostureHosts(captureId, signal).then(setHosts).catch(() => undefined),
            getPriorities(captureId, signal).then(setPriorities).catch(() => undefined),
          ]);
        })
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          if (err instanceof Error && err.message.includes("posture_not_available")) {
            setState({ status: "unavailable" });
            return;
          }
          setState({ status: "unavailable" });
        });
    },
    [captureId],
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
            <LoaderCircle className="size-4 animate-spin" aria-hidden /> Loading posture…
          </div>
        </CardContent>
      </Card>
    );
  }

  if (state.status === "unavailable") {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Cryptographic security posture</CardTitle>
          <CardDescription>
            Not computed yet — run analysis to generate the posture snapshot.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  const posture = state.posture;
  const insufficient = posture.posture_state === "insufficient_evidence";

  return (
    <div className="space-y-5">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <ShieldCheck className="size-4 text-muted-foreground" aria-hidden />
            Cryptographic security posture
          </CardTitle>
          <CardDescription>
            SecureMailScope posture — deterministic, rule-derived, version{" "}
            {posture.analysis_version} · policy {posture.policy_id} v{posture.policy_version}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {insufficient ? (
            <div className="rounded-md border border-border/60 bg-muted/20 px-4 py-6 text-center">
              <p className="text-sm font-medium">Insufficient evidence</p>
              <p className="mt-1 text-xs text-muted-foreground">
                {posture.explanation[0]}
              </p>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-x-10 gap-y-4">
              <div>
                <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
                  Posture score
                </p>
                <p className="font-mono text-3xl font-semibold tracking-tight">
                  {posture.overall_score}
                  <span className="text-sm font-normal text-muted-foreground">/100</span>
                </p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
                  State
                </p>
                <Badge className={cn("mt-1", STATE_BADGE[posture.posture_state])}>
                  {posture.posture_state.replace("_", " ")}
                </Badge>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
                  Confidence
                </p>
                <p className="mt-1 text-sm capitalize">{posture.confidence}</p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
                  Affected sessions
                </p>
                <p className="mt-1 font-mono text-sm">
                  {posture.affected_sessions}/{posture.total_sessions}
                </p>
              </div>
              <div>
                <p className="text-[11px] uppercase tracking-wider text-muted-foreground">
                  Affected hosts
                </p>
                <p className="mt-1 font-mono text-sm">
                  {posture.affected_hosts}/{posture.total_hosts}
                </p>
              </div>
            </div>
          )}

          <details className="mt-4">
            <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">
              How is this calculated?
            </summary>
            <div className="mt-2 space-y-1 rounded-md border border-border/60 bg-muted/20 px-3 py-2 font-mono text-[11px] text-muted-foreground">
              <p>base 100</p>
              <p>- factor deductions (dominant condition + 25% breadth per additional)</p>
              <p>= overall score, clamped to 0..100</p>
              <p className="pt-1">
                severity weights: critical 40, high 25, medium 12, low 5, info 0
              </p>
              <p>confidence multipliers: high 1.0, medium 0.75, low 0.5, unknown 0.25</p>
              <p>prevalence multiplier: 0.5 + 0.5 x (affected sessions / total sessions)</p>
            </div>
          </details>

          <ul className="mt-4 space-y-1 text-xs text-muted-foreground" aria-label="Posture explanation">
            {posture.explanation.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </CardContent>
      </Card>

      {!insufficient ? (
        <div className="grid gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Posture factors</CardTitle>
              <CardDescription>
                Correlated finding domains — the dominant condition sets the status.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {posture.factors.map((factor: PostureFactor) => (
                <div
                  key={factor.factor}
                  className="flex items-center justify-between gap-4 rounded-md border border-border/50 px-3 py-2"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm">{factor.label}</p>
                    <p className="text-[11px] text-muted-foreground">
                      {factor.affected_sessions} session(s) affected
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <span className="font-mono text-xs text-muted-foreground">
                      -{factor.score_contribution}
                    </span>
                    <Badge
                      className={cn("capitalize", FACTOR_STATUS_BADGE[factor.status])}
                    >
                      {factorStatusLabel(factor.status)}
                    </Badge>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Top priorities</CardTitle>
              <CardDescription>Deterministic severity x prevalence ranking.</CardDescription>
            </CardHeader>
            <CardContent>
              {priorities.length === 0 ? (
                <p className="text-sm text-muted-foreground">No prioritized findings.</p>
              ) : (
                <ul className="space-y-2">
                  {priorities.slice(0, 5).map((item) => (
                    <li
                      key={item.rule_id}
                      className="rounded-md border border-border/50 px-3 py-2"
                    >
                      <Link
                        href={`/findings/${item.finding_ids[0]}`}
                        className="text-sm hover:text-primary"
                      >
                        {item.title}
                      </Link>
                      <p className="mt-0.5 text-[11px] text-muted-foreground">
                        {item.explanation}
                      </p>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      ) : null}

      {!insufficient ? (
        <div className="grid gap-5 lg:grid-cols-2">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Hosts</CardTitle>
              <CardDescription>
                Server endpoints observed in the capture (no external resolution).
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {hosts.map((host) => (
                <div
                  key={host.host_id}
                  className="flex items-center justify-between gap-4 rounded-md border border-border/50 px-3 py-2"
                >
                  <div className="min-w-0">
                    <p className="truncate font-mono text-xs">{host.ip}</p>
                    <p className="text-[11px] text-muted-foreground">
                      {host.protocols.join(" · ") || "—"} · {host.sessions} session(s) ·{" "}
                      {host.findings_count} finding(s)
                    </p>
                  </div>
                  {host.highest_severity ? (
                    <Badge variant="outline" className="shrink-0 capitalize">
                      {host.highest_severity}
                    </Badge>
                  ) : (
                    <Badge variant="outline" className="shrink-0 text-muted-foreground">
                      clean
                    </Badge>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Protocol posture</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {protocols.map((protocol) => {
                const width = Math.min(
                  100,
                  Math.round(
                    (protocol.findings / Math.max(1, protocol.sessions + protocol.findings)) * 100
                  ),
                );
                return (
                  <div key={protocol.protocol}>
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-mono uppercase">{protocol.protocol}</span>
                      <span className="text-muted-foreground">
                        {protocol.sessions} session(s) · {protocol.findings} finding(s)
                      </span>
                    </div>
                    <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full bg-primary/60"
                        style={{ width: `${width}%` }}
                        aria-hidden
                      />
                    </div>
                    <p className="mt-0.5 text-[11px] capitalize text-muted-foreground">
                      posture: {factorStatusLabel(protocol.status)}
                    </p>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>
      ) : null}
    </div>
  );
}
