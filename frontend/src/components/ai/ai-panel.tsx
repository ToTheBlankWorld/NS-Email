"use client";

import { useCallback, useEffect, useState } from "react";
import { LoaderCircle, Send, Sparkles } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  getAIStatus,
  queryAI,
  type AIQueryResult,
  type AIStatus,
  type FindingRecord,
} from "@/lib/api";

type AIState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "loaded"; result: AIQueryResult }
  | { status: "error"; message: string };

function ResultSection({ label, items }: { label: string; items: string[] }) {
  if (items.length === 0) return null;
  return (
    <section aria-label={label} className="mt-3">
      <h4 className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
        {label}
      </h4>
      <ul className="mt-1 space-y-1 text-sm">
        {items.map((item, i) => (
          <li key={i} className="text-foreground/90">
            {item}
          </li>
        ))}
      </ul>
    </section>
  );
}

interface AIPanelProps {
  sessionId: string;
  finding?: FindingRecord | null;
}

/** Evidence-grounded AI analyst panel for one session. */
export function AIPanel({ sessionId, finding }: AIPanelProps) {
  const [aiStatus, setAIStatus] = useState<AIStatus | null>(null);
  const [question, setQuestion] = useState("Explain this session");
  const [state, setState] = useState<AIState>({ status: "idle" });
  const result = state.status === "loaded" ? state.result : null;

  useEffect(() => {
    const controller = new AbortController();
    getAIStatus(controller.signal)
      .then(setAIStatus)
      .catch(() => setAIStatus({ configured: false, provider: "", model: "", local: true }));
    return () => controller.abort();
  }, []);

  const ask = useCallback(
    (q: string) => {
      if (!q.trim()) return;
      setState({ status: "loading" });
      queryAI(sessionId, q)
        .then((r) => setState({ status: "loaded", result: r }))
        .catch((err: unknown) => {
          setState({
            status: "error",
            message: err instanceof Error ? err.message : "Request failed",
          });
        });
    },
    [sessionId],
  );

  const explainFinding = useCallback(() => {
    if (!finding) return;
    const q = `Explain the finding "${finding.title}" (${finding.rule_id}) on this session.`;
    setQuestion(q);
    ask(q);
  }, [finding, ask]);

  if (aiStatus && !aiStatus.configured) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-sm font-medium">
            <Sparkles className="size-4 text-muted-foreground" aria-hidden />
            SecureMail AI Analyst
          </CardTitle>
          <CardDescription>
            Not configured. Set NS_EMAIL_AI_PROVIDER to enable the AI analyst.
          </CardDescription>
        </CardHeader>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-sm font-medium">
          <Sparkles className="size-4 text-muted-foreground" aria-hidden />
          SecureMail AI Analyst
        </CardTitle>
        <CardDescription>
          Evidence-grounded assistant. Sources from structured evidence only.
          {aiStatus ? (
            <Badge variant="outline" className="ml-2 font-mono text-[10px]">
              {aiStatus.provider || "not configured"} / {aiStatus.model || "—"}
              {aiStatus.local ? " (local)" : " (external)"}
            </Badge>
          ) : null}
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex gap-2">
          <input
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && ask(question)}
            placeholder="Ask about this evidence..."
            className="flex-1 rounded-md border border-border/70 bg-background px-3 py-1.5 text-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/60"
            aria-label="Ask the AI analyst"
          />
          <Button size="sm" onClick={() => ask(question)} disabled={state.status === "loading"}>
            {state.status === "loading" ? (
              <LoaderCircle className="size-4 animate-spin" aria-hidden />
            ) : (
              <Send className="size-4" aria-hidden />
            )}
          </Button>
        </div>

        {state.status === "loading" ? (
          <div className="mt-3 flex items-center gap-2 text-sm text-muted-foreground">
            <LoaderCircle className="size-4 animate-spin" aria-hidden /> Analyzing evidence…
          </div>
        ) : null}

        {state.status === "error" ? (
          <p className="mt-3 text-xs text-destructive">{state.message}</p>
        ) : null}

        {result ? (
          <div className="mt-4 space-y-3 rounded-md border border-border/50 bg-muted/10 px-4 py-3">
            <p className="text-sm">{result.answer}</p>
            <ResultSection label="OBSERVED" items={result.key_observations ?? []} />
            <ResultSection label="INTERPRETATION" items={result.interpretations ?? []} />
            <ResultSection label="UNCERTAINTY" items={result.uncertainties ?? []} />
            <p className="text-[10px] text-muted-foreground">
              {result.provider} · {result.model} · {result.validation_status}
            </p>
          </div>
        ) : null}

        {!result && state.status === "idle" && finding ? (
          <Button variant="outline" size="sm" className="mt-2" onClick={explainFinding}>
            Explain finding
          </Button>
        ) : null}
      </CardContent>
    </Card>
  );
}
