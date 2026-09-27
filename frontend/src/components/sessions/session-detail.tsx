"use client";

import Link from "next/link";
import { useCallback, useEffect, useState, type ReactNode } from "react";
import {
  ArrowDown,
  ArrowLeft,
  ArrowUp,
  CircleDashed,
  LoaderCircle,
  RefreshCw,
  ShieldQuestion,
} from "lucide-react";

import { HashRow } from "@/components/hash-row";
import { EmptyState } from "@/components/empty-state";
import { AIPanel } from "@/components/ai/ai-panel";
import { SessionGraphContext } from "@/components/sessions/session-graph-context";
import { SessionSecuritySummary } from "@/components/sessions/session-security-summary";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  ApiError,
  getSession,
  type SessionEvent,
  type SessionRecord,
  type TlsCertificate,
  type TlsHandshake,
} from "@/lib/api";
import { formatBytes, formatCount, formatDuration, formatTimestamp } from "@/lib/format";
import { cn } from "@/lib/utils";

type DetailState =
  | { status: "loading" }
  | { status: "loaded"; session: SessionRecord }
  | { status: "error"; error: ApiError };

function InfoRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-6 border-b border-border/30 py-2 last:border-0">
      <dt className="shrink-0 text-xs text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-all text-right text-sm">{children}</dd>
    </div>
  );
}

const EVENT_LABELS: Record<string, string> = {
  connection_established: "TCP connection established",
  connection_closed: "Connection closed",
  server_greeting: "Server greeting",
  client_command: "Client command",
  server_response: "Server response",
  starttls_advertised: "STARTTLS advertised",
  starttls_requested: "STARTTLS requested",
  starttls_response: "STARTTLS accepted",
  tls_transition: "TLS transition boundary",
  authentication: "Authentication command",
  mail_transaction_start: "Mail transaction started",
  mail_transaction_complete: "Mail transaction complete",
};

function DirectionIcon({ direction }: { direction: string }) {
  if (direction === "client_to_server") {
    return <ArrowUp className="size-3.5 text-primary" aria-label="client to server" />;
  }
  if (direction === "server_to_client") {
    return <ArrowDown className="size-3.5 text-muted-foreground" aria-label="server to client" />;
  }
  return <CircleDashed className="size-3.5 text-muted-foreground/60" aria-label="transport" />;
}

function EventLine({ event }: { event: SessionEvent }) {
  const detailEntries = Object.entries(event.detail).filter(([, value]) => value !== "");
  return (
    <li className="relative ml-3 border-l border-border/60 py-2 pl-5">
      <span
        className={cn(
          "absolute -left-[5px] top-3.5 size-2.5 rounded-full border",
          event.type === "tls_transition"
            ? "border-warning bg-warning/30"
            : "border-border bg-muted",
        )}
        aria-hidden
      />
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="font-mono text-xs text-muted-foreground">
          {formatTimestamp(event.timestamp)}
        </span>
        <span className="text-sm font-medium">{EVENT_LABELS[event.type] ?? event.type}</span>
        <DirectionIcon direction={event.direction} />
      </div>
      {detailEntries.length > 0 ? (
        <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5">
          {detailEntries.map(([key, value]) => (
            <span key={key} className="text-xs text-muted-foreground">
              {key}: <span className="font-mono">{value}</span>
            </span>
          ))}
        </div>
      ) : null}
      {event.packet_numbers.length > 0 ? (
        <p className="mt-1 font-mono text-[11px] text-muted-foreground/70">
          evidence: packets {event.packet_numbers.join(", ")}
        </p>
      ) : null}
    </li>
  );
}

function TlsEvidence({ handshake }: { handshake: TlsHandshake }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">TLS handshake</CardTitle>
        <CardDescription>
          Facts reconstructed from the ciphertext stream — no security verdicts at this stage.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <dl>
          <InfoRow label="Negotiated version">
            <span className="font-mono text-xs">{handshake.tls_version}</span>
          </InfoRow>
          <InfoRow label="Cipher suite">
            <span className="font-mono text-xs">{handshake.cipher_suite ?? "—"}</span>
          </InfoRow>
          <InfoRow label="Key exchange">
            <span className="font-mono text-xs">{handshake.key_exchange}</span>
          </InfoRow>
          <InfoRow label="Server name (SNI)">
            {handshake.sni_server_name ? (
              <span className="font-mono text-xs">{handshake.sni_server_name}</span>
            ) : (
              "—"
            )}
          </InfoRow>
          <InfoRow label="Suites offered">
            <span className="font-mono text-xs">{handshake.cipher_suites_offered.length}</span>
          </InfoRow>
          <InfoRow label="Handshake">
            {handshake.handshake_complete ? (
              <Badge className="bg-success/15 text-success">Complete</Badge>
            ) : (
              <Badge variant="outline" className="text-warning">
                Incomplete
              </Badge>
            )}
          </InfoRow>
          {handshake.completeness_reason ? (
            <InfoRow label="Why">
              <span className="text-xs text-muted-foreground">
                {handshake.completeness_reason}
              </span>
            </InfoRow>
          ) : null}
        </dl>

        {handshake.extensions.length > 0 ? (
          <details className="mt-3">
            <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">
              Hello extensions ({handshake.extensions.length})
            </summary>
            <ul className="mt-2 space-y-1">
              {handshake.extensions.map((extension) => (
                <li
                  key={`${extension.type_code}-${extension.name}`}
                  className="flex items-baseline justify-between gap-4 border-b border-border/30 pb-1 text-xs last:border-0"
                >
                  <span className="font-mono text-muted-foreground">{extension.name}</span>
                  <span className="min-w-0 truncate text-right font-mono">{extension.value ?? "—"}</span>
                </li>
              ))}
            </ul>
          </details>
        ) : null}

        {handshake.warnings.length > 0 ? (
          <ul className="mt-3 space-y-1 rounded-md border border-warning/30 bg-warning/5 px-3 py-2">
            {handshake.warnings.map((warning) => (
              <li key={warning} className="text-[11px] text-warning/90">
                {warning}
              </li>
            ))}
          </ul>
        ) : null}
      </CardContent>
    </Card>
  );
}

function CertificateChain({ certificates }: { certificates: TlsCertificate[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Certificate chain</CardTitle>
        <CardDescription>
          {certificates.length} certificate{certificates.length === 1 ? "" : "s"} observed in
          the plaintext handshake.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {certificates.map((certificate) => (
          <div
            key={certificate.id}
            className="rounded-md border border-border/60 bg-muted/20 px-4 py-3"
          >
            <div className="mb-2 flex items-center gap-2">
              <Badge variant="outline" className="font-mono text-[11px]">
                {certificate.position_in_chain === 0 ? "leaf" : `#${certificate.position_in_chain ?? "?"}`}
              </Badge>
              <span className="font-mono text-[11px] text-muted-foreground">{certificate.id}</span>
            </div>
            <dl>
              <HashRow label="Subject" value={certificate.subject} />
              <InfoRow label="Issuer">{certificate.issuer}</InfoRow>
              <InfoRow label="Valid from">{formatTimestamp(certificate.not_before)}</InfoRow>
              <InfoRow label="Valid until">{formatTimestamp(certificate.not_after)}</InfoRow>
              <InfoRow label="Signature">
                <span className="font-mono text-xs">{certificate.signature_algorithm}</span>
              </InfoRow>
              <InfoRow label="Public key">
                {certificate.public_key_algorithm
                  ? `${certificate.public_key_algorithm} ${certificate.public_key_size_bits ?? "?"} bit`
                  : "—"}
              </InfoRow>
              {certificate.subject_alternative_names.length > 0 ? (
                <InfoRow label="SANs">
                  <span className="font-mono text-xs">
                    {certificate.subject_alternative_names.join(", ")}
                  </span>
                </InfoRow>
              ) : null}
            </dl>
            <div className="mt-2 flex items-baseline justify-between gap-4">
              <span className="shrink-0 text-xs text-muted-foreground">SHA-256 fingerprint</span>
              <code className="min-w-0 break-all text-right font-mono text-[11px] text-muted-foreground">
                {certificate.fingerprint_sha256}
              </code>
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

/** Forensic session detail: connection, transport, protocol, TLS boundary, timeline. */
export function SessionDetail({ sessionId }: { sessionId: string }) {
  const [state, setState] = useState<DetailState>({ status: "loading" });

  const load = useCallback(
    (signal?: AbortSignal) => {
      getSession(sessionId, signal)
        .then((session) => setState({ status: "loaded", session }))
        .catch((err: unknown) => {
          if (err instanceof DOMException && err.name === "AbortError") return;
          setState({
            status: "error",
            error:
              err instanceof ApiError ? err : new ApiError("network_error", "Request failed", 0),
          });
        });
    },
    [sessionId],
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
          <EmptyState icon={LoaderCircle} title="Loading session…" />
        </CardContent>
      </Card>
    );
  }

  if (state.status === "error") {
    const notFound = state.error.code === "session_not_found";
    return (
      <Card>
        <CardContent className="p-0">
          <EmptyState
            icon={notFound ? ShieldQuestion : RefreshCw}
            title={notFound ? "Session not found" : "Session could not be loaded"}
            description={state.error.message}
          >
            <Button render={<Link href="/captures" />} variant="outline" size="sm">
              <ArrowLeft aria-hidden /> Captures
            </Button>
          </EmptyState>
        </CardContent>
      </Card>
    );
  }

  const session = state.session;

  return (
    <div className="space-y-5">
      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Connection</CardTitle>
          </CardHeader>
          <CardContent>
            <dl>
              <InfoRow label="Session">
                <code className="font-mono text-xs">{session.id}</code>
              </InfoRow>
              <InfoRow label="Protocol">
                <Badge variant="outline" className="font-mono text-[11px]">
                  {(session.protocol ?? "unknown").toUpperCase()}
                </Badge>
              </InfoRow>
              <InfoRow label="Client">
                <span className="font-mono text-xs">
                  {session.client_ip}:{session.client_port}
                </span>
              </InfoRow>
              <InfoRow label="Server">
                <span className="font-mono text-xs">
                  {session.server_ip}:{session.server_port}
                </span>
              </InfoRow>
              <InfoRow label="Orientation">
                {session.orientation === "client_server" ? (
                  "Client / Server"
                ) : (
                  <span className="text-muted-foreground">Unknown</span>
                )}
              </InfoRow>
              <InfoRow label="Start">{formatTimestamp(session.started_at)}</InfoRow>
              <InfoRow label="End">{formatTimestamp(session.ended_at)}</InfoRow>
              <InfoRow label="Duration">{formatDuration(session.duration_seconds)}</InfoRow>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Transport</CardTitle>
          </CardHeader>
          <CardContent>
            <dl>
              <InfoRow label="Packets">{formatCount(session.packet_count)}</InfoRow>
              <InfoRow label="Bytes client → server">
                <span className="font-mono text-xs">{formatBytes(session.bytes_client_to_server)}</span>
              </InfoRow>
              <InfoRow label="Bytes server → client">
                <span className="font-mono text-xs">{formatBytes(session.bytes_server_to_client)}</span>
              </InfoRow>
              <InfoRow label="Completeness">
                {session.complete ? (
                  <Badge className="bg-success/15 text-success">Complete</Badge>
                ) : (
                  <Badge variant="outline" className="text-warning">
                    Incomplete
                  </Badge>
                )}
              </InfoRow>
              {session.completeness_reason ? (
                <InfoRow label="Why">
                  <span className="text-xs text-muted-foreground">{session.completeness_reason}</span>
                </InfoRow>
              ) : null}
              <InfoRow label="Retransmissions">{formatCount(session.retransmissions)}</InfoRow>
              <InfoRow label="Gaps">
                {session.gap_count} ({formatBytes(session.gap_bytes)})
              </InfoRow>
            </dl>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-5 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">Protocol</CardTitle>
          </CardHeader>
          <CardContent>
            <dl>
              <InfoRow label="Detected protocol">
                {(session.protocol ?? "unknown").toUpperCase()}
              </InfoRow>
              <InfoRow label="Confidence">
                <span className="capitalize">{session.confidence}</span>
              </InfoRow>
              <InfoRow label="Basis">
                <span className="text-xs text-muted-foreground">
                  greetings, commands, and service ports observed on the wire
                </span>
              </InfoRow>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm font-medium">TLS boundary</CardTitle>
            <CardDescription>
              Existence of a plaintext STARTTLS/STLS negotiation only.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {session.starttls ? (
              <dl>
                <InfoRow label="Advertised">
                  {session.starttls.advertised ? "Yes" : "No"}
                </InfoRow>
                <InfoRow label="Requested">{session.starttls.requested ? "Yes" : "No"}</InfoRow>
                <InfoRow label="Response seen">
                  {session.starttls.response_seen ? "Yes" : "No"}
                </InfoRow>
                {session.starttls.packet_number ? (
                  <InfoRow label="Boundary packet">
                    <span className="font-mono text-xs">#{session.starttls.packet_number}</span>
                  </InfoRow>
                ) : null}
              </dl>
            ) : (
              <p className="text-sm text-muted-foreground">
                No STARTTLS/STLS negotiation observed in this session.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      {session.handshake ? <TlsEvidence handshake={session.handshake} /> : null}

      {session.certificates && session.certificates.length > 0 ? (
        <CertificateChain certificates={session.certificates} />
      ) : null}

      <SessionSecuritySummary sessionId={session.id} />

      <SessionGraphContext captureId={session.capture_id} sessionId={session.id} />

      <AIPanel sessionId={session.id} />

      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-medium">Timeline</CardTitle>
          <CardDescription>Observed session events with packet evidence.</CardDescription>
        </CardHeader>
        <CardContent>
          {(session.events ?? []).length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No protocol events — the session carried no recognizable email conversation.
            </p>
          ) : (
            <ul className="ml-1">
              {(session.events ?? []).map((event) => (
                <EventLine key={event.seq} event={event} />
              ))}
            </ul>
          )}
          {session.warnings.length > 0 ? (
            <ul className="mt-4 space-y-1 rounded-md border border-warning/30 bg-warning/5 px-3 py-2">
              {session.warnings.map((warning) => (
                <li key={warning} className="text-[11px] text-warning/90">
                  {warning}
                </li>
              ))}
            </ul>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
