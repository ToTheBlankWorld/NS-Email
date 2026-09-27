"use client";

import { Check, Copy } from "lucide-react";
import { useCallback, useState } from "react";

/** Monospace technical value with a copy-to-clipboard affordance. */
export function HashRow({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    navigator.clipboard.writeText(value).then(
      () => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      },
      () => setCopied(false),
    );
  }, [value]);

  return (
    <div className="flex items-baseline justify-between gap-6 border-b border-border/30 py-2 last:border-0">
      <dt className="shrink-0 text-xs text-muted-foreground">{label}</dt>
      <dd className="flex min-w-0 items-center gap-1.5">
        <code className="min-w-0 break-all text-right font-mono text-xs">{value}</code>
        <button
          type="button"
          onClick={copy}
          aria-label={`Copy ${label}`}
          className="shrink-0 rounded-sm p-1 text-muted-foreground transition-colors hover:text-foreground"
        >
          {copied ? (
            <Check className="size-3.5 text-success" aria-hidden />
          ) : (
            <Copy className="size-3.5" aria-hidden />
          )}
        </button>
      </dd>
    </div>
  );
}
