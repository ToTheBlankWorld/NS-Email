import type { Metadata } from "next";
import { Suspense } from "react";

import { GraphWorkspace } from "@/components/graph/graph-workspace";

export const metadata: Metadata = {
  title: "Evidence graph",
};

export default function GraphPage() {
  return (
    <div className="mx-auto w-full max-w-7xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Investigation
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">Evidence Graph</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Typed forensic relationships across hosts, sessions, TLS evidence, findings,
          and anomalies.
        </p>
      </header>
      <Suspense fallback={null}>
        <GraphWorkspace />
      </Suspense>
    </div>
  );
}
