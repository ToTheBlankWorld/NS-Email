import type { Metadata } from "next";
import { Suspense } from "react";

import { FindingsWorkspace } from "@/components/findings/findings-workspace";

export const metadata: Metadata = {
  title: "Findings",
};

export default function FindingsPage() {
  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Investigation
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">Findings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Deterministic, evidence-backed security findings produced by the policy engine.
        </p>
      </header>
      <Suspense fallback={null}>
        <FindingsWorkspace />
      </Suspense>
    </div>
  );
}
