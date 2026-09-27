import type { Metadata } from "next";
import { Suspense } from "react";

import { AnomaliesWorkspace } from "@/components/anomalies/anomalies-workspace";

export const metadata: Metadata = {
  title: "Anomalies",
};

export default function AnomaliesPage() {
  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Investigation
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">Behavioral Anomalies</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          TLS sessions whose behavior deviates from the capture-local baseline.
        </p>
      </header>
      <Suspense fallback={null}>
        <AnomaliesWorkspace />
      </Suspense>
    </div>
  );
}
