import type { Metadata } from "next";
import { Suspense } from "react";

import { ReportCenter } from "@/components/reports/report-center";

export const metadata: Metadata = {
  title: "Reports",
};

export default function ReportsPage() {
  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Reporting
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">Report Center</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Deterministic forensic reports assembled from persisted evidence.
        </p>
      </header>
      <Suspense fallback={null}>
        <ReportCenter />
      </Suspense>
    </div>
  );
}
