import type { Metadata } from "next";
import { Suspense } from "react";

import { SessionsWorkspace } from "@/components/sessions/sessions-workspace";

export const metadata: Metadata = {
  title: "Sessions",
};

export default function SessionsPage() {
  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Investigation
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">Sessions</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Reconstructed TCP sessions carrying email protocol traffic.
        </p>
      </header>
      <Suspense fallback={null}>
        <SessionsWorkspace />
      </Suspense>
    </div>
  );
}
