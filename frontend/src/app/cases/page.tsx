import type { Metadata } from "next";

import { CaseList } from "@/components/cases/case-list";

export const metadata: Metadata = {
  title: "Cases",
};

export default function CasesPage() {
  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Investigation
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">Cases</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Forensic investigations around one or more captures — evidence is referenced, never
          copied, and case metadata never alters forensic conclusions.
        </p>
      </header>
      <CaseList />
    </div>
  );
}
