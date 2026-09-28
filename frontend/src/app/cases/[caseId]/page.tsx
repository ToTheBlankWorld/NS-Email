import type { Metadata } from "next";
import { Suspense } from "react";

import { CaseDetail } from "@/components/cases/case-detail";

export const metadata: Metadata = {
  title: "Case detail",
};

export default async function CaseDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ caseId: string }>;
  searchParams: Promise<{ tab?: string }>;
}) {
  const { caseId } = await params;
  const { tab } = await searchParams;
  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">
      <Suspense fallback={null}>
        <CaseDetail caseId={caseId} initialTab={tab} />
      </Suspense>
    </div>
  );
}
