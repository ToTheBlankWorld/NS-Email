import type { Metadata } from "next";
import Link from "next/link";
import { ChevronRight } from "lucide-react";

import { FindingDetail } from "@/components/findings/finding-detail";

export const metadata: Metadata = {
  title: "Finding detail",
};

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  return (
    <div className="mx-auto w-full max-w-4xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-xs text-muted-foreground">
          <Link href="/captures" className="hover:text-foreground">
            Captures
          </Link>
          <ChevronRight className="size-3" aria-hidden />
          <span>Finding</span>
        </nav>
        <h1 className="mt-2 text-xl font-semibold tracking-tight">Security finding</h1>
      </header>
      <FindingDetail findingId={id} />
    </div>
  );
}
