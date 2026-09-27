import type { Metadata } from "next";
import Link from "next/link";
import { ChevronRight } from "lucide-react";

import { CaptureDetail } from "@/components/captures/capture-detail";

export const metadata: Metadata = {
  title: "Capture detail",
};

export default async function CaptureDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-xs text-muted-foreground">
          <Link href="/captures" className="hover:text-foreground">
            Captures
          </Link>
          <ChevronRight className="size-3" aria-hidden />
          <span className="font-mono">{id}</span>
        </nav>
        <h1 className="mt-2 text-xl font-semibold tracking-tight">Capture</h1>
      </header>
      <CaptureDetail captureId={id} />
    </div>
  );
}
