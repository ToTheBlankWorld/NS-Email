import type { Metadata } from "next";
import Link from "next/link";
import { ChevronRight } from "lucide-react";

import { SessionDetail } from "@/components/sessions/session-detail";

export const metadata: Metadata = {
  title: "Session detail",
};

export default async function SessionDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;

  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <nav aria-label="Breadcrumb" className="flex items-center gap-1 text-xs text-muted-foreground">
          <Link href="/sessions" className="hover:text-foreground">
            Sessions
          </Link>
          <ChevronRight className="size-3" aria-hidden />
          <span>Session</span>
        </nav>
        <h1 className="mt-2 text-xl font-semibold tracking-tight">Session</h1>
      </header>
      <SessionDetail sessionId={id} />
    </div>
  );
}
