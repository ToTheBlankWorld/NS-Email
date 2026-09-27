import type { Metadata } from "next";

import { CaptureList } from "@/components/captures/capture-list";

export const metadata: Metadata = {
  title: "Captures",
};

export default function CapturesPage() {
  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Evidence
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">Captures</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Registered PCAP/PCAPNG evidence, identified by content hash.
        </p>
      </header>
      <CaptureList />
    </div>
  );
}
