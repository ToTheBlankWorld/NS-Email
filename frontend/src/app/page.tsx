import { CaptureUpload } from "@/components/dashboard/capture-upload";
import { RecentCases } from "@/components/dashboard/recent-cases";
import { SystemStatus } from "@/components/dashboard/system-status";

export default function DashboardPage() {
  return (
    <div className="mx-auto w-full max-w-6xl px-4 py-6 md:px-8 md:py-8">
      <header className="mb-6">
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          Overview
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Current state of the NS-Email forensic platform.
        </p>
      </header>

      <div className="space-y-5">
        <section aria-label="System status">
          <SystemStatus />
        </section>
        <section aria-label="Capture analysis">
          <CaptureUpload />
        </section>
        <section aria-label="Recent cases">
          <RecentCases />
        </section>
      </div>
    </div>
  );
}
