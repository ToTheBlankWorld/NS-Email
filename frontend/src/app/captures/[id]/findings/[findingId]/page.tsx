import { redirect } from "next/navigation";

/**
 * Deep link /captures/{captureId}/findings/{findingId} — the finding
 * detail itself lives at /findings/{findingId}; the capture context is
 * preserved through the finding record.
 */
export default async function CaptureFindingPage({
  params,
}: {
  params: Promise<{ id: string; findingId: string }>;
}) {
  const { findingId } = await params;
  redirect(`/findings/${findingId}`);
}
