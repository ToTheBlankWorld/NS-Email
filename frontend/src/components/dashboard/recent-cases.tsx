import { FolderOpen } from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** Cases are created by the ingestion pipeline, which does not exist yet. */
export function RecentCases() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium">Recent cases</CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <EmptyState
          icon={FolderOpen}
          title="No cases yet"
          description="Cases are created when captures are analyzed. Upload a capture to begin."
        />
      </CardContent>
    </Card>
  );
}
