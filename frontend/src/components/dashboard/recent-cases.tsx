"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { FolderOpen } from "lucide-react";

import { EmptyState } from "@/components/empty-state";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { listCases, type CaseRecord } from "@/lib/cases";

/** Recent forensic cases, loaded live from the backend. */
export function RecentCases() {
  const [cases, setCases] = useState<CaseRecord[] | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    listCases(controller.signal)
      .then((records) => setCases(records.slice(0, 5)))
      .catch(() => setCases([]));
    return () => controller.abort();
  }, []);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm font-medium">Recent cases</CardTitle>
        <Button render={<Link href="/cases" />} variant="outline" size="sm">
          All cases
        </Button>
      </CardHeader>
      <CardContent className="p-0">
        {cases === null ? (
          <EmptyState icon={FolderOpen} title="Loading cases…" />
        ) : cases.length === 0 ? (
          <EmptyState
            icon={FolderOpen}
            title="No cases yet"
            description="Create a case to organize captures into a forensic investigation."
          >
            <Button render={<Link href="/cases" />} size="sm">
              Open cases
            </Button>
          </EmptyState>
        ) : (
          <ul className="divide-y divide-border">
            {cases.map((c) => (
              <li key={c.case_id} className="flex items-center gap-3 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <Link
                    href={`/cases/${encodeURIComponent(c.case_id)}`}
                    className="truncate text-sm font-medium hover:underline"
                  >
                    {c.title}
                  </Link>
                  <p className="font-mono text-xs text-muted-foreground">{c.case_number}</p>
                </div>
                <Badge variant="outline">{c.status}</Badge>
                <Badge variant="outline">{c.priority}</Badge>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
