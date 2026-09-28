"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { CaseWorkspace } from "@/components/cases/case-workspace";
import { getCase, type CaseRecord } from "@/lib/cases";

/** Case detail shell: header plus the workspace tabs. */
export function CaseDetail({ caseId, initialTab }: { caseId: string; initialTab?: string }) {
  const [record, setRecord] = useState<CaseRecord | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    getCase(caseId, controller.signal).then(setRecord).catch(() => {});
    return () => controller.abort();
  }, [caseId]);

  return (
    <div className="space-y-5">
      <header>
        <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
          <Link href="/cases" className="hover:underline">
            Cases
          </Link>
          {record ? ` · ${record.case_number}` : ""}
        </p>
        <h1 className="mt-1 text-xl font-semibold tracking-tight">
          {record ? record.title : "Case"}
        </h1>
        <p className="mt-1 font-mono text-xs text-muted-foreground">{caseId}</p>
      </header>
      <CaseWorkspace caseId={caseId} initialTab={initialTab} />
      <Card>
        <CardContent className="py-3">
          <Button render={<Link href="/cases" />} variant="outline" size="sm">
            Back to cases
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
