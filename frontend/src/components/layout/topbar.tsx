"use client";

import { Menu } from "lucide-react";

import { BackendStatus } from "@/components/status/backend-status";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

type TopbarProps = {
  onMenuClick: () => void;
};

export function Topbar({ onMenuClick }: TopbarProps) {
  return (
    <header className="sticky top-0 z-20 flex h-14 shrink-0 items-center gap-2 border-b border-border/60 bg-background/95 px-4 backdrop-blur-sm md:px-6">
      <Button
        variant="ghost"
        size="icon"
        className="md:hidden"
        onClick={onMenuClick}
        aria-label="Open navigation"
      >
        <Menu className="size-4" aria-hidden />
      </Button>

      {/* Wordmark is visible only when the sidebar is hidden. */}
      <div className="flex items-baseline gap-2 md:hidden">
        <span className="shrink-0 whitespace-nowrap text-sm font-semibold tracking-tight">
          NS-Email
        </span>
        <span className="hidden text-[11px] text-muted-foreground min-[420px]:inline">
          SecureMailScope
        </span>
      </div>

      <div className="ml-auto flex items-center gap-2.5">
        <BackendStatus />
        <Badge
          variant="outline"
          className="hidden font-mono text-[11px] text-muted-foreground sm:inline-flex"
        >
          v0.1.0
        </Badge>
      </div>
    </header>
  );
}
