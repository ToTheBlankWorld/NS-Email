"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldCheck } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { NAV_SECTIONS } from "@/lib/nav";
import { cn } from "@/lib/utils";

type SidebarProps = {
  /** Called after a navigation action; used to close the mobile overlay. */
  onNavigate?: () => void;
  className?: string;
};

const navRowClasses =
  "flex w-full items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors outline-none focus-visible:ring-2 focus-visible:ring-ring/60";

export function Sidebar({ onNavigate, className }: SidebarProps) {
  const pathname = usePathname();

  return (
    <aside
      className={cn("flex h-full flex-col bg-sidebar text-sidebar-foreground", className)}
    >
      <div className="flex h-14 shrink-0 items-center gap-2.5 border-b border-sidebar-border px-4">
        <div className="flex size-7 items-center justify-center rounded-md bg-primary/15 text-primary">
          <ShieldCheck className="size-4" aria-hidden />
        </div>
        <div className="min-w-0 leading-tight">
          <p className="truncate text-sm font-semibold tracking-tight">NS-Email</p>
          <p className="truncate text-[11px] text-muted-foreground">SecureMailScope</p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-4" aria-label="Primary">
        {NAV_SECTIONS.map((section) => (
          <div key={section.label} className="mb-5 last:mb-0">
            <p className="px-2 pb-1.5 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
              {section.label}
            </p>
            <ul className="space-y-0.5">
              {section.items.map((item) => {
                const Icon = item.icon;
                if (item.available) {
                  const active = pathname === item.href;
                  return (
                    <li key={item.href}>
                      <Link
                        href={item.href}
                        onClick={onNavigate}
                        aria-current={active ? "page" : undefined}
                        className={cn(
                          navRowClasses,
                          "hover:bg-sidebar-accent hover:text-sidebar-accent-foreground",
                          active &&
                            "bg-sidebar-accent font-medium text-sidebar-accent-foreground",
                        )}
                      >
                        <Icon className="size-4 shrink-0" aria-hidden />
                        <span className="truncate">{item.label}</span>
                      </Link>
                    </li>
                  );
                }
                return (
                  <li key={item.href}>
                    <Tooltip>
                      <TooltipTrigger
                        aria-disabled="true"
                        onClick={(event) => event.preventDefault()}
                        className={cn(
                          navRowClasses,
                          "cursor-not-allowed text-muted-foreground/70 hover:bg-transparent",
                        )}
                      >
                        <Icon className="size-4 shrink-0" aria-hidden />
                        <span className="truncate">{item.label}</span>
                        <Badge
                          variant="outline"
                          className="ml-auto border-border/60 px-1.5 text-[10px] font-normal text-muted-foreground"
                        >
                          Soon
                        </Badge>
                      </TooltipTrigger>
                      <TooltipContent side="right">
                        Arrives in a later stage
                      </TooltipContent>
                    </Tooltip>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>

      <div className="shrink-0 border-t border-sidebar-border px-4 py-3">
        <p className="font-mono text-[11px] text-muted-foreground">
          v0.5.0 · Stage 5 posture
        </p>
      </div>
    </aside>
  );
}
