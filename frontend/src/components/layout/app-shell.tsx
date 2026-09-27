"use client";

import { useEffect, useState, type ReactNode } from "react";

import { Sidebar } from "@/components/layout/sidebar";
import { Topbar } from "@/components/layout/topbar";
import { BackendHealthProvider } from "@/lib/backend-health";

/**
 * Application shell: persistent sidebar (fixed on desktop, overlay on
 * mobile), top bar with live backend status, and the routed content area.
 */
export function AppShell({ children }: { children: ReactNode }) {
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    if (!navOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setNavOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [navOpen]);

  return (
    <BackendHealthProvider>
      <div className="flex min-h-dvh">
        <Sidebar className="fixed inset-y-0 left-0 z-30 hidden w-60 border-r border-sidebar-border md:flex" />

        {navOpen ? (
          <div
            className="fixed inset-0 z-40 md:hidden"
            role="dialog"
            aria-modal="true"
            aria-label="Navigation"
          >
            <div
              className="absolute inset-0 bg-black/60"
              onClick={() => setNavOpen(false)}
              aria-hidden
            />
            <Sidebar
              onNavigate={() => setNavOpen(false)}
              className="absolute inset-y-0 left-0 w-64 border-r border-sidebar-border shadow-xl"
            />
          </div>
        ) : null}

        <div className="flex min-w-0 flex-1 flex-col md:ml-60">
          <Topbar onMenuClick={() => setNavOpen(true)} />
          <main className="flex-1">{children}</main>
        </div>
      </div>
    </BackendHealthProvider>
  );
}
