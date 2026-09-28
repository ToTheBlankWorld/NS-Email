import {
  FileArchive,
  FileText,
  FolderOpen,
  LayoutDashboard,
  Network,
  ShieldAlert,
  ShieldQuestion,
  Waypoints,
  type LucideIcon,
} from "lucide-react";

export type NavItem = {
  label: string;
  href: string;
  icon: LucideIcon;
  /**
   * Modules whose stages are not implemented yet are rendered as
   * disabled entries — the shell must not pretend routes exist.
   */
  available: boolean;
};

export type NavSection = {
  label: string;
  items: NavItem[];
};

export const NAV_SECTIONS: NavSection[] = [
  {
    label: "Analysis",
    items: [
      { label: "Dashboard", href: "/", icon: LayoutDashboard, available: true },
      { label: "Captures", href: "/captures", icon: FileArchive, available: true },
      { label: "Sessions", href: "/sessions", icon: Waypoints, available: true },
      { label: "Findings", href: "/findings", icon: ShieldAlert, available: true },
      { label: "Anomalies", href: "/anomalies", icon: ShieldQuestion, available: true },
      { label: "Evidence Graph", href: "/graph", icon: Network, available: true },
      { label: "Reports", href: "/reports", icon: FileText, available: true },
      { label: "Cases", href: "/cases", icon: FolderOpen, available: true },
    ],
  },
];
