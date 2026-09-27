import {
  FileArchive,
  FileText,
  KeyRound,
  LayoutDashboard,
  Settings,
  ShieldAlert,
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
      { label: "Sessions", href: "/sessions", icon: Waypoints, available: false },
      { label: "TLS & Certificates", href: "/certificates", icon: KeyRound, available: false },
      { label: "Findings", href: "/findings", icon: ShieldAlert, available: false },
      { label: "Reports", href: "/reports", icon: FileText, available: false },
    ],
  },
  {
    label: "System",
    items: [
      { label: "Settings", href: "/settings", icon: Settings, available: false },
    ],
  },
];
