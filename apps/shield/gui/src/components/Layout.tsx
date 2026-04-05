import { useEffect, useRef, useState, type ReactNode } from "react";
import {
  Activity,
  ChevronDown,
  Clock,
  Database,
  FileSearch,
  FileText,
  FolderOpen,
  FolderTree,
  Globe,
  HardDrive,
  Hash,
  LayoutDashboard,
  LogOut,
  MessageSquare,
  Moon,
  ScrollText,
  Scissors,
  Search,
  Settings,
  Sun,
  UserCog,
  UserRound,
} from "lucide-react";
import { cn } from "@/lib/utils";
import brandLogo from "@/assets/vantor_icon_source_transparent.png";

export type ShellSection =
  | "dashboard"
  | "case-overview"
  | "evidence-sources"
  | "file-system"
  | "timeline"
  | "artifacts"
  | "registry"
  | "communications"
  | "browser-data"
  | "carved-files"
  | "hash-sets"
  | "reports"
  | "logs"
  | "settings";

type HeaderMenuId = "file" | "view" | "help" | "examiner" | null;

interface LayoutProps {
  caseName?: string | null;
  evidenceSource?: string | null;
  currentSection: ShellSection;
  onSectionChange: (section: ShellSection) => void;
  onOpenEvidence: () => void;
  searchQuery: string;
  onSearchQueryChange: (value: string) => void;
  taskCount: number;
  currentExaminer: string;
  theme: "light" | "dark";
  onToggleTheme: () => void;
  onOpenProfile: () => void;
  onOpenPreferences: () => void;
  onSignOut: () => void;
  children: ReactNode;
}

const NAV_ITEMS: Array<{
  id: ShellSection;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
  { id: "case-overview", label: "Case Overview", icon: FolderOpen },
  { id: "evidence-sources", label: "Evidence Sources", icon: HardDrive },
  { id: "file-system", label: "File System", icon: FolderTree },
  { id: "timeline", label: "Timeline", icon: Clock },
  { id: "artifacts", label: "Artifacts", icon: FileSearch },
  { id: "registry", label: "Registry", icon: Database },
  { id: "communications", label: "Communications", icon: MessageSquare },
  { id: "browser-data", label: "Browser Data", icon: Globe },
  { id: "carved-files", label: "Carved Files", icon: Scissors },
  { id: "hash-sets", label: "Hash Sets", icon: Hash },
  { id: "reports", label: "Reports", icon: FileText },
  { id: "logs", label: "Logs", icon: ScrollText },
  { id: "settings", label: "Settings", icon: Settings },
];

function SidebarNav({
  currentSection,
  onSectionChange,
}: {
  currentSection: ShellSection;
  onSectionChange: (section: ShellSection) => void;
}) {
  return (
    <nav className="fs-sidebar-nav" aria-label="Primary navigation">
      {NAV_ITEMS.map((item) => {
        const isActive = currentSection === item.id;
        return (
          <button
            key={item.id}
            type="button"
            className={cn("fs-nav-item", isActive && "is-active")}
            onClick={() => onSectionChange(item.id)}
          >
            <item.icon className="fs-nav-icon" />
            <span>{item.label}</span>
          </button>
        );
      })}
    </nav>
  );
}

function ClickMenu({
  id,
  label,
  openMenu,
  setOpenMenu,
  triggerClassName,
  menuClassName,
  children,
}: {
  id: Exclude<HeaderMenuId, null>;
  label: ReactNode;
  openMenu: HeaderMenuId;
  setOpenMenu: (next: HeaderMenuId) => void;
  triggerClassName?: string;
  menuClassName?: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement | null>(null);
  const isOpen = openMenu === id;

  useEffect(() => {
    if (!isOpen) return;
    const handlePointerDown = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        setOpenMenu(null);
      }
    };
    window.addEventListener("mousedown", handlePointerDown);
    return () => window.removeEventListener("mousedown", handlePointerDown);
  }, [isOpen, setOpenMenu]);

  return (
    <div className={cn("fs-header-menu", isOpen && "is-open", menuClassName)} ref={ref}>
      <button
        type="button"
        className={cn("fs-header-menu-trigger", triggerClassName, isOpen && "is-open")}
        onClick={() => setOpenMenu(isOpen ? null : id)}
      >
        {label}
      </button>
      {isOpen ? <div className="fs-header-menu-content">{children}</div> : null}
    </div>
  );
}

export default function Layout({
  caseName,
  evidenceSource,
  currentSection,
  onSectionChange,
  onOpenEvidence,
  searchQuery,
  onSearchQueryChange,
  taskCount,
  currentExaminer,
  theme,
  onToggleTheme,
  onOpenProfile,
  onOpenPreferences,
  onSignOut,
  children,
}: LayoutProps) {
  const [openMenu, setOpenMenu] = useState<HeaderMenuId>(null);
  const examinerInitial = currentExaminer.trim().slice(0, 1).toUpperCase() || "E";

  return (
    <div className="fs-shell">
      <aside className="fs-sidebar">
        <div className="fs-sidebar-brand">
          <img src={brandLogo} alt="Vantor Shield" className="fs-sidebar-brand-image" />
        </div>

        <SidebarNav currentSection={currentSection} onSectionChange={onSectionChange} />

        <div className="fs-sidebar-status">
          <div className="fs-sidebar-status-label">System Status</div>
          <div className="fs-sidebar-status-value">
            <span className="fs-status-pulse" />
            <span>Engine Ready</span>
          </div>
        </div>
      </aside>

      <div className="fs-main-shell">
        <header className="fs-topbar-shell">
          <div className="fs-topbar-left-cluster">
            <div className="fs-topbar-status">
              <span className="fs-status-pulse fs-status-pulse--header" />
              <span className="fs-topbar-case">{caseName || "No case loaded"}</span>
            </div>
            <div className="fs-topbar-divider" />
            <div className="fs-topbar-source">
              <HardDrive className="w-3 h-3" />
              <span>{evidenceSource || "No evidence source"}</span>
            </div>
          </div>

          <div className="fs-topbar-search-wrap">
            <Search className="fs-topbar-search-icon" />
            <input
              value={searchQuery}
              onChange={(event) => onSearchQueryChange(event.target.value)}
              className="fs-topbar-search"
              placeholder="Search artifacts, files, hashes..."
            />
          </div>

          <div className="fs-topbar-right-cluster">
            <ClickMenu
              id="file"
              label={
                <>
                  <span>File</span>
                  <ChevronDown className="w-3 h-3" />
                </>
              }
              openMenu={openMenu}
              setOpenMenu={setOpenMenu}
            >
              <button
                type="button"
                className="fs-header-menu-item"
                onClick={() => {
                  setOpenMenu(null);
                  onOpenEvidence();
                }}
              >
                <FolderOpen className="w-3.5 h-3.5" />
                <span>Add Evidence</span>
              </button>
            </ClickMenu>

            <ClickMenu
              id="view"
              label={
                <>
                  <span>View</span>
                  <ChevronDown className="w-3 h-3" />
                </>
              }
              openMenu={openMenu}
              setOpenMenu={setOpenMenu}
            >
              {NAV_ITEMS.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className="fs-header-menu-item"
                  onClick={() => {
                    setOpenMenu(null);
                    onSectionChange(item.id);
                  }}
                >
                  <item.icon className="w-3.5 h-3.5" />
                  <span>{item.label}</span>
                </button>
              ))}
            </ClickMenu>

            <ClickMenu
              id="help"
              label={
                <>
                  <span>Help</span>
                  <ChevronDown className="w-3 h-3" />
                </>
              }
              openMenu={openMenu}
              setOpenMenu={setOpenMenu}
            >
              <button type="button" className="fs-header-menu-item" onClick={() => setOpenMenu(null)}>
                <FileText className="w-3.5 h-3.5" />
                <span>Suite Guide</span>
              </button>
              <button type="button" className="fs-header-menu-item" onClick={() => setOpenMenu(null)}>
                <FileText className="w-3.5 h-3.5" />
                <span>License &amp; Version</span>
              </button>
            </ClickMenu>

            <div className="fs-activity-pill">
              <Activity className="w-3 h-3" />
              <span>{taskCount} tasks</span>
            </div>

            <button type="button" className="fs-icon-button" aria-label="Theme toggle" onClick={onToggleTheme}>
              {theme === "dark" ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>

            <ClickMenu
              id="examiner"
              openMenu={openMenu}
              setOpenMenu={setOpenMenu}
              triggerClassName="fs-user-button"
              menuClassName="fs-user-menu-wrap"
              label={
                <>
                  <span className="fs-user-avatar">{examinerInitial}</span>
                  <span>{currentExaminer}</span>
                  <ChevronDown className="w-3 h-3" />
                </>
              }
            >
              <button
                type="button"
                className="fs-header-menu-item"
                onClick={() => {
                  setOpenMenu(null);
                  onOpenProfile();
                }}
              >
                <UserRound className="w-3.5 h-3.5" />
                <span>Profile</span>
              </button>
              <button
                type="button"
                className="fs-header-menu-item"
                onClick={() => {
                  setOpenMenu(null);
                  onOpenPreferences();
                }}
              >
                <UserCog className="w-3.5 h-3.5" />
                <span>Preferences</span>
              </button>
              <button
                type="button"
                className="fs-header-menu-item"
                onClick={() => {
                  setOpenMenu(null);
                  onSignOut();
                }}
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign out</span>
              </button>
            </ClickMenu>
          </div>
        </header>

        <main className="fs-page-shell">{children}</main>
      </div>
    </div>
  );
}
