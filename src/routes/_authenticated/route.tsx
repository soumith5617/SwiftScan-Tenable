import {
  createFileRoute,
  Outlet,
  redirect,
  Link,
  useRouter,
  useLocation,
} from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import {
  ShieldCheck,
  LayoutDashboard,
  Radar,
  Bug,
  Server,
  Database,
  Upload,
  ListChecks,
  ClipboardCheck,
  Timer,
  Plug,
  Code2,
  Bot,
  Network,
  LogOut,
  Menu,
  FileText,
  Settings,
  Search,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { ThemeToggle } from "@/components/theme-toggle";
import { GlobalCommandDialog } from "@/components/command-dialog";

export const Route = createFileRoute("/_authenticated")({
  ssr: false,
  beforeLoad: async () => {
    const { data: sessionData } = await supabase.auth.getSession();
    if (sessionData.session?.user) {
      return { user: sessionData.session.user };
    }
    const { data, error } = await supabase.auth.getUser();
    if (error || !data?.user) throw redirect({ to: "/auth" });
    return { user: data.user };
  },
  component: Shell,
});

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/copilot", label: "Copilot", icon: Bot },
  { to: "/templates", label: "Templates", icon: ListChecks },
  { to: "/scans", label: "Scans", icon: Radar },
  { to: "/findings", label: "Findings", icon: Bug },
  { to: "/assets", label: "Assets", icon: Server },
  { to: "/attack-graph", label: "Attack graph", icon: Network },
  { to: "/compliance", label: "Compliance", icon: ClipboardCheck },
  { to: "/monitoring", label: "Monitoring", icon: Timer },
  { to: "/intel", label: "Intelligence", icon: Database },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/integrations", label: "Integrations", icon: Plug },
  { to: "/api-docs", label: "API", icon: Code2 },
  { to: "/import", label: "Import", icon: Upload },
  { to: "/settings", label: "Settings", icon: Settings },
] as const;

function Shell() {
  const router = useRouter();
  const location = useLocation();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => setEmail(data.user?.email ?? null));
  }, []);

  async function signOut() {
    await queryClient.cancelQueries();
    queryClient.clear();
    await supabase.auth.signOut();
    router.navigate({ to: "/auth", replace: true });
  }

  return (
    <div className="flex min-h-screen bg-background">
      <GlobalCommandDialog />

      {/* SIDEBAR */}
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 flex w-60 flex-col border-r border-border bg-card transition-transform lg:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-14 items-center justify-between border-b border-border px-4 font-semibold">
          <Link to="/dashboard" className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-primary" />
            <span>AegisScan</span>
          </Link>
          <span className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-bold text-primary">
            v2.4
          </span>
        </div>

        {/* Global Search Shortcut Button */}
        <div className="p-3 pb-1">
          <button
            type="button"
            onClick={() => {
              const event = new KeyboardEvent("keydown", {
                key: "k",
                ctrlKey: true,
                metaKey: true,
              });
              document.dispatchEvent(event);
            }}
            className="flex w-full items-center justify-between rounded-md border border-border bg-muted/40 px-2.5 py-1.5 text-xs text-muted-foreground transition-colors hover:bg-muted hover:text-foreground"
          >
            <div className="flex items-center gap-2">
              <Search className="size-3.5" />
              <span>Search...</span>
            </div>
            <kbd className="rounded bg-background px-1.5 py-0.5 font-mono text-[10px] font-semibold">
              ⌘K
            </kbd>
          </button>
        </div>

        <nav className="flex-1 space-y-0.5 overflow-y-auto p-3">
          {NAV.map((item) => {
            const active = location.pathname.startsWith(item.to);
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setOpen(false)}
                className={cn(
                  "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm transition-colors",
                  active
                    ? "bg-primary/12 font-medium text-primary"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                )}
              >
                <item.icon className="size-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="border-t border-border p-3">
          <div className="flex items-center justify-between gap-2 px-2 pb-2">
            <p className="truncate text-xs text-muted-foreground">{email}</p>
            <ThemeToggle />
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start gap-2"
            onClick={signOut}
          >
            <LogOut className="size-4" /> Sign out
          </Button>
        </div>
      </aside>

      {/* MAIN VIEW */}
      <div className="flex min-w-0 flex-1 flex-col lg:pl-60">
        <header className="flex h-14 items-center gap-3 border-b border-border px-4 lg:hidden">
          <Button variant="ghost" size="icon" onClick={() => setOpen((v) => !v)}>
            <Menu className="size-5" />
          </Button>
          <span className="font-semibold">AegisScan</span>
          <ThemeToggle className="ml-auto" />
        </header>
        <main className="min-w-0 flex-1 p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
