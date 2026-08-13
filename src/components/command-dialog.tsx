import { useEffect, useState } from "react";
import { useRouter } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { globalSearch } from "@/lib/enterprise.functions";
import {
  CommandDialog as CmdDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import { SeverityBadge } from "@/components/soc";
import { Badge } from "@/components/ui/badge";
import { Server, Bug, Radar, Flame, ArrowRight } from "lucide-react";

export function GlobalCommandDialog() {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const router = useRouter();

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  const { data } = useQuery({
    queryKey: ["global-search", search],
    queryFn: () => globalSearch({ data: { query: search } }),
    enabled: search.trim().length >= 2,
  });

  const findings = data?.findings ?? [];
  const assets = data?.assets ?? [];
  const scans = data?.scans ?? [];

  return (
    <CmdDialog open={open} onOpenChange={setOpen}>
      <CommandInput
        placeholder="Search findings, assets, CVEs, scans... (or press ESC to close)"
        value={search}
        onValueChange={setSearch}
      />
      <CommandList>
        <CommandEmpty>No results found for &quot;{search}&quot;</CommandEmpty>

        {findings.length > 0 && (
          <CommandGroup heading="Vulnerability Findings">
            {findings.map((f) => (
              <CommandItem
                key={f.id}
                onSelect={() => {
                  setOpen(false);
                  router.navigate({ to: "/findings" });
                }}
                className="flex items-center gap-2 cursor-pointer"
              >
                <SeverityBadge severity={f.severity} />
                <span className="flex-1 truncate font-medium">{f.title}</span>
                {Array.isArray(f.cve_ids) && f.cve_ids.length > 0 && (
                  <span className="font-mono text-xs text-muted-foreground">{f.cve_ids[0]}</span>
                )}
                <span className="font-mono text-xs font-bold">
                  P {Number(f.priority ?? 0).toFixed(1)}
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}

        {assets.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Assets & Targets">
              {assets.map((a) => (
                <CommandItem
                  key={a.id}
                  onSelect={() => {
                    setOpen(false);
                    router.navigate({ to: "/assets" });
                  }}
                  className="flex items-center gap-2 cursor-pointer"
                >
                  <Server className="size-4 text-primary" />
                  <span className="font-medium">{a.name}</span>
                  <span className="font-mono text-xs text-muted-foreground">{a.target}</span>
                  <Badge variant="outline" className="ml-auto text-[10px] capitalize">
                    {a.criticality}
                  </Badge>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        {scans.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Scans">
              {scans.map((s) => (
                <CommandItem
                  key={s.id}
                  onSelect={() => {
                    setOpen(false);
                    router.navigate({ to: "/scans/$scanId", params: { scanId: s.id } });
                  }}
                  className="flex items-center gap-2 cursor-pointer"
                >
                  <Radar className="size-4 text-orange-500" />
                  <span className="font-medium">{s.name}</span>
                  <span className="font-mono text-xs text-muted-foreground">{s.target}</span>
                  <Badge variant="outline" className="ml-auto text-[10px] capitalize">
                    {s.status}
                  </Badge>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        <CommandSeparator />
        <CommandGroup heading="Quick Navigation">
          <CommandItem
            onSelect={() => {
              setOpen(false);
              router.navigate({ to: "/dashboard" });
            }}
          >
            Dashboard
          </CommandItem>
          <CommandItem
            onSelect={() => {
              setOpen(false);
              router.navigate({ to: "/scans" });
            }}
          >
            Scans Console
          </CommandItem>
          <CommandItem
            onSelect={() => {
              setOpen(false);
              router.navigate({ to: "/reports" });
            }}
          >
            Security Reports
          </CommandItem>
          <CommandItem
            onSelect={() => {
              setOpen(false);
              router.navigate({ to: "/intel" });
            }}
          >
            Vulnerability Intelligence (NVD / KEV / EPSS)
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CmdDialog>
  );
}
