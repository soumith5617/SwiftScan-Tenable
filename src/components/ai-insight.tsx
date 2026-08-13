import { useMutation } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Sparkles, RefreshCw } from "lucide-react";
import { analyseFinding } from "@/lib/ai.functions";
import { toast } from "sonner";

import { sanitizeHtml } from "@/lib/sanitize";

const TABS = [
  { id: "remediation", label: "Remediation" },
  { id: "explain", label: "Plain language" },
  { id: "script", label: "Fix scripts" },
] as const;

type Kind = (typeof TABS)[number]["id"];

/** Renders lightweight markdown (headings, bold, lists, code fences) safely with DOMPurify sanitization. */
function Markdown({ text }: { text: string }) {
  const blocks = text.split(/```/);
  return (
    <div className="space-y-2 text-sm leading-relaxed">
      {blocks.map((block, i) =>
        i % 2 === 1 ? (
          <pre key={i} className="overflow-auto rounded-md bg-secondary/60 p-3 font-mono text-xs">
            {block.replace(/^\w+\n/, "")}
          </pre>
        ) : (
          block
            .split("\n")
            .filter((line) => line.trim())
            .map((line, j) => {
              const formatted = line
                .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
                .replace(/`(.+?)`/g, '<code class="font-mono text-xs">$1</code>');
              return (
                <p
                  key={`${i}-${j}`}
                  className={
                    line.trim().startsWith("-") || /^\d+\./.test(line.trim())
                      ? "pl-4 text-muted-foreground"
                      : ""
                  }
                  dangerouslySetInnerHTML={{
                    __html: sanitizeHtml(formatted),
                  }}
                />
              );
            })
        ),
      )}
    </div>
  );
}

export function AiInsight({ findingId }: { findingId: string }) {
  const analyse = useServerFn(analyseFinding);
  const [kind, setKind] = useState<Kind>("remediation");
  const [content, setContent] = useState<Record<string, string>>({});

  const mut = useMutation({
    mutationFn: (input: { kind: Kind; refresh: boolean }) =>
      analyse({ data: { findingId, kind: input.kind, refresh: input.refresh } }),
    onSuccess: (r, vars) => setContent((c) => ({ ...c, [vars.kind]: r.content })),
    onError: (e: Error) => toast.error(e.message),
  });

  return (
    <div className="rounded-md border border-border bg-secondary/30 p-3">
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Sparkles className="size-4 text-primary" />
        <span className="text-sm font-medium">AI analysis</span>
        <div className="ml-auto flex gap-1">
          {TABS.map((t) => (
            <Button
              key={t.id}
              size="sm"
              variant={kind === t.id ? "secondary" : "ghost"}
              onClick={() => {
                setKind(t.id);
                if (!content[t.id]) mut.mutate({ kind: t.id, refresh: false });
              }}
            >
              {t.label}
            </Button>
          ))}
          {content[kind] && (
            <Button
              size="sm"
              variant="ghost"
              disabled={mut.isPending}
              onClick={() => mut.mutate({ kind, refresh: true })}
            >
              <RefreshCw className="size-3.5" />
            </Button>
          )}
        </div>
      </div>

      {mut.isPending ? (
        <p className="text-sm text-muted-foreground">Interpreting the scanner evidence…</p>
      ) : content[kind] ? (
        <Markdown text={content[kind]!} />
      ) : (
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-muted-foreground">
            Generate remediation steps, an executive explanation or ready-to-run fix scripts from
            this finding&apos;s evidence.
          </p>
          <Button size="sm" onClick={() => mut.mutate({ kind, refresh: false })}>
            Analyse
          </Button>
        </div>
      )}
    </div>
  );
}
