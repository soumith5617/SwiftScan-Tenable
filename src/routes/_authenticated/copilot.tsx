import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useRef, useState } from "react";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import ReactMarkdown from "react-markdown";
import { supabase } from "@/integrations/supabase/client";
import { PageHeader } from "@/components/soc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Bot, Send, Sparkles, Wrench, Square } from "lucide-react";

export const Route = createFileRoute("/_authenticated/copilot")({
  head: () => ({
    meta: [
      { title: "AI Security Copilot — AegisScan" },
      {
        name: "description",
        content:
          "Ask your vulnerability data questions in plain language: exploitable findings, internet-facing assets, remediation plans and scan comparisons.",
      },
      { property: "og:title", content: "AI Security Copilot — AegisScan" },
      {
        property: "og:description",
        content: "Conversational analysis over your own scan results.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: CopilotPage,
});

const SUGGESTIONS = [
  "List exploitable vulnerabilities (KEV or high EPSS).",
  "Show all internet-facing assets and their risk.",
  "Generate a 30-day remediation plan.",
  "Compare my last two scans.",
  "Why is my highest-priority finding critical?",
  "Map the attack paths to my crown jewels.",
];

function CopilotPage() {
  const [input, setInput] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => setToken(data.session?.access_token ?? null));
  }, []);

  const transport = useMemo(
    () =>
      new DefaultChatTransport({
        api: "/api/chat",
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      }),
    [token],
  );

  const { messages, sendMessage, status, stop, error } = useChat({ transport });

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const busy = status === "submitted" || status === "streaming";

  const send = (text: string) => {
    if (!text.trim() || !token) return;
    sendMessage({ text });
    setInput("");
  };

  return (
    <div className="flex h-[calc(100vh-7rem)] flex-col">
      <PageHeader
        title="Security copilot"
        description="Grounded in your own findings, assets and scan history — every answer comes from a tool call, not a guess."
      />

      <div className="mt-4 flex-1 overflow-y-auto rounded-lg border border-border bg-card/40 p-4">
        {messages.length === 0 && (
          <div className="mx-auto max-w-2xl py-10 text-center">
            <Bot className="mx-auto mb-3 size-10 text-primary" />
            <h2 className="text-base font-semibold">Ask about your environment</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              The copilot queries findings, assets, scan diffs and the attack graph, and can open
              tickets through your integrations.
            </p>
            <div className="mt-5 grid gap-2 sm:grid-cols-2">
              {SUGGESTIONS.map((s) => (
                <button
                  key={s}
                  onClick={() => send(s)}
                  className="rounded-md border border-border bg-background px-3 py-2 text-left text-xs hover:border-primary hover:bg-accent"
                >
                  <Sparkles className="mr-1.5 inline size-3 text-primary" />
                  {s}
                </button>
              ))}
            </div>
          </div>
        )}

        <div className="mx-auto max-w-3xl space-y-4">
          {messages.map((m) => (
            <div key={m.id} className={m.role === "user" ? "flex justify-end" : ""}>
              <div
                className={
                  m.role === "user"
                    ? "max-w-[85%] rounded-lg bg-primary px-3 py-2 text-sm text-primary-foreground"
                    : "w-full space-y-2"
                }
              >
                {m.parts.map((part, i) => {
                  if (part.type === "text")
                    return m.role === "user" ? (
                      <span key={i}>{part.text}</span>
                    ) : (
                      <div key={i} className="md-body">
                        <ReactMarkdown>{part.text}</ReactMarkdown>
                      </div>
                    );
                  if (part.type.startsWith("tool-"))
                    return (
                      <Badge key={i} variant="outline" className="gap-1 font-mono text-[10px]">
                        <Wrench className="size-3" />
                        {part.type.replace("tool-", "")}
                      </Badge>
                    );
                  return null;
                })}
              </div>
            </div>
          ))}
          {busy && <p className="text-xs text-muted-foreground">Querying your scan data…</p>}
          {error && (
            <Card className="border-destructive/40">
              <CardContent className="py-3 text-sm text-destructive">{error.message}</CardContent>
            </Card>
          )}
          <div ref={endRef} />
        </div>
      </div>

      <form
        className="mt-3 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          send(input);
        }}
      >
        <Input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={
            token ? "Ask about findings, assets, exposure or remediation…" : "Loading session…"
          }
          disabled={!token}
        />
        {busy ? (
          <Button type="button" variant="outline" onClick={() => stop()}>
            <Square className="size-4" /> Stop
          </Button>
        ) : (
          <Button type="submit" disabled={!input.trim() || !token}>
            <Send className="size-4" /> Send
          </Button>
        )}
      </form>
    </div>
  );
}
