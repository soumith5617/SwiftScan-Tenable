import { createFileRoute, Link, useRouter, redirect } from "@tanstack/react-router";
import { ThemeToggle } from "@/components/theme-toggle";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { ShieldCheck, Mail, AlertCircle, RefreshCw, KeyRound, CheckCircle2 } from "lucide-react";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: "Sign in — AegisScan Vulnerability Platform" },
      {
        name: "description",
        content:
          "Sign in to AegisScan to run vulnerability scans, triage findings and track remediation SLAs across your attack surface.",
      },
      { property: "og:title", content: "Sign in — AegisScan" },
      { property: "og:description", content: "Access your vulnerability management workspace." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"signin" | "signup" | "forgot">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [unconfirmed, setUnconfirmed] = useState(false);
  const [resending, setResending] = useState(false);

  useEffect(() => {
    // Check existing session
    supabase.auth.getSession().then(({ data }) => {
      if (data.session?.user) {
        router.navigate({ to: "/dashboard", replace: true });
      }
    });

    // Subscribe to auth changes
    const { data: authListener } = supabase.auth.onAuthStateChange((event, session) => {
      if (session?.user) {
        router.navigate({ to: "/dashboard", replace: true });
      }
    });

    return () => {
      authListener.subscription.unsubscribe();
    };
  }, [router]);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setUnconfirmed(false);

    try {
      if (mode === "signup") {
        const { data, error } = await supabase.auth.signUp({
          email: email.trim(),
          password,
          options: {
            emailRedirectTo: `${window.location.origin}/dashboard`,
            data: { full_name: name.trim() },
          },
        });
        if (error) throw error;

        if (data.session) {
          toast.success("Account created! Redirecting to dashboard...");
          router.navigate({ to: "/dashboard", replace: true });
        } else {
          setUnconfirmed(true);
          toast.info("Account created! Please check your email inbox to confirm your account.");
        }
      } else if (mode === "signin") {
        const { data, error } = await supabase.auth.signInWithPassword({
          email: email.trim(),
          password,
        });
        if (error) {
          if (error.message.toLowerCase().includes("email not confirmed")) {
            setUnconfirmed(true);
            throw new Error(
              "Your email has not been confirmed yet. Please verify your email before logging in.",
            );
          }
          throw error;
        }

        if (data.session) {
          toast.success("Welcome back!");
          router.navigate({ to: "/dashboard", replace: true });
        }
      } else if (mode === "forgot") {
        const { error } = await supabase.auth.resetPasswordForEmail(email.trim(), {
          redirectTo: `${window.location.origin}/auth`,
        });
        if (error) throw error;
        toast.success("Password reset instructions sent to your email.");
        setMode("signin");
      }
    } catch (err: unknown) {
      console.error("Auth error:", err);
      toast.error(
        err instanceof Error
          ? err.message
          : "Authentication failed. Please check your credentials.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function resendConfirmation() {
    if (!email) {
      toast.error("Please enter your email address first.");
      return;
    }
    setResending(true);
    try {
      const { error } = await supabase.auth.resend({
        type: "signup",
        email: email.trim(),
        options: { emailRedirectTo: `${window.location.origin}/dashboard` },
      });
      if (error) throw error;
      toast.success("Confirmation link resent! Please check your email inbox.");
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Could not resend confirmation email.");
    } finally {
      setResending(false);
    }
  }

  async function google() {
    try {
      const { lovable } = await import("@/integrations/lovable/index");
      const result = await lovable.auth.signInWithOAuth("google", {
        redirect_uri: `${window.location.origin}/dashboard`,
      });
      if (result.error) {
        toast.error("Google sign-in failed");
        return;
      }
      if (result.redirected) return;
      router.navigate({ to: "/dashboard", replace: true });
    } catch (err: unknown) {
      toast.error(err instanceof Error ? err.message : "Google OAuth failed");
    }
  }

  return (
    <div className="relative grid min-h-screen lg:grid-cols-2">
      <ThemeToggle className="absolute right-4 top-4 z-10" />

      {/* LEFT BRANDING PANEL */}
      <div className="relative hidden flex-col justify-between border-r border-border bg-card p-10 lg:flex">
        <Link to="/" className="flex items-center gap-2 font-semibold">
          <ShieldCheck className="size-6 text-primary" />
          <span className="text-xl font-bold">AegisScan</span>
        </Link>
        <div className="space-y-4">
          <h2 className="text-3xl font-semibold tracking-tight">
            Enterprise Vulnerability Management
          </h2>
          <p className="text-sm text-muted-foreground leading-relaxed">
            Continuous attack surface discovery, real-time NVD/KEV/EPSS intelligence, multi-factor
            risk scoring and SLA remediation tracking in a unified console.
          </p>
        </div>
        <p className="text-xs text-muted-foreground">
          SOC2 Ready · RBAC Access Controls · Distributed Ingest API
        </p>
      </div>

      {/* RIGHT AUTH CARD */}
      <div className="flex items-center justify-center p-6">
        <Card className="w-full max-w-sm">
          <CardHeader>
            <CardTitle>
              {mode === "signin"
                ? "Sign in"
                : mode === "signup"
                  ? "Create your workspace"
                  : "Reset your password"}
            </CardTitle>
            <CardDescription>
              {mode === "signin"
                ? "Welcome back to your AegisScan console."
                : mode === "signup"
                  ? "Start vulnerability scanning in under a minute."
                  : "Enter your work email to receive a recovery link."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {mode !== "forgot" && (
              <>
                <Button variant="outline" className="w-full" onClick={google} type="button">
                  Continue with Google
                </Button>
                <div className="relative text-center text-xs text-muted-foreground">
                  <span className="bg-card px-2">or continue with email</span>
                  <div className="absolute inset-x-0 top-1/2 -z-10 h-px bg-border" />
                </div>
              </>
            )}

            {unconfirmed && (
              <div className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-xs space-y-2 text-foreground">
                <div className="flex items-center gap-1.5 font-semibold text-amber-500">
                  <Mail className="size-4" /> Email Confirmation Required
                </div>
                <p className="text-muted-foreground">
                  We sent a confirmation link to{" "}
                  <span className="font-mono font-medium">{email}</span>. Please check your inbox or
                  spam folder.
                </p>
                <Button
                  size="sm"
                  variant="outline"
                  className="w-full gap-1.5 text-xs"
                  onClick={resendConfirmation}
                  disabled={resending}
                >
                  <RefreshCw className={resending ? "size-3.5 animate-spin" : "size-3.5"} />
                  {resending ? "Resending..." : "Resend Confirmation Email"}
                </Button>
              </div>
            )}

            <form onSubmit={submit} className="space-y-3">
              {mode === "signup" && (
                <div className="space-y-1.5">
                  <Label htmlFor="name">Full Name</Label>
                  <Input
                    id="name"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Alex Chen"
                    required
                  />
                </div>
              )}
              <div className="space-y-1.5">
                <Label htmlFor="email">Work Email</Label>
                <Input
                  id="email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                />
              </div>
              {mode !== "forgot" && (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="password">Password</Label>
                    {mode === "signin" && (
                      <button
                        type="button"
                        onClick={() => setMode("forgot")}
                        className="text-xs text-primary hover:underline"
                      >
                        Forgot password?
                      </button>
                    )}
                  </div>
                  <Input
                    id="password"
                    type="password"
                    required
                    minLength={6}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                  />
                </div>
              )}

              <Button type="submit" className="w-full" disabled={busy}>
                {busy
                  ? "Working..."
                  : mode === "signin"
                    ? "Sign In"
                    : mode === "signup"
                      ? "Create Account"
                      : "Send Reset Link"}
              </Button>
            </form>

            <div className="space-y-1.5 pt-1 text-center text-xs text-muted-foreground">
              {mode === "signin" ? (
                <button
                  type="button"
                  className="hover:text-foreground hover:underline"
                  onClick={() => {
                    setMode("signup");
                    setUnconfirmed(false);
                  }}
                >
                  Don&apos;t have an account? Create one
                </button>
              ) : mode === "signup" ? (
                <button
                  type="button"
                  className="hover:text-foreground hover:underline"
                  onClick={() => {
                    setMode("signin");
                    setUnconfirmed(false);
                  }}
                >
                  Already have an account? Sign in
                </button>
              ) : (
                <button
                  type="button"
                  className="hover:text-foreground hover:underline"
                  onClick={() => {
                    setMode("signin");
                    setUnconfirmed(false);
                  }}
                >
                  Back to Sign In
                </button>
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

export { redirect };
