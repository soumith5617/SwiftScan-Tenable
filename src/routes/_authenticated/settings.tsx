import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getOrgSettings, updateOrgSettings } from "@/lib/enterprise.functions";
import { PageHeader } from "@/components/soc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, Building, KeyRound, Mail, Palette, Save, CheckCircle2, Lock } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/_authenticated/settings")({
  head: () => ({
    meta: [
      { title: "Organization Settings & Security Policy — AegisScan" },
      {
        name: "description",
        content:
          "Configure enterprise security policies, mandatory MFA, session idle timeout, SMTP notifications, branding and RBAC access controls.",
      },
      { property: "og:title", content: "Settings — AegisScan" },
      { property: "og:description", content: "Organization and security policy configuration." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: SettingsPage,
});

interface SmtpConfig {
  host?: string;
  port?: number;
  username?: string;
  from_email?: string;
}

interface BrandingConfig {
  primary_color?: string;
  logo_url?: string;
}

function SettingsPage() {
  const qc = useQueryClient();
  const { data: settings, isLoading } = useQuery({
    queryKey: ["org-settings"],
    queryFn: () => getOrgSettings(),
  });

  const [form, setForm] = useState({
    org_name: "Aegis Enterprise",
    mfa_required: false,
    session_timeout_minutes: 60,
    min_password_length: 12,
    smtp_config: { host: "", port: 587, username: "", from_email: "" } as SmtpConfig,
    branding: { primary_color: "#0f172a", logo_url: "" } as BrandingConfig,
  });

  useEffect(() => {
    if (settings) {
      setForm({
        org_name: settings.org_name || "Aegis Enterprise",
        mfa_required: Boolean(settings.mfa_required),
        session_timeout_minutes: settings.session_timeout_minutes || 60,
        min_password_length: settings.min_password_length || 12,
        smtp_config: (settings.smtp_config as SmtpConfig) || {},
        branding: (settings.branding as BrandingConfig) || {
          primary_color: "#0f172a",
          logo_url: "",
        },
      });
    }
  }, [settings]);

  const save = useMutation({
    mutationFn: () => updateOrgSettings({ data: form }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["org-settings"] });
      toast.success("Security policies & organization settings saved");
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Could not save settings"),
  });

  return (
    <div className="space-y-6">
      <PageHeader
        title="Organization &amp; Security Settings"
        description="Manage workspace identity, mandatory multi-factor authentication, session expiration policies and notification channels."
      >
        <Button
          size="sm"
          className="gap-1.5"
          disabled={save.isPending || isLoading}
          onClick={() => save.mutate()}
        >
          <Save className="size-4" />
          {save.isPending ? "Saving..." : "Save Changes"}
        </Button>
      </PageHeader>

      <Tabs defaultValue="security" className="space-y-4">
        <TabsList className="grid w-full grid-cols-4 sm:w-auto">
          <TabsTrigger value="security" className="gap-2">
            <Shield className="size-4" /> Security Policies
          </TabsTrigger>
          <TabsTrigger value="organization" className="gap-2">
            <Building className="size-4" /> Organization
          </TabsTrigger>
          <TabsTrigger value="notifications" className="gap-2">
            <Mail className="size-4" /> SMTP &amp; Alerts
          </TabsTrigger>
          <TabsTrigger value="branding" className="gap-2">
            <Palette className="size-4" /> Branding
          </TabsTrigger>
        </TabsList>

        {/* 1. SECURITY POLICIES */}
        <TabsContent value="security" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-semibold">
                Access &amp; Authentication Controls
              </CardTitle>
              <CardDescription className="text-xs">
                Configure organization-wide security boundaries
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between rounded-lg border border-border p-4">
                <div className="space-y-0.5">
                  <Label className="text-sm font-semibold">
                    Mandatory Multi-Factor Authentication (MFA)
                  </Label>
                  <p className="text-xs text-muted-foreground">
                    Require TOTP authenticator app or WebAuthn hardware key for all workspace
                    members.
                  </p>
                </div>
                <Switch
                  checked={form.mfa_required}
                  onCheckedChange={(v) => setForm({ ...form, mfa_required: v })}
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label>Session Idle Timeout (Minutes)</Label>
                  <Input
                    type="number"
                    min={5}
                    max={1440}
                    value={form.session_timeout_minutes}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        session_timeout_minutes: parseInt(e.target.value, 10) || 60,
                      })
                    }
                  />
                  <p className="text-[11px] text-muted-foreground">
                    Automatic logout after inactivity period
                  </p>
                </div>

                <div className="space-y-1.5">
                  <Label>Minimum Password Length</Label>
                  <Input
                    type="number"
                    min={8}
                    max={64}
                    value={form.min_password_length}
                    onChange={(e) =>
                      setForm({ ...form, min_password_length: parseInt(e.target.value, 10) || 12 })
                    }
                  />
                  <p className="text-[11px] text-muted-foreground">
                    NIST SP 800-63B recommends minimum 12 characters
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 2. ORGANIZATION */}
        <TabsContent value="organization" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-semibold">Workspace Profile</CardTitle>
              <CardDescription className="text-xs">
                Identity information displayed on reports and alerts
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label>Organization Name</Label>
                <Input
                  value={form.org_name}
                  onChange={(e) => setForm({ ...form, org_name: e.target.value })}
                  placeholder="e.g. Acme Cyber Defense SOC"
                />
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 3. SMTP & ALERTS */}
        <TabsContent value="notifications" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-semibold">SMTP Mail Relay</CardTitle>
              <CardDescription className="text-xs">
                Configure outgoing mail for scan completion alerts and SLA breach notices
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label>SMTP Host</Label>
                  <Input
                    value={form.smtp_config?.host || ""}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        smtp_config: { ...form.smtp_config, host: e.target.value },
                      })
                    }
                    placeholder="smtp.sendgrid.net"
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>SMTP Port</Label>
                  <Input
                    type="number"
                    value={form.smtp_config?.port || 587}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        smtp_config: {
                          ...form.smtp_config,
                          port: parseInt(e.target.value, 10) || 587,
                        },
                      })
                    }
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Sender Address (From)</Label>
                  <Input
                    value={form.smtp_config?.from_email || ""}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        smtp_config: { ...form.smtp_config, from_email: e.target.value },
                      })
                    }
                    placeholder="security-alerts@yourcompany.com"
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* 4. BRANDING */}
        <TabsContent value="branding" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base font-semibold">
                Console &amp; Report Branding
              </CardTitle>
              <CardDescription className="text-xs">
                Customize the appearance of reports generated for stakeholders
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label>Primary Theme Color</Label>
                <div className="flex items-center gap-2">
                  <input
                    type="color"
                    value={form.branding?.primary_color || "#0f172a"}
                    onChange={(e) =>
                      setForm({
                        ...form,
                        branding: { ...form.branding, primary_color: e.target.value },
                      })
                    }
                    className="size-9 cursor-pointer rounded border border-border bg-transparent p-0.5"
                  />
                  <span className="font-mono text-xs text-muted-foreground">
                    {form.branding?.primary_color || "#0f172a"}
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
