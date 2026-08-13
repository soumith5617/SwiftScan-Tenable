/**
 * AegisScan Enterprise Core Domain Types
 */

export type AppRole = "owner" | "admin" | "analyst" | "viewer";

export type SeverityLevel = 0 | 1 | 2 | 3 | 4; // 0: Info, 1: Low, 2: Medium, 3: High, 4: Critical
export type FindingState = "open" | "fixed" | "accepted" | "false_positive";
export type AssetKind = "web" | "host" | "api" | "cloud" | "container";
export type AssetCriticality = "low" | "medium" | "high" | "critical";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type ReportFormat = "pdf" | "csv" | "json";
export type ReportKind = "executive" | "technical" | "asset" | "compliance";

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  role: AppRole;
  created_at: string;
}

export interface AssetGroup {
  id: string;
  user_id: string;
  name: string;
  description: string;
  color: string;
  dynamic_rule?: {
    tags?: string[];
    criticality?: AssetCriticality;
    kind?: AssetKind;
  };
  asset_count?: number;
  created_at: string;
  updated_at: string;
}

export interface HostPort {
  id: string;
  user_id: string;
  asset_id: string;
  port: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered";
  service_name?: string;
  product?: string;
  version?: string;
  cpe?: string;
  banner?: string;
  last_seen: string;
  created_at: string;
}

export interface RiskOverride {
  id: string;
  user_id: string;
  finding_id: string;
  original_severity: SeverityLevel;
  overridden_severity: SeverityLevel;
  reason: string;
  approved_by?: string;
  expires_at?: string;
  created_at: string;
}

export interface RiskHistoryPoint {
  id: string;
  user_id: string;
  asset_id?: string;
  risk_score: number;
  open_critical: number;
  open_high: number;
  open_medium: number;
  open_low: number;
  recorded_at: string;
}

export interface SavedFilter {
  id: string;
  user_id: string;
  name: string;
  entity_type: "findings" | "assets" | "scans" | "intel";
  query_params: Record<string, unknown>;
  is_default: boolean;
  is_shared: boolean;
  created_at: string;
}

export interface PluginRegistryItem {
  id: string;
  plugin_id: string;
  name: string;
  family: string;
  category: string;
  version: string;
  description: string;
  solution: string;
  default_severity: SeverityLevel;
  cve_ids: string[];
  cwe?: string;
  enabled: boolean;
  author: string;
  created_at: string;
}

export interface GeneratedReport {
  id: string;
  user_id: string;
  title: string;
  format: ReportFormat;
  kind: ReportKind;
  status: "generating" | "completed" | "failed";
  summary: Record<string, unknown>;
  download_url?: string;
  file_size_bytes?: number;
  created_at: string;
}

export interface OrganizationSettings {
  id: string;
  user_id: string;
  org_name: string;
  mfa_required: boolean;
  session_timeout_minutes: number;
  min_password_length: number;
  smtp_config: {
    host?: string;
    port?: number;
    username?: string;
    from_email?: string;
  };
  branding: {
    primary_color: string;
    logo_url?: string;
  };
  created_at: string;
  updated_at: string;
}

export interface RiskCalculationInput {
  cvssScore: number;
  epssScore?: number | null | undefined;
  isKev: boolean;
  assetCriticality: AssetCriticality;
  isInternetFacing: boolean;
  customSeverityOverride?: SeverityLevel | null | undefined;
}

export interface RiskCalculationResult {
  baseCvss: number;
  effectiveSeverity: SeverityLevel;
  adjustedPriority: number; // 0.0 - 100.0 score
  riskFactors: {
    epssMultiplier: number;
    kevBoost: number;
    criticalityWeight: number;
    exposureWeight: number;
  };
}
