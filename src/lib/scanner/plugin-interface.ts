import { RawFinding, ProbeResult } from "../scan-engine.server";

export interface PluginMetadata {
  id: string;
  name: string;
  family: string; // e.g. 'tls', 'headers', 'cors', 'ports', 'disclosure'
  category: "vulnerability" | "configuration" | "discovery" | "compliance";
  version: string;
  description: string;
  solution: string;
  defaultSeverity: number;
  cveIds?: string[];
  cwe?: string;
  references?: { title: string; url: string }[];
}

export interface ScanContext {
  targetUrl: URL;
  rootProbe: ProbeResult | null;
  technologies: Array<{ name: string; version?: string; source: string }>;
  httpsSupported: boolean;
  probes: Map<string, ProbeResult>;
}

export interface ScanPlugin {
  metadata: PluginMetadata;

  /**
   * Called before execution to verify if target is compatible (e.g. requires HTTPS or specific headers)
   */
  isApplicable(ctx: ScanContext): boolean | Promise<boolean>;

  /**
   * Executes the vulnerability probe logic and returns raw findings
   */
  execute(ctx: ScanContext): Promise<RawFinding[]>;
}
