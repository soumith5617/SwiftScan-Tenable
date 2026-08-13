export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[];

export type Database = {
  // Allows to automatically instantiate createClient with right options
  // instead of createClient<Database, { PostgrestVersion: 'XX' }>(URL, KEY)
  __InternalSupabase: {
    PostgrestVersion: "14.15";
  };
  public: {
    Tables: {
      ai_insights: {
        Row: {
          content: string;
          created_at: string;
          finding_id: string | null;
          id: string;
          kind: string;
          model: string;
          user_id: string;
        };
        Insert: {
          content: string;
          created_at?: string;
          finding_id?: string | null;
          id?: string;
          kind?: string;
          model?: string;
          user_id: string;
        };
        Update: {
          content?: string;
          created_at?: string;
          finding_id?: string | null;
          id?: string;
          kind?: string;
          model?: string;
          user_id?: string;
        };
        Relationships: [];
      };
      api_keys: {
        Row: {
          created_at: string;
          id: string;
          key_hash: string;
          last_used_at: string | null;
          name: string;
          prefix: string;
          user_id: string;
        };
        Insert: {
          created_at?: string;
          id?: string;
          key_hash: string;
          last_used_at?: string | null;
          name: string;
          prefix: string;
          user_id: string;
        };
        Update: {
          created_at?: string;
          id?: string;
          key_hash?: string;
          last_used_at?: string | null;
          name?: string;
          prefix?: string;
          user_id?: string;
        };
        Relationships: [];
      };
      asset_changes: {
        Row: {
          after_value: Json;
          asset_id: string | null;
          before_value: Json;
          created_at: string;
          id: string;
          kind: string;
          scan_id: string | null;
          summary: string;
          user_id: string;
        };
        Insert: {
          after_value?: Json;
          asset_id?: string | null;
          before_value?: Json;
          created_at?: string;
          id?: string;
          kind: string;
          scan_id?: string | null;
          summary: string;
          user_id: string;
        };
        Update: {
          after_value?: Json;
          asset_id?: string | null;
          before_value?: Json;
          created_at?: string;
          id?: string;
          kind?: string;
          scan_id?: string | null;
          summary?: string;
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "asset_changes_asset_id_fkey";
            columns: ["asset_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id"];
          },
        ];
      };
      assets: {
        Row: {
          created_at: string;
          criticality: string;
          first_seen: string;
          id: string;
          internet_facing: boolean;
          kind: string;
          last_seen: string | null;
          name: string;
          os: string | null;
          risk_score: number;
          tags: string[];
          target: string;
          technologies: Json;
          user_id: string;
        };
        Insert: {
          created_at?: string;
          criticality?: string;
          first_seen?: string;
          id?: string;
          internet_facing?: boolean;
          kind?: string;
          last_seen?: string | null;
          name: string;
          os?: string | null;
          risk_score?: number;
          tags?: string[];
          target: string;
          technologies?: Json;
          user_id: string;
        };
        Update: {
          created_at?: string;
          criticality?: string;
          first_seen?: string;
          id?: string;
          internet_facing?: boolean;
          kind?: string;
          last_seen?: string | null;
          name?: string;
          os?: string | null;
          risk_score?: number;
          tags?: string[];
          target?: string;
          technologies?: Json;
          user_id?: string;
        };
        Relationships: [];
      };
      audit_log: {
        Row: {
          action: string;
          created_at: string;
          detail: Json;
          entity: string | null;
          entity_id: string | null;
          id: string;
          user_id: string;
        };
        Insert: {
          action: string;
          created_at?: string;
          detail?: Json;
          entity?: string | null;
          entity_id?: string | null;
          id?: string;
          user_id: string;
        };
        Update: {
          action?: string;
          created_at?: string;
          detail?: Json;
          entity?: string | null;
          entity_id?: string | null;
          id?: string;
          user_id?: string;
        };
        Relationships: [];
      };
      cve_cache: {
        Row: {
          cve_id: string;
          cvss: number | null;
          cvss_vector: string | null;
          cwe: string | null;
          description: string | null;
          epss: number | null;
          kev: boolean;
          kev_due_date: string | null;
          product: string | null;
          published: string | null;
          refs: Json;
          severity: number;
          synced_at: string;
          vendor: string | null;
        };
        Insert: {
          cve_id: string;
          cvss?: number | null;
          cvss_vector?: string | null;
          cwe?: string | null;
          description?: string | null;
          epss?: number | null;
          kev?: boolean;
          kev_due_date?: string | null;
          product?: string | null;
          published?: string | null;
          refs?: Json;
          severity?: number;
          synced_at?: string;
          vendor?: string | null;
        };
        Update: {
          cve_id?: string;
          cvss?: number | null;
          cvss_vector?: string | null;
          cwe?: string | null;
          description?: string | null;
          epss?: number | null;
          kev?: boolean;
          kev_due_date?: string | null;
          product?: string | null;
          published?: string | null;
          refs?: Json;
          severity?: number;
          synced_at?: string;
          vendor?: string | null;
        };
        Relationships: [];
      };
      findings: {
        Row: {
          asset_id: string | null;
          assigned_to: string | null;
          attack_tactics: string[];
          confidence: string;
          created_at: string;
          cve_ids: string[];
          cvss: number | null;
          cvss_vector: string | null;
          cwe: string | null;
          description: string | null;
          due_at: string | null;
          epss: number | null;
          evidence: string | null;
          family: string;
          first_seen: string;
          id: string;
          is_new: boolean;
          kev: boolean;
          last_seen: string;
          plugin_id: string;
          port: number | null;
          priority: number;
          refs: Json;
          scan_id: string | null;
          service: string | null;
          severity: number;
          solution: string | null;
          state: string;
          title: string;
          user_id: string;
          verifications: string[];
        };
        Insert: {
          asset_id?: string | null;
          assigned_to?: string | null;
          attack_tactics?: string[];
          confidence?: string;
          created_at?: string;
          cve_ids?: string[];
          cvss?: number | null;
          cvss_vector?: string | null;
          cwe?: string | null;
          description?: string | null;
          due_at?: string | null;
          epss?: number | null;
          evidence?: string | null;
          family?: string;
          first_seen?: string;
          id?: string;
          is_new?: boolean;
          kev?: boolean;
          last_seen?: string;
          plugin_id: string;
          port?: number | null;
          priority?: number;
          refs?: Json;
          scan_id?: string | null;
          service?: string | null;
          severity?: number;
          solution?: string | null;
          state?: string;
          title: string;
          user_id: string;
          verifications?: string[];
        };
        Update: {
          asset_id?: string | null;
          assigned_to?: string | null;
          attack_tactics?: string[];
          confidence?: string;
          created_at?: string;
          cve_ids?: string[];
          cvss?: number | null;
          cvss_vector?: string | null;
          cwe?: string | null;
          description?: string | null;
          due_at?: string | null;
          epss?: number | null;
          evidence?: string | null;
          family?: string;
          first_seen?: string;
          id?: string;
          is_new?: boolean;
          kev?: boolean;
          last_seen?: string;
          plugin_id?: string;
          port?: number | null;
          priority?: number;
          refs?: Json;
          scan_id?: string | null;
          service?: string | null;
          severity?: number;
          solution?: string | null;
          state?: string;
          title?: string;
          user_id?: string;
          verifications?: string[];
        };
        Relationships: [
          {
            foreignKeyName: "findings_asset_id_fkey";
            columns: ["asset_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "findings_scan_id_fkey";
            columns: ["scan_id"];
            isOneToOne: false;
            referencedRelation: "scans";
            referencedColumns: ["id"];
          },
        ];
      };
      integration_deliveries: {
        Row: {
          created_at: string;
          detail: string | null;
          finding_id: string | null;
          http_status: number | null;
          id: string;
          integration_id: string | null;
          status: string;
          user_id: string;
        };
        Insert: {
          created_at?: string;
          detail?: string | null;
          finding_id?: string | null;
          http_status?: number | null;
          id?: string;
          integration_id?: string | null;
          status?: string;
          user_id: string;
        };
        Update: {
          created_at?: string;
          detail?: string | null;
          finding_id?: string | null;
          http_status?: number | null;
          id?: string;
          integration_id?: string | null;
          status?: string;
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "integration_deliveries_integration_id_fkey";
            columns: ["integration_id"];
            isOneToOne: false;
            referencedRelation: "integrations";
            referencedColumns: ["id"];
          },
        ];
      };
      integrations: {
        Row: {
          config: Json;
          created_at: string;
          enabled: boolean;
          endpoint: string;
          id: string;
          kind: string;
          last_delivery_at: string | null;
          last_status: string | null;
          min_severity: number;
          name: string;
          user_id: string;
        };
        Insert: {
          config?: Json;
          created_at?: string;
          enabled?: boolean;
          endpoint: string;
          id?: string;
          kind?: string;
          last_delivery_at?: string | null;
          last_status?: string | null;
          min_severity?: number;
          name: string;
          user_id: string;
        };
        Update: {
          config?: Json;
          created_at?: string;
          enabled?: boolean;
          endpoint?: string;
          id?: string;
          kind?: string;
          last_delivery_at?: string | null;
          last_status?: string | null;
          min_severity?: number;
          name?: string;
          user_id?: string;
        };
        Relationships: [];
      };
      profiles: {
        Row: {
          created_at: string;
          email: string | null;
          full_name: string | null;
          id: string;
        };
        Insert: {
          created_at?: string;
          email?: string | null;
          full_name?: string | null;
          id: string;
        };
        Update: {
          created_at?: string;
          email?: string | null;
          full_name?: string | null;
          id?: string;
        };
        Relationships: [];
      };
      scan_jobs: {
        Row: {
          attempts: number;
          claimed_at: string | null;
          completed_at: string | null;
          created_at: string;
          error: string | null;
          id: string;
          payload: Json;
          region: string;
          result: Json;
          scan_id: string | null;
          status: string;
          target: string;
          template: string;
          user_id: string;
          worker_id: string | null;
        };
        Insert: {
          attempts?: number;
          claimed_at?: string | null;
          completed_at?: string | null;
          created_at?: string;
          error?: string | null;
          id?: string;
          payload?: Json;
          region?: string;
          result?: Json;
          scan_id?: string | null;
          status?: string;
          target: string;
          template?: string;
          user_id: string;
          worker_id?: string | null;
        };
        Update: {
          attempts?: number;
          claimed_at?: string | null;
          completed_at?: string | null;
          created_at?: string;
          error?: string | null;
          id?: string;
          payload?: Json;
          region?: string;
          result?: Json;
          scan_id?: string | null;
          status?: string;
          target?: string;
          template?: string;
          user_id?: string;
          worker_id?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "scan_jobs_scan_id_fkey";
            columns: ["scan_id"];
            isOneToOne: false;
            referencedRelation: "scans";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "scan_jobs_worker_id_fkey";
            columns: ["worker_id"];
            isOneToOne: false;
            referencedRelation: "workers";
            referencedColumns: ["id"];
          },
        ];
      };
      scans: {
        Row: {
          asset_id: string | null;
          baseline_scan_id: string | null;
          created_at: string;
          current_step: string | null;
          error: string | null;
          finished_at: string | null;
          id: string;
          mode: string;
          name: string;
          progress: number;
          region: string;
          source: string;
          started_at: string | null;
          stats: Json;
          status: string;
          target: string;
          template: string;
          user_id: string;
          worker_id: string | null;
        };
        Insert: {
          asset_id?: string | null;
          baseline_scan_id?: string | null;
          created_at?: string;
          current_step?: string | null;
          error?: string | null;
          finished_at?: string | null;
          id?: string;
          mode?: string;
          name: string;
          progress?: number;
          region?: string;
          source?: string;
          started_at?: string | null;
          stats?: Json;
          status?: string;
          target: string;
          template?: string;
          user_id: string;
          worker_id?: string | null;
        };
        Update: {
          asset_id?: string | null;
          baseline_scan_id?: string | null;
          created_at?: string;
          current_step?: string | null;
          error?: string | null;
          finished_at?: string | null;
          id?: string;
          mode?: string;
          name?: string;
          progress?: number;
          region?: string;
          source?: string;
          started_at?: string | null;
          stats?: Json;
          status?: string;
          target?: string;
          template?: string;
          user_id?: string;
          worker_id?: string | null;
        };
        Relationships: [
          {
            foreignKeyName: "scans_asset_id_fkey";
            columns: ["asset_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "scans_baseline_scan_id_fkey";
            columns: ["baseline_scan_id"];
            isOneToOne: false;
            referencedRelation: "scans";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "scans_worker_id_fkey";
            columns: ["worker_id"];
            isOneToOne: false;
            referencedRelation: "workers";
            referencedColumns: ["id"];
          },
        ];
      };
      schedules: {
        Row: {
          asset_id: string | null;
          cadence: string;
          created_at: string;
          enabled: boolean;
          id: string;
          last_run_at: string | null;
          last_scan_id: string | null;
          name: string;
          next_run_at: string;
          runs: number;
          target: string;
          template: string;
          user_id: string;
        };
        Insert: {
          asset_id?: string | null;
          cadence?: string;
          created_at?: string;
          enabled?: boolean;
          id?: string;
          last_run_at?: string | null;
          last_scan_id?: string | null;
          name: string;
          next_run_at?: string;
          runs?: number;
          target: string;
          template?: string;
          user_id: string;
        };
        Update: {
          asset_id?: string | null;
          cadence?: string;
          created_at?: string;
          enabled?: boolean;
          id?: string;
          last_run_at?: string | null;
          last_scan_id?: string | null;
          name?: string;
          next_run_at?: string;
          runs?: number;
          target?: string;
          template?: string;
          user_id?: string;
        };
        Relationships: [
          {
            foreignKeyName: "schedules_asset_id_fkey";
            columns: ["asset_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id"];
          },
        ];
      };
      user_roles: {
        Row: {
          created_at: string;
          id: string;
          role: Database["public"]["Enums"]["app_role"];
          user_id: string;
        };
        Insert: {
          created_at?: string;
          id?: string;
          role: Database["public"]["Enums"]["app_role"];
          user_id: string;
        };
        Update: {
          created_at?: string;
          id?: string;
          role?: Database["public"]["Enums"]["app_role"];
          user_id?: string;
        };
        Relationships: [];
      };
      wasm_plugins: {
        Row: {
          created_at: string;
          description: string;
          enabled: boolean;
          family: string;
          id: string;
          last_result: string | null;
          last_run_at: string | null;
          name: string;
          plugin_id: string;
          severity: number;
          size_bytes: number;
          user_id: string;
          version: string;
          wasm_base64: string;
        };
        Insert: {
          created_at?: string;
          description?: string;
          enabled?: boolean;
          family?: string;
          id?: string;
          last_result?: string | null;
          last_run_at?: string | null;
          name: string;
          plugin_id: string;
          severity?: number;
          size_bytes?: number;
          user_id: string;
          version?: string;
          wasm_base64: string;
        };
        Update: {
          created_at?: string;
          description?: string;
          enabled?: boolean;
          family?: string;
          id?: string;
          last_result?: string | null;
          last_run_at?: string | null;
          name?: string;
          plugin_id?: string;
          severity?: number;
          size_bytes?: number;
          user_id?: string;
          version?: string;
          wasm_base64?: string;
        };
        Relationships: [];
      };
      workers: {
        Row: {
          capabilities: Json;
          created_at: string;
          id: string;
          jobs_completed: number;
          kind: string;
          last_heartbeat: string | null;
          max_concurrency: number;
          name: string;
          region: string;
          status: string;
          user_id: string;
          version: string | null;
        };
        Insert: {
          capabilities?: Json;
          created_at?: string;
          id?: string;
          jobs_completed?: number;
          kind?: string;
          last_heartbeat?: string | null;
          max_concurrency?: number;
          name: string;
          region?: string;
          status?: string;
          user_id: string;
          version?: string | null;
        };
        Update: {
          capabilities?: Json;
          created_at?: string;
          id?: string;
          jobs_completed?: number;
          kind?: string;
          last_heartbeat?: string | null;
          max_concurrency?: number;
          name?: string;
          region?: string;
          status?: string;
          user_id?: string;
          version?: string | null;
        };
        Relationships: [];
      };
      asset_groups: {
        Row: {
          id: string;
          user_id: string;
          name: string;
          description: string;
          color: string;
          dynamic_rule: Json | null;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          name: string;
          description?: string;
          color?: string;
          dynamic_rule?: Json | null;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          name?: string;
          description?: string;
          color?: string;
          dynamic_rule?: Json | null;
          created_at?: string;
          updated_at?: string;
        };
        Relationships: [];
      };
      asset_group_memberships: {
        Row: {
          id: string;
          group_id: string;
          asset_id: string;
          user_id: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          group_id: string;
          asset_id: string;
          user_id: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          group_id?: string;
          asset_id?: string;
          user_id?: string;
          created_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "asset_group_memberships_asset_id_fkey";
            columns: ["asset_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id"];
          },
          {
            foreignKeyName: "asset_group_memberships_group_id_fkey";
            columns: ["group_id"];
            isOneToOne: false;
            referencedRelation: "asset_groups";
            referencedColumns: ["id"];
          },
        ];
      };
      host_ports: {
        Row: {
          id: string;
          user_id: string;
          asset_id: string;
          port: number;
          protocol: string;
          state: string;
          service_name: string | null;
          product: string | null;
          version: string | null;
          cpe: string | null;
          banner: string | null;
          last_seen: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          asset_id: string;
          port: number;
          protocol?: string;
          state?: string;
          service_name?: string | null;
          product?: string | null;
          version?: string | null;
          cpe?: string | null;
          banner?: string | null;
          last_seen?: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          asset_id?: string;
          port?: number;
          protocol?: string;
          state?: string;
          service_name?: string | null;
          product?: string | null;
          version?: string | null;
          cpe?: string | null;
          banner?: string | null;
          last_seen?: string;
          created_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "host_ports_asset_id_fkey";
            columns: ["asset_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id"];
          },
        ];
      };
      risk_overrides: {
        Row: {
          id: string;
          user_id: string;
          finding_id: string;
          original_severity: number;
          overridden_severity: number;
          reason: string;
          approved_by: string | null;
          expires_at: string | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          finding_id: string;
          original_severity: number;
          overridden_severity: number;
          reason: string;
          approved_by?: string | null;
          expires_at?: string | null;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          finding_id?: string;
          original_severity?: number;
          overridden_severity?: number;
          reason?: string;
          approved_by?: string | null;
          expires_at?: string | null;
          created_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "risk_overrides_finding_id_fkey";
            columns: ["finding_id"];
            isOneToOne: false;
            referencedRelation: "findings";
            referencedColumns: ["id"];
          },
        ];
      };
      risk_history: {
        Row: {
          id: string;
          user_id: string;
          asset_id: string | null;
          risk_score: number;
          open_critical: number;
          open_high: number;
          open_medium: number;
          open_low: number;
          recorded_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          asset_id?: string | null;
          risk_score: number;
          open_critical?: number;
          open_high?: number;
          open_medium?: number;
          open_low?: number;
          recorded_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          asset_id?: string | null;
          risk_score?: number;
          open_critical?: number;
          open_high?: number;
          open_medium?: number;
          open_low?: number;
          recorded_at?: string;
        };
        Relationships: [
          {
            foreignKeyName: "risk_history_asset_id_fkey";
            columns: ["asset_id"];
            isOneToOne: false;
            referencedRelation: "assets";
            referencedColumns: ["id"];
          },
        ];
      };
      saved_filters: {
        Row: {
          id: string;
          user_id: string;
          name: string;
          entity_type: string;
          query_params: Json;
          is_default: boolean;
          is_shared: boolean;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          name: string;
          entity_type: string;
          query_params?: Json;
          is_default?: boolean;
          is_shared?: boolean;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          name?: string;
          entity_type?: string;
          query_params?: Json;
          is_default?: boolean;
          is_shared?: boolean;
          created_at?: string;
        };
        Relationships: [];
      };
      plugin_registry: {
        Row: {
          id: string;
          plugin_id: string;
          name: string;
          family: string;
          category: string;
          version: string;
          description: string;
          solution: string;
          default_severity: number;
          cve_ids: string[];
          cwe: string | null;
          enabled: boolean;
          author: string;
          created_at: string;
        };
        Insert: {
          id?: string;
          plugin_id: string;
          name: string;
          family?: string;
          category?: string;
          version?: string;
          description?: string;
          solution?: string;
          default_severity?: number;
          cve_ids?: string[];
          cwe?: string | null;
          enabled?: boolean;
          author?: string;
          created_at?: string;
        };
        Update: {
          id?: string;
          plugin_id?: string;
          name?: string;
          family?: string;
          category?: string;
          version?: string;
          description?: string;
          solution?: string;
          default_severity?: number;
          cve_ids?: string[];
          cwe?: string | null;
          enabled?: boolean;
          author?: string;
          created_at?: string;
        };
        Relationships: [];
      };
      reports: {
        Row: {
          id: string;
          user_id: string;
          title: string;
          format: string;
          kind: string;
          status: string;
          summary: Json;
          download_url: string | null;
          file_size_bytes: number | null;
          created_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          title: string;
          format?: string;
          kind?: string;
          status?: string;
          summary?: Json;
          download_url?: string | null;
          file_size_bytes?: number | null;
          created_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          title?: string;
          format?: string;
          kind?: string;
          status?: string;
          summary?: Json;
          download_url?: string | null;
          file_size_bytes?: number | null;
          created_at?: string;
        };
        Relationships: [];
      };
      organization_settings: {
        Row: {
          id: string;
          user_id: string;
          org_name: string;
          mfa_required: boolean;
          session_timeout_minutes: number;
          min_password_length: number;
          smtp_config: Json;
          branding: Json;
          created_at: string;
          updated_at: string;
        };
        Insert: {
          id?: string;
          user_id: string;
          org_name?: string;
          mfa_required?: boolean;
          session_timeout_minutes?: number;
          min_password_length?: number;
          smtp_config?: Json;
          branding?: Json;
          created_at?: string;
          updated_at?: string;
        };
        Update: {
          id?: string;
          user_id?: string;
          org_name?: string;
          mfa_required?: boolean;
          session_timeout_minutes?: number;
          min_password_length?: number;
          smtp_config?: Json;
          branding?: Json;
          created_at?: string;
          updated_at?: string;
        };
        Relationships: [];
      };
    };
    Views: {
      [_ in never]: never;
    };
    Functions: {
      has_role: {
        Args: {
          _role: Database["public"]["Enums"]["app_role"];
          _user_id: string;
        };
        Returns: boolean;
      };
    };
    Enums: {
      app_role: "owner" | "admin" | "analyst" | "viewer";
    };
    CompositeTypes: {
      [_ in never]: never;
    };
  };
};

type DatabaseWithoutInternals = Omit<Database, "__InternalSupabase">;

type DefaultSchema = DatabaseWithoutInternals[Extract<keyof Database, "public">];

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? (DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R;
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] & DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R;
      }
      ? R
      : never
    : never;

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I;
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I;
      }
      ? I
      : never
    : never;

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    keyof DefaultSchema["Tables"] | { schema: keyof DatabaseWithoutInternals },
  TableName extends (DefaultSchemaTableNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never) = never,
> = DefaultSchemaTableNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U;
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U;
      }
      ? U
      : never
    : never;

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    keyof DefaultSchema["Enums"] | { schema: keyof DatabaseWithoutInternals },
  EnumName extends (DefaultSchemaEnumNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never) = never,
> = DefaultSchemaEnumNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never;

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    keyof DefaultSchema["CompositeTypes"] | { schema: keyof DatabaseWithoutInternals },
  CompositeTypeName extends (PublicCompositeTypeNameOrOptions extends {
    schema: keyof DatabaseWithoutInternals;
  }
    ? keyof DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never) = never,
> = PublicCompositeTypeNameOrOptions extends {
  schema: keyof DatabaseWithoutInternals;
}
  ? DatabaseWithoutInternals[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never;

export const Constants = {
  public: {
    Enums: {
      app_role: ["owner", "admin", "analyst", "viewer"],
    },
  },
} as const;
