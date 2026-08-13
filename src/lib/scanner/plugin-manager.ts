import { ScanPlugin, PluginMetadata, ScanContext } from "./plugin-interface";
import { RawFinding } from "../scan-engine.server";
import { BUILTIN_PLUGINS } from "./builtin-plugins";

export class PluginManager {
  private static instance: PluginManager;
  private plugins: Map<string, ScanPlugin> = new Map();

  private constructor() {
    // Register built-in detection plugins
    for (const p of BUILTIN_PLUGINS) {
      this.registerPlugin(p);
    }
  }

  public static getInstance(): PluginManager {
    if (!PluginManager.instance) {
      PluginManager.instance = new PluginManager();
    }
    return PluginManager.instance;
  }

  /**
   * Register a new plugin into the scanner architecture
   */
  public registerPlugin(plugin: ScanPlugin): void {
    this.plugins.set(plugin.metadata.id, plugin);
  }

  /**
   * Unregister a plugin
   */
  public unregisterPlugin(pluginId: string): boolean {
    return this.plugins.delete(pluginId);
  }

  /**
   * Get plugin metadata list
   */
  public getRegisteredPlugins(): PluginMetadata[] {
    return Array.from(this.plugins.values()).map((p) => p.metadata);
  }

  /**
   * Run applicable plugins against target scan context
   */
  public async executePlugins(ctx: ScanContext, familyFilter?: string): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const pluginsToRun = Array.from(this.plugins.values()).filter((plugin) => {
      if (familyFilter && plugin.metadata.family !== familyFilter) return false;
      return true;
    });

    for (const plugin of pluginsToRun) {
      try {
        const applicable = await plugin.isApplicable(ctx);
        if (applicable) {
          const results = await plugin.execute(ctx);
          findings.push(...results);
        }
      } catch (err) {
        console.error(`Error running plugin ${plugin.metadata.id}:`, err);
      }
    }

    return findings;
  }
}
