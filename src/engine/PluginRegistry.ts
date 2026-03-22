import type { IPlugin, PluginPhase, PluginSummary, ResourceContext } from "./types.js";
import { ErrorUtils } from "../utils/ErrorUtils.js";

export class PluginRegistry {
    private plugins: IPlugin[] = [];

    register(plugin: IPlugin): this {
        this.plugins.push(plugin);
        return this;
    }

    list(): IPlugin[] {
        return [...this.plugins];
    }

    async runPhase(phase: PluginPhase, ctx: ResourceContext): Promise<void> {
        for (const plugin of this.plugins) {
            if (!plugin.phases.includes(phase) || !plugin.applies(ctx)) {
                continue;
            }
            try {
                await plugin.run(phase, ctx);
            } catch (e) {
                ctx.findings.push({
                    plugin: plugin.name,
                    type: "error",
                    code: "UNEXPECTED_ERROR",
                    message: ErrorUtils.errorMessage("Failed to run the plugin", e),
                    url: ctx.url,
                });
            }
        }
    }

    getSummaries(): PluginSummary[] {
        return this.plugins
            .filter((plugin) => plugin.includeInSummary?.() ?? false)
            .map((plugin) => plugin.getSummary?.())
            .filter((summary): summary is PluginSummary => summary !== null);
    }
}
