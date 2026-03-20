import type { PluginSummary } from "./types.js";

export abstract class BasePlugin {
    protected auditedUrls = 0;
    protected infos = 0;
    protected warnings = 0;
    protected errors = 0;

    includeInSummary(): boolean {
        return true;
    }

    getSummary(): PluginSummary {
        return {
            plugin: (this as unknown as { name: string }).name,
            auditedUrls: this.auditedUrls,
            infos: this.infos,
            warnings: this.warnings,
            errors: this.errors,
        };
    }

    protected registerUrl(): void {
        this.auditedUrls += 1;
    }

    protected registerInfo(): void {
        this.infos += 1;
    }

    protected registerWarning(): void {
        this.warnings += 1;
    }

    protected registerError(): void {
        this.errors += 1;
    }
}
