import tls from "node:tls";
import { BasePlugin } from "../engine/BasePlugin.js";
import { IPlugin, PluginPhase, ResourceContext } from "../engine/types.js";
import { TextUtils } from "../utils/TextUtils.js";

type TlsCertificatePluginOptions = {
    auditOnlyStartUrl?: boolean;
    warnIfExpiresInDays?: number;
    timeoutMs?: number;
};

type TlsCertInfo = {
    host: string;
    port: number;
    servername: string;
    protocol: string | null;
    cipherName: string | null;
    cipherVersion: string | null;
    authorized: boolean;
    authorizationError: string | null;
    validFrom: string | null;
    validTo: string | null;
    validToIso: string | null;
    daysRemaining: number | null;
    expired: boolean;
    subject: Record<string, unknown> | null;
    issuer: Record<string, unknown> | null;
    subjectAltName: string | null;
    serialNumber: string | null;
    fingerprint: string | null;
    fingerprint256: string | null;
    selfSigned: boolean;
    chainDepth: number;
};

export class TlsCertificatePlugin extends BasePlugin implements IPlugin {
    name = "tls-certificate";
    phases: PluginPhase[] = ["afterGoto", "error"];

    private readonly auditOnlyStartUrl: boolean;
    private readonly warnIfExpiresInDays: number;
    private readonly timeoutMs: number;

    constructor(options: TlsCertificatePluginOptions = {}) {
        super();
        this.auditOnlyStartUrl = options.auditOnlyStartUrl ?? true;
        this.warnIfExpiresInDays = options.warnIfExpiresInDays ?? 30;
        this.timeoutMs = options.timeoutMs ?? 10000;
    }

    applies(ctx: ResourceContext): boolean {
        return !this.auditOnlyStartUrl || ctx.depth === 0;
    }

    async run(phase: PluginPhase, ctx: ResourceContext): Promise<void> {
        if (this.auditOnlyStartUrl && ctx.depth !== 0) {
            return;
        }

        const targetUrl = ctx.finalUrl ?? ctx.url;

        if (phase === "error") {
            this.registerWarning(
                ctx,
                "TLS_CERTIFICATE_NOT_AUDITED",
                "TLS certificate could not be audited because the start URL failed to load.",
                { targetUrl },
            );
            this.register(ctx);
            return;
        }

        let parsedUrl: URL;
        try {
            parsedUrl = new URL(targetUrl);
        } catch {
            this.registerWarning(
                ctx,
                "TLS_CERTIFICATE_INVALID_URL",
                "TLS certificate audit skipped because the URL is invalid.",
                { targetUrl },
            );
            this.register(ctx);
            return;
        }

        if (parsedUrl.protocol !== "https:") {
            this.registerInfo(
                ctx,
                "TLS_CERTIFICATE_NOT_APPLICABLE",
                "TLS certificate audit skipped because the URL is not HTTPS.",
                { targetUrl, protocol: parsedUrl.protocol },
            );
            this.register(ctx);
            return;
        }

        const host = parsedUrl.hostname;
        const port = parsedUrl.port ? Number(parsedUrl.port) : 443;
        const servername = host;

        try {
            const cert = await this.inspectCertificate(host, port, servername);

            this.registerInfo(
                ctx,
                "TLS_CERTIFICATE_DETAILS",
                "TLS certificate details collected for the start URL.",
                cert,
            );

            if (!cert.authorized) {
                this.registerError(
                    ctx,
                    "TLS_CERTIFICATE_INVALID",
                    `The TLS certificate is not trusted by Node/OpenSSL: ${cert.authorizationError ?? "unknown error"}.`,
                    cert,
                );
            }

            if (cert.expired) {
                this.registerError(
                    ctx,
                    "TLS_CERTIFICATE_EXPIRED",
                    "The TLS certificate is expired.",
                    cert,
                );
            } else if (
                cert.daysRemaining !== null &&
                cert.daysRemaining <= this.warnIfExpiresInDays
            ) {
                this.registerWarning(
                    ctx,
                    "TLS_CERTIFICATE_EXPIRING_SOON",
                    `The TLS certificate expires in ${cert.daysRemaining} day(s).`,
                    cert,
                );
            }

            if (cert.selfSigned) {
                this.registerWarning(
                    ctx,
                    "TLS_CERTIFICATE_SELF_SIGNED",
                    "The TLS certificate appears to be self-signed.",
                    cert,
                );
            }

            if (!cert.subjectAltName) {
                this.registerWarning(
                    ctx,
                    "TLS_CERTIFICATE_NO_SAN",
                    "The TLS certificate does not expose a Subject Alternative Name (SAN).",
                    cert,
                );
            }

            const summary = this.buildSummary(cert);
            if (cert.authorized && !cert.expired && !cert.selfSigned) {
                this.registerInfo(ctx, "TLS_CERTIFICATE_SUMMARY", summary, cert);
            } else {
                this.registerWarning(ctx, "TLS_CERTIFICATE_SUMMARY", summary, cert);
            }
        } catch (error) {
            this.registerError(
                ctx,
                "TLS_CERTIFICATE_AUDIT_FAILED",
                "TLS certificate audit failed.",
                {
                    targetUrl,
                    error: error instanceof Error ? error.message : String(error),
                },
            );
        }

        this.register(ctx);
    }

    private inspectCertificate(
        host: string,
        port: number,
        servername: string,
    ): Promise<TlsCertInfo> {
        return new Promise((resolve, reject) => {
            const socket = tls.connect({
                host,
                port,
                servername,
                rejectUnauthorized: false,
            });

            const onError = (error: Error) => {
                cleanup();
                reject(error);
            };

            const onTimeout = () => {
                cleanup();
                socket.destroy();
                reject(new Error(`TLS connection timed out after ${this.timeoutMs} ms`));
            };

            const onSecureConnect = () => {
                try {
                    const peer = socket.getPeerCertificate(true);
                    const protocol = socket.getProtocol();
                    const cipher = socket.getCipher();

                    const validToIso = this.toIsoDate(peer?.valid_to);
                    const daysRemaining =
                        validToIso !== null
                            ? Math.ceil(
                                  (new Date(validToIso).getTime() - Date.now()) /
                                      (1000 * 60 * 60 * 24),
                              )
                            : null;

                    const expired = daysRemaining !== null ? daysRemaining < 0 : false;
                    const selfSigned = this.isSelfSigned(peer);
                    const chainDepth = this.getChainDepth(peer);

                    const result: TlsCertInfo = {
                        host,
                        port,
                        servername,
                        protocol: typeof protocol === "string" ? protocol : null,
                        cipherName: cipher?.name ?? null,
                        cipherVersion: cipher?.version ?? null,
                        authorized: socket.authorized,
                        authorizationError: TextUtils.asString(socket.authorizationError ?? null),
                        validFrom: peer?.valid_from ?? null,
                        validTo: peer?.valid_to ?? null,
                        validToIso,
                        daysRemaining,
                        expired,
                        subject: this.toPlainRecord(peer?.subject),
                        issuer: this.toPlainRecord(peer?.issuer),
                        subjectAltName: peer?.subjectaltname ?? null,
                        serialNumber: peer?.serialNumber ?? null,
                        fingerprint: peer?.fingerprint ?? null,
                        fingerprint256: peer?.fingerprint256 ?? null,
                        selfSigned,
                        chainDepth,
                    };

                    cleanup();
                    socket.end();
                    resolve(result);
                } catch (error) {
                    cleanup();
                    socket.destroy();
                    reject(error);
                }
            };

            const cleanup = () => {
                socket.off("error", onError);
                socket.off("timeout", onTimeout);
                socket.off("secureConnect", onSecureConnect);
            };

            socket.setTimeout(this.timeoutMs);
            socket.once("error", onError);
            socket.once("timeout", onTimeout);
            socket.once("secureConnect", onSecureConnect);
        });
    }

    private buildSummary(cert: TlsCertInfo): string {
        const parts = [
            `TLS ${cert.protocol ?? "unknown"}`,
            cert.authorized ? "trusted" : "untrusted",
        ];

        if (cert.daysRemaining !== null) {
            parts.push(
                cert.expired ? "certificate expired" : `expires in ${cert.daysRemaining} day(s)`,
            );
        }

        if (cert.selfSigned) {
            parts.push("self-signed");
        }

        if (cert.cipherName) {
            parts.push(`cipher ${cert.cipherName}`);
        }

        return `Start URL certificate: ${parts.join(", ")}.`;
    }

    private toIsoDate(value: unknown): string | null {
        if (typeof value !== "string" || value.trim().length === 0) {
            return null;
        }

        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? null : date.toISOString();
    }

    private toPlainRecord(value: unknown): Record<string, unknown> | null {
        if (!value || typeof value !== "object" || Array.isArray(value)) {
            return null;
        }
        return { ...(value as Record<string, unknown>) };
    }

    private isSelfSigned(peer: tls.PeerCertificate): boolean {
        const subject = this.toPlainRecord(peer?.subject);
        const issuer = this.toPlainRecord(peer?.issuer);

        if (!subject || !issuer) {
            return false;
        }

        return JSON.stringify(subject) === JSON.stringify(issuer);
    }

    private getChainDepth(peer: tls.PeerCertificate): number {
        let depth = 0;
        let current: tls.DetailedPeerCertificate | tls.PeerCertificate | undefined = peer;
        const visited = new Set<string>();

        while (current && typeof current === "object") {
            depth += 1;

            const fingerprint =
                "fingerprint256" in current && typeof current.fingerprint256 === "string"
                    ? current.fingerprint256
                    : `depth-${depth}`;

            if (visited.has(fingerprint)) {
                break;
            }
            visited.add(fingerprint);

            if (
                !("issuerCertificate" in current) ||
                !current.issuerCertificate ||
                current.issuerCertificate === current
            ) {
                break;
            }

            current = current.issuerCertificate;
        }

        return depth;
    }
}
