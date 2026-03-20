export function normalizeUrl(u: string): string {
    const url = new URL(u);
    url.hash = "";
    // optionnel: uniformiser trailing slash (attention aux sites sensibles)
    return url.toString();
}

export function parseMime(contentType?: string): string | undefined {
    if (!contentType) return undefined;
    return contentType.split(";")[0].trim().toLowerCase();
}

export function isSameOrigin(a: string, b: string): boolean {
    return new URL(a).origin === new URL(b).origin;
}

export function sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
