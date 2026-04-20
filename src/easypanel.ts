import { EASYPANEL_URL, API_TOKEN, NODE_ENV } from './config';

if (!API_TOKEN) console.warn('[epTrpc] API_TOKEN is not set — authenticated endpoints will fail');

const BASE_HEADERS: Record<string, string> = {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${API_TOKEN}`,
};

const debug = NODE_ENV !== 'production';

if (debug) {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

export async function epTrpc<T>(procedure: string): Promise<T | null> {
    const url = `${EASYPANEL_URL}/api/trpc/${procedure}`;
    try {
        const res = await fetch(url, { headers: BASE_HEADERS });
        const body = await res.json();
        if (debug) console.log(`[epTrpc] ${procedure} (${res.status}):`, JSON.stringify(body, null, 2));
        if (!res.ok) return null;
        return (body as { result?: { data?: { json?: T } } })?.result?.data?.json ?? null;
    } catch (err) {
        if (debug) console.error(`[epTrpc] ${procedure} failed:`, err);
        return null;
    }
}

export async function epTrpcPost<T>(procedure: string, data: unknown): Promise<T | null> {
    const url = `${EASYPANEL_URL}/api/trpc/${procedure}`;
    try {
        const res = await fetch(url, {
            method: 'POST',
            headers: BASE_HEADERS,
            body: JSON.stringify({ json: data }),
        });
        const body = await res.json();
        if (debug) console.log(`[epTrpc] POST ${procedure} (${res.status}):`, JSON.stringify(body, null, 2));
        if (!res.ok) return null;
        return (body as { result?: { data?: { json?: T } } })?.result?.data?.json ?? null;
    } catch (err) {
        if (debug) console.error(`[epTrpc] POST ${procedure} failed:`, err);
        return null;
    }
}

export async function epTrpcWithToken<T>(procedure: string, token: string): Promise<T | null> {
    const url = `${EASYPANEL_URL}/api/trpc/${procedure}?input=${encodeURIComponent(JSON.stringify({ json: null, meta: { values: ['undefined'], v: 1 } }))}`;
    try {
        const res = await fetch(url, {
            headers: { ...BASE_HEADERS, Authorization: token },
        });
        const body = await res.json();
        if (debug) console.log(`[epTrpc] ${procedure} (${res.status}):`, JSON.stringify(body, null, 2));
        if (!res.ok) return null;
        return (body as { result?: { data?: { json?: T } } })?.result?.data?.json ?? null;
    } catch (err) {
        if (debug) console.error(`[epTrpc] ${procedure} failed:`, err);
        return null;
    }
}
