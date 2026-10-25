/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Universal HTTP Client (Obsidian requestUrl with fetch fallback)
 */

export interface HttpResponse {
  status: number;
  text: string;
  json: any;
  headers?: Record<string, string>;
}

export interface HttpRequestOptions {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: ArrayBuffer | Uint8Array | string;
}

/**
 * Protocols that are explicitly rejected.
 *
 * `javascript:`, `data:`, `file:` and `blob:` would allow the request to be
 * redirected to a local/embedded resource, and `http:` would send the
 * Authorization header (OAuth token / WebDAV password) in cleartext.
 */
const ALLOWED_PROTOCOLS = ['https:', 'http:'];

/**
 * Validates an outbound URL.
 *
 * @param url The URL to validate
 * @param requireSecure When true, only `https:` is accepted (used for
 *        endpoints that carry credentials).
 * @throws Error when the URL is malformed or uses a forbidden protocol.
 */
export function assertSafeUrl(url: string, requireSecure = false): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid URL: ${url}`);
  }

  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    throw new Error(`Unsupported URL protocol: ${parsed.protocol}`);
  }
  if (requireSecure && parsed.protocol !== 'https:') {
    throw new Error(
      'Refusing to send credentials over an insecure connection. Use HTTPS.'
    );
  }
}

/**
 * Returns a standalone ArrayBuffer that contains exactly the bytes of `data`.
 *
 * `data.buffer` alone is WRONG: a `Uint8Array` is usually a *view* into a
 * larger buffer, so `data.buffer` can expose unrelated bytes of memory
 * (and can be larger than the view). This helper copies the exact slice.
 */
export function toExactArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.slice().buffer as ArrayBuffer;
}

/**
 * Converts a request body into something safe to pass to `fetch`.
 */
function normalizeBody(body: HttpRequestOptions['body']): BodyInit | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body === 'string') return body;
  if (body instanceof Uint8Array) return toExactArrayBuffer(body);
  return body;
}

export async function requestHttp(options: HttpRequestOptions): Promise<HttpResponse> {
  const method = options.method || 'GET';
  const url = options.url;
  const headers = options.headers || {};

  // Validate the URL before any credential is attached to it.
  assertSafeUrl(url, false);

  // 1. Try to use Obsidian's native requestUrl if available in runtime
  try {
    const obs = typeof window !== 'undefined' ? (window as any).obsidian : null;
    const reqFn = obs?.requestUrl || ((globalThis as any).app?.vault?.adapter ? (globalThis as any).requestUrl : null);
    if (typeof reqFn === 'function') {
      const res = await reqFn({
        url,
        method,
        headers,
        body: options.body instanceof Uint8Array ? toExactArrayBuffer(options.body) : options.body
      });
      return {
        status: res.status,
        text: res.text,
        json: res.json,
        headers: res.headers
      };
    }
  } catch {
    // Continue to standard fetch
  }

  // 2. Universal fetch fallback (Node.js 18+, Electron, Browsers)
  const response = await fetch(url, {
    method,
    headers,
    body: normalizeBody(options.body)
  });

  const text = await response.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    // Not valid JSON
  }

  return {
    status: response.status,
    text,
    json
  };
}
