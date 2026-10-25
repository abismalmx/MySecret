/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * WebAuthn Relying Party (RP) Identifier Computation
 *
 * A WebAuthn credential is bound to a "relying party id" (the RP ID). For a
 * credential to be usable on `https://foo.pages.dev`, the RP ID must be a
 * *registrable domain* of that origin: either `foo.pages.dev` itself (when
 * `pages.dev` is a public suffix) or `example.com` for `auth.example.com`.
 *
 * WHY THIS MATTERS FOR THE EXTERNAL BRIDGE
 * -----------------------------------------
 * The bridge web app performs the WebAuthn ceremony on behalf of Obsidian.
 * If the RP ID is not pinned, a credential enrolled for `foo.pages.dev` could
 * be replayed from a *sibling* origin that shares the same registrable
 * domain (`evil.example.com` when the credential was created for
 * `auth.example.com`), because both share the RP ID `example.com`.
 *
 * Pinning the RP ID (and the exact origin) inside the biometric envelope
 * closes that hole: an envelope can only ever be used from the very origin
 * where it was enrolled.
 */

/**
 * Public suffixes that are commonly relevant for a self-hosted bridge.
 *
 * This is a deliberately SMALL, curated list. It is NOT a replacement for
 * the full Public Suffix List: it only exists to compute the registrable
 * domain of the handful of hosting providers the bridge is realistically
 * deployed on. A wrong guess makes the ceremony FAIL CLOSED (the browser
 * rejects an RP ID that is not a registrable domain suffix of the origin),
 * never silently insecure.
 */
const COMMON_PUBLIC_SUFFIXES = new Set<string>([
  // Cloudflare Pages / Workers (the documented deployment target).
  'pages.dev',
  'workers.dev',
  'r2.dev',
  // Vercel / Netlify / Firebase Hosting.
  'vercel.app',
  'netlify.app',
  'web.app',
  'firebaseapp.com',
  // GitHub Pages.
  'github.io',
  // Heroku.
  'herokuapp.com',
  // Common multi-label country-code suffixes.
  'co.uk',
  'org.uk',
  'gov.uk',
  'ac.uk',
  'me.uk',
  'net.uk',
  'com.au',
  'net.au',
  'org.au',
  'com.br',
  'com.mx',
  'com.ar',
  'com.tr',
  'co.jp',
  'ne.jp',
  'co.kr',
  'co.in',
  'co.nz',
  'co.za',
  'com.cn',
  'com.hk',
  'com.sg',
  'com.tw',
  'co.il',
  'com.my',
  'com.pl',
  'com.ua',
  'com.es',
  'com.pt'
]);

/**
 * Matches an IPv4 literal.
 */
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Matches an IPv6 literal (the bracketed form used in URLs is stripped
 * before this function is called).
 */
const IPV6_RE = /^[0-9a-f:]+$/i;

/**
 * Computes the WebAuthn relying party id for a given hostname.
 *
 * @param hostname The hostname of the bridge origin (no port, no brackets).
 * @returns the RP ID to use in the WebAuthn ceremony.
 */
export function computeRpId(hostname: string): string {
  const host = (hostname || '').trim().toLowerCase().replace(/^\[|\]$/g, '');

  if (!host) {
    throw new Error('No se pudo determinar el dominio del puente biométrico.');
  }

  // IP literals and localhost are registrable on their own.
  if (host === 'localhost' || IPV4_RE.test(host) || (host.includes(':') && IPV6_RE.test(host))) {
    return host;
  }

  const labels = host.split('.');
  if (labels.length <= 1) {
    // A single-label host (intranet). It is its own registrable domain.
    return host;
  }

  // Multi-tenant worker/bucket subdomains (e.g. `service.account.workers.dev` or `bucket.account.r2.dev`)
  // represent distinct application origins: use the full host.
  if (labels.length >= 4 && (host.endsWith('.workers.dev') || host.endsWith('.r2.dev'))) {
    return host;
  }

  // Find the LONGEST known public suffix that is a proper suffix of the host.
  // The registrable domain is then one label in front of it.
  let suffixLabels = 0;
  for (const n of [3, 2]) {
    if (labels.length > n && COMMON_PUBLIC_SUFFIXES.has(labels.slice(-n).join('.'))) {
      suffixLabels = n;
      break;
    }
  }

  if (suffixLabels > 0) {
    const registrable = labels.slice(-(suffixLabels + 1)).join('.');
    // `mi-boveda.pages.dev` is itself the registrable domain: the public
    // suffix is `pages.dev`, so the host is the domain in front of it.
    if (registrable && registrable !== host) {
      return registrable;
    }
    return host;
  }

  // Default: the classic `tld + 1` rule.
  return labels.slice(-2).join('.');
}

/**
 * Returns the origin (scheme + host + port) of a URL, without any trailing
 * slash. It is the exact value the browser reports as `clientData.origin`.
 */
export function computeOrigin(url: string): string {
  const parsed = new URL(url);
  return parsed.origin;
}
