/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Biometric Bridge URL Validation
 *
 * The bridge URL is the ORIGIN of the WebAuthn ceremony. It is:
 *   - opened in the SYSTEM browser (`window.open(url, '_system')`), and
 *   - PINNED as the RP ID / origin of the biometric envelope.
 *
 * A malicious or simply malformed value would therefore be able to:
 *   - execute arbitrary code through a `javascript:` URL,
 *   - read local files through a `file:` URL,
 *   - or bind the biometric envelope to an attacker controlled host.
 *
 * This module is the single source of truth for validating it.
 */

export interface BridgeUrlValidation {
  valid: boolean;
  /** The normalized URL (only meaningful when `valid` is true). */
  url: string;
  /** Human readable reason of the rejection (null when valid). */
  reason: string | null;
}

/**
 * Validates and normalizes the biometric bridge URL.
 *
 * Rules:
 *  - A missing scheme defaults to `https://`.
 *  - ONLY `https:` is accepted. `http:` is rejected because the WebAuthn
 *    ceremony (and the RP ID pinning) would be exposed to the network.
 *    `localhost` is allowed over plain HTTP for local development only.
 *  - Credentials in the URL (`https://user:pass@host`) are rejected.
 *  - The URL must have a hostname.
 */
export function validateBridgeUrl(rawUrl: string): BridgeUrlValidation {
  const reject = (reason: string): BridgeUrlValidation => ({ valid: false, url: '', reason });

  const trimmed = (rawUrl || '').trim();
  if (!trimmed) {
    return reject('La URL del puente está vacía.');
  }

  // Reject dangerous schemes EXPLICITLY before the URL parser can treat them
  // as relative paths.
  if (/^\s*(javascript|data|file|blob|about|vbscript):/i.test(trimmed)) {
    return reject('El esquema de la URL no es permitido. Usa una URL https:// de Cloudflare Pages.');
  }

  let candidate = trimmed;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
    candidate = 'https://' + candidate.replace(/^\/+/, '');
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return reject('La URL del puente no tiene un formato válido.');
  }

  if (parsed.protocol !== 'https:') {
    // Plain HTTP is only tolerated for a local development server.
    if (parsed.protocol === 'http:' && parsed.hostname === 'localhost') {
      // Allowed.
    } else {
      return reject('La URL del puente debe usar HTTPS.');
    }
  }

  if (parsed.username || parsed.password) {
    return reject('La URL del puente no debe incluir credenciales.');
  }

  if (!parsed.hostname) {
    return reject('La URL del puente no incluye un dominio.');
  }

  // Strip the query and the fragment: they are meaningless for a bridge root
  // and could smuggle unexpected data into the ceremony URL.
  const normalized = `${parsed.origin}${parsed.pathname.replace(/\/+$/, '')}`;

  return { valid: true, url: normalized, reason: null };
}
