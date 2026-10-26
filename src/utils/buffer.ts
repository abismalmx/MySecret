/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Buffer & Encoding Utilities (Uint8Array, Hex, Base64)
 */

/**
 * Converts a Uint8Array to a hex string
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Converts a hex string to a Uint8Array
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.replace(/[^0-9a-fA-F]/g, '');
  if (cleanHex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Strictly decodes a hex string.
 *
 * SECURITY: unlike {@link hexToBytes} it REJECTS any non-hex character and
 * any odd length instead of silently repairing them. It is the only decoder
 * allowed for values that arrive from an untrusted source (the protocol
 * callback of the biometric bridge), where a "repaired" value would otherwise
 * be accepted as if it were well formed.
 *
 * @throws Error when the input is not a valid, even-length hex string.
 */
export function hexToBytesStrict(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length === 0) {
    throw new Error('Invalid hex string');
  }
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  if (!/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}


/**
 * Converts a Uint8Array to a Base64 string
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Converts a Base64 string to a Uint8Array
 */
export function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64.replace(/\s+/g, ''));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Converts a Uint8Array to a Base64URL string (RFC 4648 §5).
 *
 * Base64URL is the encoding used by the WebAuthn API for credential ids and
 * for the PRF extension outputs. It differs from standard Base64 in the
 * alphabet (`-` and `_` instead of `+` and `/`) and in the absence of the
 * `=` padding.
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Converts a Base64URL string to a Uint8Array.
 *
 * It restores the standard Base64 alphabet and the padding before decoding,
 * because `atob()` rejects the Base64URL alphabet.
 */
export function base64UrlToBytes(base64url: string): Uint8Array {
  const normalized = base64url.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.length % 4;
  const padded = padding === 0 ? normalized : normalized + '='.repeat(4 - padding);
  return base64ToBytes(padded);
}

/**
 * Converts a UTF-8 string to a Uint8Array
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts a Uint8Array to a UTF-8 string
 */
export function bytesToString(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/**
 * Compares two Uint8Arrays in constant time
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let c = 0;
  for (let i = 0; i < a.length; i++) {
    c |= a[i] ^ b[i];
  }
  return c === 0;
}

/**
 * Decodes bytes as UTF-8 only when the round trip is lossless.
 *
 * Text notes are handled as JS strings; a file in another encoding would be
 * silently altered (invalid bytes become U+FFFD) the moment it is encrypted.
 *
 * @returns the string, or null when the bytes are not valid UTF-8.
 */
export function decodeUtf8Strict(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}
