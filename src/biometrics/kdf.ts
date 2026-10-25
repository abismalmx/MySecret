/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Biometric Cryptographic Helpers
 *
 * Shared primitives used by every biometric provider:
 *  - HKDF-SHA256 key derivation from a high-entropy secret.
 *  - AAD construction that cryptographically BINDS a biometric envelope to
 *    the vault it belongs to (so an envelope can never be transplanted from
 *    one vault into another one).
 *  - Constant-time comparison of the key verification hash.
 */

import { bytesToHex, hexToBytes, constantTimeEqual, stringToBytes } from '../utils/buffer';

/**
 * Version of the on-disk biometric envelope format.
 *
 * Version 2 introduced:
 *  - A vault-bound AAD (`biometricAad`), so an envelope created for vault A
 *    can never decrypt under vault B.
 *  - A per-provider secret model (the raw vault key is NEVER handed over to
 *    an OS keystore).
 *  - Credential binding metadata for WebAuthn (PRF salt + credential id).
 *
 * Version 1 envelopes are intentionally rejected by the manager: they were
 * produced with the weaker key-derivation schemes described in the security
 * review and must be re-enrolled.
 */
export const BIOMETRIC_ENVELOPE_VERSION = 2;

/**
 * Builds the Additional Authenticated Data used to encrypt the vault key.
 *
 * Because AES-GCM authenticates the AAD, binding the vault identifier into it
 * means that a biometric envelope is cryptographically bound to exactly one
 * vault. Copying an envelope (or its localStorage entry) to another vault on
 * the same machine makes the decryption fail closed instead of silently
 * installing a wrong key.
 */
export function biometricAad(providerType: string, vaultId: string): string {
  return `mysecret-bio:v${BIOMETRIC_ENVELOPE_VERSION}:${providerType}:${vaultId}`;
}

/**
 * Computes the SHA-256 of a buffer and returns it as a lowercase hex string.
 */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await window.crypto.subtle.digest('SHA-256', data as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Constant-time comparison of two hex-encoded digests.
 *
 * Uses the shared `constantTimeEqual` helper so the key verification hash is
 * never compared with a short-circuiting `===` (which leaks the matching
 * prefix length through timing).
 */
export function constantTimeHexEqual(a: string, b: string): boolean {
  if (!a || !b || a.length !== b.length) return false;
  try {
    return constantTimeEqual(hexToBytes(a), hexToBytes(b));
  } catch {
    return false;
  }
}

/**
 * Derives an AES-256-GCM key from a high-entropy secret using HKDF-SHA256.
 *
 * @param secret  High-entropy secret material (e.g. a random device secret).
 * @param salt    Context string mixed in as the HKDF salt.
 * @param info    Context string mixed in as the HKDF info (usually the AAD).
 */
export async function deriveAesKeyFromSecret(
  secret: Uint8Array,
  salt: string,
  info: string
): Promise<CryptoKey> {
  const hkdfKey = await window.crypto.subtle.importKey(
    'raw',
    secret as BufferSource,
    'HKDF',
    false,
    ['deriveBits']
  );

  const bits = await window.crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: stringToBytes(salt) as BufferSource,
      info: stringToBytes(info) as BufferSource
    },
    hkdfKey,
    256
  );

  return await window.crypto.subtle.importKey(
    'raw',
    bits as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt']
  );
}
