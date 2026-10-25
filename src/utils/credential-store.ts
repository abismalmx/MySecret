/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Credential Store: Encryption of cloud backup credentials at rest
 *
 * The plugin settings (`data.json`) are stored as PLAIN JSON inside the vault.
 * Storing OAuth bearer tokens and WebDAV passwords there in cleartext means
 * that anyone who can copy the vault off the disk also gets full access to the
 * user's cloud storage.
 *
 * This module encrypts the sensitive fields with the *vault key* (the same
 * AES-256 key that protects the notes) using a distinct AAD context, so the
 * credentials are:
 *  - unreadable by anyone who only has the vault files on disk, and
 *  - unreadable while the vault is locked (the vault key is wiped from RAM).
 *
 * Because the vault key itself never changes when the master password changes
 * (only its *wrapping* envelope does), the credentials survive a password
 * change without any re-encryption.
 */

import { encryptAesGcm, decryptAesGcm } from '../crypto/aes';
import { bytesToHex, hexToBytes } from './buffer';
import { stringToBytes, bytesToString } from './buffer';

/**
 * Marker prefix used to detect an encrypted credential value.
 */
export const ENCRYPTED_CREDENTIAL_PREFIX = 'enc:v1:';

/**
 * AAD context bound to the credential envelope. It is different from the
 * file-encryption AAD (a vault path), so a credential envelope can never be
 * confused with an encrypted note.
 */
const CREDENTIAL_AAD = 'mysecret-credential-v1';

interface CredentialEnvelope {
  iv: string;
  tag: string;
  ciphertext: string;
}

/**
 * Encrypts a plaintext credential into a self-describing envelope string.
 *
 * @param vaultKey The vault AES key (must be available, i.e. vault unlocked)
 * @param plaintext The credential value
 */
export async function encryptCredential(
  vaultKey: CryptoKey,
  plaintext: string
): Promise<string> {
  if (!plaintext) return '';

  const enc = await encryptAesGcm(stringToBytes(plaintext), vaultKey, CREDENTIAL_AAD);

  const envelope: CredentialEnvelope = {
    iv: bytesToHex(enc.iv),
    tag: bytesToHex(enc.tag),
    ciphertext: bytesToHex(enc.ciphertext)
  };

  return ENCRYPTED_CREDENTIAL_PREFIX + JSON.stringify(envelope);
}

/**
 * Decrypts a credential envelope string.
 *
 * @returns the plaintext, or `null` when the value is not an encrypted
 *          envelope or when it cannot be decrypted with the given key.
 */
export async function decryptCredential(
  vaultKey: CryptoKey,
  stored: string
): Promise<string | null> {
  if (!stored) return '';
  if (!stored.startsWith(ENCRYPTED_CREDENTIAL_PREFIX)) {
    // Legacy plain-text value: nothing to decrypt.
    return null;
  }

  let envelope: CredentialEnvelope;
  try {
    envelope = JSON.parse(stored.slice(ENCRYPTED_CREDENTIAL_PREFIX.length));
  } catch {
    return null;
  }
  if (!envelope || !envelope.iv || !envelope.tag || !envelope.ciphertext) {
    return null;
  }

  try {
    const plain = await decryptAesGcm(
      hexToBytes(envelope.ciphertext),
      vaultKey,
      hexToBytes(envelope.iv),
      hexToBytes(envelope.tag),
      CREDENTIAL_AAD
    );
    return bytesToString(plain);
  } catch {
    return null;
  }
}

/**
 * Checks whether a stored credential value is already encrypted.
 */
export function isEncryptedCredential(stored: string | undefined | null): boolean {
  return typeof stored === 'string' && stored.startsWith(ENCRYPTED_CREDENTIAL_PREFIX);
}
