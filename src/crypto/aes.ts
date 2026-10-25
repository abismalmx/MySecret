/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * AES-256-GCM Authenticated Encryption & Decryption (Web Crypto API)
 */

import { AES_GCM_IV_LENGTH, AES_GCM_TAG_LENGTH } from '../constants';
import { stringToBytes } from '../utils/buffer';

export interface AesGcmResult {
  iv: Uint8Array;
  tag: Uint8Array;
  ciphertext: Uint8Array;
}

/**
 * Generates a cryptographically secure random 96-bit (12-byte) IV
 */
export function generateIv(): Uint8Array {
  const iv = new Uint8Array(AES_GCM_IV_LENGTH);
  window.crypto.getRandomValues(iv);
  return iv;
}

/**
 * Imports raw 256-bit (32 bytes) key into a WebCrypto CryptoKey for AES-GCM
 */
export async function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  return await window.crypto.subtle.importKey(
    'raw',
    rawKey as BufferSource,
    { name: 'AES-GCM' },
    false, // not extractable for security in memory
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts data using AES-256-GCM with hardware acceleration.
 * Automatically appends the 16-byte authentication tag or separates it.
 * In WebCrypto, subtle.encrypt returns [ciphertext + tag] concatenated together.
 * 
 * @param plainBytes Data to encrypt
 * @param key CryptoKey
 * @param aad Optional additional authenticated data (e.g. normalized relative file path)
 */
export async function encryptAesGcm(
  plainBytes: Uint8Array,
  key: CryptoKey,
  aad?: string
): Promise<AesGcmResult> {
  const iv = generateIv();
  const additionalData = aad ? stringToBytes(aad) : undefined;

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: additionalData as BufferSource | undefined,
      tagLength: AES_GCM_TAG_LENGTH * 8 // 128 bits
    },
    key,
    plainBytes as BufferSource
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  // WebCrypto AES-GCM appends the 16-byte tag to the end of ciphertext
  const ciphertextLength = encryptedBytes.length - AES_GCM_TAG_LENGTH;
  const ciphertext = encryptedBytes.slice(0, ciphertextLength);
  const tag = encryptedBytes.slice(ciphertextLength);

  return {
    iv,
    tag,
    ciphertext
  };
}

/**
 * Decrypts AES-256-GCM ciphertext, verifying authentication tag and AAD.
 * Throws an error if ciphertext or tag was tampered with.
 * 
 * @param ciphertext Ciphertext bytes
 * @param key CryptoKey
 * @param iv 12-byte IV
 * @param tag 16-byte auth tag
 * @param aad Optional additional authenticated data
 */
export async function decryptAesGcm(
  ciphertext: Uint8Array,
  key: CryptoKey,
  iv: Uint8Array,
  tag: Uint8Array,
  aad?: string
): Promise<Uint8Array> {
  const additionalData = aad ? stringToBytes(aad) : undefined;

  // WebCrypto expects [ciphertext + tag] concatenated
  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.length);

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as BufferSource,
      additionalData: additionalData as BufferSource | undefined,
      tagLength: AES_GCM_TAG_LENGTH * 8
    },
    key,
    combined as BufferSource
  );

  return new Uint8Array(decryptedBuffer);
}
