/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Hybrid Envelope Serialization & Deserialization (Armored Text & Compact Binary)
 */

import { EncryptedPayload } from '../types';
import {
  ARMORED_HEADER_START,
  ARMORED_HEADER_END,
  BINARY_MAGIC,
  BINARY_HEADER_LENGTH,
  CURRENT_ENVELOPE_VERSION,
  AES_GCM_IV_LENGTH,
  AES_GCM_TAG_LENGTH
} from '../constants';
import { bytesToBase64, base64ToBytes } from '../utils/buffer';

/**
 * Checks if a string contains the armored encryption header
 */
export function isArmoredEncrypted(text: string): boolean {
  if (!text) return false;
  return text.trimStart().startsWith(ARMORED_HEADER_START);
}

/**
 * Serializes an EncryptedPayload into safe Armored ASCII text (CRLF/LF immune)
 */
export function serializeArmored(payload: EncryptedPayload): string {
  const ivB64 = bytesToBase64(payload.iv);
  const tagB64 = bytesToBase64(payload.tag);
  const cipherB64 = bytesToBase64(payload.ciphertext);

  // Split base64 ciphertext into 64-character lines for clean readability
  const chunks: string[] = [];
  for (let i = 0; i < cipherB64.length; i += 64) {
    chunks.push(cipherB64.substring(i, i + 64));
  }
  const formattedBody = chunks.join('\n');

  return `${ARMORED_HEADER_START}
Version: ${payload.version}
IV: ${ivB64}
Tag: ${tagB64}

${formattedBody ? formattedBody + '\n' : ''}${ARMORED_HEADER_END}
`;
}

/**
 * Deserializes an Armored ASCII text into an EncryptedPayload
 */
export function deserializeArmored(text: string): EncryptedPayload {
  const startIndex = text.indexOf(ARMORED_HEADER_START);
  const endIndex = text.indexOf(ARMORED_HEADER_END);

  if (startIndex === -1 || endIndex === -1 || endIndex <= startIndex) {
    throw new Error('Invalid or corrupted armored file: missing header/footer');
  }

  // Extract inner text between headers without trimming end (which could swallow empty body separator)
  const rawInner = text.substring(startIndex + ARMORED_HEADER_START.length, endIndex);
  const lines = rawInner.split(/\r?\n/);

  let version = CURRENT_ENVELOPE_VERSION;
  let ivStr = '';
  let tagStr = '';
  let bodyStartIndex = -1;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '') {
      if (ivStr && tagStr) {
        bodyStartIndex = i + 1;
        break;
      }
      continue;
    }
    const colonIdx = line.indexOf(':');
    if (colonIdx !== -1) {
      const key = line.substring(0, colonIdx).trim().toLowerCase();
      const val = line.substring(colonIdx + 1).trim();
      if (key === 'version') version = parseInt(val, 10);
      else if (key === 'iv') ivStr = val;
      else if (key === 'tag') tagStr = val;
    }
  }

  // If we found IV and Tag, but hit the end without an explicit body separator:
  // this is a valid empty body (e.g. freshly created or emptied note)
  if (ivStr && tagStr && bodyStartIndex === -1) {
    bodyStartIndex = lines.length;
  }

  if (!ivStr || !tagStr) {
    throw new Error('Malformed armored file headers (missing IV or Tag)');
  }

  const bodyLines = bodyStartIndex < lines.length
    ? lines.slice(bodyStartIndex).map(l => l.trim()).join('')
    : '';
  const iv = base64ToBytes(ivStr);
  const tag = base64ToBytes(tagStr);
  const ciphertext = bodyLines ? base64ToBytes(bodyLines) : new Uint8Array(0);

  return {
    version,
    iv,
    tag,
    ciphertext
  };
}

/**
 * Checks if a binary buffer begins with the "MYSE" magic header and version
 */
export function isBinaryEncrypted(data: Uint8Array): boolean {
  if (!data || data.length < BINARY_HEADER_LENGTH) return false;
  return (
    data[0] === BINARY_MAGIC[0] &&
    data[1] === BINARY_MAGIC[1] &&
    data[2] === BINARY_MAGIC[2] &&
    data[3] === BINARY_MAGIC[3] &&
    data[4] === CURRENT_ENVELOPE_VERSION
  );
}

/**
 * Packs an EncryptedPayload into a compact binary format with 33-byte header
 */
export function serializeBinary(payload: EncryptedPayload): Uint8Array {
  const result = new Uint8Array(BINARY_HEADER_LENGTH + payload.ciphertext.length);
  // Magic [0..3]
  result.set(BINARY_MAGIC, 0);
  // Version [4]
  result[4] = payload.version;
  // IV [5..16]
  result.set(payload.iv, 5);
  // Tag [17..32]
  result.set(payload.tag, 5 + AES_GCM_IV_LENGTH);
  // Ciphertext [33..]
  result.set(payload.ciphertext, BINARY_HEADER_LENGTH);
  return result;
}

/**
 * Unpacks a compact binary format into an EncryptedPayload
 */
export function deserializeBinary(data: Uint8Array): EncryptedPayload {
  if (!isBinaryEncrypted(data)) {
    throw new Error('Invalid binary encrypted file (missing MYSE magic header or invalid version)');
  }

  const version = data[4];
  const iv = data.slice(5, 5 + AES_GCM_IV_LENGTH);
  const tag = data.slice(5 + AES_GCM_IV_LENGTH, BINARY_HEADER_LENGTH);
  const ciphertext = data.slice(BINARY_HEADER_LENGTH);

  return {
    version,
    iv,
    tag,
    ciphertext
  };
}
