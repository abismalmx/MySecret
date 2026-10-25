/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Shared Container Detection & Decryption Helpers
 *
 * These helpers live in their own module (instead of inside the adapter
 * interceptor) so that they can be shared by the interceptor and the media
 * manager without introducing a circular import between them.
 */

import { KeyManager } from '../crypto/key-manager';
import { decryptAesGcm } from '../crypto/aes';
import {
  isArmoredBytesEncrypted,
  isBinaryEncrypted,
  deserializeArmored,
  deserializeBinary
} from '../crypto/envelope';

/**
 * The kind of MySecret container detected on disk.
 *
 * - `binary`:  compact binary envelope (attachments).
 * - `armored`: ASCII armored envelope (text notes).
 * - `plain`:   not encrypted at all.
 */
export type ContainerFormat = 'binary' | 'armored' | 'plain';

export interface DecryptionOutcome {
  /**
   * The decrypted bytes, or the original bytes when the source was not an
   * encrypted container.
   */
  bytes: Uint8Array;
  /** Whether the source bytes were an encrypted MySecret container. */
  wasEncrypted: boolean;
  /** Which container format was detected. */
  format: ContainerFormat;
}

/**
 * Detects the container format of a raw on-disk buffer.
 *
 * The detection MUST be performed on the RAW BYTES. Deciding the format
 * after decoding the buffer as UTF-8 text is wrong: a binary encrypted
 * attachment decoded as text produces mojibake that no longer matches the
 * binary magic header, and the attachment would be treated as plaintext and
 * silently corrupted.
 */
export function detectContainerFormat(rawBytes: Uint8Array): ContainerFormat {
  if (isBinaryEncrypted(rawBytes)) return 'binary';
  if (isArmoredBytesEncrypted(rawBytes)) return 'armored';
  return 'plain';
}

/**
 * Decrypts a raw on-disk buffer when it holds a MySecret container.
 *
 * @param rawBytes The bytes as they are stored on disk.
 * @param aad      The normalized vault path bound as AES-GCM additional data.
 * @param keyManager The key manager holding the unlocked vault key.
 *
 * @throws When the container is encrypted but cannot be authenticated
 *         (wrong key, wrong AAD or tampered ciphertext).
 */
export async function decryptContainer(
  rawBytes: Uint8Array,
  aad: string,
  keyManager: KeyManager
): Promise<DecryptionOutcome> {
  const format = detectContainerFormat(rawBytes);

  if (format === 'plain') {
    return { bytes: rawBytes, wasEncrypted: false, format };
  }

  const vaultKey = keyManager.getVaultKey();
  if (!vaultKey) {
    throw new Error('[MySecret] Vault key unavailable in memory');
  }

  if (format === 'binary') {
    const payload = deserializeBinary(rawBytes);
    const plain = await decryptAesGcm(
      payload.ciphertext,
      vaultKey,
      payload.iv,
      payload.tag,
      aad
    );
    return { bytes: plain, wasEncrypted: true, format };
  }

  const payload = deserializeArmored(new TextDecoder().decode(rawBytes));
  const plain = await decryptAesGcm(
    payload.ciphertext,
    vaultKey,
    payload.iv,
    payload.tag,
    aad
  );
  return { bytes: plain, wasEncrypted: true, format };
}

/**
 * Returns an ArrayBuffer that contains exactly the bytes of `data`.
 *
 * `data.buffer` alone is WRONG: a Uint8Array is usually a *view* into a
 * larger buffer, so `data.buffer` can expose unrelated bytes of memory and
 * can be larger than the view. This helper copies the exact slice.
 */
export function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.slice().buffer as ArrayBuffer;
}

/**
 * Checks whether the given bytes are an AUTHENTICATED MySecret container.
 *
 * WHY THIS EXISTS: Obsidian Sync downloads the ciphertext of a file and writes
 * it back to disk through `vault.modifyBinary()` -> `adapter.writeBinary()`.
 * If the write hook encrypted the payload again, the file would end up
 * encrypted TWICE and could never be decrypted (the second layer would be
 * encrypted with the wrong AAD semantics and would silently rot the vault).
 *
 * The check is cryptographic, not just structural: the container is
 * authenticated by decrypting it with the AAD bound to the target path. Only
 * a container produced by MySecret itself (with the correct key and AAD)
 * passes the test, so a file that merely *looks* like a container (for
 * example an image whose first bytes happen to be "MYSE") is still encrypted
 * normally and never leaks in cleartext.
 *
 * @param rawBytes   The bytes that are about to be written to disk.
 * @param aad        The normalized vault path bound as AES-GCM AAD.
 * @param keyManager The key manager holding the unlocked vault key.
 * @returns `true` when the bytes are a valid, authenticated ciphertext for
 *          that exact path (and therefore must be stored verbatim).
 */
export async function isAuthenticContainer(
  rawBytes: Uint8Array,
  aad: string,
  keyManager: KeyManager
): Promise<boolean> {
  const format = detectContainerFormat(rawBytes);
  if (format === 'plain') return false;

  const vaultKey = keyManager.getVaultKey();
  if (!vaultKey) return false;

  try {
    if (format === 'binary') {
      const payload = deserializeBinary(rawBytes);
      await decryptAesGcm(
        payload.ciphertext,
        vaultKey,
        payload.iv,
        payload.tag,
        aad
      );
    } else {
      const payload = deserializeArmored(new TextDecoder().decode(rawBytes));
      await decryptAesGcm(
        payload.ciphertext,
        vaultKey,
        payload.iv,
        payload.tag,
        aad
      );
    }
    return true;
  } catch {
    // The authentication tag did not verify: this is NOT a container produced
    // by MySecret for this path, so it must be encrypted normally.
    return false;
  }
}
