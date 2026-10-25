/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * MetadataCache Hash Alignment (Sync consistency)
 */

import { App } from 'obsidian';
import { sha256Hex } from '../crypto/hash';

/**
 * Keeps the hash reported by the metadata cache aligned with the hash that
 * Obsidian Sync computes.
 *
 * THE PROBLEM
 * -----------
 * Obsidian computes TWO hashes for the same file:
 *
 *   * The metadata indexer computes `SHA-256(vault.readBinary(file))`. Because
 *     `Vault.readBinary` is hooked by MySecret to return the PLAINTEXT, the
 *     cached hash is the hash of the plaintext.
 *   * Obsidian Sync computes `SHA-256(adapter.readBinary(path))`, i.e. the
 *     hash of the CIPHERTEXT that is stored on disk and uploaded to the
 *     cloud.
 *
 * Sync reuses the hash cached by the metadata indexer
 * (`metadataCache.getFileInfo(path).hash`) to decide whether a file changed.
 * Since the two hashes are computed over DIFFERENT bytes they can never be
 * equal, so Sync would consider that EVERY file changed on EVERY run: it
 * would download the whole vault again and write it back, forever.
 *
 * THE FIX
 * -------
 * The hash exposed through `metadataCache.getFileInfo()` is replaced with the
 * hash of the ciphertext (the bytes that are really stored on disk and that
 * Sync uploads), which is exactly what Sync compares against.
 *
 * The returned object is a COPY on purpose: the original hash is the key of
 * the map that holds the parsed metadata
 * (`metadataCache[hash]`), so mutating it in place would make the metadata
 * cache lose the links, the footnotes and the frontmatter of every note.
 */
export class MetadataHashPatch {
  private app: App;
  private ciphertextHashes: Map<string, string> = new Map();
  private origGetFileInfo?: (path: string) => any;
  private installed: boolean = false;

  constructor(app: App) {
    this.app = app;
  }

  /**
   * Installs the patch over `metadataCache.getFileInfo()`.
   *
   * The method is an internal (but stable) API of Obsidian: it is the one
   * used by Obsidian Sync and by Obsidian Publish to read the hash of a
   * file. When it is not available the patch is simply skipped and the
   * plugin keeps working (only the Sync efficiency is degraded).
   */
  public install(): void {
    if (this.installed) return;

    const metadataCache = this.app.metadataCache as any;
    if (!metadataCache || typeof metadataCache.getFileInfo !== 'function') {
      return;
    }

    this.origGetFileInfo = metadataCache.getFileInfo.bind(metadataCache);

    // eslint-disable-next-line @typescript-eslint/no-this-alias -- Preserve the patch instance across the patched method
    const self = this;

    metadataCache.getFileInfo = function (path: string): any {
      const info = self.origGetFileInfo!(path);
      if (!info) return info;

      const ciphertextHash = self.ciphertextHashes.get(path);
      if (!ciphertextHash || info.hash === ciphertextHash) {
        return info;
      }

      // A COPY is returned: the original object keeps the hash that indexes
      // the parsed metadata, so the metadata cache stays fully functional.
      return { ...info, hash: ciphertextHash };
    };

    this.installed = true;
  }

  /**
   * Computes and records the SHA-256 hash of the ciphertext stored on disk.
   *
   * It MUST be fed the RAW bytes (the ones that are physically stored), never
   * the decrypted ones, because that is what Sync hashes and uploads.
   *
   * @param path The vault path of the file.
   * @param ciphertextBytes The bytes as they are stored on disk.
   */
  public async recordCiphertextHashFromBytes(
    path: string,
    ciphertextBytes: Uint8Array
  ): Promise<void> {
    if (!path) return;
    try {
      const hash = await sha256Hex(ciphertextBytes);
      this.ciphertextHashes.set(path, hash);
    } catch (err) {
      console.warn(`[MySecret] Could not compute the sync hash for ${path}:`, err);
    }
  }

  /**
   * Records the SHA-256 hash of the ciphertext that is stored on disk for
   * the given path.
   *
   * @param path The vault path of the file.
   * @param hash The lowercase hex SHA-256 digest of the on-disk bytes.
   */
  public recordCiphertextHash(path: string, hash: string): void {
    if (!path) return;
    this.ciphertextHashes.set(path, hash);
  }

  /**
   * Forgets the hash of a file that no longer exists.
   */
  public forget(path: string): void {
    this.ciphertextHashes.delete(path);
  }

  /**
   * Restores the original `metadataCache.getFileInfo()`.
   */
  public uninstall(): void {
    if (!this.installed) return;

    const metadataCache = this.app.metadataCache as any;
    if (metadataCache && this.origGetFileInfo) {
      metadataCache.getFileInfo = this.origGetFileInfo;
      this.origGetFileInfo = undefined;
    }

    this.ciphertextHashes.clear();
    this.installed = false;
  }
}
