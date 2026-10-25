/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * SHA-256 Hashing (Obsidian-compatible hex encoding)
 */

/**
 * Computes the SHA-256 digest of `data` and returns it as a LOWERCASE HEX
 * string.
 *
 * WHY THIS MUST MATCH OBSIDIAN EXACTLY:
 *
 * Obsidian computes two different hashes for the same file:
 *
 *   * The metadata indexer computes `SHA-256(vault.readBinary(file))`, i.e.
 *     the hash of the PLAINTEXT (because `Vault.readBinary` is hooked to
 *     decrypt).
 *   * Obsidian Sync computes `SHA-256(adapter.readBinary(path))`, i.e. the
 *     hash of the CIPHERTEXT, and it reuses the hash cached by the metadata
 *     indexer (`metadataCache.getFileInfo(path).hash`) to decide whether a
 *     file has changed.
 *
 * If the two hashes never match, Sync believes that every file changed on
 * every single run: it downloads the whole vault again and writes it back,
 * forever.
 *
 * Obsidian renders the digest with its own hex encoder, which produces
 * lowercase hexadecimal, two characters per byte, with no separator. This
 * helper reproduces that encoding byte for byte so the two hashes are
 * comparable.
 *
 * @param data The bytes to hash.
 * @returns The lowercase hex SHA-256 digest.
 */
export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = await window.crypto.subtle.digest(
    'SHA-256',
    data as BufferSource
  );
  const bytes = new Uint8Array(digest);

  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}
