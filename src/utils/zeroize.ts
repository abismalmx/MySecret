/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Cryptographic Zeroize: Securely overwrites memory buffers with zeros
 */

/**
 * Securely overwrites the underlying memory of a Uint8Array with zeros (0x00).
 * Prevents sensitive cryptographic material (keys, decrypted chunks) from lingering in memory.
 */
export function zeroize(buffer: Uint8Array | null | undefined): void {
  if (!buffer) return;
  try {
    buffer.fill(0);
  } catch {
    // Fallback if fill is not available or frozen
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] = 0;
    }
  }
}
