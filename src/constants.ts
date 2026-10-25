/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Constants & Cryptographic Parameters
 */

export const PLUGIN_NAME = 'MySecret';
export const PLUGIN_ID = 'mysecret';

// File Magic Headers & Identifiers
export const ARMORED_HEADER_START = '-----BEGIN MYSECRET ENCRYPTED FILE-----';
export const ARMORED_HEADER_END = '-----END MYSECRET ENCRYPTED FILE-----';
export const BINARY_MAGIC = new Uint8Array([0x4d, 0x59, 0x53, 0x45]); // "MYSE"
export const CURRENT_ENVELOPE_VERSION = 1;

// Binary Header Lengths (Fixed 32 bytes)
// [0..3]: Magic (4 bytes)
// [4]: Version (1 byte)
// [5..16]: IV (12 bytes)
// [17..32]: Tag (16 bytes)
// [33..]: Ciphertext
export const BINARY_HEADER_LENGTH = 33; // 4 + 1 + 12 + 16 = 33 bytes

// Cryptographic Parameters
export const AES_GCM_IV_LENGTH = 12; // 96 bits
export const AES_GCM_TAG_LENGTH = 16; // 128 bits
export const AES_KEY_BIT_LENGTH = 256; // AES-256

// Argon2id Parameters for Master Key Derivation
export const ARGON2_MEMORY_KIB = 65536; // 64 MB
export const ARGON2_ITERATIONS = 3;
export const ARGON2_PARALLELISM = 1;
export const ARGON2_HASH_LENGTH = 32; // 256 bits output
export const ARGON2_SALT_LENGTH = 16; // 128 bits salt

/**
 * Hard floors applied to the Argon2id cost parameters.
 *
 * The parameters live inside `vault-envelope.json`, which lives inside the
 * vault and is therefore editable by anyone able to read the vault. Without
 * these floors an attacker could rewrite the envelope and downgrade the KDF
 * (e.g. 8 KiB / 1 iteration instead of 64 MiB / 3 iterations), turning a
 * 240 ms key derivation into a 2 ms one and making offline brute-force
 * trivial. Envelopes whose parameters fall below the floor are REJECTED
 * (never silently upgraded, because that would derive a different key).
 */
export const MIN_ARGON2_MEMORY_KIB = 65536; // 64 MB
export const MIN_ARGON2_ITERATIONS = 3;
export const MIN_ARGON2_PARALLELISM = 1;

/**
 * Hard ceilings applied to the Argon2id cost parameters.
 *
 * They exist to prevent a denial-of-service: a tampered envelope asking for
 * 4 GiB of memory would crash the renderer.
 */
export const MAX_ARGON2_MEMORY_KIB = 1048576; // 1 GiB
export const MAX_ARGON2_ITERATIONS = 20;
export const MAX_ARGON2_PARALLELISM = 16;

/**
 * Minimum length enforced for the master password everywhere it is set
 * (initial setup wizard *and* password change flow).
 */
export const MIN_MASTER_PASSWORD_LENGTH = 12;

/**
 * Maximum number of entries accepted when restoring a backup archive.
 */
export const MAX_RESTORE_ENTRIES = 50000;

/**
 * Maximum size (in bytes) accepted for a single restored file.
 */
export const MAX_RESTORE_ENTRY_BYTES = 512 * 1024 * 1024;

/**
 * Maximum total uncompressed size (in bytes) accepted from a backup archive.
 * Protects against ZIP bombs (decompression bomb).
 */
export const MAX_RESTORE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024;

/**
 * Maximum size (in bytes) accepted for the backup archive itself.
 */
export const MAX_RESTORE_ARCHIVE_BYTES = 512 * 1024 * 1024;

// BIP-39 Parameters
export const BIP39_WORD_COUNT = 24;
export const BIP39_ENTROPY_BITS = 256; // 256 bits for 24 words

// Vault Envelope Storage Path
export const VAULT_ENVELOPE_FILENAME = 'vault-envelope.json';
export const VAULT_ENVELOPE_PATH = `.obsidian/plugins/${PLUGIN_ID}/${VAULT_ENVELOPE_FILENAME}`;

// Default Exclusions (never encrypt system or git files)
export const SYSTEM_EXCLUDED_PREFIXES = [
  '.obsidian/',
  '.git/',
  '.trash/'
];
