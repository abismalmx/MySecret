/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Argon2id Key Derivation via WebAssembly (hash-wasm)
 */

import { argon2id } from 'hash-wasm';
import {
  ARGON2_HASH_LENGTH,
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  ARGON2_SALT_LENGTH,
  MIN_ARGON2_MEMORY_KIB,
  MIN_ARGON2_ITERATIONS,
  MIN_ARGON2_PARALLELISM,
  MAX_ARGON2_MEMORY_KIB,
  MAX_ARGON2_ITERATIONS,
  MAX_ARGON2_PARALLELISM
} from '../constants';

/**
 * Generates a cryptographically secure 16-byte random salt
 */
export function generateSalt(): Uint8Array {
  const salt = new Uint8Array(ARGON2_SALT_LENGTH);
  window.crypto.getRandomValues(salt);
  return salt;
}

export interface Argon2CostParams {
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

/**
 * Validates Argon2id cost parameters against the hard floors/ceilings defined
 * in `constants.ts`.
 *
 * This is a SECURITY CONTROL, not a sanity check: the parameters are stored
 * in `vault-envelope.json`, inside the vault, so they are attacker-controlled
 * for anyone who can copy the vault off the disk. Accepting `memory=8 KiB` or
 * `iterations=1` would downgrade the key derivation from ~240 ms to ~2 ms and
 * make an offline dictionary attack against the master password trivial.
 *
 * @throws Error when the parameters are outside the allowed range.
 */
export function assertArgon2CostParams(params: Argon2CostParams): void {
  const { memoryKib, iterations, parallelism } = params;

  if (!Number.isInteger(memoryKib) || memoryKib < MIN_ARGON2_MEMORY_KIB) {
    throw new Error(
      `[MySecret] Argon2id memory cost is too low (${memoryKib} KiB). ` +
      `At least ${MIN_ARGON2_MEMORY_KIB} KiB is required.`
    );
  }
  if (memoryKib > MAX_ARGON2_MEMORY_KIB) {
    throw new Error(
      `[MySecret] Argon2id memory cost is too high (${memoryKib} KiB). ` +
      `At most ${MAX_ARGON2_MEMORY_KIB} KiB is allowed.`
    );
  }
  if (!Number.isInteger(iterations) || iterations < MIN_ARGON2_ITERATIONS) {
    throw new Error(
      `[MySecret] Argon2id iterations are too low (${iterations}). ` +
      `At least ${MIN_ARGON2_ITERATIONS} are required.`
    );
  }
  if (iterations > MAX_ARGON2_ITERATIONS) {
    throw new Error(
      `[MySecret] Argon2id iterations are too high (${iterations}). ` +
      `At most ${MAX_ARGON2_ITERATIONS} are allowed.`
    );
  }
  if (!Number.isInteger(parallelism) || parallelism < MIN_ARGON2_PARALLELISM) {
    throw new Error(
      `[MySecret] Argon2id parallelism is too low (${parallelism}). ` +
      `At least ${MIN_ARGON2_PARALLELISM} is required.`
    );
  }
  if (parallelism > MAX_ARGON2_PARALLELISM) {
    throw new Error(
      `[MySecret] Argon2id parallelism is too high (${parallelism}). ` +
      `At most ${MAX_ARGON2_PARALLELISM} is allowed.`
    );
  }
}

/**
 * Derives a 256-bit (32 bytes) master key from a user password using Argon2id
 *
 * @param password Master password entered by user
 * @param salt 16-byte random salt
 * @param memoryKib Memory cost in KiB (default: 64 MB)
 * @param iterations Iterations / Time cost (default: 3)
 */
export async function deriveKeyArgon2id(
  password: string,
  salt: Uint8Array,
  memoryKib: number = ARGON2_MEMORY_KIB,
  iterations: number = ARGON2_ITERATIONS,
  parallelism: number = ARGON2_PARALLELISM
): Promise<Uint8Array> {
  // Never derive with attacker-controlled (downgraded) cost parameters.
  assertArgon2CostParams({ memoryKib, iterations, parallelism });

  const hashBytes = await argon2id({
    password: password,
    salt: salt,
    parallelism: parallelism,
    iterations: iterations,
    memorySize: memoryKib,
    hashLength: ARGON2_HASH_LENGTH,
    outputType: 'binary'
  });

  return new Uint8Array(hashBytes);
}
