/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Device-Specific Local Storage for Biometric Envelopes
 *
 * Ensures that biometric tokens are strictly tied to the physical device
 * and are NEVER synchronized across devices (e.g. via Obsidian Sync, Git, or cloud sync).
 */

import { DeviceBiometricEnvelope } from './types';
import { bytesToHex } from '../utils/buffer';
import { BIOMETRIC_ENVELOPE_VERSION } from './kdf';

const DEVICE_ID_KEY = 'mysecret_device_id_v1';
const ENVELOPE_PREFIX = 'mysecret_bio_envelope_v1_';

export class DeviceBiometricStorage {
  private static cachedDeviceId: string | null = null;

  /**
   * Returns a persistent random Device ID unique to this physical machine/profile.
   *
   * SECURITY: the fallback path MUST NOT use `Math.random()`. The device id
   * is mixed into the key derivation, so a predictable value would weaken
   * the biometric envelope. When no CSPRNG is available the provider simply
   * refuses to work instead of degrading to a predictable identifier.
   */
  public static getDeviceId(): string {
    if (this.cachedDeviceId) {
      return this.cachedDeviceId;
    }

    try {
      if (typeof window !== 'undefined' && window.localStorage) {
        let id = window.localStorage.getItem(DEVICE_ID_KEY);
        if (!id) {
          const randomBytes = new Uint8Array(16);
          window.crypto.getRandomValues(randomBytes);
          id = bytesToHex(randomBytes);
          window.localStorage.setItem(DEVICE_ID_KEY, id);
        }
        this.cachedDeviceId = id;
        return id;
      }
    } catch {
      // Fallback if localStorage is inaccessible
    }

    // No localStorage: derive a stable-per-session id from a CSPRNG.
    const fallbackBytes = new Uint8Array(16);
    if (typeof window !== 'undefined' && window.crypto && typeof window.crypto.getRandomValues === 'function') {
      window.crypto.getRandomValues(fallbackBytes);
    } else {
      throw new Error(
        'MySecret: no hay un generador de entropía criptográfica disponible en este entorno.'
      );
    }
    this.cachedDeviceId = bytesToHex(fallbackBytes);
    return this.cachedDeviceId;
  }

  /**
   * Saves the biometric envelope for a specific vault on this physical device.
   */
  public static saveEnvelope(vaultSaltOrId: string, envelope: DeviceBiometricEnvelope): void {
    if (typeof window === 'undefined' || !window.localStorage) {
      return;
    }
    const key = `${ENVELOPE_PREFIX}${vaultSaltOrId}`;
    window.localStorage.setItem(key, JSON.stringify(envelope));
  }

  /**
   * Loads the biometric envelope for a specific vault on this physical device.
   *
   * SECURITY: envelopes whose format version is not the current one are
   * REJECTED. Version 1 envelopes were produced with the weaker key
   * derivations (public machine identifiers / public credential ids) and must
   * be re-enrolled; silently accepting them would keep the old weakness
   * alive.
   */
  public static loadEnvelope(vaultSaltOrId: string): DeviceBiometricEnvelope | null {
    const parsed = this.loadRawEnvelope(vaultSaltOrId);
    if (!parsed) {
      return null;
    }
    if (parsed.version !== BIOMETRIC_ENVELOPE_VERSION) {
      console.warn(
        `[MySecret] Sobre biométrico con versión obsoleta (${parsed.version}); se requiere re-enrolar.`
      );
      return null;
    }
    return parsed;
  }

  /**
   * Loads the stored envelope IGNORING the version check.
   *
   * It exists for housekeeping tasks (e.g. deleting the OS keyring entry of
   * a legacy enrollment), which must still run for obsolete envelopes.
   */
  public static loadRawEnvelope(vaultSaltOrId: string): DeviceBiometricEnvelope | null {
    if (typeof window === 'undefined' || !window.localStorage) {
      return null;
    }
    const key = `${ENVELOPE_PREFIX}${vaultSaltOrId}`;
    const raw = window.localStorage.getItem(key);
    if (!raw) return null;

    try {
      const parsed = JSON.parse(raw) as DeviceBiometricEnvelope;
      if (!parsed || !parsed.ciphertext) {
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  }

  /**
   * Removes the biometric envelope from this physical device.
   */
  public static clearEnvelope(vaultSaltOrId: string): void {
    if (typeof window === 'undefined' || !window.localStorage) {
      return;
    }
    const key = `${ENVELOPE_PREFIX}${vaultSaltOrId}`;
    window.localStorage.removeItem(key);
  }
}
