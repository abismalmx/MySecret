/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * KeyManager: In-Memory Key State, Argon2id Unlocking & Secure Zeroize
 */

import { VaultEnvelopeConfig, InitializeVaultResult } from '../types';
import {
  ARGON2_ITERATIONS,
  ARGON2_MEMORY_KIB,
  ARGON2_PARALLELISM,
  CURRENT_ENVELOPE_VERSION
} from '../constants';
import { deriveKeyArgon2id, generateSalt, assertArgon2CostParams } from './argon2';
import { encryptAesGcm, decryptAesGcm, importAesKey } from './aes';
import { bytesToHex, hexToBytes } from '../utils/buffer';
import { generateMnemonic, validateMnemonic, mnemonicToKey } from './bip39';
import { zeroize } from '../utils/zeroize';

export class KeyManager {
  private _isLocked: boolean = true;
  private vaultKey: CryptoKey | null = null;
  private rawVaultKey: Uint8Array | null = null;
  private envelope: VaultEnvelopeConfig | null = null;

  /**
   * The BIP-39 recovery phrase of the current vault, kept in RAM only.
   *
   * It is NOT persisted to disk (that would defeat the purpose of a
   * recovery phrase) but it is retained for the lifetime of the session so
   * the user can display it again if the setup wizard was closed before they
   * had a chance to write it down. Losing it would permanently lock the user
   * out of the vault. It is wiped whenever the vault is locked.
   */
  private recoveryMnemonic: string | null = null;

  public get isLocked(): boolean {
    return this._isLocked;
  }

  public get isInitialized(): boolean {
    return this.envelope !== null;
  }

  /**
   * Returns the recovery phrase if it is still held in memory.
   */
  public getRecoveryMnemonic(): string | null {
    return this.recoveryMnemonic;
  }

  public getVaultKey(): CryptoKey | null {
    if (this._isLocked) return null;
    return this.vaultKey;
  }

  /**
   * Returns a temporary copy of the raw 32-byte VaultKey in RAM.
   * Only accessible when the vault is currently unlocked.
   */
  public getRawVaultKey(): Uint8Array | null {
    if (this._isLocked || !this.rawVaultKey) return null;
    return new Uint8Array(this.rawVaultKey);
  }

  public getEnvelope(): VaultEnvelopeConfig | null {
    return this.envelope;
  }

  public setEnvelope(config: VaultEnvelopeConfig): void {
    this.envelope = config;
  }

  /**
   * Initializes a brand new vault:
   * Generates a 256-bit VaultKey, sets master password via Argon2id,
   * optionally generates a 24-word BIP-39 recovery mnemonic, and wraps the VaultKey.
   */
  public async initializeVault(
    masterPassword: string,
    enableRecoveryPhrase: boolean = true
  ): Promise<InitializeVaultResult> {
    // 1. Generate 256-bit random VaultKey (DEK)
    const rawKey = new Uint8Array(32);
    window.crypto.getRandomValues(rawKey);

    // 2. Generate 16-byte Argon2id salt
    const salt = generateSalt();

    let passKeyBytes: Uint8Array | null = null;
    let recoveryKeyBytes: Uint8Array | null = null;

    try {
      // 3. Derive PassKey via Argon2id
      passKeyBytes = await deriveKeyArgon2id(
        masterPassword,
        salt,
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM
      );
      const passKey = await importAesKey(passKeyBytes);

      // 4. Encrypt raw VaultKey with PassKey
      const vaultKeyEnc = await encryptAesGcm(rawKey, passKey, 'vault-envelope');

      // 5. Optionally generate 24-word BIP-39 mnemonic
      let mnemonic: string | null = null;
      let recoveryEnvelope: VaultEnvelopeConfig['recoveryEnvelope'] | undefined = undefined;

      if (enableRecoveryPhrase) {
        mnemonic = generateMnemonic();
        const recoverySalt = generateSalt();
        recoveryKeyBytes = await mnemonicToKey(mnemonic, recoverySalt);
        const recoveryKey = await importAesKey(recoveryKeyBytes);

        // 6. Encrypt raw VaultKey with Recovery Key
        const recoveryKeyEnc = await encryptAesGcm(rawKey, recoveryKey, 'recovery-envelope');
        recoveryEnvelope = {
          salt: bytesToHex(recoverySalt),
          iv: bytesToHex(recoveryKeyEnc.iv),
          tag: bytesToHex(recoveryKeyEnc.tag),
          ciphertext: bytesToHex(recoveryKeyEnc.ciphertext)
        };
      }

      const now = Date.now();
      const newEnvelope: VaultEnvelopeConfig = {
        version: CURRENT_ENVELOPE_VERSION,
        argon2: {
          memory: ARGON2_MEMORY_KIB,
          iterations: ARGON2_ITERATIONS,
          parallelism: ARGON2_PARALLELISM,
          salt: bytesToHex(salt)
        },
        vaultKeyEnvelope: {
          iv: bytesToHex(vaultKeyEnc.iv),
          tag: bytesToHex(vaultKeyEnc.tag),
          ciphertext: bytesToHex(vaultKeyEnc.ciphertext)
        },
        recoveryEnvelope,
        createdAt: now,
        updatedAt: now
      };

      return {
        mnemonic,
        envelope: newEnvelope,
        commit: async () => {
          this.envelope = newEnvelope;
          this.rawVaultKey = new Uint8Array(rawKey);
          this.vaultKey = await importAesKey(rawKey);
          this.recoveryMnemonic = mnemonic;
          this._isLocked = false;
          // SECURITY: the temporary copy of the raw vault key is no longer
          // needed once it has been imported into the CryptoKey and copied
          // into `this.rawVaultKey`. Leaving it in the heap would keep a
          // second, unprotected copy of the master key alive for the whole
          // session.
          zeroize(rawKey);
        }
      };
    } finally {
      // Clean up temporary derivation keys (also on the error path).
      zeroize(passKeyBytes);
      zeroize(recoveryKeyBytes);
    }
  }

  public hasRecoveryEnvelope(): boolean {
    return Boolean(this.envelope && this.envelope.recoveryEnvelope);
  }

  public async addRecoveryPhrase(): Promise<{ mnemonic: string; envelope: VaultEnvelopeConfig }> {
    if (this._isLocked || !this.rawVaultKey || !this.envelope) {
      throw new Error('[MySecret] La bóveda debe estar desbloqueada para generar la frase de recuperación');
    }
    const mnemonic = generateMnemonic();
    const recoverySalt = generateSalt();
    let recoveryKeyBytes: Uint8Array | null = null;
    try {
      recoveryKeyBytes = await mnemonicToKey(mnemonic, recoverySalt);
      const recoveryKey = await importAesKey(recoveryKeyBytes);
      const recoveryKeyEnc = await encryptAesGcm(this.rawVaultKey, recoveryKey, 'recovery-envelope');
      this.envelope.recoveryEnvelope = {
        salt: bytesToHex(recoverySalt),
        iv: bytesToHex(recoveryKeyEnc.iv),
        tag: bytesToHex(recoveryKeyEnc.tag),
        ciphertext: bytesToHex(recoveryKeyEnc.ciphertext)
      };
      this.envelope.updatedAt = Date.now();
      this.recoveryMnemonic = mnemonic;
      return { mnemonic, envelope: this.envelope };
    } finally {
      zeroize(recoveryKeyBytes);
    }
  }

  public removeRecoveryPhrase(): VaultEnvelopeConfig {
    if (this._isLocked || !this.envelope) {
      throw new Error('[MySecret] La bóveda debe estar desbloqueada para modificar la recuperación');
    }
    delete this.envelope.recoveryEnvelope;
    this.envelope.updatedAt = Date.now();
    this.recoveryMnemonic = null;
    return this.envelope;
  }

  /**
   * Unlocks the vault using the user's master password
   */
  public async unlockWithPassword(masterPassword: string): Promise<boolean> {
    if (!this.envelope) {
      throw new Error('[MySecret] Vault envelope configuration is missing');
    }

    // SECURITY: the envelope lives inside the vault, so its cost parameters
    // must be treated as untrusted input. Refuse to derive a key with
    // downgraded parameters instead of silently using them.
    try {
      assertArgon2CostParams({
        memoryKib: this.envelope.argon2.memory,
        iterations: this.envelope.argon2.iterations,
        parallelism: this.envelope.argon2.parallelism
      });
    } catch (err) {
      console.error('[MySecret] Refusing to unlock with tampered KDF parameters:', err);
      throw err;
    }

    let passKeyBytes: Uint8Array | null = null;
    try {
      const salt = hexToBytes(this.envelope.argon2.salt);
      passKeyBytes = await deriveKeyArgon2id(
        masterPassword,
        salt,
        this.envelope.argon2.memory,
        this.envelope.argon2.iterations,
        this.envelope.argon2.parallelism
      );
      const passKey = await importAesKey(passKeyBytes);

      const iv = hexToBytes(this.envelope.vaultKeyEnvelope.iv);
      const tag = hexToBytes(this.envelope.vaultKeyEnvelope.tag);
      const ciphertext = hexToBytes(this.envelope.vaultKeyEnvelope.ciphertext);

      const decryptedRawKey = await decryptAesGcm(ciphertext, passKey, iv, tag, 'vault-envelope');

      this.rawVaultKey = new Uint8Array(decryptedRawKey);
      this.vaultKey = await importAesKey(decryptedRawKey);
      this._isLocked = false;
      return true;
    } catch (err) {
      console.warn('[MySecret] Unlock failed (invalid password or corrupted envelope):', err);
      return false;
    } finally {
      // Always wipe the derived pass key, including on the failure path.
      zeroize(passKeyBytes);
    }
  }

  /**
   * Unlocks the vault using the 24-word BIP-39 recovery mnemonic
   */
  public async unlockWithRecoveryPhrase(mnemonic: string): Promise<boolean> {
    if (!this.envelope || !this.envelope.recoveryEnvelope) {
      throw new Error('[MySecret] Recovery envelope configuration is missing');
    }

    const cleanMnemonic = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');
    if (!validateMnemonic(cleanMnemonic)) {
      throw new Error('[MySecret] Invalid BIP-39 mnemonic phrase');
    }

    let recoveryKeyBytes: Uint8Array | null = null;
    try {
      const recoverySalt = hexToBytes(this.envelope.recoveryEnvelope.salt);
      recoveryKeyBytes = await mnemonicToKey(cleanMnemonic, recoverySalt);
      const recoveryKey = await importAesKey(recoveryKeyBytes);

      const iv = hexToBytes(this.envelope.recoveryEnvelope.iv);
      const tag = hexToBytes(this.envelope.recoveryEnvelope.tag);
      const ciphertext = hexToBytes(this.envelope.recoveryEnvelope.ciphertext);

      const decryptedRawKey = await decryptAesGcm(ciphertext, recoveryKey, iv, tag, 'recovery-envelope');

      this.rawVaultKey = new Uint8Array(decryptedRawKey);
      this.vaultKey = await importAesKey(decryptedRawKey);
      this._isLocked = false;
      return true;
    } catch (err) {
      console.warn('[MySecret] Recovery unlock failed:', err);
      return false;
    } finally {
      // Always wipe the derived recovery key, including on the failure path.
      zeroize(recoveryKeyBytes);
    }
  }

  /**
   * Unlocks the vault using the verified 32-byte VaultKey decrypted by biometrics
   *
   * SECURITY: the caller hands over ownership of `rawKey`. It is ALWAYS wiped
   * from memory, including on the rejection paths (a wrong length or a
   * missing envelope), otherwise a failed attempt would leave the vault key
   * sitting in the heap.
   */
  public async unlockWithRawVaultKey(rawKey: Uint8Array): Promise<boolean> {
    try {
      if (!this.envelope) {
        throw new Error('[MySecret] Vault envelope configuration is missing');
      }
      if (!rawKey || rawKey.length !== 32) {
        throw new Error('[MySecret] Invalid vault key length from biometrics');
      }

      try {
        this.rawVaultKey = new Uint8Array(rawKey);
        this.vaultKey = await importAesKey(rawKey);
        this._isLocked = false;
        return true;
      } catch (err) {
        console.error('[MySecret] Biometric unlock failed to import vault key:', err);
        return false;
      }
    } finally {
      zeroize(rawKey);
    }
  }

  /**
   * Instant O(1) Master Password change without touching note files on disk
   */
  public async changeMasterPassword(newPassword: string): Promise<VaultEnvelopeConfig> {
    if (this._isLocked || !this.rawVaultKey || !this.envelope) {
      throw new Error('[MySecret] Vault must be unlocked to change password');
    }

    // Never re-wrap the vault key with downgraded cost parameters.
    assertArgon2CostParams({
      memoryKib: this.envelope.argon2.memory,
      iterations: this.envelope.argon2.iterations,
      parallelism: this.envelope.argon2.parallelism
    });

    const newSalt = generateSalt();
    let newPassKeyBytes: Uint8Array | null = null;
    try {
      newPassKeyBytes = await deriveKeyArgon2id(
        newPassword,
        newSalt,
        this.envelope.argon2.memory,
        this.envelope.argon2.iterations,
        this.envelope.argon2.parallelism
      );
      const newPassKey = await importAesKey(newPassKeyBytes);

      const vaultKeyEnc = await encryptAesGcm(this.rawVaultKey, newPassKey, 'vault-envelope');

      this.envelope.argon2.salt = bytesToHex(newSalt);
      this.envelope.vaultKeyEnvelope = {
        iv: bytesToHex(vaultKeyEnc.iv),
        tag: bytesToHex(vaultKeyEnc.tag),
        ciphertext: bytesToHex(vaultKeyEnc.ciphertext)
      };
      this.envelope.updatedAt = Date.now();
    } finally {
      // Always wipe the newly derived pass key, including on the failure path.
      zeroize(newPassKeyBytes);
    }

    return this.envelope;
  }

  /**
   * Locks the vault and securely wipes keys from RAM
   */
  public lock(): void {
    this._isLocked = true;
    this.vaultKey = null;
    // The recovery phrase is secret material too: wipe it from RAM.
    this.recoveryMnemonic = null;
    if (this.rawVaultKey) {
      zeroize(this.rawVaultKey);
      this.rawVaultKey = null;
    }
  }
}
