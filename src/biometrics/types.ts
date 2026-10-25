/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Biometric Types and Contracts
 */

export type BiometricProviderType = 'windows-hello' | 'linux-secret-service' | 'webauthn' | 'external-bridge' | 'none';

export type BiometricStatus =
  | 'available'
  | 'enrolled'
  | 'unsupported'
  | 'hardware_unavailable'
  | 'permission_denied';

export interface BiometricCapabilities {
  supported: boolean;
  enrolled: boolean;
  providerType: BiometricProviderType;
  label: string;
  error?: string;
}

/**
 * Encrypted payload stored locally on the specific device.
 * Never synced across different hardware devices.
 */
export interface DeviceBiometricEnvelope {
  /**
   * Format version. See `BIOMETRIC_ENVELOPE_VERSION` in `./kdf.ts`.
   * Envelopes with a different version are rejected by the manager.
   */
  version: number;
  deviceId: string;
  providerType: BiometricProviderType;
  /**
   * Provider specific unlock mode (e.g. `fprintd` vs `secret-service` on
   * Linux). It records WHICH gate actually protects the secret, so the gate
   * can be re-applied (and fail closed) at unlock time.
   */
  mode?: string;
  createdAt: number;
  updatedAt: number;
  iv: string;
  tag: string;
  ciphertext: string;
  /**
   * SHA-256 fingerprint of the raw vault key to verify integrity
   * immediately upon decryption before instantiating in KeyManager.
   */
  keyCheck: string;
  /** WebAuthn: base64url identifier of the enrolled credential. */
  credentialId?: string;
  /** WebAuthn: base64 SPKI of the credential public key. */
  credentialPublicKey?: string;
  /** WebAuthn: hex-encoded PRF salt (32 bytes). */
  prfSalt?: string;
  /**
   * WebAuthn: the relying party id the credential was enrolled for.
   *
   * SECURITY: it is PINNED at enrollment time. A credential created for a
   * given RP ID must never be usable from another origin, otherwise a
   * sibling subdomain sharing the same registrable domain could replay it.
   */
  rpId?: string;
  /**
   * WebAuthn: the exact origin (`https://host[:port]`) the credential was
   * enrolled for. It is verified against the `clientData.origin` of every
   * assertion, which is the WebAuthn phishing protection.
   */
  origin?: string;
}

export interface BiometricProvider {
  readonly type: BiometricProviderType;
  readonly name: string;
  isAvailable(): Promise<boolean>;
  /**
   * Protects `rawVaultKey` with a device-bound secret and returns the
   * envelope to persist locally.
   *
   * @param deviceId Unique identifier of this physical device.
   * @param vaultId  Identifier of the vault the envelope belongs to. It is
   *                 mixed into the AAD so the envelope cannot be transplanted.
   */
  enroll(rawVaultKey: Uint8Array, deviceId: string, vaultId: string): Promise<DeviceBiometricEnvelope>;
  /**
   * Performs the platform unlock gate and decrypts the vault key.
   *
   * @param vaultId Identifier of the vault the envelope belongs to.
   */
  verifyAndDecrypt(envelope: DeviceBiometricEnvelope, vaultId: string): Promise<Uint8Array | null>;
}
