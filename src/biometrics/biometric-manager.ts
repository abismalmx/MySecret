/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * BiometricManager: Central Orchestrator for Biometric Authentication
 *
 * Coordinates platform-specific providers (Windows Hello, Linux fprintd/SecretService, WebAuthn)
 * and manages device-local biometric enrollment without affecting multi-device vault sync.
 */

import { Platform } from 'obsidian';
import { BiometricCapabilities, BiometricProvider, DeviceBiometricEnvelope } from './types';
import { DeviceBiometricStorage } from './device-storage';
import { WindowsHelloProvider } from './windows-provider';
import { LinuxBiometricProvider } from './linux-provider';
import { WebAuthnProvider } from './webauthn-provider';
import { ExternalBridgeProvider } from './external-bridge-provider';

export class BiometricManager {
  private activeProvider: BiometricProvider | null = null;
  private isEvaluated: boolean = false;

  constructor(bridgeUrl?: string) {
    this.selectProvider(bridgeUrl);
  }

  public selectProvider(bridgeUrl?: string): void {
    if (Platform.isWin) {
      this.activeProvider = new WindowsHelloProvider();
    } else if (Platform.isLinux && !Platform.isAndroidApp) {
      this.activeProvider = new LinuxBiometricProvider();
    } else if (Platform.isAndroidApp) {
      // Android WebView lacks native WebAuthn -> Use external Cloudflare Pages bridge
      this.activeProvider = new ExternalBridgeProvider(bridgeUrl);
    } else {
      // Mobile fallback or macOS / Web
      this.activeProvider = new WebAuthnProvider();
    }
  }

  public setBridgeUrl(url: string): void {
    if (this.activeProvider instanceof ExternalBridgeProvider) {
      this.activeProvider.setBridgeUrl(url);
    } else if (Platform.isAndroidApp) {
      this.activeProvider = new ExternalBridgeProvider(url);
    }
  }

  public getBridgeUrl(): string {
    if (this.activeProvider instanceof ExternalBridgeProvider) {
      return this.activeProvider.getBridgeUrl();
    }
    return '';
  }

  public async handleProtocolCallback(params: Record<string, string>): Promise<boolean> {
    if (this.activeProvider instanceof ExternalBridgeProvider) {
      return await this.activeProvider.handleProtocolCallback(params);
    }
    return false;
  }

  public cancelPendingSession(): void {
    if (this.activeProvider instanceof ExternalBridgeProvider) {
      this.activeProvider.cancelPendingSession();
    }
  }

  public getActiveProvider(): BiometricProvider | null {
    return this.activeProvider;
  }

  /**
   * Evaluates whether biometric authentication is available on this specific device.
   */
  public async checkBiometricAvailability(vaultSaltOrId: string): Promise<BiometricCapabilities> {
    if (!this.activeProvider) {
      return {
        supported: false,
        enrolled: false,
        providerType: 'none',
        label: 'No compatible'
      };
    }

    const isAvailable = await this.activeProvider.isAvailable();
    const enrolled = this.isBiometricsEnrolled(vaultSaltOrId);

    return {
      supported: isAvailable,
      enrolled,
      providerType: this.activeProvider.type,
      label: this.activeProvider.name
    };
  }

  /**
   * Checks if an envelope is already enrolled on this specific device for this vault.
   */
  public isBiometricsEnrolled(vaultSaltOrId: string): boolean {
    const envelope = DeviceBiometricStorage.loadEnvelope(vaultSaltOrId);
    return Boolean(envelope && envelope.ciphertext);
  }

  /**
   * Enrolls biometrics for the current vault on this device.
   *
   * SECURITY: the `vaultId` is mixed into the AAD of the produced envelope, so
   * an envelope can never be moved from one vault to another one.
   */
  public async enrollBiometrics(rawVaultKey: Uint8Array, vaultSaltOrId: string): Promise<boolean> {
    if (!this.activeProvider) {
      throw new Error('No hay un proveedor biométrico disponible para este sistema.');
    }
    if (!rawVaultKey || rawVaultKey.length !== 32) {
      throw new Error('La clave de la bóveda no es válida para el enrolment biométrico.');
    }

    const deviceId = DeviceBiometricStorage.getDeviceId();
    const envelope = await this.activeProvider.enroll(rawVaultKey, deviceId, vaultSaltOrId);

    // Defence in depth: the envelope must belong to this provider and device.
    if (envelope.providerType !== this.activeProvider.type) {
      throw new Error('El proveedor biométrico devolvió un sobre de un tipo inesperado.');
    }
    if (envelope.deviceId !== deviceId) {
      throw new Error('El sobre biométrico no corresponde a este dispositivo.');
    }

    DeviceBiometricStorage.saveEnvelope(vaultSaltOrId, envelope);
    return true;
  }

  /**
   * Triggers biometric verification and decrypts the raw 32-byte VaultKey.
   */
  public async unlockWithBiometrics(vaultSaltOrId: string): Promise<Uint8Array | null> {
    if (!this.activeProvider) {
      return null;
    }

    const envelope = DeviceBiometricStorage.loadEnvelope(vaultSaltOrId);
    if (!envelope) {
      return null;
    }

    // SECURITY: an envelope enrolled with a DIFFERENT provider must not be
    // decrypted by the currently active one.
    //
    // The `external-bridge` provider produces the SAME envelope structure as
    // `webauthn` (PRF secret + AES-GCM), but the AAD embeds the provider
    // type, so the two are NOT interchangeable: the ciphertext of one can
    // never be decrypted by the other. Accepting the cross-provider case
    // would silently always fail (and hide a real misconfiguration), so the
    // check is strict.
    const isCompatible = envelope.providerType === this.activeProvider.type;

    if (!isCompatible) {
      console.warn(
        '[MySecret] El sobre biométrico fue creado con otro proveedor; se requiere re-enrolar.'
      );
      return null;
    }

    return await this.activeProvider.verifyAndDecrypt(envelope, vaultSaltOrId);
  }

  /**
   * Removes biometric enrollment for this vault from this physical device.
   *
   * SECURITY: the local envelope is not the only artefact. The Linux
   * provider also keeps a wrapping secret in the OS keyring and a device
   * secret file on disk. They must be removed too, otherwise a stale secret
   * would survive the "disable" action.
   */
  public disableBiometrics(vaultSaltOrId: string): void {
    const envelope = DeviceBiometricStorage.loadRawEnvelope(vaultSaltOrId);
    DeviceBiometricStorage.clearEnvelope(vaultSaltOrId);

    if (envelope && this.activeProvider instanceof LinuxBiometricProvider) {
      void this.activeProvider.cleanup(envelope, vaultSaltOrId);
    }
  }
}
