/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Linux Biometric & Secret Service Provider
 *
 * Implements fingerprint verification via fprintd (fprintd-verify)
 * and secure credential storage via FreeDesktop Secret Service (secret-tool / Gnome Keyring / KWallet).
 */

import { BiometricProvider, DeviceBiometricEnvelope } from './types';
import { bytesToHex, hexToBytes } from '../utils/buffer';
import { encryptAesGcm, decryptAesGcm } from '../crypto/aes';
import { zeroize } from '../utils/zeroize';
import {
  BIOMETRIC_ENVELOPE_VERSION,
  biometricAad,
  sha256Hex,
  constantTimeHexEqual,
  deriveAesKeyFromSecret
} from './kdf';
import {
  resolveSystemBinary,
  runProcess,
  getCurrentUsername,
  getEnvHome,
  getNodeModule
} from './system-exec';
import { sha256HexSync } from '../utils/sha256';

/** Label of the Secret Service collection used by MySecret. */
const KEYRING_SERVICE = 'mysecret-vault';

/** Unlock modes recorded in the envelope. */
const MODE_FPRINTD = 'fprintd';
/**
 * Legacy mode. It only read a secret from the OS keyring, which is normally
 * already unlocked in a logged-in session: it authenticated NOBODY, so a
 * "biometric" unlock without a fingerprint reader was an unlock with no check
 * at all. New enrollments with it are refused and existing ones fail closed.
 */
const MODE_SECRET_SERVICE = 'secret-service';

export class LinuxBiometricProvider implements BiometricProvider {
  public readonly type = 'linux-secret-service';
  public readonly name = 'Linux (Huella fprintd / Secret Service)';

  /**
   * Checks that fprintd has an enrolled fingerprint.
   *
   * SECURITY: a real user-verification gate is REQUIRED. The previous
   * fallback (Secret Service alone) reported "available" on machines without
   * any fingerprint reader and then unlocked the vault with no check.
   *
   * `fprintd-list` is resolved to an absolute path in a root-owned system
   * directory so a hostile `$PATH` entry cannot impersonate it.
   */
  public async isAvailable(): Promise<boolean> {
    return await this.isFprintdReady();
  }

  /**
   * Prompts the user for fingerprint verification using fprintd-verify.
   *
   * SECURITY: only a successful `verify-match` (or an explicit exit code 0)
   * counts as a match. Any other outcome — cancel, timeout, no reader, no
   * enrolled fingers — fails closed.
   */
  private async promptFprintd(): Promise<boolean> {
    const bin = resolveSystemBinary('fprintd-verify');
    if (!bin) return false;

    const result = await runProcess({
      bin,
      args: [getCurrentUsername()],
      timeoutMs: 60000
    });

    if (result.timedOut) return false;

    const output = `${result.stdout}\n${result.stderr}`;
    if (output.includes('verify-match')) return true;
    // fprintd-verify exits 0 only on a successful match.
    return result.code === 0 && output.includes('verify-match');
  }

  /**
   * Lists the enrolled fingerprints for the current user.
   */
  private async isFprintdReady(): Promise<boolean> {
    const bin = resolveSystemBinary('fprintd-list');
    if (!bin) return false;

    const result = await runProcess({
      bin,
      args: [getCurrentUsername()],
      timeoutMs: 15000
    });

    if (result.code !== 0) return false;
    const out = result.stdout;
    return out.includes('enrolled') || out.includes('finger');
  }

  /**
   * Resolves `secret-tool` to an absolute path in a root-owned system
   * directory.
   */
  private resolveSecretTool(): string | null {
    return resolveSystemBinary('secret-tool');
  }

  /**
   * Creates (or reuses) the high-entropy device secret.
   *
   * SECURITY: the previous implementation derived the wrapping key from
   * `SHA256("/etc/machine-id" + deviceId + USER)`. EVERY one of those inputs
   * is public (`/etc/machine-id` is world-readable, `deviceId` lives in
   * `localStorage` and `USER` is a public environment variable), so ANY
   * process able to read the plugin's local storage could recompute the key
   * and decrypt the vault key without any biometric check.
   *
   * The replacement stores 32 bytes of CSPRNG entropy in a file that is
   * readable ONLY by the current user (mode 0600) inside the user's own
   * home directory. That secret never reaches the renderer.
   */
  private async getOrCreateDeviceSecret(deviceId: string, vaultId: string): Promise<Uint8Array> {
    const secretPath = this.getDeviceSecretPath(deviceId, vaultId);

    const existing = this.readDeviceSecret(secretPath);
    if (existing) return existing;

    const fs = getNodeModule('fs');
    const path = getNodeModule('path');
    if (!fs || !path) {
      throw new Error(
        'No se puede leer el secreto de dispositivo: el entorno no expone Node.js.'
      );
    }

    // Generate 32 bytes of CSPRNG entropy.
    const secret = new Uint8Array(32);
    window.crypto.getRandomValues(secret);

    const dir = path.dirname(secretPath);
    try {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
      }
      // Write with 0600 BEFORE the content is visible: `wx` fails if the file
      // already exists, preventing a symlink/TOCTOU overwrite.
      fs.writeFileSync(secretPath, Buffer.from(secret), {
        mode: 0o600,
        flag: 'wx'
      });
    } catch (err: any) {
      // The file may already exist (race): re-read it.
      const reread = this.readDeviceSecret(secretPath);
      if (reread) {
        zeroize(secret);
        return reread;
      }
      throw new Error(`No se pudo crear el secreto de dispositivo: ${err?.message || err}`);
    }

    return secret;
  }

  /**
   * Generates a brand new high-entropy device secret WITHOUT persisting it.
   *
   * It is used by the Secret Service mode, where the secret must live ONLY
   * inside the OS keyring (never on disk).
   */
  private generateDeviceSecret(): Uint8Array {
    const secret = new Uint8Array(32);
    window.crypto.getRandomValues(secret);
    return secret;
  }

  /**
   * Path of the per-device / per-vault secret file.
   *
   * It lives in the user's home directory (never in the vault) so that it is
   * NOT synchronized by Obsidian Sync / OmniSync / Google Drive.
   *
   * The file name embeds a short hash of the vault id: two vaults on the
   * same machine therefore never share a secret, and removing the enrolment
   * of one vault does not break the other.
   */
  private getDeviceSecretPath(deviceId: string, vaultId: string): string {
    const os = getNodeModule('os');
    const path = getNodeModule('path');
    const home = (os && typeof os.homedir === 'function' ? os.homedir() : '') || getEnvHome();
    const scope = sha256HexSync(vaultId).slice(0, 16);
    return path.join(home, '.config', 'mysecret', `device-${deviceId}-${scope}.key`);
  }

  /**
   * Reads the device secret, enforcing that it is a regular file and NOT
   * readable by group or others.
   */
  private readDeviceSecret(secretPath: string): Uint8Array | null {
    const fs = getNodeModule('fs');
    if (!fs) return null;

    try {
      const stats = fs.statSync(secretPath);
      if (!stats.isFile()) return null;
      // Reject group/world-readable secrets (mode & 0o077).
      if (typeof stats.mode === 'number' && (stats.mode & 0o077) !== 0) {
        console.warn('[MySecret] Device secret has insecure permissions; ignoring it.');
        return null;
      }
      const data = fs.readFileSync(secretPath);
      const bytes = new Uint8Array(data);
      if (bytes.length !== 32) return null;
      return bytes;
    } catch {
      return null;
    }
  }

  public async enroll(
    rawVaultKey: Uint8Array,
    deviceId: string,
    vaultId: string
  ): Promise<DeviceBiometricEnvelope> {
    // SECURITY: enrollment requires a working fingerprint reader. Without one
    // there would be no gate to re-apply at unlock time.
    if (!(await this.isFprintdReady())) {
      throw new Error(
        'No hay un lector de huellas (fprintd) con huellas registradas: el desbloqueo biométrico no está disponible en este equipo.'
      );
    }
    const verified = await this.promptFprintd();
    if (!verified) {
      throw new Error('Verificación de huella fprintd cancelada o no reconocida.');
    }

    // The wrapping key is derived from a high-entropy device secret stored in
    // a 0600 file in the user's home directory. NEVER from public machine
    // identifiers. The file is scoped by BOTH the device id and the vault id.
    const deviceSecret = await this.getOrCreateDeviceSecret(deviceId, vaultId);
    const aad = biometricAad(this.type, vaultId);
    let enc: { iv: Uint8Array; tag: Uint8Array; ciphertext: Uint8Array } | null = null;

    try {
      const wrapKey = await deriveAesKeyFromSecret(deviceSecret, `${deviceId}:${vaultId}`, aad);
      enc = await encryptAesGcm(rawVaultKey, wrapKey, aad);
    } finally {
      // The device secret is wiped from memory as soon as it has been used.
      zeroize(deviceSecret);
    }

    const keyCheck = await sha256Hex(rawVaultKey);

    const now = Date.now();
    return {
      version: BIOMETRIC_ENVELOPE_VERSION,
      deviceId,
      providerType: this.type,
      mode: MODE_FPRINTD,
      createdAt: now,
      updatedAt: now,
      iv: bytesToHex(enc!.iv),
      tag: bytesToHex(enc!.tag),
      ciphertext: bytesToHex(enc!.ciphertext),
      keyCheck
    };
  }

  public async verifyAndDecrypt(
    envelope: DeviceBiometricEnvelope,
    vaultId: string
  ): Promise<Uint8Array | null> {
    // FAIL CLOSED: the gate recorded at enrollment time MUST be re-applied.
    // The previous implementation silently skipped the fingerprint check when
    // fprintd was not available, which turned the biometric unlock into a
    // plain "read the key from the keyring" operation.
    const mode = envelope.mode || MODE_FPRINTD;
    let deviceSecret: Uint8Array | null = null;

    if (mode !== MODE_FPRINTD) {
      // Legacy "secret-service" enrollments authenticated nobody. They are
      // refused: the user must fall back to the master password and re-enroll.
      console.warn(
        '[MySecret] Inscripción biométrica heredada sin verificación de usuario: se requiere la contraseña maestra y volver a inscribir la huella.'
      );
      return null;
    }

    try {
      // Gate: the fingerprint MUST match.
      const hasFprintd = await this.isFprintdReady();
      if (!hasFprintd) {
        console.warn('[MySecret] fprintd no está disponible: se requiere la contraseña maestra.');
        return null;
      }
      const verified = await this.promptFprintd();
      if (!verified) {
        return null;
      }
      // The secret MUST already exist: creating a fresh one here would only
      // hide a deleted file behind a decryption failure.
      deviceSecret = this.readDeviceSecret(this.getDeviceSecretPath(envelope.deviceId, vaultId));
      if (!deviceSecret) {
        console.warn('[MySecret] Secreto de dispositivo ausente: se requiere la contraseña maestra.');
        return null;
      }

      const aad = biometricAad(this.type, vaultId);
      const wrapKey = await deriveAesKeyFromSecret(
        deviceSecret,
        `${envelope.deviceId}:${vaultId}`,
        aad
      );

      const rawKey = await decryptAesGcm(
        hexToBytes(envelope.ciphertext),
        wrapKey,
        hexToBytes(envelope.iv),
        hexToBytes(envelope.tag),
        aad
      );

      if (envelope.keyCheck) {
        const check = await sha256Hex(rawKey);
        if (!constantTimeHexEqual(check, envelope.keyCheck)) {
          zeroize(rawKey);
          throw new Error('Integrity check failed');
        }
      }

      return rawKey;
    } catch (err) {
      console.error('[MySecret] Linux decryption error:', err);
      return null;
    } finally {
      if (deviceSecret) zeroize(deviceSecret);
    }
  }

  /**
   * Removes every artefact created for an enrollment: the OS keyring entry
   * and the device secret file.
   *
   * It is called when the user disables the biometric unlock, so that no
   * stale secret survives the operation.
   */
  public async cleanup(
    envelope: DeviceBiometricEnvelope,
    vaultId: string
  ): Promise<void> {
    // 1. Remove the keyring entry (only when it was actually used).
    if (envelope.mode === MODE_SECRET_SERVICE) {
      try {
        const bin = this.resolveSecretTool();
        if (bin) {
          await runProcess({
            bin,
            args: [
              'clear',
              'service',
              KEYRING_SERVICE,
              'device',
              envelope.deviceId,
              'vault',
              vaultId
            ],
            timeoutMs: 15000
          });
        }
      } catch {
        // Best effort: the entry may not exist.
      }
    }

    // 2. Remove the device secret file (only when it was actually used).
    if (envelope.mode === MODE_FPRINTD) {
      const fs = getNodeModule('fs');
      try {
        // SECURITY: BOTH arguments are required. The path is scoped by the
        // vault id (`sha256HexSync(vaultId)`), so calling it with a single
        // argument computed a DIFFERENT path and the stale secret file was
        // silently left on disk after disabling the biometric unlock.
        const secretPath = this.getDeviceSecretPath(envelope.deviceId, vaultId);
        if (fs && fs.existsSync(secretPath)) {
          fs.unlinkSync(secretPath);
        }
      } catch {
        // Best effort.
      }
    }
  }
}
