/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Windows Hello Biometric Provider
 *
 * Implements Windows Hello verification (Fingerprint, Facial Recognition, or PIN)
 * combined with Windows DPAPI (Data Protection API) for machine-level secret encryption.
 */

import { BiometricProvider, DeviceBiometricEnvelope } from './types';
import { bytesToBase64, base64ToBytes, bytesToHex, hexToBytes } from '../utils/buffer';
import { zeroize } from '../utils/zeroize';
import {
  BIOMETRIC_ENVELOPE_VERSION,
  sha256Hex,
  constantTimeHexEqual
} from './kdf';
import { resolvePowerShell, runProcess } from './system-exec';

/**
 * PowerShell script that reports whether Windows Hello is usable.
 *
 * It is piped through stdin (`-Command -`) so that it never becomes part of
 * the process command line. It contains NO interpolated data whatsoever.
 */
const AVAILABILITY_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation\`1' }[0]
    Function Await($WinRtTask, $ResultType) {
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(5000) | Out-Null
        $netTask.Result
    }
    [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
    $op = [Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()
    $status = Await $op ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])
    if ($status -eq [Windows.Security.Credentials.UI.UserConsentVerifierAvailability]::Available) {
        Write-Output "AVAILABLE"
    } else {
        Write-Output "UNAVAILABLE"
    }
} catch {
    Write-Output "UNAVAILABLE"
}
`;

/**
 * PowerShell script that runs the Windows Hello consent prompt.
 *
 * SECURITY: the user-facing prompt text is read from the `MYSECRET_BIO_PROMPT`
 * environment variable instead of being interpolated into this source. A
 * prompt containing a double quote would otherwise terminate the string
 * literal and allow arbitrary PowerShell to be executed.
 */
const VERIFICATION_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    $asTaskGeneric = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation\`1' }[0]
    Function Await($WinRtTask, $ResultType) {
        $asTask = $asTaskGeneric.MakeGenericMethod($ResultType)
        $netTask = $asTask.Invoke($null, @($WinRtTask))
        $netTask.Wait(-1) | Out-Null
        $netTask.Result
    }
    [Windows.Security.Credentials.UI.UserConsentVerifier,Windows.Security.Credentials.UI,ContentType=WindowsRuntime] | Out-Null
    $prompt = $env:MYSECRET_BIO_PROMPT
    if ([string]::IsNullOrEmpty($prompt)) { $prompt = 'MySecret: verificacion biometrica' }
    $op = [Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($prompt)
    $status = Await $op ([Windows.Security.Credentials.UI.UserConsentVerificationResult])
    if ($status -eq [Windows.Security.Credentials.UI.UserConsentVerificationResult]::Verified) {
        Write-Output "VERIFIED"
    } else {
        Write-Output "FAILED"
    }
} catch {
    Write-Output "ERROR"
}
`;

/**
 * PowerShell script that protects a blob with DPAPI (CurrentUser scope).
 *
 * The plaintext and the optional entropy are passed through the environment
 * (base64 encoded) so that they are never concatenated into the script.
 */
const DPAPI_PROTECT_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.Security
    $plainBytes = [Convert]::FromBase64String($env:MYSECRET_BIO_DATA)
    $entropy = [Convert]::FromBase64String($env:MYSECRET_BIO_ENTROPY)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($plainBytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [Convert]::ToBase64String($encrypted)
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
`;

/**
 * PowerShell script that unprotects a DPAPI blob (CurrentUser scope).
 */
const DPAPI_UNPROTECT_SCRIPT = `
$ErrorActionPreference = 'Stop'
try {
    Add-Type -AssemblyName System.Security
    $encBytes = [Convert]::FromBase64String($env:MYSECRET_BIO_DATA)
    $entropy = [Convert]::FromBase64String($env:MYSECRET_BIO_ENTROPY)
    $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encBytes, $entropy, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
    [Convert]::ToBase64String($decrypted)
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
`;

/**
 * Interprets the output of the availability script.
 *
 * SECURITY / CORRECTNESS: the token is compared as a WHOLE LINE. A substring
 * test is wrong here because `UNAVAILABLE` contains `AVAILABLE`, which made
 * the provider report Windows Hello as usable on machines that do not have it.
 */
export function parseAvailabilityOutput(stdout: string): boolean {
  return stdout
    .split(/\r?\n/)
    .map(line => line.trim())
    .includes('AVAILABLE');
}

/**
 * Interprets the output of the verification script (whole-line match).
 */
export function parseVerificationOutput(stdout: string): boolean {
  return stdout
    .split(/\r?\n/)
    .map(line => line.trim())
    .includes('VERIFIED');
}

export class WindowsHelloProvider implements BiometricProvider {
  public readonly type = 'windows-hello';
  public readonly name = 'Windows Hello (Huella digital / PIN)';

  /**
   * Resolves PowerShell to its absolute path inside `%SystemRoot%\System32`.
   *
   * Using the absolute path prevents a malicious `powershell.exe` earlier in
   * `%PATH%` from impersonating the Windows Hello gate.
   */
  private getPowerShell(): string | null {
    return resolvePowerShell();
  }

  public async isAvailable(): Promise<boolean> {
    const ps = this.getPowerShell();
    if (!ps) return false;

    const result = await runProcess({
      bin: ps,
      args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      // The script is passed through stdin so that NO attacker-influenced
      // text is ever concatenated into the command line.
      input: AVAILABILITY_SCRIPT,
      timeoutMs: 15000
    });

    return result.code === 0 && parseAvailabilityOutput(result.stdout);
  }

  /**
   * Prompts the user for a Windows Hello verification.
   *
   * SECURITY: the prompt text is transferred through an environment variable
   * (and read back by the script with `$env:`) instead of being interpolated
   * into the PowerShell source. Interpolating it would allow a crafted prompt
   * to break out of the string literal and execute arbitrary commands.
   */
  private async promptVerification(promptMessage: string): Promise<boolean> {
    const ps = this.getPowerShell();
    if (!ps) return false;

    const result = await runProcess({
      bin: ps,
      args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      input: VERIFICATION_SCRIPT,
      env: { MYSECRET_BIO_PROMPT: promptMessage },
      timeoutMs: 120000
    });

    if (result.timedOut) return false;
    return result.code === 0 && parseVerificationOutput(result.stdout);
  }

  /**
   * Encrypts a blob with DPAPI (CurrentUser scope).
   *
   * The data travels through the environment instead of the command line, so
   * no base64 payload can ever be interpreted as PowerShell source.
   */
  private async dpapiProtect(dataBase64: string, entropyBase64: string): Promise<string> {
    const ps = this.getPowerShell();
    if (!ps) throw new Error('PowerShell no disponible');

    const result = await runProcess({
      bin: ps,
      args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      input: DPAPI_PROTECT_SCRIPT,
      env: {
        MYSECRET_BIO_DATA: dataBase64,
        MYSECRET_BIO_ENTROPY: entropyBase64
      },
      timeoutMs: 15000
    });

    if (result.code !== 0 || !result.stdout.trim()) {
      throw new Error(`DPAPI Protect failed: ${result.stderr || result.stdout}`);
    }
    return result.stdout.trim();
  }

  /**
   * Decrypts a DPAPI blob (CurrentUser scope).
   */
  private async dpapiUnprotect(encBase64: string, entropyBase64: string): Promise<string> {
    const ps = this.getPowerShell();
    if (!ps) throw new Error('PowerShell no disponible');

    const result = await runProcess({
      bin: ps,
      args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', '-'],
      input: DPAPI_UNPROTECT_SCRIPT,
      env: {
        MYSECRET_BIO_DATA: encBase64,
        MYSECRET_BIO_ENTROPY: entropyBase64
      },
      timeoutMs: 15000
    });

    if (result.code !== 0 || !result.stdout.trim()) {
      throw new Error(`DPAPI Unprotect failed: ${result.stderr || result.stdout}`);
    }
    return result.stdout.trim();
  }

  public async enroll(
    rawVaultKey: Uint8Array,
    deviceId: string,
    vaultId: string
  ): Promise<DeviceBiometricEnvelope> {
    const verified = await this.promptVerification(
      'MySecret: Confirma tu huella digital para activar el desbloqueo rápido'
    );
    if (!verified) {
      throw new Error('Verificación biométrica cancelada o fallida en Windows Hello.');
    }

    const keyCheck = await sha256Hex(rawVaultKey);

    // Entropy tied to deviceId AND vaultId, so a blob cannot be reused in
    // another vault even on the same machine.
    const entropy = new TextEncoder().encode(
      `mysecret-win-entropy-${deviceId}-${vaultId}`
    );
    const encBase64 = await this.dpapiProtect(bytesToBase64(rawVaultKey), bytesToBase64(entropy));
    const encBytes = base64ToBytes(encBase64);

    const now = Date.now();
    return {
      version: BIOMETRIC_ENVELOPE_VERSION,
      deviceId,
      providerType: this.type,
      mode: 'windows-hello',
      createdAt: now,
      updatedAt: now,
      iv: '', // Handled inside DPAPI container
      tag: '',
      ciphertext: bytesToHex(encBytes),
      keyCheck
    };
  }

  public async verifyAndDecrypt(
    envelope: DeviceBiometricEnvelope,
    vaultId: string
  ): Promise<Uint8Array | null> {
    const verified = await this.promptVerification('MySecret: Desbloquea tu bóveda cifrada');
    if (!verified) {
      return null;
    }

    let rawKey: Uint8Array | null = null;
    try {
      const entropy = new TextEncoder().encode(
        `mysecret-win-entropy-${envelope.deviceId}-${vaultId}`
      );
      const ciphertextBytes = hexToBytes(envelope.ciphertext);
      const decBase64 = await this.dpapiUnprotect(bytesToBase64(ciphertextBytes), bytesToBase64(entropy));
      rawKey = base64ToBytes(decBase64);

      if (envelope.keyCheck) {
        const check = await sha256Hex(rawKey);
        if (!constantTimeHexEqual(check, envelope.keyCheck)) {
          zeroize(rawKey);
          throw new Error('Integrity check failed: decrypted key does not match hash');
        }
      }

      return rawKey;
    } catch (err) {
      console.error('[MySecret] Windows Hello DPAPI decryption error:', err);
      if (rawKey) zeroize(rawKey);
      return null;
    }
  }
}
