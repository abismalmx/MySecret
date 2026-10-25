/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * WebAuthn Platform Biometric Provider
 *
 * Implements biometric authentication via WebAuthn (Touch ID, Face ID, Android Biometric)
 * using window.PublicKeyCredential with platform authenticators.
 */

import { BiometricProvider, DeviceBiometricEnvelope } from './types';
import {
  bytesToBase64,
  bytesToBase64Url,
  base64UrlToBytes,
  bytesToHex,
  hexToBytes,
  stringToBytes
} from '../utils/buffer';
import { encryptAesGcm, decryptAesGcm, importAesKey } from '../crypto/aes';
import { zeroize } from '../utils/zeroize';
import {
  BIOMETRIC_ENVELOPE_VERSION,
  biometricAad,
  sha256Hex,
  constantTimeHexEqual
} from './kdf';
import { verifyWebAuthnAssertion, normalizePrfOutput } from './webauthn-assertion';

/**
 * WebAuthn Platform Biometric Provider
 *
 * SECURITY MODEL (this is the subtle part)
 * -----------------------------------------
 * A WebAuthn credential ID is, by design, **public data**: any script running
 * in the same origin can call `navigator.credentials.get()` and obtain an
 * assertion (the ID is even sent to the relying party in the clear).
 *
 * The previous implementation derived the AES wrapping key from
 * `SHA256("mysecret-webauthn-" + credential.id + "-" + deviceId)`. Because
 * BOTH inputs are attacker-reachable (the ID is public, the device id lives in
 * `localStorage`), any script with access to the renderer could recompute the
 * wrapping key and decrypt the vault key — **without any biometric check at
 * all**. Worse, `userVerification` was not enforced on the assertion, so the
 * authenticator could legitimately answer with a "discouraged" verification.
 *
 * The correct design is:
 *
 *  1. The wrapping key must come from a secret that the *authenticator* only
 *     releases after a genuine user-verifying ceremony. That is exactly what
 *     the WebAuthn **PRF extension** (`prf` / `hmac-secret`) provides: it
 *     returns a 32-byte secret that only a user-verifying ceremony can
 *     evaluate.
 *  2. The assertion MUST be verified against the enrolled credential's public
 *     key, and the User Verified flag MUST be checked.
 *
 * When the PRF extension is unavailable (older authenticators, some mobile
 * WebViews) the provider degrades SAFELY: it reports that the platform
 * cannot be used and the UI falls back to the master password. It never
 * falls back to a scheme that can be bypassed.
 */
export class WebAuthnProvider implements BiometricProvider {
  public readonly type = 'webauthn';
  public readonly name = 'Biometría de Plataforma (WebAuthn / Huella)';

  /**
   * Checks whether the current environment supports a platform authenticator
   * (Fingerprint / Face ID / Touch ID / Windows Hello).
   */
  public async isAvailable(): Promise<boolean> {
    if (
      typeof window === 'undefined' ||
      !window.PublicKeyCredential ||
      typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== 'function'
    ) {
      return false;
    }

    try {
      const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      if (!available) return false;

      // The PRF extension is mandatory for this provider: without it there is
      // no secret that only a user-verifying ceremony can release.
      return await this.isPrfSupported();
    } catch {
      return false;
    }
  }

  /**
   * Detects support for the WebAuthn PRF (hmac-secret) extension.
   *
   * The check is deliberately conservative: when support cannot be PROVEN,
   * the provider reports "not available" so the UI falls back to the master
   * password instead of enabling a bypassable unlock.
   */
  private async isPrfSupported(): Promise<boolean> {
    const anyPublicKeyCredential = window.PublicKeyCredential as any;

    if (typeof anyPublicKeyCredential.getClientCapabilities === 'function') {
      try {
        // NOTE: the specification defines this method as ASYNCHRONOUS
        // (it returns a Promise<ClientCapabilities>).
        const capabilities = await anyPublicKeyCredential.getClientCapabilities();
        if (capabilities && Array.isArray(capabilities.extensions)) {
          return capabilities.extensions.includes('prf');
        }
      } catch {
        // Fall through to the conservative default.
      }
    }

    // Without an explicit positive signal we assume the extension is absent.
    return false;
  }

  /**
   * Requests the PRF output for the enrolled credential.
   *
   * Returns `null` when the authenticator did not return a PRF result (which
   * means the user verification ceremony was not honoured).
   *
   * SECURITY: the returned assertion is ALSO returned to the caller so the
   * SIGNATURE can be verified against the enrolled credential public key.
   * The PRF secret alone proves nothing: it is just bytes handed over by the
   * page, and any script able to run in the same renderer could produce it.
   */
  private async requestPrfOutput(
    credentialId: string,
    prfSalt: Uint8Array,
    userVerification: 'required' | 'preferred' = 'required'
  ): Promise<{ prfSecret: Uint8Array; assertion: any; challenge: Uint8Array } | null> {
    const allowCredentials: PublicKeyCredentialDescriptor[] | undefined = credentialId
      ? [{ type: 'public-key', id: base64UrlToBytes(credentialId) as BufferSource }]
      : undefined;

    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    const assertion: any = await navigator.credentials.get({
      publicKey: {
        challenge: challenge as BufferSource,
        rpId: this.getRelyingPartyId(),
        userVerification,
        timeout: 60000,
        ...(allowCredentials ? { allowCredentials } : {}),
        extensions: {
          prf: {
            eval: {
              first: prfSalt as BufferSource
            }
          }
        }
      }
    });

    if (!assertion) return null;

    // SECURITY: the ceremony MUST have been user-verified. Without this check
    // the authenticator may legitimately answer without any biometric proof.
    const authData = assertion.response?.authenticatorData
      ? new Uint8Array(assertion.response.authenticatorData)
      : null;
    const isUv = (authData && authData.length >= 33 && (authData[32] & 0x04) !== 0) || assertion.response?.userVerified === true;
    if (!isUv) {
      throw new Error(
        'La verificación de usuario no fue confirmada por el autenticador.'
      );
    }

    const extensionResults = (assertion.getClientExtensionResults?.() ?? {}) as any;
    const prfResult = extensionResults.prf?.results?.first;
    if (!prfResult) return null;

    // SECURITY: the PRF output is a `BufferSource` according to the WebAuthn
    // IDL (the JSON flavour of the same dictionary uses a base64url string).
    // Both encodings are accepted, but a result shorter than 32 bytes is
    // REJECTED: an empty secret would hash to a public constant and would
    // make the wrapping key computable by anybody.
    const prfSecret = normalizePrfOutput(prfResult);

    return { prfSecret, assertion, challenge };
  }

  private getRelyingPartyId(): string {
    if (typeof window !== 'undefined' && window.location && window.location.hostname) {
      return window.location.hostname;
    }
    return 'localhost';
  }

  public async enroll(
    rawVaultKey: Uint8Array,
    deviceId: string,
    vaultId: string
  ): Promise<DeviceBiometricEnvelope> {
    if (!navigator.credentials || !navigator.credentials.create) {
      throw new Error('WebAuthn navigator.credentials no disponible en este entorno.');
    }

    const challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    const userIdBytes = stringToBytes(deviceId.slice(0, 16));

    // A random PRF salt: the authenticator will compute
    // `HMAC(prfKey, salt)` and only release it after a user-verifying
    // ceremony. The salt itself is not secret, but it binds the derived
    // secret to this enrollment.
    const prfSalt = new Uint8Array(32);
    window.crypto.getRandomValues(prfSalt);

    let credential: any;
    try {
      credential = await navigator.credentials.create({
        publicKey: {
          challenge: challenge as BufferSource,
          rp: {
            name: 'MySecret Bóveda Cifrada',
            id: this.getRelyingPartyId()
          },
          user: {
            id: userIdBytes as BufferSource,
            name: 'mysecret-user',
            displayName: 'Usuario MySecret'
          },
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' },   // ES256
            { alg: -257, type: 'public-key' }  // RS256
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            residentKey: 'required',
            userVerification: 'required'
          },
          // Request the PRF extension: it is the ONLY source of the
          // wrapping secret, and it is only released after a genuine
          // user-verifying ceremony.
          extensions: {
            prf: {}
          },
          timeout: 60000
        }
      });
    } catch (err: any) {
      console.warn('[MySecret] WebAuthn enrollment failed:', err);
      throw new Error(`Registro biométrico fallido: ${err?.message || 'Operación cancelada'}`);
    }

    if (!credential || !credential.id) {
      throw new Error('No se recibió credencial biométrica válida.');
    }

    // The credential MUST have been user-verified during the registration.
    if (credential.response?.userVerified === false) {
      throw new Error(
        'El autenticador no confirmó la verificación de usuario: usa tu contraseña maestra.'
      );
    }

    // Obtain the PRF secret with a second, user-verifying ceremony.
    const prfResult = await this.requestPrfOutput(credential.id, prfSalt);
    if (!prfResult) {
      throw new Error(
        'El autenticador no liberó el secreto PRF: el desbloqueo biométrico no es posible en este dispositivo.'
      );
    }
    const prfSecret = prfResult.prfSecret;

    // SECURITY: the enrollment itself must be bound to the credential that
    // was just created. Verifying the assertion signature with the NEW
    // credential public key proves that the PRF secret really comes from the
    // authenticator that owns this credential (and not from a spoofed
    // extension result).
    const credentialSpki = credential.response?.publicKey;
    if (!credentialSpki) {
      throw new Error('La credencial biométrica no expuso su clave pública.');
    }
    const credentialPublicKey = bytesToBase64(new Uint8Array(credentialSpki));
    await verifyWebAuthnAssertion(
      {
        id: credential.id,
        response: prfResult.assertion.response
      },
      {
        expectedCredentialId: credential.id,
        expectedChallenge: prfResult.challenge,
        expectedOrigin: window.location.origin,
        expectedRpId: this.getRelyingPartyId(),
        publicKeySpkiBase64: credentialPublicKey
      }
    );

    // Derive the wrapping key from the PRF secret. It is bound to the
    // authenticator AND to the vault through the AAD.
    const aad = biometricAad(this.type, vaultId);
    let wrapKey: CryptoKey | null = null;
    let enc: { iv: Uint8Array; tag: Uint8Array; ciphertext: Uint8Array } | null = null;

    try {
      const digest = await window.crypto.subtle.digest('SHA-256', prfSecret as BufferSource);
      wrapKey = await importAesKey(new Uint8Array(digest));
      enc = await encryptAesGcm(rawVaultKey, wrapKey, aad);
    } finally {
      zeroize(prfSecret);
    }

    const keyCheck = await sha256Hex(rawVaultKey);

    const now = Date.now();
    return {
      version: BIOMETRIC_ENVELOPE_VERSION,
      deviceId,
      providerType: this.type,
      mode: 'webauthn-prf',
      createdAt: now,
      updatedAt: now,
      iv: bytesToHex(enc!.iv),
      tag: bytesToHex(enc!.tag),
      ciphertext: bytesToHex(enc!.ciphertext),
      keyCheck,
      // The credential id is normalised to Base64URL so that it can be fed
      // back to `allowCredentials` without any ambiguity.
      credentialId: bytesToBase64Url(base64UrlToBytes(credential.id)),
      credentialPublicKey,
      prfSalt: bytesToHex(prfSalt),
      // The origin and the relying party id are pinned so that the envelope
      // can only be used from the exact place where it was enrolled.
      rpId: this.getRelyingPartyId(),
      origin: typeof window !== 'undefined' && window.location ? window.location.origin : undefined
    };
  }

  public async verifyAndDecrypt(
    envelope: DeviceBiometricEnvelope,
    vaultId: string
  ): Promise<Uint8Array | null> {
    if (!navigator.credentials || !navigator.credentials.get) {
      return null;
    }

    // The PRF salt and the credential id are mandatory: without them the
    // authenticator cannot release the wrapping secret.
    if (!envelope.prfSalt || !envelope.credentialId) {
      console.warn('[MySecret] Sobre biométrico WebAuthn incompleto: se requiere la contraseña maestra.');
      return null;
    }

    let prfSecret: Uint8Array | null = null;
    let prfResult: { prfSecret: Uint8Array; assertion: any; challenge: Uint8Array } | null = null;
    try {
      prfResult = await this.requestPrfOutput(
        envelope.credentialId,
        hexToBytes(envelope.prfSalt)
      );
      if (!prfResult) {
        return null;
      }
      prfSecret = prfResult.prfSecret;

      // SECURITY: the PRF secret is only trustworthy because the ENROLLED
      // AUTHENTICATOR signed this assertion after a user-verifying ceremony.
      // Without this check, any script able to run in the renderer could
      // hand over an arbitrary "PRF secret" and unlock the vault.
      if (!envelope.credentialPublicKey) {
        throw new Error(
          'El sobre biométrico no contiene la clave pública de la credencial: re-enrolar.'
        );
      }
      await verifyWebAuthnAssertion(prfResult.assertion, {
        expectedCredentialId: envelope.credentialId,
        expectedChallenge: prfResult.challenge,
        expectedOrigin: window.location.origin,
        expectedRpId: this.getRelyingPartyId(),
        publicKeySpkiBase64: envelope.credentialPublicKey
      });

      const aad = biometricAad(this.type, vaultId);
      const digest = await window.crypto.subtle.digest('SHA-256', prfSecret as BufferSource);
      const wrapKey = await importAesKey(new Uint8Array(digest));

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
          throw new Error('Integrity check failed: decrypted key mismatch');
        }
      }

      return rawKey;
    } catch (err) {
      console.warn('[MySecret] WebAuthn unlock cancelled or failed:', err);
      return null;
    } finally {
      if (prfSecret) zeroize(prfSecret);
    }
  }
}
