/**
 * Automated Unit Test Suite for MySecret Biometric Subsystem
 */

import assert from 'node:assert';
import test from 'node:test';
import { webcrypto } from 'node:crypto';

// Polyfill window, window.crypto, and localStorage for Node.js test environment
const mockStorage = new Map();
if (!globalThis.window) {
  globalThis.window = {
    crypto: webcrypto,
    localStorage: {
      getItem: (k) => (mockStorage.has(k) ? mockStorage.get(k) : null),
      setItem: (k, v) => mockStorage.set(k, String(v)),
      removeItem: (k) => mockStorage.delete(k),
      clear: () => mockStorage.clear()
    }
  };
}

import { DeviceBiometricStorage } from '../src/biometrics/device-storage.ts';
import { BiometricManager } from '../src/biometrics/biometric-manager.ts';
import { KeyManager } from '../src/crypto/key-manager.ts';
import { bytesToHex, hexToBytes } from '../src/utils/buffer.ts';
import { BIOMETRIC_ENVELOPE_VERSION, biometricAad, sha256Hex, constantTimeHexEqual } from '../src/biometrics/kdf.ts';
import { sha256HexSync } from '../src/utils/sha256.ts';

test('Biometrics Storage: Device ID is generated and stays persistent', () => {
  mockStorage.clear();
  const id1 = DeviceBiometricStorage.getDeviceId();
  assert.ok(id1 && id1.length === 32, 'Device ID should be a 32-char hex string');

  const id2 = DeviceBiometricStorage.getDeviceId();
  assert.strictEqual(id1, id2, 'Device ID must remain consistent across calls');
});

test('Biometrics Storage: Saves, loads, and clears envelope per vault identifier', () => {
  const vaultA = 'salt-vault-aaa';
  const vaultB = 'salt-vault-bbb';

  const envelopeA = {
    version: BIOMETRIC_ENVELOPE_VERSION,
    deviceId: 'dev-123',
    providerType: 'webauthn',
    createdAt: Date.now(),
    updatedAt: Date.now(),
    iv: 'aabbcc',
    tag: 'ddeeff',
    ciphertext: '11223344',
    keyCheck: 'check-hash-a'
  };

  DeviceBiometricStorage.saveEnvelope(vaultA, envelopeA);
  const loadedA = DeviceBiometricStorage.loadEnvelope(vaultA);
  assert.deepStrictEqual(loadedA, envelopeA);

  const loadedB = DeviceBiometricStorage.loadEnvelope(vaultB);
  assert.strictEqual(loadedB, null, 'Vault B should not see Vault A envelope');

  DeviceBiometricStorage.clearEnvelope(vaultA);
  assert.strictEqual(DeviceBiometricStorage.loadEnvelope(vaultA), null);
});

test('Biometrics Storage: Legacy v1 envelopes are REJECTED (fail closed)', () => {
  const vaultId = 'salt-vault-legacy';

  // A v1 envelope was produced with the insecure key derivations
  // (public machine-id / public credential id). It must not be usable.
  const legacyEnvelope = {
    version: 1,
    deviceId: 'dev-123',
    providerType: 'linux-secret-service',
    createdAt: Date.now(),
    updatedAt: Date.now(),
    iv: 'aabbcc',
    tag: 'ddeeff',
    ciphertext: '11223344',
    keyCheck: 'legacy-hash'
  };

  DeviceBiometricStorage.saveEnvelope(vaultId, legacyEnvelope);
  assert.strictEqual(
    DeviceBiometricStorage.loadEnvelope(vaultId),
    null,
    'Legacy biometric envelopes must be rejected and require re-enrollment'
  );

  const bm = new BiometricManager();
  assert.strictEqual(
    bm.isBiometricsEnrolled(vaultId),
    false,
    'A legacy envelope must not be reported as enrolled'
  );

  DeviceBiometricStorage.clearEnvelope(vaultId);
});

test('Biometric KDF: AAD binds the envelope to exactly one vault', () => {
  const aadA = biometricAad('webauthn', 'vault-AAAA');
  const aadB = biometricAad('webauthn', 'vault-BBBB');
  const aadOtherProvider = biometricAad('linux-secret-service', 'vault-AAAA');

  assert.notStrictEqual(aadA, aadB, 'Different vaults must produce different AAD');
  assert.notStrictEqual(aadA, aadOtherProvider, 'Different providers must produce different AAD');
  assert.ok(aadA.includes('vault-AAAA'), 'The AAD must embed the vault identifier');
  assert.ok(aadA.includes('webauthn'), 'The AAD must embed the provider type');
});

test('Biometric KDF: constant-time comparison rejects mismatches', () => {
  const a = 'a'.repeat(64);
  const b = 'a'.repeat(63) + 'b';
  assert.strictEqual(constantTimeHexEqual(a, a), true, 'Identical digests must compare equal');
  assert.strictEqual(constantTimeHexEqual(a, b), false, 'Different digests must not compare equal');
  assert.strictEqual(constantTimeHexEqual(a, 'zz'), false, 'Malformed hex must not compare equal');
  assert.strictEqual(constantTimeHexEqual('', ''), false, 'Empty digests must not compare equal');
});

test('SHA-256: pure-JS fallback matches the WebCrypto digest', async () => {
  const inputs = ['', 'abc', 'vault/path/MySecret', 'x'.repeat(200)];
  for (const input of inputs) {
    const expected = await sha256Hex(new TextEncoder().encode(input));
    const actual = sha256HexSync(input);
    assert.strictEqual(actual, expected, `SHA-256 mismatch for input of length ${input.length}`);
  }
  // Known test vector (NIST FIPS 180-4).
  assert.strictEqual(
    sha256HexSync('abc'),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
  );
});

test('KeyManager: Biometric raw key unlock and getRawVaultKey integrity', async () => {
  const km = new KeyManager();
  const masterPassword = 'MasterPassword123!';
  const { envelope, commit } = await km.initializeVault(masterPassword, false);
  await commit();

  assert.strictEqual(km.isLocked, false);
  const rawKey = km.getRawVaultKey();
  assert.ok(rawKey && rawKey.length === 32, 'Raw vault key must be 32 bytes');

  // Lock vault
  km.lock();
  assert.strictEqual(km.isLocked, true);
  assert.strictEqual(km.getRawVaultKey(), null, 'Raw vault key must be wiped when locked');

  // Reject invalid key length
  await assert.rejects(
    async () => km.unlockWithRawVaultKey(new Uint8Array(16)),
    /Invalid vault key length/
  );

  // Unlock with valid raw key
  const success = await km.unlockWithRawVaultKey(rawKey);
  assert.strictEqual(success, true);
  assert.strictEqual(km.isLocked, false);
  assert.ok(km.getVaultKey() !== null);

  km.lock();
});

test('BiometricManager: Detects enrollment state correctly', () => {
  const bm = new BiometricManager();
  const vaultId = 'test-vault-detect';

  assert.strictEqual(bm.isBiometricsEnrolled(vaultId), false);

  const mockEnvelope = {
    version: BIOMETRIC_ENVELOPE_VERSION,
    deviceId: 'dev-abc',
    providerType: 'linux-secret-service',
    createdAt: Date.now(),
    updatedAt: Date.now(),
    iv: '1234',
    tag: '5678',
    ciphertext: '90ab',
    keyCheck: 'hash'
  };

  DeviceBiometricStorage.saveEnvelope(vaultId, mockEnvelope);
  assert.strictEqual(bm.isBiometricsEnrolled(vaultId), true);

  bm.disableBiometrics(vaultId);
  assert.strictEqual(bm.isBiometricsEnrolled(vaultId), false);
});

// ============================================================================
// SECURITY REGRESSION TESTS
// These lock in the fixes applied after the biometric security review.
// ============================================================================

/**
 * Removes the comments from a TypeScript source file so that the security
 * assertions below inspect the EXECUTABLE CODE only.
 *
 * Without this, a developer who documents the historical vulnerability in a
 * comment (as this very file does) would make the test fail for the wrong
 * reason.
 */
function stripComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')   // block comments
    .replace(/(^|[^:])\/\/.*$/gm, '$1'); // line comments (avoiding http://)
}

/**
 * Reads a source file and returns its code with the comments removed.
 */
async function readCode(file) {
  const fs = await import('node:fs');
  return stripComments(fs.readFileSync(file, 'utf8'));
}

test('SECURITY: KeyManager wipes the raw key even when the unlock is rejected', async () => {
  const km = new KeyManager();
  const { envelope, commit } = await km.initializeVault('MasterPassword123!', false);
  await commit();

  // A key with a wrong length must be zeroized, not left in the heap.
  const badKey = new Uint8Array(16).fill(0xaa);
  await assert.rejects(
    async () => km.unlockWithRawVaultKey(badKey),
    /Invalid vault key length/
  );
  assert.ok(
    badKey.every(b => b === 0),
    'A rejected vault key must be wiped from memory'
  );

  // The same applies to a missing envelope.
  const freshManager = new KeyManager();
  const orphanKey = new Uint8Array(32).fill(0xbb);
  await assert.rejects(
    async () => freshManager.unlockWithRawVaultKey(orphanKey),
    /envelope configuration is missing/
  );
  assert.ok(
    orphanKey.every(b => b === 0),
    'An orphaned vault key must be wiped from memory'
  );

  km.lock();
});

test('SECURITY: An envelope enrolled with another provider is refused', async () => {
  const bm = new BiometricManager();
  const vaultId = 'test-vault-provider-mismatch';

  // The active provider in the test environment is the Linux one, so an
  // envelope claiming a different provider must not be decrypted.
  DeviceBiometricStorage.saveEnvelope(vaultId, {
    version: BIOMETRIC_ENVELOPE_VERSION,
    deviceId: 'dev-xyz',
    providerType: 'webauthn',
    mode: 'webauthn-prf',
    createdAt: Date.now(),
    updatedAt: Date.now(),
    iv: '1234',
    tag: '5678',
    ciphertext: '90ab',
    keyCheck: 'hash'
  });

  const result = await bm.unlockWithBiometrics(vaultId);
  assert.strictEqual(
    result,
    null,
    'An envelope from a different provider must not be decrypted'
  );

  DeviceBiometricStorage.clearEnvelope(vaultId);
});

test('SECURITY: The biometric wrapping key is not derived from public identifiers', async () => {
  // Regression for the Linux provider flaw where the wrapping key was
  // SHA256(machine-id + deviceId + USER): every input was public.
  const linuxProviderSource = await readCode('src/biometrics/linux-provider.ts');

  assert.ok(
    !/machine-id/.test(linuxProviderSource),
    'The Linux provider must not derive keys from /etc/machine-id'
  );
  assert.ok(
    !/process\.env\.USER/.test(linuxProviderSource),
    'The Linux provider must not derive keys from the USER environment variable'
  );
  assert.ok(
    /getOrCreateDeviceSecret/.test(linuxProviderSource),
    'The Linux provider must use a high-entropy device secret'
  );
  assert.ok(
    /mode: 0o600/.test(linuxProviderSource),
    'The device secret must be stored with 0600 permissions'
  );
});

test('SECURITY: The WebAuthn provider never derives the key from the credential id', async () => {
  // Regression: the credential id is PUBLIC data, so deriving the wrapping
  // key from it allowed a full bypass of the biometric check.
  const webauthnSource = await readCode('src/biometrics/webauthn-provider.ts');

  assert.ok(
    !/mysecret-webauthn-/.test(webauthnSource),
    'The WebAuthn provider must not derive the wrapping key from the credential id'
  );
  assert.ok(
    /prf/.test(webauthnSource),
    'The WebAuthn provider must use the PRF extension to obtain the secret'
  );
  assert.ok(
    /userVerified/.test(webauthnSource),
    'The WebAuthn provider must verify the User Verified flag'
  );
});

test('SECURITY: OS helpers are never resolved through PATH and never use a shell', async () => {
  const execSource = await readCode('src/biometrics/system-exec.ts');

  assert.ok(
    /resolveSystemBinary/.test(execSource),
    'A dedicated binary resolver must exist'
  );
  assert.ok(
    /shell: false/.test(execSource),
    'Processes must be spawned without a shell'
  );

  // The providers must not spawn bare binary names anymore.
  for (const file of [
    'src/biometrics/linux-provider.ts',
    'src/biometrics/windows-provider.ts'
  ]) {
    const source = await readCode(file);
    assert.ok(
      !/spawn\(\s*['"](fprintd-verify|fprintd-list|secret-tool|powershell\.exe)['"]/.test(source),
      `${file} must not spawn a bare binary name (PATH hijacking)`
    );
  }
});

test('SECURITY: PowerShell scripts receive no interpolated data', async () => {
  const windowsSource = await readCode('src/biometrics/windows-provider.ts');

  assert.ok(
    !/FromBase64String\("\$\{/.test(windowsSource),
    'Base64 payloads must not be interpolated into the PowerShell source'
  );
  assert.ok(
    !/RequestVerificationAsync\("\$\{/.test(windowsSource),
    'The verification prompt must not be interpolated into the PowerShell source'
  );
  assert.ok(
    /MYSECRET_BIO_PROMPT/.test(windowsSource),
    'The prompt must be transferred through the environment'
  );
});

test('SECURITY: The vault identifier is unique per vault', async () => {
  const mainSource = await readCode('src/main.ts');

  assert.ok(
    !/appId \|\| 'default-vault'/.test(mainSource),
    'The shared appId must not be used as the vault identifier fallback'
  );
  assert.ok(
    /getVaultPathFingerprint/.test(mainSource),
    'A per-vault fingerprint must be used as fallback'
  );
});

test('SECURITY: The device id never falls back to Math.random()', async () => {
  const storageSource = await readCode('src/biometrics/device-storage.ts');

  assert.ok(
    !/Math\.random/.test(storageSource),
    'Math.random() must never be used to build the device identifier'
  );
});

test('SECURITY: HKDF wrapping key round-trip is bound to one single vault', async () => {
  const { encryptAesGcm, decryptAesGcm } = await import('../src/crypto/aes.ts');
  const { deriveAesKeyFromSecret } = await import('../src/biometrics/kdf.ts');

  // A random 32-byte device secret (like the one stored with 0600).
  const deviceSecret = new Uint8Array(32);
  webcrypto.getRandomValues(deviceSecret);

  const vaultKey = new Uint8Array(32);
  webcrypto.getRandomValues(vaultKey);

  const vaultA = 'vault-AAAA';
  const vaultB = 'vault-BBBB';

  const aadA = biometricAad('linux-secret-service', vaultA);
  const aadB = biometricAad('linux-secret-service', vaultB);

  const keyA = await deriveAesKeyFromSecret(deviceSecret, 'dev:vaultA', aadA);
  const enc = await encryptAesGcm(vaultKey, keyA, aadA);

  // Correct vault: the round-trip works.
  const decrypted = await decryptAesGcm(enc.ciphertext, keyA, enc.iv, enc.tag, aadA);
  assert.deepStrictEqual(
    Array.from(decrypted),
    Array.from(vaultKey),
    'The correct vault must recover the vault key'
  );

  // A DIFFERENT vault: the AAD mismatch must make the decryption fail.
  const keyB = await deriveAesKeyFromSecret(deviceSecret, 'dev:vaultB', aadB);
  await assert.rejects(
    async () => decryptAesGcm(enc.ciphertext, keyB, enc.iv, enc.tag, aadB),
    'An envelope must NOT decrypt under a different vault identifier'
  );

  // The very same key with the WRONG AAD must also fail.
  await assert.rejects(
    async () => decryptAesGcm(enc.ciphertext, keyA, enc.iv, enc.tag, aadB),
    'The AAD must authenticate the vault identifier'
  );
});

test('SECURITY: A different device secret cannot decrypt the envelope', async () => {
  const { encryptAesGcm, decryptAesGcm } = await import('../src/crypto/aes.ts');
  const { deriveAesKeyFromSecret } = await import('../src/biometrics/kdf.ts');

  const secretA = new Uint8Array(32);
  const secretB = new Uint8Array(32);
  webcrypto.getRandomValues(secretA);
  webcrypto.getRandomValues(secretB);

  const vaultKey = new Uint8Array(32);
  webcrypto.getRandomValues(vaultKey);

  const vaultId = 'vault-CCCC';
  const aad = biometricAad('linux-secret-service', vaultId);

  const keyA = await deriveAesKeyFromSecret(secretA, 'dev:vaultC', aad);
  const enc = await encryptAesGcm(vaultKey, keyA, aad);

  const keyB = await deriveAesKeyFromSecret(secretB, 'dev:vaultC', aad);
  await assert.rejects(
    async () => decryptAesGcm(enc.ciphertext, keyB, enc.iv, enc.tag, aad),
    'A different device secret must not decrypt the envelope'
  );
});

test('Base64URL: WebAuthn credential ids round-trip correctly', async () => {
  const { bytesToBase64Url, base64UrlToBytes } = await import('../src/utils/buffer.ts');

  // Bytes that produce the `+`, `/` and `=` characters in standard Base64,
  // i.e. exactly the cases where the two alphabets differ.
  const samples = [
    new Uint8Array([0xfb, 0xff, 0xbe]),
    new Uint8Array([0x00, 0x10, 0x83, 0x10, 0x51, 0x87, 0x20, 0x92, 0x8b, 0x30]),
    new Uint8Array(32).fill(0xab),
    new Uint8Array(16)
  ];

  for (const sample of samples) {
    const encoded = bytesToBase64Url(sample);
    assert.ok(
      !/[+/=]/.test(encoded),
      `Base64URL output must not contain '+', '/' or '=': ${encoded}`
    );
    assert.deepStrictEqual(
      Array.from(base64UrlToBytes(encoded)),
      Array.from(sample),
      'Base64URL must round-trip without data loss'
    );
  }
});

// ===========================================================================
// External Biometric Bridge (Android / external browser)
// ===========================================================================

/**
 * Minimal but REALISTIC WebAuthn authenticator simulator.
 *
 * It produces a genuine ES256 key pair, signs the authenticator data and the
 * client data exactly like a platform authenticator does, and encodes the
 * signature in the ASN.1 DER form required by WebAuthn.
 *
 * It is used to prove that the plugin really verifies the ASSERTION SIGNATURE
 * (and not just the PRF secret), which is the whole point of the hardening.
 */
class FakeAuthenticator {
  constructor(origin, rpId) {
    this.origin = origin;
    this.rpId = rpId;
    this.credentialId = null;
    this.keyPair = null;
    this.userVerified = true;
  }

  async create() {
    this.keyPair = await webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const rawId = new Uint8Array(32);
    webcrypto.getRandomValues(rawId);
    this.credentialId = rawId;
    return this;
  }

  get spkiBase64() {
    return Buffer.from(
      this.keyPair.publicKey.export
        ? Buffer.from(this.keyPair.publicKey.export({ format: 'jwk' }))
        : Buffer.alloc(0)
    ).toString('base64');
  }

  async exportSpkiBase64() {
    const spki = new Uint8Array(await webcrypto.subtle.exportKey('spki', this.keyPair.publicKey));
    return Buffer.from(spki).toString('base64');
  }

  /** Builds the 37-byte authenticator data (rpIdHash + flags + counter). */
  async authenticatorData() {
    const rpIdHash = new Uint8Array(
      await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(this.rpId))
    );
    const out = new Uint8Array(37);
    out.set(rpIdHash, 0);
    out[32] = 0x01 | (this.userVerified ? 0x04 : 0x00); // UP (0x01) + UV (0x04)
    out.set(new Uint8Array([0, 0, 0, 1]), 33); // sign counter
    return out;
  }

  /** Signs the assertion and returns the DER-encoded ECDSA signature. */
  async sign(authData, clientDataJSON) {
    const clientDataHash = new Uint8Array(
      await webcrypto.subtle.digest('SHA-256', clientDataJSON)
    );
    const signed = new Uint8Array(authData.length + clientDataHash.length);
    signed.set(authData, 0);
    signed.set(clientDataHash, authData.length);

    const raw = new Uint8Array(
      await webcrypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        this.keyPair.privateKey,
        signed
      )
    );
    // WebCrypto produces the raw r||s form; WebAuthn expects ASN.1 DER.
    return rawToDer(raw);
  }

  async assertion(challenge, rpIdOverride) {
    const rpId = rpIdOverride || this.rpId;
    const clientData = Buffer.from(
      JSON.stringify({
        type: 'webauthn.get',
        challenge: toBase64Url(challenge),
        origin: this.origin,
        crossOrigin: false
      })
    );
    const clientDataJSON = new Uint8Array(clientData);
    const authData = await this.authenticatorData();
    const signature = await this.sign(authData, clientDataJSON);
    return {
      authenticatorData: Buffer.from(authData).toString('base64'),
      clientDataJSON: Buffer.from(clientDataJSON).toString('base64'),
      signature: Buffer.from(signature).toString('base64'),
      userVerified: this.userVerified,
      challenge: toBase64Url(challenge)
    };
  }
}

/** Encodes a raw r||s ECDSA signature as an ASN.1 DER SEQUENCE. */
function rawToDer(raw) {
  const r = raw.slice(0, 32);
  const s = raw.slice(32, 64);
  const encodeInt = (bytes) => {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0x00) start++;
    let value = bytes.slice(start);
    if (value[0] & 0x80) {
      const padded = new Uint8Array(value.length + 1);
      padded.set(value, 1);
      value = padded;
    }
    return value;
  };
  const rInt = encodeInt(r);
  const sInt = encodeInt(s);
  const bodyLength = 2 + rInt.length + 2 + sInt.length;
  const out = new Uint8Array(2 + bodyLength);
  out[0] = 0x30;
  out[1] = bodyLength;
  let off = 2;
  out[off++] = 0x02;
  out[off++] = rInt.length;
  out.set(rInt, off);
  off += rInt.length;
  out[off++] = 0x02;
  out[off++] = sInt.length;
  out.set(sInt, off);
  return out;
}

function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Reproduces the one-way vault binding that the plugin puts in the URL
 * fragment (see `vaultBinding()` in `external-bridge-provider.ts`).
 */
function vaultBindingOf(vaultId) {
  return sha256HexSync(`mysecret-bridge-vault:${vaultId}`);
}

/**
 * Builds the encrypted bridge message exactly like `auth-bridge/auth.js` does:
 * ECDH -> HKDF-SHA256 -> AES-256-GCM with the bound AAD.
 */
async function buildBridgeMessage({
  obsidianPubHex,
  payload,
  session,
  action,
  vaultBinding,
  protocolVersion = 2
}) {
  const obsidianPubKey = await webcrypto.subtle.importKey(
    'raw',
    hexToBytes(obsidianPubHex),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const browserKeyPair = await webcrypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );

  const sharedSecret = await webcrypto.subtle.deriveBits(
    { name: 'ECDH', public: obsidianPubKey },
    browserKeyPair.privateKey,
    256
  );

  // The plugin sends a one-way `vb` binding of the vault id in the URL
  // fragment and always recomputes it, so the browser just echoes it back.
  const aad = `mysecret-bridge:v${protocolVersion}:${action}:${session}:${vaultBinding}`;

  const hkdfKey = await webcrypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveBits']);
  const okm = await webcrypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode(`mysecret-bridge:${session}`),
      info: new TextEncoder().encode(aad)
    },
    hkdfKey,
    256
  );
  const sharedKey = await webcrypto.subtle.importKey('raw', okm, { name: 'AES-GCM' }, false, ['encrypt']);

  const browserPubBytes = new Uint8Array(await webcrypto.subtle.exportKey('raw', browserKeyPair.publicKey));
  const iv = new Uint8Array(12);
  webcrypto.getRandomValues(iv);

  const encBuffer = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(aad), tagLength: 128 },
    sharedKey,
    new TextEncoder().encode(JSON.stringify(payload))
  );

  const fullEncBytes = new Uint8Array(encBuffer);
  const tagBytes = fullEncBytes.slice(fullEncBytes.length - 16);
  const cipherBytes = fullEncBytes.slice(0, fullEncBytes.length - 16);

  return {
    pub: bytesToHex(browserPubBytes),
    iv: bytesToHex(iv),
    tag: bytesToHex(tagBytes),
    data: bytesToHex(cipherBytes)
  };
}

test('ExternalBridgeProvider: End-to-end ECDH enrollment, verification, and session security', async () => {
  const { ExternalBridgeProvider, BRIDGE_PROTOCOL_VERSION } = await import('../src/biometrics/external-bridge-provider.ts');
  const { hexToBytes, bytesToHex } = await import('../src/utils/buffer.ts');

  const BRIDGE_URL = 'https://mysecret-vault.pages.dev';
  const ORIGIN = 'https://mysecret-vault.pages.dev';
  const RP_ID = 'mysecret-vault.pages.dev';

  const provider = new ExternalBridgeProvider(BRIDGE_URL);
  assert.strictEqual(await provider.isAvailable(), true, 'Valid HTTPS bridge URL should report available');

  const invalidProvider = new ExternalBridgeProvider('');
  assert.strictEqual(await invalidProvider.isAvailable(), false, 'Empty bridge URL should not be available');

  // Track the URL passed to window.open
  let capturedUrl = '';
  globalThis.window.open = (url) => {
    capturedUrl = url;
    return {};
  };

  const rawVaultKey = new Uint8Array(32);
  webcrypto.getRandomValues(rawVaultKey);
  const rawKeyOriginal = new Uint8Array(rawVaultKey);
  const vaultId = 'test-android-vault-123';
  const deviceId = 'test-device-android-xyz';

  // --- 1. Enrollment ---------------------------------------------------
  const enrollPromise = provider.enroll(rawVaultKey, deviceId, vaultId);
  await new Promise(r => setTimeout(r, 20));
  assert.ok(capturedUrl.includes('action=enroll'), 'Target URL must contain action=enroll in hash');
  assert.ok(
    capturedUrl.includes(`v=${BRIDGE_PROTOCOL_VERSION}`),
    'Target URL must carry the protocol version'
  );

  const urlParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const sessionToken = urlParams.get('session');
  const obsidianPubHex = urlParams.get('pub');
  const saltHex = urlParams.get('salt');
  const challengeHex = urlParams.get('challenge');

  assert.ok(sessionToken && sessionToken.length === 64, 'Session token must be 32 bytes hex');
  assert.ok(obsidianPubHex && obsidianPubHex.length === 130, 'Obsidian P-256 public key must be 65 bytes (130 hex chars)');
  assert.ok(saltHex && saltHex.length === 64, 'Salt must be 32 bytes hex');
  assert.ok(challengeHex && challengeHex.length === 64, 'The relying party must provide the WebAuthn challenge');

  // SECURITY: the raw vault id must NEVER travel to the browser. Only a
  // one-way binding (`vb`) does.
  const vaultBindingParam = urlParams.get('vb');
  assert.ok(vaultBindingParam && vaultBindingParam.length === 64, 'URL must carry the vault binding');
  assert.strictEqual(vaultBindingParam, vaultBindingOf(vaultId), 'The binding must match the vault');
  assert.ok(!capturedUrl.includes(vaultId), 'The raw vault id must not leak into the bridge URL');
  assert.strictEqual(urlParams.get('vaultId'), null, 'The vault id must not be sent as a parameter');

  const fakePrfSecret = new Uint8Array(32);
  webcrypto.getRandomValues(fakePrfSecret);

  // The authenticator signs the assertion over the challenge chosen by the plugin.
  const authenticator = await new FakeAuthenticator(ORIGIN, RP_ID).create();
  const enrollAssertion = await authenticator.assertion(hexToBytes(challengeHex));
  const publicKeyBase64 = await authenticator.exportSpkiBase64();

  const enrollMessage = await buildBridgeMessage({
    obsidianPubHex,
    session: sessionToken,
    action: 'enroll',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'enroll',
      credentialId: toBase64Url(authenticator.credentialId),
      publicKey: publicKeyBase64,
      prfSecret: bytesToHex(fakePrfSecret),
      session: sessionToken,
      assertion: enrollAssertion
    }
  });

  const handled = await provider.handleProtocolCallback({
    session: sessionToken,
    ...enrollMessage
  });
  assert.strictEqual(handled, true, 'Provider should claim and handle matching protocol callback');

  const envelope = await enrollPromise;
  assert.strictEqual(envelope.providerType, 'external-bridge');
  assert.strictEqual(envelope.credentialId, toBase64Url(authenticator.credentialId));
  assert.strictEqual(envelope.prfSalt, saltHex);
  assert.ok(envelope.ciphertext && envelope.tag && envelope.iv, 'Envelope must contain AES-GCM ciphertext');
  assert.strictEqual(envelope.credentialPublicKey, publicKeyBase64, 'The credential public key must be persisted');
  assert.strictEqual(envelope.rpId, RP_ID, 'The relying party id must be pinned in the envelope');
  assert.strictEqual(envelope.origin, ORIGIN, 'The origin must be pinned in the envelope');

  // --- 2. Verification -------------------------------------------------
  capturedUrl = '';
  const verifyPromise = provider.verifyAndDecrypt(envelope, vaultId);
  await new Promise(r => setTimeout(r, 20));
  assert.ok(capturedUrl.includes('action=verify'), 'Verification URL must contain action=verify');

  const verifyParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const verifySessionToken = verifyParams.get('session');
  const verifyObsidianPubHex = verifyParams.get('pub');
  const verifyChallengeHex = verifyParams.get('challenge');
  assert.ok(verifyChallengeHex, 'The verification ceremony must also carry a fresh challenge');

  const verifyAssertion = await authenticator.assertion(hexToBytes(verifyChallengeHex));

  const verifyMessage = await buildBridgeMessage({
    obsidianPubHex: verifyObsidianPubHex,
    session: verifySessionToken,
    action: 'verify',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'verify',
      credentialId: toBase64Url(authenticator.credentialId),
      prfSecret: bytesToHex(fakePrfSecret),
      session: verifySessionToken,
      assertion: verifyAssertion
    }
  });

  const verifyHandled = await provider.handleProtocolCallback({
    session: verifySessionToken,
    ...verifyMessage
  });
  assert.strictEqual(verifyHandled, true);

  const decryptedVaultKey = await verifyPromise;
  assert.ok(decryptedVaultKey, 'Decryption must succeed');
  assert.deepStrictEqual(
    Array.from(decryptedVaultKey),
    Array.from(rawKeyOriginal),
    'Decrypted vault key must exactly match the original raw vault key'
  );

  // --- 3. Replay / session mismatch protection --------------------------
  const replayHandled = await provider.handleProtocolCallback({
    session: 'bogus-session-token',
    ...verifyMessage
  });
  assert.strictEqual(replayHandled, false, 'Stale or mismatched session tokens must be rejected');

  // --- 4. Cancellation --------------------------------------------------
  const pendingCancelPromise = provider.enroll(new Uint8Array(32), deviceId, vaultId);
  await new Promise(r => setTimeout(r, 20));
  assert.strictEqual(provider.hasPendingSession(), true);
  provider.cancelPendingSession();
  assert.strictEqual(provider.hasPendingSession(), false);
  await assert.rejects(
    async () => await pendingCancelPromise,
    /cancelada/i,
    'Cancelling pending session must cleanly reject the promise'
  );
});

test('SECURITY: The bridge rejects an assertion signed by a DIFFERENT credential', async () => {
  const { ExternalBridgeProvider, BRIDGE_PROTOCOL_VERSION } = await import('../src/biometrics/external-bridge-provider.ts');
  const { hexToBytes, bytesToHex } = await import('../src/utils/buffer.ts');

  const BRIDGE_URL = 'https://mysecret-vault.pages.dev';
  const ORIGIN = 'https://mysecret-vault.pages.dev';
  const RP_ID = 'mysecret-vault.pages.dev';

  const provider = new ExternalBridgeProvider(BRIDGE_URL);
  let capturedUrl = '';
  globalThis.window.open = (url) => {
    capturedUrl = url;
    return {};
  };

  const rawVaultKey = new Uint8Array(32);
  webcrypto.getRandomValues(rawVaultKey);
  const vaultId = 'test-bridge-tamper-vault';
  const deviceId = 'test-device-tamper';

  const enrollPromise = provider.enroll(rawVaultKey, deviceId, vaultId);
  await new Promise(r => setTimeout(r, 20));

  const urlParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const sessionToken = urlParams.get('session');
  const obsidianPubHex = urlParams.get('pub');
  const challengeHex = urlParams.get('challenge');

  const fakePrfSecret = new Uint8Array(32);
  webcrypto.getRandomValues(fakePrfSecret);

  // The HONEST authenticator is enrolled...
  const honest = await new FakeAuthenticator(ORIGIN, RP_ID).create();
  const honestAssertion = await honest.assertion(hexToBytes(challengeHex));
  const honestPubKey = await honest.exportSpkiBase64();

  const enrollMessage = await buildBridgeMessage({
    obsidianPubHex,
    session: sessionToken,
    action: 'enroll',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'enroll',
      credentialId: toBase64Url(honest.credentialId),
      publicKey: honestPubKey,
      prfSecret: bytesToHex(fakePrfSecret),
      session: sessionToken,
      assertion: honestAssertion
    }
  });

  await provider.handleProtocolCallback({ session: sessionToken, ...enrollMessage });
  const envelope = await enrollPromise;

  // ...but a MALICIOUS authenticator (a different key pair) tries to unlock.
  capturedUrl = '';
  const verifyPromise = provider.verifyAndDecrypt(envelope, vaultId);
  await new Promise(r => setTimeout(r, 20));

  const verifyParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const verifySessionToken = verifyParams.get('session');
  const verifyObsidianPubHex = verifyParams.get('pub');
  const verifyChallengeHex = verifyParams.get('challenge');

  const attacker = await new FakeAuthenticator(ORIGIN, RP_ID).create();
  const attackerAssertion = await attacker.assertion(hexToBytes(verifyChallengeHex));

  const attackMessage = await buildBridgeMessage({
    obsidianPubHex: verifyObsidianPubHex,
    session: verifySessionToken,
    action: 'verify',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'verify',
      credentialId: toBase64Url(attacker.credentialId),
      prfSecret: bytesToHex(fakePrfSecret),
      session: verifySessionToken,
      assertion: attackerAssertion
    }
  });

  await provider.handleProtocolCallback({ session: verifySessionToken, ...attackMessage });

  const result = await verifyPromise;
  assert.strictEqual(
    result,
    null,
    'A signature made by a different credential must NOT unlock the vault'
  );
});

test('SECURITY: The bridge rejects an assertion without user verification', async () => {
  const { ExternalBridgeProvider, BRIDGE_PROTOCOL_VERSION } = await import('../src/biometrics/external-bridge-provider.ts');
  const { hexToBytes, bytesToHex } = await import('../src/utils/buffer.ts');

  const BRIDGE_URL = 'https://mysecret-vault.pages.dev';
  const ORIGIN = 'https://mysecret-vault.pages.dev';
  const RP_ID = 'mysecret-vault.pages.dev';

  const provider = new ExternalBridgeProvider(BRIDGE_URL);
  let capturedUrl = '';
  globalThis.window.open = (url) => {
    capturedUrl = url;
    return {};
  };

  const rawVaultKey = new Uint8Array(32);
  webcrypto.getRandomValues(rawVaultKey);
  const vaultId = 'test-bridge-uv-vault';
  const deviceId = 'test-device-uv';

  const authenticator = await new FakeAuthenticator(ORIGIN, RP_ID).create();

  const enrollPromise = provider.enroll(rawVaultKey, deviceId, vaultId);
  await new Promise(r => setTimeout(r, 20));
  const urlParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const sessionToken = urlParams.get('session');
  const obsidianPubHex = urlParams.get('pub');
  const challengeHex = urlParams.get('challenge');
  const publicKeyBase64 = await authenticator.exportSpkiBase64();

  const fakePrfSecret = new Uint8Array(32);
  webcrypto.getRandomValues(fakePrfSecret);

  const enrollAssertion = await authenticator.assertion(hexToBytes(challengeHex));
  const enrollMessage = await buildBridgeMessage({
    obsidianPubHex,
    session: sessionToken,
    action: 'enroll',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'enroll',
      credentialId: toBase64Url(authenticator.credentialId),
      publicKey: publicKeyBase64,
      prfSecret: bytesToHex(fakePrfSecret),
      session: sessionToken,
      assertion: enrollAssertion
    }
  });
  await provider.handleProtocolCallback({ session: sessionToken, ...enrollMessage });
  const envelope = await enrollPromise;

  // Now the authenticator reports "user present but NOT verified".
  capturedUrl = '';
  const verifyPromise = provider.verifyAndDecrypt(envelope, vaultId);
  await new Promise(r => setTimeout(r, 20));
  const verifyParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const verifySessionToken = verifyParams.get('session');
  const verifyObsidianPubHex = verifyParams.get('pub');
  const verifyChallengeHex = verifyParams.get('challenge');

  authenticator.userVerified = false;
  const unverifiedAssertion = await authenticator.assertion(hexToBytes(verifyChallengeHex));

  const attackMessage = await buildBridgeMessage({
    obsidianPubHex: verifyObsidianPubHex,
    session: verifySessionToken,
    action: 'verify',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'verify',
      credentialId: toBase64Url(authenticator.credentialId),
      prfSecret: bytesToHex(fakePrfSecret),
      session: verifySessionToken,
      assertion: unverifiedAssertion
    }
  });

  await provider.handleProtocolCallback({ session: verifySessionToken, ...attackMessage });

  const result = await verifyPromise;
  assert.strictEqual(
    result,
    null,
    'An assertion without user verification must NOT unlock the vault'
  );
});

test('SECURITY: The bridge rejects a replayed assertion (stale challenge)', async () => {
  const { ExternalBridgeProvider, BRIDGE_PROTOCOL_VERSION } = await import('../src/biometrics/external-bridge-provider.ts');
  const { hexToBytes, bytesToHex } = await import('../src/utils/buffer.ts');

  const BRIDGE_URL = 'https://mysecret-vault.pages.dev';
  const ORIGIN = 'https://mysecret-vault.pages.dev';
  const RP_ID = 'mysecret-vault.pages.dev';

  const provider = new ExternalBridgeProvider(BRIDGE_URL);
  let capturedUrl = '';
  globalThis.window.open = (url) => {
    capturedUrl = url;
    return {};
  };

  const rawVaultKey = new Uint8Array(32);
  webcrypto.getRandomValues(rawVaultKey);
  const vaultId = 'test-bridge-replay-vault';
  const deviceId = 'test-device-replay';

  const authenticator = await new FakeAuthenticator(ORIGIN, RP_ID).create();
  const publicKeyBase64 = await authenticator.exportSpkiBase64();
  const fakePrfSecret = new Uint8Array(32);
  webcrypto.getRandomValues(fakePrfSecret);

  const enrollPromise = provider.enroll(rawVaultKey, deviceId, vaultId);
  await new Promise(r => setTimeout(r, 20));
  const urlParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const sessionToken = urlParams.get('session');
  const obsidianPubHex = urlParams.get('pub');
  const challengeHex = urlParams.get('challenge');

  const enrollAssertion = await authenticator.assertion(hexToBytes(challengeHex));
  const enrollMessage = await buildBridgeMessage({
    obsidianPubHex,
    session: sessionToken,
    action: 'enroll',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'enroll',
      credentialId: toBase64Url(authenticator.credentialId),
      publicKey: publicKeyBase64,
      prfSecret: bytesToHex(fakePrfSecret),
      session: sessionToken,
      assertion: enrollAssertion
    }
  });
  await provider.handleProtocolCallback({ session: sessionToken, ...enrollMessage });
  const envelope = await enrollPromise;

  // Capture a VALID assertion of the first verification ceremony...
  capturedUrl = '';
  const verifyPromise = provider.verifyAndDecrypt(envelope, vaultId);
  await new Promise(r => setTimeout(r, 20));
  const verifyParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const verifySessionToken = verifyParams.get('session');
  const verifyObsidianPubHex = verifyParams.get('pub');
  const verifyChallengeHex = verifyParams.get('challenge');

  const goodAssertion = await authenticator.assertion(hexToBytes(verifyChallengeHex));

  // ...and REPLAY it in a SECOND ceremony, with a DIFFERENT challenge.
  capturedUrl = '';
  const replayPromise = provider.verifyAndDecrypt(envelope, vaultId);
  await new Promise(r => setTimeout(r, 20));
  const replayParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const replaySessionToken = replayParams.get('session');
  const replayObsidianPubHex = replayParams.get('pub');

  const replayMessage = await buildBridgeMessage({
    obsidianPubHex: replayObsidianPubHex,
    session: replaySessionToken,
    action: 'verify',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'verify',
      credentialId: toBase64Url(authenticator.credentialId),
      prfSecret: bytesToHex(fakePrfSecret),
      session: replaySessionToken,
      assertion: goodAssertion
    }
  });

  await provider.handleProtocolCallback({ session: replaySessionToken, ...replayMessage });

  const replayResult = await replayPromise;
  assert.strictEqual(
    replayResult,
    null,
    'An assertion signed for a PREVIOUS challenge must NOT unlock the vault'
  );

  // Sanity: the honest flow still works with a fresh challenge.
  capturedUrl = '';
  const okPromise = provider.verifyAndDecrypt(envelope, vaultId);
  await new Promise(r => setTimeout(r, 20));
  const okParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const okSessionToken = okParams.get('session');
  const okObsidianPubHex = okParams.get('pub');
  const okChallengeHex = okParams.get('challenge');
  const okAssertion = await authenticator.assertion(hexToBytes(okChallengeHex));
  const okMessage = await buildBridgeMessage({
    obsidianPubHex: okObsidianPubHex,
    session: okSessionToken,
    action: 'verify',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'verify',
      credentialId: toBase64Url(authenticator.credentialId),
      prfSecret: bytesToHex(fakePrfSecret),
      session: okSessionToken,
      assertion: okAssertion
    }
  });
  await provider.handleProtocolCallback({ session: okSessionToken, ...okMessage });
  const okResult = await okPromise;
  assert.ok(okResult, 'A fresh, correctly signed assertion must unlock the vault');
  assert.deepStrictEqual(Array.from(okResult), Array.from(rawVaultKey));
});

// ===========================================================================
// Security regression tests for the external biometric bridge
// ===========================================================================

test('SECURITY: The bridge URL validator rejects dangerous schemes and plain HTTP', async () => {
  const { validateBridgeUrl } = await import('../src/biometrics/bridge-url.ts');

  const dangerous = [
    'javascript:alert(1)',
    'JavaScript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'file:///etc/passwd',
    'blob:https://example.com/abc',
    'http://evil.example.com',
    'https://user:pass@example.com',
    ''
  ];

  for (const url of dangerous) {
    const result = validateBridgeUrl(url);
    assert.strictEqual(
      result.valid,
      false,
      `The URL "${url}" must be rejected`
    );
    assert.ok(result.reason, `The URL "${url}" must explain why it was rejected`);
  }

  // A valid HTTPS Cloudflare Pages URL is accepted and normalized.
  const good = validateBridgeUrl('https://mi-boveda.pages.dev/');
  assert.strictEqual(good.valid, true);
  assert.strictEqual(good.url, 'https://mi-boveda.pages.dev');

  // A bare host is upgraded to HTTPS.
  const bare = validateBridgeUrl('mi-boveda.pages.dev');
  assert.strictEqual(bare.valid, true);
  assert.strictEqual(bare.url, 'https://mi-boveda.pages.dev');
});

test('SECURITY: The RP ID is pinned to the registrable domain of the bridge', async () => {
  const { computeRpId } = await import('../src/biometrics/rp-id.ts');

  // `pages.dev` IS a public suffix (verified against the Public Suffix List),
  // so the host itself is the registrable domain.
  assert.strictEqual(computeRpId('mi-boveda.pages.dev'), 'mi-boveda.pages.dev');
  assert.strictEqual(computeRpId('workers.dev'), 'workers.dev');
  assert.strictEqual(computeRpId('mysecret.riiosanthony.workers.dev'), 'mysecret.riiosanthony.workers.dev');

  // A plain domain uses the classic tld+1 rule.
  assert.strictEqual(computeRpId('example.com'), 'example.com');
  assert.strictEqual(computeRpId('auth.example.com'), 'example.com');

  // A multi-label public suffix keeps the whole registrable domain.
  assert.strictEqual(computeRpId('auth.example.co.uk'), 'example.co.uk');

  // IP literals and localhost are registrable on their own.
  assert.strictEqual(computeRpId('localhost'), 'localhost');
  assert.strictEqual(computeRpId('192.168.1.10'), '192.168.1.10');
});

test('SECURITY: The strict hex decoder rejects malformed values', async () => {
  const { hexToBytesStrict } = await import('../src/utils/buffer.ts');

  assert.throws(() => hexToBytesStrict(''), /Invalid hex string/);
  assert.throws(() => hexToBytesStrict('abc'), /Invalid hex string length/);
  assert.throws(() => hexToBytesStrict('zz'), /Invalid hex string/);
  assert.throws(() => hexToBytesStrict('00 11'), /Invalid hex string/);

  const ok = hexToBytesStrict('00ff10');
  assert.strictEqual(ok.length, 3);
  assert.strictEqual(ok[0], 0x00);
  assert.strictEqual(ok[1], 0xff);
  assert.strictEqual(ok[2], 0x10);
});

test('SECURITY: A PRF output shorter than 32 bytes is REJECTED', async () => {
  const { normalizePrfOutput, MIN_PRF_SECRET_LENGTH } = await import('../src/biometrics/webauthn-assertion.ts');

  assert.strictEqual(MIN_PRF_SECRET_LENGTH, 32);

  // An EMPTY result would hash to a PUBLIC constant: it must never be
  // accepted, otherwise the wrapping key would be known to everybody.
  assert.throws(() => normalizePrfOutput(new Uint8Array(0)), /demasiado corto/);
  assert.throws(() => normalizePrfOutput(''), /demasiado corto/);
  assert.throws(() => normalizePrfOutput(undefined), /válido/);
  assert.throws(() => normalizePrfOutput(null), /válido/);
  assert.throws(() => normalizePrfOutput({}), /válido/);

  // A valid 32-byte secret is accepted.
  const good = normalizePrfOutput(new Uint8Array(32).fill(7));
  assert.strictEqual(good.length, 32);
});

test('SECURITY: The DER to raw ECDSA signature conversion is correct', async () => {
  const { derToRawEcdsaSignature } = await import('../src/biometrics/webauthn-assertion.ts');

  // SEQUENCE { INTEGER 1, INTEGER 2 }
  const der = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
  const raw = derToRawEcdsaSignature(der);
  assert.strictEqual(raw.length, 64);
  assert.strictEqual(raw[31], 0x01);
  assert.strictEqual(raw[63], 0x02);
  // The remaining bytes must be zero (left padding).
  assert.strictEqual(raw[0], 0x00);
  assert.strictEqual(raw[32], 0x00);

  // A malformed signature must throw instead of producing garbage.
  assert.throws(() => derToRawEcdsaSignature(new Uint8Array([0x31, 0x00])));
  assert.throws(() => derToRawEcdsaSignature(new Uint8Array([0x30, 0x06, 0x02])));
});

test('SECURITY: The vault id NEVER travels to the browser, only a one-way binding', async () => {
  const { sha256HexSync: sha } = await import('../src/utils/sha256.ts');

  const vaultId = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  // The binding is deterministic and domain-separated.
  const binding = vaultBindingOf(vaultId);
  assert.strictEqual(binding.length, 64);
  assert.strictEqual(binding, sha(`mysecret-bridge-vault:${vaultId}`));
  assert.strictEqual(binding, vaultBindingOf(vaultId), 'Binding must be stable');

  // It must NOT be the raw vault id, nor a plain hash of it (which would let
  // an attacker confirm a guessed vault id).
  assert.notStrictEqual(binding, vaultId);
  assert.notStrictEqual(binding, sha(vaultId));
  assert.strictEqual(binding, sha(`mysecret-bridge-vault:${vaultId}`));

  // Different vaults produce different bindings.
  assert.notStrictEqual(binding, vaultBindingOf(`${vaultId}-other`));
});

test('SECURITY: A tampered vault binding makes the bridge message fail to decrypt', async () => {
  const { ExternalBridgeProvider, BRIDGE_PROTOCOL_VERSION } = await import('../src/biometrics/external-bridge-provider.ts');
  const { hexToBytes, bytesToHex } = await import('../src/utils/buffer.ts');

  const BRIDGE_URL = 'https://mysecret-vault.pages.dev';
  const ORIGIN = 'https://mysecret-vault.pages.dev';
  const RP_ID = 'mysecret-vault.pages.dev';

  const provider = new ExternalBridgeProvider(BRIDGE_URL);

  let capturedUrl = '';
  globalThis.window.open = (url) => {
    capturedUrl = url;
    return {};
  };

  const rawVaultKey = new Uint8Array(32);
  webcrypto.getRandomValues(rawVaultKey);
  const vaultId = 'vault-binding-tamper';
  const deviceId = 'device-binding-tamper';

  // --- Enroll -----------------------------------------------------------
  const enrollPromise = provider.enroll(rawVaultKey, deviceId, vaultId);
  for (let i = 0; i < 50 && !capturedUrl; i++) await new Promise(r => setTimeout(r, 10));

  const enrollParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const sessionToken = enrollParams.get('session');
  const obsidianPubHex = enrollParams.get('pub');
  const challengeHex = enrollParams.get('challenge');

  const authenticator = await new FakeAuthenticator(ORIGIN, RP_ID).create();
  const enrollAssertion = await authenticator.assertion(hexToBytes(challengeHex));

  const prfSecret = new Uint8Array(32);
  webcrypto.getRandomValues(prfSecret);

  const enrollMessage = await buildBridgeMessage({
    obsidianPubHex,
    session: sessionToken,
    action: 'enroll',
    vaultBinding: vaultBindingOf(vaultId),
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'enroll',
      credentialId: toBase64Url(authenticator.credentialId),
      publicKey: await authenticator.exportSpkiBase64(),
      prfSecret: bytesToHex(prfSecret),
      session: sessionToken,
      assertion: enrollAssertion
    }
  });

  await provider.handleProtocolCallback({ session: sessionToken, ...enrollMessage });
  const envelope = await enrollPromise;
  assert.ok(envelope, 'Enrollment must succeed with the correct binding');

  // --- Verify with a TAMPERED binding (as a malicious page would try) ---
  capturedUrl = '';
  const verifyPromise = provider.verifyAndDecrypt(envelope, vaultId);
  for (let i = 0; i < 50 && !capturedUrl; i++) await new Promise(r => setTimeout(r, 10));

  const verifyParams = new URLSearchParams(capturedUrl.split('#')[1]);
  const verifySessionToken = verifyParams.get('session');
  const verifyPubHex = verifyParams.get('pub');
  const verifyChallengeHex = verifyParams.get('challenge');

  const verifyAssertion = await authenticator.assertion(hexToBytes(verifyChallengeHex));

  // The browser uses a WRONG binding: the plugin must refuse to decrypt.
  const tamperedBinding = vaultBindingOf('some-other-vault');

  const tamperedMessage = await buildBridgeMessage({
    obsidianPubHex: verifyPubHex,
    session: verifySessionToken,
    action: 'verify',
    vaultBinding: tamperedBinding,
    payload: {
      v: BRIDGE_PROTOCOL_VERSION,
      action: 'verify',
      credentialId: toBase64Url(authenticator.credentialId),
      prfSecret: bytesToHex(prfSecret),
      session: verifySessionToken,
      assertion: verifyAssertion
    }
  });

  await provider.handleProtocolCallback({ session: verifySessionToken, ...tamperedMessage });

  const result = await verifyPromise;
  assert.strictEqual(result, null, 'A tampered vault binding MUST fail closed (no key returned)');
});
