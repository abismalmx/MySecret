/**
 * Regression tests for the findings of the second security audit.
 *
 * Every test here FAILS against the code as it was before the fixes and
 * passes now. Grouped by finding:
 *
 *   A2  password change: current password required, stable vault id
 *   A3  Linux biometrics: no unlock path without a user-verification gate
 *   W   Windows availability parser ("UNAVAILABLE" contains "AVAILABLE")
 *   F   path filter: hidden text notes are not left in cleartext
 *   R   restore: ciphertext must authenticate; the manifest is not trusted
 *   B   backup: files that cannot be included are reported, never dropped
 *   I   interceptor: per-path serialization, deferred re-binds, policy changes
 *   P   Publish guard follows the Publish plugin instance
 *   X   bridge: error messages containing "%" do not hang the session
 */

import assert from 'node:assert';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { zipSync, strToU8 } from 'fflate';

const mockStorage = new Map();
if (!globalThis.window) {
  globalThis.window = {
    crypto: webcrypto,
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
    addEventListener: () => {},
    removeEventListener: () => {},
    localStorage: {
      getItem: (k) => (mockStorage.has(k) ? mockStorage.get(k) : null),
      setItem: (k, v) => mockStorage.set(k, String(v)),
      removeItem: (k) => mockStorage.delete(k)
    }
  };
}
if (!globalThis.document) {
  globalThis.document = { body: { classList: { add: () => {}, remove: () => {} } }, querySelectorAll: () => [] };
}
if (!globalThis.MutationObserver) {
  globalThis.MutationObserver = class { observe() {} disconnect() {} };
}

import { KeyManager, isValidEnvelopeShape } from '../src/crypto/key-manager.ts';
import { importAesKey } from '../src/crypto/aes.ts';
import { PathFilter } from '../src/adapter/path-filter.ts';
import { AdapterInterceptor } from '../src/adapter/adapter-interceptor.ts';
import { PublishGuard } from '../src/adapter/publish-guard.ts';
import { BackupEngine } from '../src/backup/backup-engine.ts';
import { decodeUtf8Strict } from '../src/utils/buffer.ts';
import { isArmoredEncrypted, isBinaryEncrypted } from '../src/crypto/envelope.ts';
import { detectContainerFormat } from '../src/adapter/decrypt.ts';
import { LinuxBiometricProvider } from '../src/biometrics/linux-provider.ts';
import { parseAvailabilityOutput, parseVerificationOutput } from '../src/biometrics/windows-provider.ts';
import { BIOMETRIC_ENVELOPE_VERSION } from '../src/biometrics/kdf.ts';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function createFakeAdapter() {
  const files = new Map();
  const dirs = new Set();
  return {
    files,
    dirs,
    async exists(p) { return files.has(p) || dirs.has(p); },
    async mkdir(p) { dirs.add(p); },
    async read(p) {
      if (!files.has(p)) throw new Error('not found: ' + p);
      return new TextDecoder().decode(files.get(p));
    },
    async readBinary(p) {
      if (!files.has(p)) throw new Error('not found: ' + p);
      const b = files.get(p);
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    },
    async write(p, data) { files.set(p, new TextEncoder().encode(data)); },
    async writeBinary(p, data) { files.set(p, new Uint8Array(data)); },
    async list() { return { files: [], folders: [] }; },
    async stat(p) { return files.has(p) ? { type: 'file' } : null; },
    async rename(oldPath, newPath) {
      for (const key of [...files.keys()]) {
        if (key === oldPath) { files.set(newPath, files.get(key)); files.delete(key); }
      }
    },
    async copy(a, b) { files.set(b, files.get(a)); }
  };
}

async function createUnlockedKeyManager(fill = 7) {
  const km = new KeyManager();
  km.rawVaultKey = new Uint8Array(32).fill(fill);
  km.vaultKey = await importAesKey(km.rawVaultKey);
  km._isLocked = false;
  return km;
}

function lockKm(km) {
  km._isLocked = true;
}
function unlockKm(km) {
  km._isLocked = false;
}

function createPlugin(adapter, keyManager, pathFilter, extra = {}) {
  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();
  return {
    keyManager,
    pathFilter,
    interceptor,
    app: {
      vault: {
        adapter,
        getFiles: () => [...adapter.files.keys()].map((path) => ({ path })),
        getName: () => 'TestVault'
      }
    },
    ...extra
  };
}

// ---------------------------------------------------------------------------
// A2 — password change
// ---------------------------------------------------------------------------

test('A2: verifyPassword checks the password without changing the lock state', async () => {
  const km = new KeyManager();
  const { commit } = await km.initializeVault('Correct-Horse-Battery-Staple-42', false);
  await commit();

  assert.strictEqual(await km.verifyPassword('Correct-Horse-Battery-Staple-42'), true);
  assert.strictEqual(await km.verifyPassword('wrong-password-123456'), false);
  assert.strictEqual(await km.verifyPassword(''), false);
  assert.strictEqual(km.isLocked, false, 'verifying must not touch the lock state');
  km.lock();
  assert.strictEqual(await km.verifyPassword('Correct-Horse-Battery-Staple-42'), true);
  assert.strictEqual(km.isLocked, true, 'verifying must not unlock the vault');
});

test('A2: changing the master password requires the CURRENT password', async () => {
  const km = new KeyManager();
  const { commit } = await km.initializeVault('Correct-Horse-Battery-Staple-42', false);
  await commit();
  const before = JSON.stringify(km.getEnvelope());

  await assert.rejects(
    () => km.changeMasterPassword('A-Brand-New-Passphrase-2026!', 'not-the-password'),
    /current password is incorrect/i
  );
  assert.strictEqual(JSON.stringify(km.getEnvelope()), before, 'a rejected change must not alter the envelope');

  await km.changeMasterPassword('A-Brand-New-Passphrase-2026!', 'Correct-Horse-Battery-Staple-42');
  km.lock();
  assert.strictEqual(await km.unlockWithPassword('A-Brand-New-Passphrase-2026!'), true);
});

test('A2: the vault id (biometric slot) survives a password change', async () => {
  const km = new KeyManager();
  const { commit, envelope } = await km.initializeVault('Correct-Horse-Battery-Staple-42', false);
  await commit();

  assert.ok(envelope.vaultId, 'new vaults carry a stable vault id');
  const idBefore = km.getEnvelope().vaultId;
  const saltBefore = km.getEnvelope().argon2.salt;

  await km.changeMasterPassword('A-Brand-New-Passphrase-2026!', 'Correct-Horse-Battery-Staple-42');

  assert.notStrictEqual(km.getEnvelope().argon2.salt, saltBefore, 'the salt is renewed');
  assert.strictEqual(km.getEnvelope().vaultId, idBefore, 'the vault id must NOT change');
});

test('A2: a legacy envelope (no vaultId) pins the CURRENT salt as its id', async () => {
  const km = new KeyManager();
  const { commit } = await km.initializeVault('Correct-Horse-Battery-Staple-42', false);
  await commit();
  const env = km.getEnvelope();
  delete env.vaultId; // what an envelope created by an older version looks like
  const legacySalt = env.argon2.salt;

  await km.changeMasterPassword('A-Brand-New-Passphrase-2026!', 'Correct-Horse-Battery-Staple-42');

  assert.strictEqual(
    km.getEnvelope().vaultId,
    legacySalt,
    'existing biometric enrollments were keyed with the old salt: it must become the id'
  );
});

test('Envelope shape validation rejects malformed or tampered envelopes', async () => {
  const km = new KeyManager();
  const { envelope } = await km.initializeVault('Correct-Horse-Battery-Staple-42', true);
  assert.strictEqual(isValidEnvelopeShape(envelope), true);

  const clone = () => JSON.parse(JSON.stringify(envelope));
  const bad = [];
  let e = clone(); delete e.argon2; bad.push(e);
  e = clone(); e.argon2.salt = 'zz'; bad.push(e);
  e = clone(); e.argon2.salt = 'abcd'; bad.push(e); // wrong length
  e = clone(); e.vaultKeyEnvelope.iv = 'abc'; bad.push(e); // odd length
  e = clone(); e.vaultKeyEnvelope.ciphertext = 'aa'; bad.push(e);
  e = clone(); e.argon2.memory = '65536'; bad.push(e);
  e = clone(); e.recoveryEnvelope.tag = 123; bad.push(e);
  bad.push(null, 'string', 42, {});
  for (const candidate of bad) {
    assert.strictEqual(isValidEnvelopeShape(candidate), false, JSON.stringify(candidate)?.slice(0, 80));
  }
});

// ---------------------------------------------------------------------------
// A3 — Linux biometrics
// ---------------------------------------------------------------------------

test('A3: Linux biometrics are NOT available without a fingerprint reader', async () => {
  const provider = new LinuxBiometricProvider();
  provider.isFprintdReady = async () => false;
  provider.resolveSecretTool = () => '/usr/bin/secret-tool'; // present, and it must not matter

  assert.strictEqual(await provider.isAvailable(), false);
  await assert.rejects(
    () => provider.enroll(new Uint8Array(32).fill(1), 'device-1', 'vault-1'),
    /fprintd|lector de huellas/i,
    'enrollment must be refused instead of falling back to a keyring-only secret'
  );
});

test('A3: a legacy "secret-service" enrollment fails closed', async () => {
  const provider = new LinuxBiometricProvider();
  provider.isFprintdReady = async () => true;
  provider.promptFprintd = async () => true;
  provider.secretToolLookup = async () => {
    throw new Error('the keyring must never be consulted');
  };

  const legacy = {
    version: BIOMETRIC_ENVELOPE_VERSION,
    deviceId: 'device-1',
    providerType: 'linux-secret-service',
    mode: 'secret-service',
    createdAt: 1,
    updatedAt: 1,
    iv: '00'.repeat(12),
    tag: '00'.repeat(16),
    ciphertext: '00'.repeat(32),
    keyCheck: '00'.repeat(32)
  };
  assert.strictEqual(await provider.verifyAndDecrypt(legacy, 'vault-1'), null);
});

test('A3: fprintd mode refuses to invent a new device secret at unlock time', async () => {
  const provider = new LinuxBiometricProvider();
  provider.isFprintdReady = async () => true;
  provider.promptFprintd = async () => true;
  provider.readDeviceSecret = () => null; // the secret file was deleted
  provider.getOrCreateDeviceSecret = async () => {
    throw new Error('must not create a secret while unlocking');
  };
  const env = {
    version: BIOMETRIC_ENVELOPE_VERSION, deviceId: 'd', providerType: 'linux-secret-service',
    mode: 'fprintd', createdAt: 1, updatedAt: 1,
    iv: '00'.repeat(12), tag: '00'.repeat(16), ciphertext: '00'.repeat(32), keyCheck: '00'.repeat(32)
  };
  assert.strictEqual(await provider.verifyAndDecrypt(env, 'vault-1'), null);
});

// ---------------------------------------------------------------------------
// W — Windows availability parser
// ---------------------------------------------------------------------------

test('W: "UNAVAILABLE" is not mistaken for "AVAILABLE"', () => {
  assert.strictEqual(parseAvailabilityOutput('AVAILABLE\r\n'), true);
  assert.strictEqual(parseAvailabilityOutput('  AVAILABLE  '), true);
  assert.strictEqual(parseAvailabilityOutput('UNAVAILABLE\r\n'), false);
  assert.strictEqual(parseAvailabilityOutput(''), false);
  assert.strictEqual(parseVerificationOutput('VERIFIED\n'), true);
  assert.strictEqual(parseVerificationOutput('UNVERIFIED\n'), false);
  assert.strictEqual(parseVerificationOutput('FAILED\n'), false);
});

// ---------------------------------------------------------------------------
// F — path filter
// ---------------------------------------------------------------------------

test('F: hidden folders are excluded, hidden text notes inside folders are encrypted', () => {
  const f = new PathFilter([], true);
  assert.strictEqual(f.shouldEncrypt('.DS_Store'), false, 'root dotfile');
  assert.strictEqual(f.shouldEncrypt('Notes/.gitkeep'), false, 'nested non-note dotfile');
  assert.strictEqual(f.shouldEncrypt('Projects/.git/config'), false, 'hidden directory at depth');
  assert.strictEqual(f.shouldEncrypt('Notes/.cache/x.md'), false, 'hidden directory at depth');
  assert.strictEqual(f.shouldEncrypt('Notes/.private.md'), true, 'a hidden TEXT NOTE is user content');
  assert.strictEqual(f.shouldEncrypt('Notes/visible.md'), true);
});

// ---------------------------------------------------------------------------
// R — restore
// ---------------------------------------------------------------------------

async function makeEncryptedEntry(plugin, path, text) {
  await plugin.app.vault.adapter.write(path, text);
  return new Uint8Array(await plugin.interceptor.getRawAdapter().readBinary(path));
}

test('R: ciphertext from ANOTHER vault key is rejected, not written', async () => {
  const mine = createPlugin(createFakeAdapter(), await createUnlockedKeyManager(7), new PathFilter([], true));
  const other = createPlugin(createFakeAdapter(), await createUnlockedKeyManager(9), new PathFilter([], true));
  const foreign = await makeEncryptedEntry(other, 'Notas/a.md', 'foreign secret');

  const zip = zipSync({ 'Notas/a.md': foreign }, { level: 0 });
  const result = await BackupEngine.restoreFromZip(mine, zip);

  assert.strictEqual(mine.app.vault.adapter.files.has('Notas/a.md'), false, 'nothing may be written');
  assert.strictEqual(result.restoredFiles, 0);
  assert.ok(result.errors.some((e) => /autentica/i.test(e.error)));
});

test('R: ciphertext bound to a DIFFERENT path is rejected', async () => {
  const plugin = createPlugin(createFakeAdapter(), await createUnlockedKeyManager(7), new PathFilter([], true));
  const entry = await makeEncryptedEntry(plugin, 'Notas/original.md', 'secret');

  const zip = zipSync({ 'Notas/renamed.md': entry }, { level: 0 });
  const result = await BackupEngine.restoreFromZip(plugin, zip);

  assert.strictEqual(plugin.app.vault.adapter.files.has('Notas/renamed.md'), false);
  assert.ok(result.errors.length >= 1);
});

test('R: authentic ciphertext is restored verbatim (still encrypted on disk)', async () => {
  const src = createPlugin(createFakeAdapter(), await createUnlockedKeyManager(7), new PathFilter([], true));
  const entry = await makeEncryptedEntry(src, 'Notas/a.md', 'my secret');

  const dst = createPlugin(createFakeAdapter(), await createUnlockedKeyManager(7), new PathFilter([], true));
  const result = await BackupEngine.restoreFromZip(dst, zipSync({ 'Notas/a.md': entry }, { level: 0 }));

  assert.strictEqual(result.restoredFiles, 1);
  const onDisk = await dst.interceptor.getRawAdapter().read('Notas/a.md');
  assert.ok(isArmoredEncrypted(onDisk), 'must remain encrypted on disk');
  assert.strictEqual(await dst.app.vault.adapter.read('Notas/a.md'), 'my secret');
});

test('R: a manifest that CLAIMS "encrypted" cannot make plaintext land on disk in cleartext', async () => {
  const plugin = createPlugin(createFakeAdapter(), await createUnlockedKeyManager(7), new PathFilter([], true));
  const manifest = { version: 1, plugin: 'MySecret', mode: 'encrypted', createdAt: 1, vaultName: 'x', totalFiles: 1, files: [] };
  const zip = zipSync({
    'mysecret-manifest.json': strToU8(JSON.stringify(manifest)),
    'Notas/injected.md': strToU8('# attacker controlled plaintext')
  }, { level: 0 });

  const result = await BackupEngine.restoreFromZip(plugin, zip);

  assert.strictEqual(result.restoredFiles, 1);
  const onDisk = await plugin.interceptor.getRawAdapter().read('Notas/injected.md');
  assert.ok(isArmoredEncrypted(onDisk), 'plaintext is encrypted on the way in, never stored as-is');
});

test('R: restoring requires an unlocked vault', async () => {
  const km = await createUnlockedKeyManager(7);
  const plugin = createPlugin(createFakeAdapter(), km, new PathFilter([], true));
  lockKm(km);

  const result = await BackupEngine.restoreFromZip(plugin, zipSync({ 'a.md': strToU8('x') }, { level: 0 }));
  assert.strictEqual(result.restoredFiles, 0);
  assert.strictEqual(plugin.app.vault.adapter.files.size, 0);
  assert.ok(result.errors.length >= 1);
});

test('R: a non-UTF-8 text entry is not silently altered by encryption', async () => {
  const plugin = createPlugin(createFakeAdapter(), await createUnlockedKeyManager(7), new PathFilter([], true));
  const latin1 = new Uint8Array([0x63, 0x61, 0x66, 0xe9]); // "café" in Latin-1, invalid UTF-8
  assert.strictEqual(decodeUtf8Strict(latin1), null);

  const result = await BackupEngine.restoreFromZip(plugin, zipSync({ 'old.txt': latin1 }, { level: 0 }));
  assert.strictEqual(result.restoredFiles, 0);
  assert.ok(result.errors.some((e) => /UTF-8/i.test(e.error)));
});

// ---------------------------------------------------------------------------
// B — backup
// ---------------------------------------------------------------------------

test('B: plaintext files are reported (not dropped) when no key is available', async () => {
  const adapter = createFakeAdapter();
  const km = await createUnlockedKeyManager(7);
  const plugin = createPlugin(adapter, km, new PathFilter([], true));

  // One note encrypted, one still plaintext on disk (written through the raw adapter).
  await adapter.write('Notas/enc.md', 'encrypted note');
  await plugin.interceptor.getRawAdapter().write('Notas/plain.md', 'still plaintext');

  lockKm(km);
  km.vaultKey = null; // what lock() does
  const locked = await BackupEngine.createVaultZip(plugin, { mode: 'encrypted', includeEnvelope: false });
  const skipped = locked.stats.skippedFiles.map((s) => s.path);
  assert.deepStrictEqual(skipped, ['Notas/plain.md'], 'the plaintext file must be reported');
  assert.ok(locked.manifest.files.some((f) => f.path === 'Notas/enc.md'));

  // With the key handed over explicitly (on-lock auto-backup) it is included, encrypted.
  const key = await importAesKey(new Uint8Array(32).fill(7));
  const withKey = await BackupEngine.createVaultZip(plugin, { mode: 'encrypted', includeEnvelope: false, vaultKey: key });
  assert.deepStrictEqual(withKey.stats.skippedFiles, []);
  assert.ok(withKey.manifest.files.some((f) => f.path === 'Notas/plain.md' && f.isEncrypted));
});

test('B: a non-UTF-8 note is reported instead of being corrupted in the archive', async () => {
  const adapter = createFakeAdapter();
  const km = await createUnlockedKeyManager(7);
  const plugin = createPlugin(adapter, km, new PathFilter([], true));
  plugin.interceptor.getRawAdapter().writeBinary('legacy.txt', new Uint8Array([0x63, 0x61, 0x66, 0xe9]).buffer);

  const result = await BackupEngine.createVaultZip(plugin, { mode: 'encrypted', includeEnvelope: false });
  assert.strictEqual(result.stats.skippedFiles.length, 1);
  assert.match(result.stats.skippedFiles[0].reason, /UTF-8/i);
});

// ---------------------------------------------------------------------------
// I — interceptor
// ---------------------------------------------------------------------------

test('I: concurrent process() calls on one note do not lose updates', async () => {
  const adapter = createFakeAdapter();
  const interceptor = new AdapterInterceptor(adapter, new PathFilter([], true), await createUnlockedKeyManager());
  interceptor.install();
  await adapter.write('Notas/contador.md', '0');

  // Each call reads the CURRENT value, waits a tick, then writes value+1.
  const bump = () => adapter.process('Notas/contador.md', (text) => String(Number(text) + 1));
  await Promise.all(Array.from({ length: 12 }, bump));

  assert.strictEqual(await adapter.read('Notas/contador.md'), '12', 'every increment must be applied exactly once');
  interceptor.uninstall();
});

test('I: a rename while the vault is locked is queued and replayed on unlock', async () => {
  const adapter = createFakeAdapter();
  const km = await createUnlockedKeyManager();
  const interceptor = new AdapterInterceptor(adapter, new PathFilter([], true), km);
  interceptor.install();

  let persisted = [];
  interceptor.setPendingRebinds([], (list) => { persisted = list; });

  await adapter.write('Notas/a.md', 'contenido');
  lockKm(km);
  await adapter.rename('Notas/a.md', 'Notas/b.md');
  await interceptor.handleVaultRename({ path: 'Notas/b.md', name: 'b.md' }, 'Notas/a.md');

  assert.deepStrictEqual(persisted, [{ from: 'Notas/a.md', to: 'Notas/b.md' }], 'the re-bind must be persisted');

  unlockKm(km);
  assert.strictEqual(await interceptor.processPendingRebinds(), 1);
  assert.deepStrictEqual(persisted, []);
  assert.strictEqual(await adapter.read('Notas/b.md'), 'contenido', 'the note must be readable again');
  interceptor.uninstall();
});

test('I: replaying a re-bind that was already applied is a harmless no-op', async () => {
  const adapter = createFakeAdapter();
  const interceptor = new AdapterInterceptor(adapter, new PathFilter([], true), await createUnlockedKeyManager());
  interceptor.install();

  await adapter.write('Notas/a.md', 'contenido');
  await adapter.rename('Notas/a.md', 'Notas/b.md');
  await interceptor.handleVaultRename({ path: 'Notas/b.md', name: 'b.md' }, 'Notas/a.md');

  let persisted = null;
  interceptor.setPendingRebinds([{ from: 'Notas/a.md', to: 'Notas/b.md' }], (list) => { persisted = list; });

  await interceptor.processPendingRebinds();
  assert.deepStrictEqual(persisted, [], 'the queue is drained');
  assert.strictEqual(await adapter.read('Notas/b.md'), 'contenido', 'and the note is untouched');
  interceptor.uninstall();
});

test('I: decryptFilesToPlain converts ciphertext to plaintext on disk before a policy change', async () => {
  const adapter = createFakeAdapter();
  const interceptor = new AdapterInterceptor(adapter, new PathFilter([], true), await createUnlockedKeyManager());
  interceptor.install();

  await adapter.write('Publico/nota.md', 'texto');
  await adapter.writeBinary('Publico/img.png', new Uint8Array([1, 2, 3, 4]).buffer);
  const raw = interceptor.getRawAdapter();
  assert.ok(isArmoredEncrypted(await raw.read('Publico/nota.md')));
  assert.ok(isBinaryEncrypted(new Uint8Array(await raw.readBinary('Publico/img.png'))));

  const { converted, failed } = await interceptor.decryptFilesToPlain(['Publico/nota.md', 'Publico/img.png', 'Publico/missing.md']);

  assert.deepStrictEqual(converted.sort(), ['Publico/img.png', 'Publico/nota.md']);
  assert.strictEqual(failed.length, 1, 'a missing file is reported, not fatal');
  assert.strictEqual(await raw.read('Publico/nota.md'), 'texto');
  assert.deepStrictEqual([...new Uint8Array(await raw.readBinary('Publico/img.png'))], [1, 2, 3, 4]);
  assert.strictEqual(detectContainerFormat(new Uint8Array(await raw.readBinary('Publico/nota.md'))), 'plain');
  interceptor.uninstall();
});

test('I: decryptFilesToPlain leaves a file untouched when it cannot be authenticated', async () => {
  const adapter = createFakeAdapter();
  const km = await createUnlockedKeyManager(7);
  const interceptor = new AdapterInterceptor(adapter, new PathFilter([], true), km);
  interceptor.install();
  await adapter.write('Notas/a.md', 'texto');
  const before = await interceptor.getRawAdapter().read('Notas/a.md');

  km.vaultKey = await importAesKey(new Uint8Array(32).fill(1)); // wrong key
  const { converted, failed } = await interceptor.decryptFilesToPlain(['Notas/a.md']);

  assert.strictEqual(converted.length, 0);
  assert.strictEqual(failed.length, 1);
  assert.strictEqual(await interceptor.getRawAdapter().read('Notas/a.md'), before, 'no partial write');
  interceptor.uninstall();
});

// ---------------------------------------------------------------------------
// P — Publish guard follows the plugin instance
// ---------------------------------------------------------------------------

test('P: the guard is installed when Publish is enabled AFTER the plugin loaded, and again for a new instance', async () => {
  const adapter = createFakeAdapter();
  const keyManager = await createUnlockedKeyManager();
  const interceptor = new AdapterInterceptor(adapter, new PathFilter([], true), keyManager);
  interceptor.install();
  await adapter.write('Notas/x.md', 'secret');

  let current = null;
  const app = {
    vault: { adapter },
    metadataCache: { getFileInfo: () => null },
    internalPlugins: { getEnabledPluginById: (id) => (id === 'publish' ? current : null) }
  };
  const makeInstance = () => ({
    uploaded: false,
    async apiUploadFile() { this.uploaded = true; return 'ok'; }
  });

  const guard = new PublishGuard(app);
  assert.strictEqual(guard.install(), false, 'Publish is disabled at load time');

  // The user enables Publish later.
  current = makeInstance();
  guard.refresh();
  await assert.rejects(() => current.apiUploadFile({ path: 'Notas/x.md' }), /Publish no puede publicar/);
  assert.strictEqual(current.uploaded, false);

  // Publish is disabled and re-enabled: a NEW instance, with a fresh, unwrapped method.
  const second = makeInstance();
  current = second;
  guard.refresh();
  await assert.rejects(() => second.apiUploadFile({ path: 'Notas/x.md' }), /Publish no puede publicar/);
  assert.strictEqual(second.uploaded, false);

  guard.uninstall();
  interceptor.uninstall();
});

// ---------------------------------------------------------------------------
// X — bridge error with a literal "%"
// ---------------------------------------------------------------------------

test('X: a bridge error message containing "%" settles the session instead of hanging it', async () => {
  const { ExternalBridgeProvider } = await import('../src/biometrics/external-bridge-provider.ts');
  const provider = new ExternalBridgeProvider('https://mysecret-vault.pages.dev');

  let captured = '';
  globalThis.window.open = (url) => { captured = url; return {}; };

  const envelope = {
    version: BIOMETRIC_ENVELOPE_VERSION, deviceId: 'd', providerType: 'external-bridge',
    createdAt: 1, updatedAt: 1, iv: '', tag: '', ciphertext: 'aa', keyCheck: '',
    credentialId: 'Y3JlZA', prfSalt: '11'.repeat(32)
  };
  const pending = provider.verifyAndDecrypt(envelope, 'vault-1');
  await new Promise((r) => setTimeout(r, 20));
  const session = new URLSearchParams(captured.split('#')[1]).get('session');
  assert.ok(session);

  const handled = await provider.handleProtocolCallback({ session, error: 'Fallo al 100% (%E0%A4%A)' });
  assert.strictEqual(handled, true);

  const outcome = await Promise.race([pending, new Promise((r) => setTimeout(() => r('HUNG'), 1000))]);
  assert.strictEqual(outcome, null, 'the pending verification must resolve (to null), not hang');
});
