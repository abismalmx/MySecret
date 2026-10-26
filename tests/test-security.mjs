/**
 * Security Verification Test Suite for MySecret
 *
 * These tests systematically verify the active defenses against key attack vectors:
 *   1. Zip Slip / arbitrary file write prevention during backup restore
 *   2. Blocking of unauthorized file drops into `.obsidian/plugins/`
 *   3. Enforced Argon2id KDF cost bounds against tampering
 *   4. Prototype pollution immunity
 *   5. Filtering of unsafe URL schemes in outbound requests
 *   6. Memory isolation ensuring no adjacent buffer leakage
 *   7. Path sanitizer coverage against directory traversal
 *   8. Authenticated encryption at rest for cloud credentials
 */

import assert from 'node:assert';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { zipSync, unzipSync, strToU8, strFromU8 } from 'fflate';
import { assertSafeUrl, toExactArrayBuffer } from '../src/utils/http.ts';
import { assertArgon2CostParams, deriveKeyArgon2id } from '../src/crypto/argon2.ts';
import { importAesKey } from '../src/crypto/aes.ts';
import {
  encryptCredential,
  decryptCredential,
  isEncryptedCredential
} from '../src/utils/credential-store.ts';
import { BackupEngine } from '../src/backup/backup-engine.ts';
import {
  sanitizeVaultRelativePath,
  isSafeVaultRelativePath,
  hasForbiddenSegment
} from '../src/utils/path-sanitizer.ts';
import {
  MIN_ARGON2_MEMORY_KIB,
  MIN_ARGON2_ITERATIONS,
  MAX_ARGON2_MEMORY_KIB,
  MAX_ARGON2_ITERATIONS,
  MAX_ARGON2_PARALLELISM
} from '../src/constants.ts';

if (!globalThis.window) {
  globalThis.window = {
    crypto: webcrypto,
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis)
  };
}

// --- 1. Path sanitizer (Zip Slip protection) ---

test('Path Sanitizer: blocks path traversal (Zip Slip)', () => {
  const malicious = [
    '../../../../tmp/pwned.txt',
    '../../../etc/passwd',
    '..\\..\\windows\\system32\\evil.dll',
    'notes/../../../outside.md',
    '/etc/passwd',
    '/absolute/path.md',
    'C:/Windows/evil.dll',
    'c:\\windows\\evil.dll'
  ];

  for (const p of malicious) {
    const result = sanitizeVaultRelativePath(p);
    assert.strictEqual(result.safe, false, `should reject: ${p}`);
    assert.ok(result.reason, `should explain why: ${p}`);
  }
});

test('Path Sanitizer: blocks hidden/system directories (plugin drop)', () => {
  const malicious = [
    '.obsidian/plugins/evil/main.js',
    '.obsidian/plugins/evil/manifest.json',
    '.git/config',
    '.trash/secret.md',
    '.obsidian/workspace.json',
    'notes/.hidden/evil.md'
  ];

  for (const p of malicious) {
    const result = sanitizeVaultRelativePath(p);
    assert.strictEqual(result.safe, false, `should reject: ${p}`);
  }
});

test('Path Sanitizer: blocks prototype pollution segment names', () => {
  for (const p of ['__proto__', 'notes/__proto__', '__PROTO__/x.md']) {
    const result = sanitizeVaultRelativePath(p);
    assert.strictEqual(result.safe, false, `should reject: ${p}`);
  }
});

test('Path Sanitizer: ordinary names that look like Object members are valid folders', () => {
  for (const p of ['Prototype/idea.md', 'notes/constructor/x.md', 'Constructor.md']) {
    assert.strictEqual(sanitizeVaultRelativePath(p).safe, true, `should accept: ${p}`);
  }
});

test('Path Sanitizer: blocks null bytes and illegal characters', () => {
  for (const p of ['notes/a\u0000.md', 'notes/a<b>.md', 'notes/a|b.md', 'notes/a*b.md']) {
    const result = sanitizeVaultRelativePath(p);
    assert.strictEqual(result.safe, false, `should reject: ${p}`);
  }
});

test('Path Sanitizer: accepts legitimate vault paths', () => {
  const legit = [
    'note.md',
    'Notes/Subfolder/My Note.md',
    'Images/photo.png',
    'a/b/c/d/e.md'
  ];
  for (const p of legit) {
    const result = sanitizeVaultRelativePath(p);
    assert.strictEqual(result.safe, true, `should accept: ${p} (${result.reason})`);
  }
  assert.strictEqual(sanitizeVaultRelativePath('Notes//Sub///Note.md').path, 'Notes/Sub/Note.md');
});

test('Path Sanitizer: rejects empty and overlong paths', () => {
  assert.strictEqual(sanitizeVaultRelativePath('').safe, false);
  assert.strictEqual(sanitizeVaultRelativePath('/').safe, false);
  assert.strictEqual(sanitizeVaultRelativePath('./').safe, false);
  assert.strictEqual(sanitizeVaultRelativePath('a'.repeat(2000)).safe, false);
  assert.strictEqual(isSafeVaultRelativePath('ok.md'), true);
});

// --- 2. Argon2id KDF downgrade protection ---

test('Argon2 Params: rejects downgraded cost parameters', () => {
  const downgrades = [
    { memoryKib: 8, iterations: 1, parallelism: 1 },
    { memoryKib: 1024, iterations: 1, parallelism: 1 },
    { memoryKib: 8192, iterations: 2, parallelism: 1 },
    { memoryKib: MIN_ARGON2_MEMORY_KIB - 1, iterations: MIN_ARGON2_ITERATIONS, parallelism: 1 },
    { memoryKib: MIN_ARGON2_MEMORY_KIB, iterations: MIN_ARGON2_ITERATIONS - 1, parallelism: 1 }
  ];

  for (const params of downgrades) {
    assert.throws(
      () => assertArgon2CostParams(params),
      /too low/,
      `should reject downgrade: ${JSON.stringify(params)}`
    );
  }
});

test('Argon2 Params: rejects DoS-inducing (oversized) cost parameters', () => {
  assert.throws(
    () => assertArgon2CostParams({ memoryKib: MAX_ARGON2_MEMORY_KIB + 1, iterations: 3, parallelism: 1 }),
    /too high/
  );
  assert.throws(
    () => assertArgon2CostParams({ memoryKib: 65536, iterations: MAX_ARGON2_ITERATIONS + 1, parallelism: 1 }),
    /too high/
  );
  assert.throws(
    () => assertArgon2CostParams({ memoryKib: 65536, iterations: 3, parallelism: MAX_ARGON2_PARALLELISM + 1 }),
    /too high/
  );
});

test('Argon2 Params: accepts the default (secure) parameters', () => {
  assert.doesNotThrow(() =>
    assertArgon2CostParams({ memoryKib: MIN_ARGON2_MEMORY_KIB, iterations: MIN_ARGON2_ITERATIONS, parallelism: 1 })
  );
});

test('Argon2id: deriveKey refuses downgraded parameters at runtime', async () => {
  const salt = new Uint8Array(16).fill(9);
  await assert.rejects(
    () => deriveKeyArgon2id('password', salt, 8, 1, 1),
    /too low/
  );
});

// --- 3. Prototype pollution ---

test('Backup: a null-prototype map is not polluted by a "__proto__" file', () => {
  const safe = Object.create(null);
  safe['__proto__'] = 'polluted';
  assert.strictEqual(Object.prototype.polluted, undefined);
  assert.strictEqual(({}).polluted, undefined);
  assert.strictEqual(Object.getPrototypeOf(safe), null);
});

test('Backup: a "__proto__" file name cannot pollute Object.prototype', () => {
  // A plain object cannot safely hold a "__proto__" key: the assignment does
  // not create a property (it targets the prototype setter instead).
  // The backup engine therefore skips such file names (see
  // `hasForbiddenSegment`) rather than passing them to the ZIP writer.
  const plain = {};
  plain['__proto__'] = 'polluted';
  assert.strictEqual(Object.prototype.polluted, undefined);
  assert.strictEqual(({}).polluted, undefined);
  assert.strictEqual(Object.prototype.hasOwnProperty.call(plain, '__proto__'), false);

  // The backup engine detects and skips the dangerous file name.
  // NOTE: the check is per *segment*, because only an exact "__proto__" /
  // key is able to tamper with an object's prototype.
  assert.strictEqual(hasForbiddenSegment('__proto__'), true);
  assert.strictEqual(hasForbiddenSegment('notes/__proto__/x.md'), true);
  assert.strictEqual(hasForbiddenSegment('notes/constructor/x.md'), false);
  assert.strictEqual(hasForbiddenSegment('Prototype/x.md'), false);
  assert.strictEqual(hasForbiddenSegment('notes/normal.md'), false);
  assert.strictEqual(hasForbiddenSegment('notes/constructor.md'), false);
});

// --- 4. URL validation ---

test('HTTP: rejects dangerous URL schemes', () => {
  for (const url of [
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'file:///etc/passwd',
    'blob:https://example.com/abc',
    'ftp://example.com/x'
  ]) {
    assert.throws(() => assertSafeUrl(url), /Unsupported URL protocol|Invalid URL/, `should reject: ${url}`);
  }
});

test('HTTP: rejects malformed URLs', () => {
  assert.throws(() => assertSafeUrl('not a url'), /Invalid URL/);
  assert.throws(() => assertSafeUrl(''), /Invalid URL/);
});

test('HTTP: accepts http/https, and enforces HTTPS when required', () => {
  assert.doesNotThrow(() => assertSafeUrl('https://example.com/dav'));
  assert.doesNotThrow(() => assertSafeUrl('http://example.com/dav'));
  assert.doesNotThrow(() => assertSafeUrl('https://example.com/dav', true));
  assert.throws(() => assertSafeUrl('http://example.com/dav', true), /insecure/);
});

// --- 5. ArrayBuffer byteOffset confusion ---

test('HTTP: toExactArrayBuffer returns only the view bytes, not the whole buffer', () => {
  const backing = new Uint8Array(100);
  backing.fill(0x41);
  const view = backing.subarray(10, 20);

  // The classic bug: `view.buffer` carries all 100 bytes.
  assert.strictEqual(view.buffer.byteLength, 100);

  // The fix: only the 10 bytes of the view are returned.
  const exact = toExactArrayBuffer(view);
  assert.strictEqual(exact.byteLength, 10);
  assert.strictEqual(new Uint8Array(exact).length, 10);
  assert.strictEqual(new Uint8Array(exact)[0], 0x41);
});

// --- 6. Credential encryption at rest ---

test('Credentials: are encrypted at rest and decryptable with the vault key', async () => {
  const vaultKey = await importAesKey(new Uint8Array(32).fill(0x42));

  const secret = 'super-secret-oauth-token';
  const stored = await encryptCredential(vaultKey, secret);

  assert.ok(isEncryptedCredential(stored), 'stored value must be marked as encrypted');
  assert.ok(!stored.includes(secret), 'the plaintext must not appear in the stored value');
  assert.notStrictEqual(stored, secret);

  const decrypted = await decryptCredential(vaultKey, stored);
  assert.strictEqual(decrypted, secret);
});

test('Credentials: a different vault key cannot decrypt the envelope', async () => {
  const vaultKey = await importAesKey(new Uint8Array(32).fill(0x42));
  const otherKey = await importAesKey(new Uint8Array(32).fill(0x43));

  const stored = await encryptCredential(vaultKey, 'top-secret');
  const decrypted = await decryptCredential(otherKey, stored);
  assert.strictEqual(decrypted, null);
});

test('Credentials: a tampered envelope is rejected (authenticated encryption)', async () => {
  const vaultKey = await importAesKey(new Uint8Array(32).fill(0x42));
  const stored = await encryptCredential(vaultKey, 'top-secret');

  // Flip characters in the ciphertext portion of the envelope.
  const tampered = stored.slice(0, -8) + 'AAAAAAAA' + stored.slice(-8);
  const decrypted = await decryptCredential(vaultKey, tampered);
  assert.strictEqual(decrypted, null);
});

test('Credentials: legacy plain-text values are detected as NOT encrypted', () => {
  assert.strictEqual(isEncryptedCredential('plain-token'), false);
  assert.strictEqual(isEncryptedCredential(''), false);
  assert.strictEqual(isEncryptedCredential(undefined), false);
  assert.strictEqual(isEncryptedCredential(null), false);
});

// --- 7. End-to-end Zip Slip regression through the real restore path ---

/**
 * Minimal in-memory vault adapter used to exercise the restore path.
 */
function createFakeAdapter() {
  const files = new Map();
  const dirs = new Set();

  return {
    files,
    dirs,
    exists: async (p) => files.has(p) || dirs.has(p),
    mkdir: async (p) => { dirs.add(p); },
    read: async (p) => {
      if (!files.has(p)) throw new Error('not found: ' + p);
      return files.get(p).toString();
    },
    readBinary: async (p) => {
      if (!files.has(p)) throw new Error('not found: ' + p);
      const buf = files.get(p);
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    },
    write: async (p, data) => { files.set(p, new TextEncoder().encode(data)); },
    writeBinary: async (p, data) => { files.set(p, new Uint8Array(data)); }
  };
}

function createFakePlugin(adapter, vaultKey = null) {
  const rawAdapter = {
    read: adapter.read,
    write: adapter.write,
    readBinary: adapter.readBinary,
    writeBinary: adapter.writeBinary,
    exists: adapter.exists
  };
  return {
    // The restore now validates ciphertext against the vault key, so it needs
    // an unlocked key manager (the key is only used for authentication here).
    keyManager: { isLocked: false, getVaultKey: () => vaultKey },
    interceptor: { getRawAdapter: () => rawAdapter },
    app: {
      vault: {
        adapter: {
          exists: adapter.exists,
          mkdir: adapter.mkdir,
          write: adapter.write,
          writeBinary: adapter.writeBinary
        }
      }
    },
    pathFilter: {
      isTextNote: (p) => p.toLowerCase().endsWith('.md') || p.toLowerCase().endsWith('.txt'),
      normalizePath: (p) => p,
      shouldEncrypt: () => true
    }
  };
}

test('Restore: a malicious ZIP cannot escape the vault (Zip Slip regression)', async () => {
  const adapter = createFakeAdapter();
  const fakePlugin = createFakePlugin(adapter);

  const evil = zipSync({
    '../../../../tmp/mysecret_pwned.txt': strToU8('PWNED'),
    '/etc/mysecret_pwned.txt': strToU8('PWNED'),
    '.obsidian/plugins/evil/main.js': strToU8('require("child_process").exec("id")'),
    'legit/note.md': strToU8('# Hello')
  }, { level: 6 });

  const result = await BackupEngine.restoreFromZip(fakePlugin, evil);

  // The legitimate file was restored.
  assert.ok(adapter.files.has('legit/note.md'), 'the legitimate note must be restored');
  assert.strictEqual(strFromU8(adapter.files.get('legit/note.md')), '# Hello');

  // Nothing escaped the vault.
  assert.strictEqual(adapter.files.has('../../../../tmp/mysecret_pwned.txt'), false);
  assert.strictEqual(adapter.files.has('/etc/mysecret_pwned.txt'), false);
  assert.strictEqual(adapter.files.has('.obsidian/plugins/evil/main.js'), false);

  // Every write landed strictly inside the vault.
  for (const key of adapter.files.keys()) {
    assert.ok(!key.includes('..'), `no path may contain "..": ${key}`);
    assert.ok(!key.startsWith('/'), `no path may be absolute: ${key}`);
    assert.ok(!key.startsWith('.'), `no path may target a hidden directory: ${key}`);
  }

  // The attempts were reported as errors/skips.
  assert.ok(result.skippedFiles >= 3, 'the malicious entries must be skipped');
  assert.ok(result.errors.length >= 3, 'the malicious entries must be reported');
});

test('Restore: restoreVaultZip alias exists and behaves like restoreFromZip', async () => {
  const adapter = createFakeAdapter();
  const fakePlugin = createFakePlugin(adapter);

  const zip = zipSync({ 'note.md': strToU8('# ok') }, { level: 6 });
  const result = await BackupEngine.restoreVaultZip(fakePlugin, zip);
  assert.strictEqual(result.restoredFiles, 1);
  assert.strictEqual(strFromU8(adapter.files.get('note.md')), '# ok');
});
