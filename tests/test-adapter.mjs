/**
 * Adapter Interceptor Security & Integrity Tests
 *
 * These tests verify the AAD re-bind logic used when a file or folder is
 * renamed or copied, which is the mechanism that prevents silent
 * and irreversible data loss.
 *
 * They specifically test:
 *   - `DataAdapter.list()` vault path resolution and exact normalization.
 *   - The rename handling through the public `vault.on('rename')`
 *     event, ensuring every rename performed by Obsidian correctly re-binds AAD.
 */

import assert from 'node:assert';
import test from 'node:test';
import { webcrypto } from 'node:crypto';

if (!globalThis.window) {
  globalThis.window = {
    crypto: webcrypto,
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis),
    addEventListener: () => {},
    removeEventListener: () => {}
  };
} else {
  if (!globalThis.window.addEventListener) globalThis.window.addEventListener = () => {};
  if (!globalThis.window.removeEventListener) globalThis.window.removeEventListener = () => {};
  if (!globalThis.window.setTimeout) globalThis.window.setTimeout = globalThis.setTimeout.bind(globalThis);
  if (!globalThis.window.clearTimeout) globalThis.window.clearTimeout = globalThis.clearTimeout.bind(globalThis);
}

if (!globalThis.document) {
  globalThis.document = {
    body: {
      classList: { add: () => {}, remove: () => {} }
    },
    querySelectorAll: () => []
  };
}

if (!globalThis.MutationObserver) {
  globalThis.MutationObserver = class {
    observe() {}
    disconnect() {}
  };
}

import { AdapterInterceptor } from '../src/adapter/adapter-interceptor.ts';
import { MediaManager } from '../src/adapter/media-manager.ts';
import { PathFilter } from '../src/adapter/path-filter.ts';
import { KeyManager } from '../src/crypto/key-manager.ts';
import { importAesKey, decryptAesGcm } from '../src/crypto/aes.ts';
import {
  isArmoredEncrypted,
  deserializeArmored,
  isBinaryEncrypted,
  deserializeBinary
} from '../src/crypto/envelope.ts';
import { MetadataHashPatch } from '../src/adapter/metadata-hash-patch.ts';
import { PublishGuard } from '../src/adapter/publish-guard.ts';
import { sha256Hex } from '../src/crypto/hash.ts';
import { TFolder, TFile, Vault } from 'obsidian';

/**
 * In-memory vault adapter.
 *
 * `list()` returns ABSOLUTE vault paths, exactly like Obsidian's
 * `ListedFiles` contract documents:
 *   "The vault absolute paths of the files directly in the folder."
 */
function createFakeAdapter() {
  const files = new Map();   // path -> Uint8Array (on-disk bytes)
  const dirs = new Set();

  return {
    files,
    dirs,
    async exists(p) {
      return files.has(p) || dirs.has(p);
    },
    async mkdir(p) {
      dirs.add(p);
    },
    async read(p) {
      if (!files.has(p)) throw new Error('not found: ' + p);
      return new TextDecoder().decode(files.get(p));
    },
    async readBinary(p) {
      if (!files.has(p)) throw new Error('not found: ' + p);
      const b = files.get(p);
      return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
    },
    async write(p, data) {
      files.set(p, new TextEncoder().encode(data));
    },
    async writeBinary(p, data) {
      files.set(p, new Uint8Array(data));
    },
    async append(p, data) {
      const existing = files.has(p) ? new TextDecoder().decode(files.get(p)) : '';
      files.set(p, new TextEncoder().encode(existing + data));
    },
    async appendBinary(p, data) {
      const existing = files.has(p) ? files.get(p) : new Uint8Array(0);
      const appended = new Uint8Array(data);
      const merged = new Uint8Array(existing.length + appended.length);
      merged.set(existing, 0);
      merged.set(appended, existing.length);
      files.set(p, merged);
    },
    async list(p) {
      // Absolute paths, like the real Obsidian adapter.
      const filesOut = [];
      const foldersOut = [];
      const prefix = p === '' ? '' : p + '/';
      for (const key of files.keys()) {
        if (!key.startsWith(prefix)) continue;
        const rest = key.slice(prefix.length);
        if (rest.includes('/')) {
          const folder = prefix + rest.split('/')[0];
          if (!foldersOut.includes(folder)) foldersOut.push(folder);
        } else {
          filesOut.push(key);
        }
      }
      for (const key of dirs.keys()) {
        if (!key.startsWith(prefix)) continue;
        const rest = key.slice(prefix.length);
        if (rest.includes('/')) continue;
        foldersOut.push(key);
      }
      return { files: filesOut, folders: foldersOut };
    },
    async stat(p) {
      if (files.has(p)) return { type: 'file' };
      if (dirs.has(p)) return { type: 'folder' };
      return null;
    },
    async rename(oldPath, newPath) {
      // Move the file/folder (and its descendants) on disk.
      for (const key of [...files.keys()]) {
        if (key === oldPath || key.startsWith(oldPath + '/')) {
          const suffix = key.slice(oldPath.length);
          files.set(newPath + suffix, files.get(key));
          files.delete(key);
        }
      }
      for (const key of [...dirs.keys()]) {
        if (key === oldPath || key.startsWith(oldPath + '/')) {
          const suffix = key.slice(oldPath.length);
          dirs.add(newPath + suffix);
          dirs.delete(key);
        }
      }
    },
    async copy(oldPath, newPath) {
      files.set(newPath, files.get(oldPath));
    }
  };
}

/**
 * Builds an unlocked KeyManager with a known vault key.

/**
 * Builds an unlocked KeyManager with a known vault key.
 */
async function createUnlockedKeyManager() {
  const km = new KeyManager();
  // Inject the vault key directly (bypassing Argon2 for test speed).
  km.rawVaultKey = new Uint8Array(32).fill(7);
  km.vaultKey = await importAesKey(km.rawVaultKey);
  km._isLocked = false;
  return km;
}

test('Adapter: renaming a file re-binds the AAD so the content stays readable', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  // Write an encrypted note through the intercepted adapter.
  await adapter.write('Notas/Privada.md', '# secreto');

  const onDiskBefore = await interceptor.getRawAdapter().read('Notas/Privada.md');
  assert.ok(isArmoredEncrypted(onDiskBefore), 'the file must be encrypted on disk');

  // Rename it, as Obsidian would do.
  await adapter.rename('Notas/Privada.md', 'Notas/Publica.md');

  // The rename event handler re-binds the AAD.
  await interceptor.handleVaultRename(
    { path: 'Notas/Publica.md', name: 'Publica.md' },
    'Notas/Privada.md'
  );

  // The file must still be readable through the intercepted adapter.
  const content = await adapter.read('Notas/Publica.md');
  assert.strictEqual(content, '# secreto', 'the note must still decrypt after the rename');

  // And it must still be encrypted on disk.
  const onDiskAfter = await interceptor.getRawAdapter().read('Notas/Publica.md');
  assert.ok(isArmoredEncrypted(onDiskAfter), 'the renamed file must remain encrypted on disk');
});

test('Adapter: renaming a folder re-binds the AAD of every descendant', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  await adapter.write('Carpeta/a.md', '# a');
  await adapter.write('Carpeta/sub/b.md', '# b');
  await adapter.write('Carpeta/sub/c.md', '# c');

  await adapter.rename('Carpeta', 'Renombrada');

  await interceptor.handleVaultRename(
    new TFolder('Renombrada'),
    'Carpeta'
  );

  assert.strictEqual(await adapter.read('Renombrada/a.md'), '# a');
  assert.strictEqual(await adapter.read('Renombrada/sub/b.md'), '# b');
  assert.strictEqual(await adapter.read('Renombrada/sub/c.md'), '# c');
});

test('Adapter: collectSubtreeFiles returns ABSOLUTE paths (Obsidian contract)', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  await adapter.write('Carpeta/a.md', '# a');
  await adapter.write('Carpeta/sub/b.md', '# b');

  // Access the method through the instance (test-only introspection).
  const files = await interceptor.collectSubtreeFiles('Carpeta');

  assert.deepStrictEqual(
    [...files].sort(),
    ['Carpeta/a.md', 'Carpeta/sub/b.md'],
    'the listed paths must be absolute vault paths, not names relative to the folder'
  );
});

test('Adapter: renaming a file leaves NO stale AAD binding', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  await adapter.write('A.md', 'contenido');
  await adapter.rename('A.md', 'B.md');
  await interceptor.handleVaultRename({ path: 'B.md', name: 'B.md' }, 'A.md');

  // Decrypt manually with the NEW aad: it must succeed.
  const raw = await interceptor.getRawAdapter().read('B.md');
  const payload = deserializeArmored(raw);
  const plain = await decryptAesGcm(
    payload.ciphertext, keyManager.getVaultKey(), payload.iv, payload.tag, 'B.md'
  );
  assert.strictEqual(new TextDecoder().decode(plain), 'contenido');

  // Decrypting with the OLD aad must FAIL (the AAD was really re-bound).
  await assert.rejects(
    () => decryptAesGcm(
      payload.ciphertext, keyManager.getVaultKey(), payload.iv, payload.tag, 'A.md'
    ),
    'the old AAD must no longer be accepted'
  );
});

test('Adapter: copy re-binds the AAD to the destination path', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  await adapter.write('Original.md', 'copia');
  await adapter.copy('Original.md', 'Copia.md');

  // The adapter's copy hook re-binds the AAD.
  assert.strictEqual(await adapter.read('Copia.md'), 'copia');
  assert.strictEqual(await adapter.read('Original.md'), 'copia');
});

test('Adapter: writeBinary encrypts image on disk while getResourcePath returns decrypted in-memory blob', async () => {
  const adapter = createFakeAdapter();
  adapter.getResourcePath = (p) => `app://local/${p}`;

  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const fakeApp = {
    vault: {
      adapter,
      getAbstractFileByPath: () => null,
      getFiles: () => []
    },
    metadataCache: {
      getFirstLinkpathDest: () => null
    }
  };

  const mediaManager = new MediaManager(fakeApp, pathFilter, keyManager);
  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager, mediaManager);
  interceptor.install();

  const fakeImageBytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 1, 2, 3, 4]);
  await adapter.writeBinary('Pasted image.png', fakeImageBytes.buffer);

  // 1. On disk, the file must be encrypted binary!
  const rawDiskBuffer = await interceptor.getRawAdapter().readBinary('Pasted image.png');
  const rawDiskBytes = new Uint8Array(rawDiskBuffer);
  assert.strictEqual(isBinaryEncrypted(rawDiskBytes), true, 'The disk file must be encrypted binary');

  // 2. The raw adapter returns the CIPHERTEXT (Obsidian Sync must never see
  //    the cleartext), while the interceptor exposes the plaintext on demand.
  const rawBuffer = await adapter.readBinary('Pasted image.png');
  assert.ok(
    isBinaryEncrypted(new Uint8Array(rawBuffer)),
    'the raw adapter must return the ciphertext of the image'
  );

  const decryptedBuffer = await interceptor.readPlaintextBinary('Pasted image.png');
  assert.deepStrictEqual(new Uint8Array(decryptedBuffer), fakeImageBytes);

  // 3. adapter.getResourcePath must return the in-memory Blob URL
  const resourceUrl = adapter.getResourcePath('Pasted image.png');
  assert.strictEqual(resourceUrl.startsWith('blob:'), true, 'Pasted image resource path must be a blob URL');

  // 4. Revoking media blobs on vault lock clears the cache
  mediaManager.revokeAll();
  assert.strictEqual(mediaManager.getCachedBlobUrl('Pasted image.png'), null);

  mediaManager.destroy();
  interceptor.uninstall();
});

test('Adapter: vault.readBinary transparently decrypts armored Markdown notes (required for Obsidian metadataCache & footnotes)', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();
  const vault = createFakeVault(adapter);

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager, undefined, vault);
  interceptor.install();
  interceptor.installVaultHooks();

  const noteContent = 'Texto con nota al pie[^1].\n\n[^1]: Definición de la nota al pie.';
  await adapter.write('Notas/Footnote.md', noteContent);

  // On disk, the file must be armored encrypted
  const diskRaw = await interceptor.getRawAdapter().read('Notas/Footnote.md');
  assert.ok(isArmoredEncrypted(diskRaw), 'File on disk must be armored encrypted');

  // When Obsidian's indexing engine calls `vault.readBinary()`, it MUST
  // receive the decrypted plaintext bytes, otherwise the footnotes are not
  // indexed.
  const binaryBuffer = await vault.readBinary(createFakeFile('Notas/Footnote.md'));
  const readBackText = new TextDecoder().decode(binaryBuffer);
  assert.strictEqual(readBackText, noteContent, 'vault.readBinary must return the decrypted note content');

  // The raw adapter MUST keep returning the ciphertext (Obsidian Sync).
  const rawText = new TextDecoder().decode(await adapter.readBinary('Notas/Footnote.md'));
  assert.ok(isArmoredEncrypted(rawText), 'adapter.readBinary must keep returning the ciphertext');

  // When Obsidian calls vault.process() to append a missing footnote definition:
  await adapter.process('Notas/Footnote.md', current => {
    return current + '\n\n[^2]: Segunda nota creada nativamente.';
  });

  const updatedBinary = await vault.readBinary(createFakeFile('Notas/Footnote.md'));
  const updatedText = new TextDecoder().decode(updatedBinary);
  assert.ok(updatedText.includes('[^2]: Segunda nota creada nativamente.'));

  interceptor.uninstall();
});

test('SECURITY: adapter.process throws when vault is locked and never wipes existing notes', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  // Create an encrypted note
  await adapter.write('Notas/Importante.md', 'Contenido confidencial original');

  // Lock the vault
  keyManager.lock();

  // Attempting adapter.process on an existing file while locked MUST throw
  await assert.rejects(
    async () => {
      await adapter.process('Notas/Importante.md', current => current + ' modificado');
    },
    /locked/i,
    'adapter.process must reject when vault is locked'
  );

  // Verify the file was NOT corrupted or overwritten on disk
  const rawDisk = await interceptor.getRawAdapter().read('Notas/Importante.md');
  assert.ok(isArmoredEncrypted(rawDisk), 'File must remain intact and encrypted on disk');

  interceptor.uninstall();
});

/**
 * Builds a `Vault` stub bound to the fake adapter.
 */
function createFakeVault(adapter) {
  return new Vault(adapter);
}

/**
 * Creates a `TFile` that mimics the real Obsidian `TFile`.
 */
function createFakeFile(path) {
  const file = new TFile(path);
  file.extension = 'md';
  return file;
}

/**
 * Decrypts an armored payload read from disk.
 */
async function decryptArmoredOnDisk(keyManager, rawText, aad) {
  const payload = deserializeArmored(rawText);
  const plain = await decryptAesGcm(
    payload.ciphertext,
    keyManager.getVaultKey(),
    payload.iv,
    payload.tag,
    aad
  );
  return new TextDecoder().decode(plain);
}

test('SECURITY: adapter.readBinary returns the CIPHERTEXT so Obsidian Sync cannot upload the cleartext', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();
  const vault = createFakeVault(adapter);

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager, undefined, vault);
  interceptor.install();
  interceptor.installVaultHooks();

  const secret = 'Contraseña: hunter2-secreto';
  await adapter.write('Notas/Secreto.md', secret);

  // Obsidian Sync reads the files through `app.vault.adapter.readBinary(path)`
  // and uploads whatever it receives to the cloud.
  const rawBuffer = await adapter.readBinary('Notas/Secreto.md');
  const rawText = new TextDecoder().decode(rawBuffer);

  assert.ok(
    !rawText.includes('hunter2-secreto'),
    'adapter.readBinary must NEVER return the cleartext of an encrypted note'
  );
  assert.ok(
    isArmoredEncrypted(rawText),
    'adapter.readBinary must return the armored ciphertext'
  );

  interceptor.uninstall();
});

test('SECURITY: vault.readBinary decrypts for the indexer while the adapter keeps the ciphertext', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();
  const vault = createFakeVault(adapter);

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager, undefined, vault);
  interceptor.install();
  interceptor.installVaultHooks();

  const noteContent = 'Texto con nota al pie[^1].\n\n[^1]: Definición de la nota al pie.';
  await adapter.write('Notas/Footnote.md', noteContent);

  const file = createFakeFile('Notas/Footnote.md');

  // The metadata indexer goes through `vault.readBinary(file)` and MUST
  // receive the plaintext, otherwise the footnotes are not indexed.
  const vaultBuffer = await vault.readBinary(file);
  assert.strictEqual(
    new TextDecoder().decode(vaultBuffer),
    noteContent,
    'vault.readBinary must return the decrypted note so the footnotes are indexed'
  );

  // But the raw adapter MUST still return the ciphertext for Obsidian Sync.
  const rawText = new TextDecoder().decode(await adapter.readBinary('Notas/Footnote.md'));
  assert.ok(isArmoredEncrypted(rawText), 'the raw adapter must still return the ciphertext');
  assert.ok(!rawText.includes('Definición'), 'the raw adapter must not leak the cleartext');

  interceptor.uninstall();
});

test('SECURITY: vault.readBinary refreshes the in-memory TFile cache with the plaintext', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();
  const vault = createFakeVault(adapter);

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager, undefined, vault);
  interceptor.install();
  interceptor.installVaultHooks();

  const noteContent = 'Contenido de la nota.\n\n[^1]: Nota al pie real.';
  await adapter.write('Notas/Cache.md', noteContent);

  const file = createFakeFile('Notas/Cache.md');
  await vault.readBinary(file);

  // `Vault.cachedRead()` must return the plaintext, not the armored envelope.
  const cached = await vault.cachedRead(file);
  assert.strictEqual(
    cached,
    noteContent,
    'the in-memory cache must hold the plaintext, not the ciphertext'
  );
  assert.ok(!cached.includes('BEGIN MYSECRET'), 'the cache must not hold the armored envelope');

  interceptor.uninstall();
});

test('DATA INTEGRITY: Obsidian Sync writing back the ciphertext does NOT double-encrypt the note', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();
  const vault = createFakeVault(adapter);

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager, undefined, vault);
  interceptor.install();
  interceptor.installVaultHooks();

  const noteContent = 'Nota que Sync descarga y reescribe.';
  await adapter.write('Notas/Sync.md', noteContent);

  // This is exactly what Obsidian Sync does: it downloads the ciphertext and
  // writes it back verbatim through `vault.modifyBinary()` ->
  // `adapter.writeBinary()`.
  const downloadedCiphertext = await adapter.readBinary('Notas/Sync.md');
  await adapter.writeBinary('Notas/Sync.md', downloadedCiphertext);

  // The file must still be a SINGLE layer of encryption and must still be
  // readable. A double encryption would make it unreadable forever.
  const onDisk = await interceptor.getRawAdapter().read('Notas/Sync.md');
  assert.ok(isArmoredEncrypted(onDisk), 'the file must remain armored on disk');

  const plain = await decryptArmoredOnDisk(keyManager, onDisk, 'Notas/Sync.md');
  assert.strictEqual(
    plain,
    noteContent,
    'the note must still decrypt after Sync wrote the ciphertext back (no double encryption)'
  );

  interceptor.uninstall();
});

test('DATA INTEGRITY: a file that merely LOOKS like a container is still encrypted normally', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  // A file whose first bytes happen to be "MYSE" but that was never
  // encrypted by MySecret must NOT be stored verbatim in cleartext.
  const lookalike = new Uint8Array([0x4d, 0x59, 0x53, 0x45, 0x01, 9, 9, 9]);
  await adapter.writeBinary('datos.bin', lookalike.buffer);

  const onDisk = new Uint8Array(
    await interceptor.getRawAdapter().readBinary('datos.bin')
  );

  assert.ok(
    isBinaryEncrypted(onDisk),
    'the lookalike file must be encrypted as a normal MySecret container'
  );

  // And it must decrypt back to the original bytes.
  const payload = deserializeBinary(onDisk);
  const plain = await decryptAesGcm(
    payload.ciphertext,
    keyManager.getVaultKey(),
    payload.iv,
    payload.tag,
    'datos.bin'
  );
  assert.deepStrictEqual(new Uint8Array(plain), lookalike, 'the file must round-trip');

  interceptor.uninstall();
});

test('DATA INTEGRITY: append propagates a read failure instead of truncating the note', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  const original = 'Contenido original que NO debe perderse.';
  await adapter.write('Notas/Truncada.md', original);

  // Keep a reference to the key: `lock()` wipes it from RAM on purpose.
  const vaultKey = keyManager.getVaultKey();

  // Break the decryption by locking the vault: the read will fail.
  keyManager.lock();

  await assert.rejects(
    async () => {
      await adapter.append('Notas/Truncada.md', ' fragmento añadido');
    },
    /could not be read/i,
    'append must propagate the read failure'
  );

  // The file on disk must be untouched.
  const onDisk = await interceptor.getRawAdapter().read('Notas/Truncada.md');
  assert.ok(isArmoredEncrypted(onDisk), 'the note must remain encrypted on disk');

  const payload = deserializeArmored(onDisk);
  const plain = await decryptAesGcm(
    payload.ciphertext,
    vaultKey,
    payload.iv,
    payload.tag,
    'Notas/Truncada.md'
  );
  assert.strictEqual(
    new TextDecoder().decode(plain),
    original,
    'the note must NOT be truncated'
  );

  interceptor.uninstall();
});

test('DATA INTEGRITY: appendBinary refuses to corrupt an armored text note', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  const noteContent = 'Nota de texto que no debe destruirse.';
  await adapter.write('Notas/Texto.md', noteContent);

  await assert.rejects(
    async () => {
      await adapter.appendBinary('Notas/Texto.md', new Uint8Array([1, 2, 3]).buffer);
    },
    /Refusing to append binary data/i,
    'appendBinary must refuse to corrupt an armored text note'
  );

  // The note must be intact.
  const onDisk = await interceptor.getRawAdapter().read('Notas/Texto.md');
  const plain = await decryptArmoredOnDisk(keyManager, onDisk, 'Notas/Texto.md');
  assert.strictEqual(plain, noteContent, 'the note must be intact');

  interceptor.uninstall();
});

test('DATA INTEGRITY: renaming a plaintext, armored and binary file keeps the content readable', async () => {
  const adapter = createFakeAdapter();
  // The "excluido" folder is NOT encrypted, so it holds a real plaintext file.
  const pathFilter = new PathFilter(['excluido'], true);
  const keyManager = await createUnlockedKeyManager();

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager);
  interceptor.install();

  // 1. A file that is NOT encrypted (it lives in an excluded folder).
  const plainContent = 'Texto plano sin cifrar.';
  await adapter.write('excluido/plain.md', plainContent);

  // 2. An armored Markdown note.
  const armoredContent = '# Nota blindada\n\n[^1]: pie de nota.';
  await adapter.write('Notas/Blindada.md', armoredContent);

  // 3. A binary attachment.
  const binaryContent = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 7, 7, 7]);
  await adapter.writeBinary('adjunto.png', binaryContent.buffer);

  // Rename all three.
  await adapter.rename('excluido/plain.md', 'excluido/renombrado.md');
  await adapter.rename('Notas/Blindada.md', 'Notas/Renombrada.md');
  await adapter.rename('adjunto.png', 'adjunto-renombrado.png');

  await interceptor.handleVaultRename(
    { path: 'excluido/renombrado.md', name: 'renombrado.md' },
    'excluido/plain.md'
  );
  await interceptor.handleVaultRename(
    { path: 'Notas/Renombrada.md', name: 'Renombrada.md' },
    'Notas/Blindada.md'
  );
  await interceptor.handleVaultRename(
    { path: 'adjunto-renombrado.png', name: 'adjunto-renombrado.png' },
    'adjunto.png'
  );

  // 1. The plaintext file is still plaintext and readable.
  assert.strictEqual(
    await adapter.read('excluido/renombrado.md'),
    plainContent,
    'the plaintext file must stay readable after the rename'
  );

  // 2. The armored note still decrypts.
  assert.strictEqual(
    await adapter.read('Notas/Renombrada.md'),
    armoredContent,
    'the armored note must still decrypt after the rename'
  );

  // 3. The binary attachment still decrypts byte for byte.
  const binaryBuffer = await interceptor.readPlaintextBinary('adjunto-renombrado.png');
  assert.deepStrictEqual(
    new Uint8Array(binaryBuffer),
    binaryContent,
    'the binary attachment must still decrypt after the rename'
  );

  interceptor.uninstall();
});

test('SECURITY: the metadata cache hash is aligned with the ciphertext hash used by Obsidian Sync', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();
  const vault = createFakeVault(adapter);

  // A minimal metadata cache that stores the hash of the bytes returned by
  // `vault.readBinary()` (the plaintext), exactly like Obsidian does.
  const fileCache = new Map();
  const metadataCache = {
    fileCache,
    getFileInfo(path) {
      return fileCache.get(path) || null;
    }
  };
  const app = { vault, metadataCache, internalPlugins: null };

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager, undefined, vault);
  interceptor.install();
  interceptor.installVaultHooks();

  const hashPatch = new MetadataHashPatch(app);
  hashPatch.install();
  interceptor.setMetadataHashPatch(hashPatch);

  const noteContent = 'Nota para el indexador.';
  await adapter.write('Notas/Hash.md', noteContent);

  const file = createFakeFile('Notas/Hash.md');

  // The metadata indexer reads the note and stores the hash of what it read
  // (the plaintext).
  const vaultBytes = new Uint8Array(await vault.readBinary(file));
  const plaintextHash = await sha256Hex(vaultBytes);
  fileCache.set('Notas/Hash.md', { mtime: 1, size: vaultBytes.length, hash: plaintextHash });

  // The hash of the ciphertext (what Sync computes).
  const ciphertextBytes = new Uint8Array(await adapter.readBinary('Notas/Hash.md'));
  const ciphertextHash = await sha256Hex(ciphertextBytes);

  assert.notStrictEqual(
    plaintextHash,
    ciphertextHash,
    'the plaintext hash and the ciphertext hash must be different (sanity check)'
  );

  // Without the patch the two hashes would never match and Sync would
  // re-download the whole vault on every run.
  const info = metadataCache.getFileInfo('Notas/Hash.md');
  assert.strictEqual(
    info.hash,
    ciphertextHash,
    'the hash exposed to Sync must be the hash of the ciphertext'
  );

  // The metadata cache must keep working: the returned object is a copy, so
  // the original entry (the key of the parsed metadata) is untouched.
  assert.strictEqual(
    fileCache.get('Notas/Hash.md').hash,
    plaintextHash,
    'the original metadata entry must not be mutated'
  );

  hashPatch.uninstall();
  interceptor.uninstall();
});

test('SECURITY: Obsidian Publish cannot upload the cleartext of an encrypted note', async () => {
  const adapter = createFakeAdapter();
  // The "publico" folder is NOT encrypted, so it holds a real plaintext note.
  const pathFilter = new PathFilter(['publico'], true);
  const keyManager = await createUnlockedKeyManager();
  const vault = createFakeVault(adapter);

  let uploaded = null;
  const publishInstance = {
    async apiUploadFile(file) {
      const bytes = await vault.readBinary(file);
      uploaded = new TextDecoder().decode(new Uint8Array(bytes));
      return 'ok';
    }
  };
  const app = {
    vault,
    metadataCache: { getFileInfo: () => null },
    internalPlugins: {
      getEnabledPluginById: (id) => (id === 'publish' ? publishInstance : null)
    }
  };

  const guard = new PublishGuard(app);
  assert.strictEqual(guard.install(), true, 'the guard must be installed');

  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager, undefined, vault);
  interceptor.install();
  interceptor.installVaultHooks();

  const secret = 'Contenido que jamas debe publicarse.';
  await adapter.write('Notas/Publicada.md', secret);

  const file = createFakeFile('Notas/Publicada.md');

  await assert.rejects(
    async () => {
      await publishInstance.apiUploadFile(file);
    },
    /Publish no puede publicar|encrypted/i,
    'the upload of an encrypted note must be blocked'
  );

  assert.strictEqual(uploaded, null, 'no cleartext must have been uploaded');

  // A plaintext note (in the excluded folder) can still be published.
  await adapter.write('publico/Libre.md', 'Nota publica de ejemplo.');
  const publicFile = createFakeFile('publico/Libre.md');
  await publishInstance.apiUploadFile(publicFile);
  assert.strictEqual(uploaded, 'Nota publica de ejemplo.', 'a plaintext note must still publish');

  guard.uninstall();
  interceptor.uninstall();
});



// ---------------------------------------------------------------------------
// Regression tests (bug hunt 2026-10-26)
// ---------------------------------------------------------------------------

import { BackupEngine } from '../src/backup/backup-engine.ts';

async function createHookedVault() {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();
  const vault = new Vault(adapter);
  const interceptor = new AdapterInterceptor(adapter, pathFilter, keyManager, undefined, vault);
  interceptor.install();
  interceptor.installVaultHooks();
  return { adapter, pathFilter, keyManager, vault, interceptor };
}

test('Regression: a text note written through writeBinary stays readable', async () => {
  const { adapter } = await createHookedVault();
  await adapter.writeBinary('dropped.md', new TextEncoder().encode('# dropped note').buffer);

  assert.strictEqual(await adapter.read('dropped.md'), '# dropped note');
  const onDisk = new TextDecoder().decode(new Uint8Array(await adapter.readBinary('dropped.md')));
  assert.ok(isArmoredEncrypted(onDisk), 'text notes are stored armored, like every other write path');
});

test('Regression: read() decrypts a text note already stored as a binary container', async () => {
  const { adapter, interceptor, keyManager } = await createHookedVault();
  // Reproduce what the old writeBinary produced for a note: a MYSE container.
  const { encryptAesGcm } = await import('../src/crypto/aes.ts');
  const { serializeBinary } = await import('../src/crypto/envelope.ts');
  const enc = await encryptAesGcm(new TextEncoder().encode('legacy note'), keyManager.getVaultKey(), 'legacy.md');
  await interceptor.getRawAdapter().writeBinary(
    'legacy.md',
    serializeBinary({ version: 1, iv: enc.iv, tag: enc.tag, ciphertext: enc.ciphertext }).buffer
  );

  assert.strictEqual(await adapter.read('legacy.md'), 'legacy note');
  await adapter.append('legacy.md', '!');
  assert.strictEqual(await adapter.read('legacy.md'), 'legacy note!');
});

test('Regression: a plain note that merely starts with "MYSE" is returned untouched', async () => {
  const { adapter, interceptor } = await createHookedVault();
  await interceptor.getRawAdapter().write('plain.md', 'MYSELF and I');
  assert.strictEqual(await adapter.read('plain.md'), 'MYSELF and I');
});

test('Regression: a leading BOM survives encrypt/decrypt', async () => {
  const { adapter, interceptor } = await createHookedVault();
  await adapter.write('bom.md', '﻿hello');
  assert.strictEqual(await adapter.read('bom.md'), '﻿hello');

  const r = await interceptor.decryptFilesToPlain(['bom.md']);
  assert.strictEqual(r.failed.length, 0);
  // The fake adapter's own read() strips the BOM, so the bytes are compared.
  const onDisk = new Uint8Array(await interceptor.getRawAdapter().readBinary('bom.md'));
  assert.deepStrictEqual([...onDisk], [0xef, 0xbb, 0xbf, ...new TextEncoder().encode('hello')]);
});

test('Regression: a save racing with the rename re-bind is not overwritten', async () => {
  const { adapter, interceptor } = await createHookedVault();
  await adapter.write('x.md', 'OLD');
  await adapter.rename('x.md', 'y.md');

  const rebind = interceptor.handleVaultRename({ path: 'y.md', name: 'y.md' }, 'x.md');
  const save = adapter.write('y.md', 'NEW');
  await Promise.all([rebind, save]);

  assert.strictEqual(await adapter.read('y.md'), 'NEW');
});

test('Regression: the media cache follows an attachment written verbatim (Sync)', async () => {
  const adapter = createFakeAdapter();
  const pathFilter = new PathFilter([], true);
  const keyManager = await createUnlockedKeyManager();
  const mediaManager = new MediaManager({ vault: { adapter } }, pathFilter, keyManager);
  new AdapterInterceptor(adapter, pathFilter, keyManager, mediaManager).install();

  await adapter.writeBinary('img.png', new Uint8Array([1, 1, 1]).buffer);
  const first = new Uint8Array(await (await fetch(mediaManager.getCachedBlobUrl('img.png'))).arrayBuffer());
  assert.deepStrictEqual([...first], [1, 1, 1]);

  // Another device re-encrypted the attachment; Sync writes that ciphertext back.
  const other = createFakeAdapter();
  new AdapterInterceptor(other, pathFilter, keyManager).install();
  await other.writeBinary('img.png', new Uint8Array([2, 2, 2, 2]).buffer);
  await adapter.writeBinary('img.png', await other.readBinary('img.png'));
  // invalidate() re-resolves in the background
  await new Promise(resolve => setTimeout(resolve, 50));

  const url = mediaManager.getCachedBlobUrl('img.png');
  assert.ok(url, 'the attachment is cached again after the refresh');
  const second = new Uint8Array(await (await fetch(url)).arrayBuffer());
  assert.deepStrictEqual([...second], [2, 2, 2, 2]);
});

test('Regression: a folder named "Prototype" is backed up; unarchivable files are reported', async () => {
  const { adapter, pathFilter, keyManager, interceptor } = await createHookedVault();
  await adapter.write('Prototype/idea.md', 'my idea');
  await adapter.write('__proto__/idea.md', 'reserved');
  await adapter.write('ok.md', 'ok');
  const plugin = {
    keyManager,
    interceptor,
    pathFilter,
    app: { vault: { adapter, getFiles: () => [...adapter.files.keys()].map(p => new TFile(p)), getName: () => 'V' } }
  };

  const zip = await BackupEngine.createVaultZip(plugin, { mode: 'encrypted' });
  const inZip = zip.manifest.files.map(f => f.path);
  const reported = zip.stats.skippedFiles.map(f => f.path);
  assert.ok(inZip.includes('Prototype/idea.md'), 'a folder named Prototype is backed up');
  assert.ok(reported.includes('__proto__/idea.md'), 'a file that cannot be archived is reported');
  assert.ok(inZip.includes('ok.md'));

  // ...and the archive restores into a fresh vault.
  const dst = await createHookedVault();
  const dstPlugin = {
    keyManager: dst.keyManager,
    interceptor: dst.interceptor,
    pathFilter: dst.pathFilter,
    app: { vault: { adapter: dst.adapter, getFiles: () => [], getName: () => 'V' } }
  };
  const restored = await BackupEngine.restoreFromZip(dstPlugin, zip.zipBytes);
  assert.deepStrictEqual(restored.errors, []);
  assert.strictEqual(await dst.adapter.read('Prototype/idea.md'), 'my idea');
});
