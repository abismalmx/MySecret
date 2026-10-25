/**
 * Adapter Interceptor Regression Tests
 *
 * These tests cover the AAD re-bind logic used when a file or folder is
 * renamed or copied (VUL-03), which is the mechanism that prevents silent
 * and irreversible data loss.
 *
 * They specifically reproduce the two defects found while reviewing the
 * first implementation of the patch:
 *   - `DataAdapter.list()` returns ABSOLUTE vault paths, not relative names.
 *     Treating them as relative produced paths such as
 *     `Notas/sub/Notas/sub/file.md` and silently broke the re-bind.
 *   - The rename must be handled through the public `vault.on('rename')`
 *     event, because the `DataAdapter.rename()` hook is not guaranteed to
 *     fire for every rename performed by Obsidian.
 */

import assert from 'node:assert';
import test from 'node:test';
import { webcrypto } from 'node:crypto';

if (!globalThis.window) {
  globalThis.window = {
    crypto: webcrypto,
    addEventListener: () => {},
    removeEventListener: () => {}
  };
} else {
  if (!globalThis.window.addEventListener) globalThis.window.addEventListener = () => {};
  if (!globalThis.window.removeEventListener) globalThis.window.removeEventListener = () => {};
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
import { isArmoredEncrypted, deserializeArmored, isBinaryEncrypted } from '../src/crypto/envelope.ts';
import { TFolder } from 'obsidian';

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

  // 2. adapter.readBinary must return the original decrypted image bytes
  const decryptedBuffer = await adapter.readBinary('Pasted image.png');
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
