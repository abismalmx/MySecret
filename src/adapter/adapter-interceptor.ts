/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Transparent DataAdapter Interceptor (VaultAdapter Hook)
 */

import { DataAdapter, TAbstractFile, TFolder } from 'obsidian';
import { PathFilter } from './path-filter';
import { KeyManager } from '../crypto/key-manager';
import { encryptAesGcm, decryptAesGcm } from '../crypto/aes';
import {
  isArmoredEncrypted,
  serializeArmored,
  deserializeArmored,
  isBinaryEncrypted,
  serializeBinary,
  deserializeBinary
} from '../crypto/envelope';
import { stringToBytes, bytesToString } from '../utils/buffer';

import { MediaManager } from './media-manager';

export class AdapterInterceptor {
  private adapter: DataAdapter;
  private pathFilter: PathFilter;
  private keyManager: KeyManager;
  private mediaManager?: MediaManager;
  private isHooked: boolean = false;

  // Stored original adapter methods
  private origRead!: (path: string) => Promise<string>;
  private origWrite!: (path: string, data: string, options?: any) => Promise<void>;
  private origReadBinary!: (path: string) => Promise<ArrayBuffer>;
  private origWriteBinary!: (path: string, data: ArrayBuffer, options?: any) => Promise<void>;
  private origAppend!: (path: string, data: string, options?: any) => Promise<void>;
  private origAppendBinary!: (path: string, data: ArrayBuffer, options?: any) => Promise<void>;
  private origProcess!: (path: string, fn: (data: string) => string, options?: any) => Promise<string>;
  private origCopy!: (path: string, newPath: string) => Promise<void>;
  private origList!: (path: string) => Promise<{ files: string[]; folders: string[] }>;
  private origStat!: (path: string) => Promise<{ type: string } | null>;
  private origGetResourcePath!: (path: string) => string;

  constructor(adapter: DataAdapter, pathFilter: PathFilter, keyManager: KeyManager, mediaManager?: MediaManager) {
    this.adapter = adapter;
    this.pathFilter = pathFilter;
    this.keyManager = keyManager;
    this.mediaManager = mediaManager;
  }

  public setMediaManager(mediaManager: MediaManager): void {
    this.mediaManager = mediaManager;
  }

  /**
   * Installs the transparent interception hooks onto the Obsidian Vault DataAdapter
   */
  public install(): void {
    if (this.isHooked) return;

    const a = this.adapter as any;

    this.origRead = a.read.bind(this.adapter);
    this.origWrite = a.write.bind(this.adapter);
    this.origReadBinary = a.readBinary.bind(this.adapter);
    this.origWriteBinary = a.writeBinary.bind(this.adapter);
    if (a.append) this.origAppend = a.append.bind(this.adapter);
    if (a.appendBinary) this.origAppendBinary = a.appendBinary.bind(this.adapter);
    if (a.process) this.origProcess = a.process.bind(this.adapter);
    if (a.copy) this.origCopy = a.copy.bind(this.adapter);
    if (a.list) this.origList = a.list.bind(this.adapter);
    if (a.stat) this.origStat = a.stat.bind(this.adapter);
    if (a.getResourcePath) this.origGetResourcePath = a.getResourcePath.bind(this.adapter);

    // eslint-disable-next-line @typescript-eslint/no-this-alias
    const self = this;

    // 0. Hook getResourcePath
    if (a.getResourcePath) {
      a.getResourcePath = function (path: string): string {
        const norm = self.pathFilter.normalizePath(path);
        if (self.pathFilter.shouldEncrypt(norm)) {
          const cached = self.mediaManager?.getCachedBlobUrl(norm);
          if (cached) {
            return cached;
          }
          void self.mediaManager?.getOrResolveMediaBlob(norm);
        }
        return self.origGetResourcePath(path);
      };
    }

    // 1. Hook read
    a.read = async function (path: string): Promise<string> {
      if (!self.pathFilter.shouldEncrypt(path)) {
        return await self.origRead(path);
      }

      if (self.keyManager.isLocked) {
        // Vault is locked: await unlock or throw security exception
        throw new Error(`[MySecret] Access denied: Vault is locked (${path})`);
      }

      const rawContent = await self.origRead(path);

      if (!isArmoredEncrypted(rawContent)) {
        // File is not encrypted yet (e.g. before initial migration)
        return rawContent;
      }

      const vaultKey = self.keyManager.getVaultKey();
      if (!vaultKey) {
        throw new Error('[MySecret] Vault key unavailable in memory');
      }

      try {
        const payload = deserializeArmored(rawContent);
        const decryptedBytes = await decryptAesGcm(
          payload.ciphertext,
          vaultKey,
          payload.iv,
          payload.tag,
          self.pathFilter.normalizePath(path)
        );
        return bytesToString(decryptedBytes);
      } catch (err) {
        console.error(`[MySecret] Failed to decrypt ${path}:`, err);
        throw new Error(`[MySecret] Decryption failed for ${path}: Authentication check failed`);
      }
    };

    // 2. Hook write
    a.write = async function (path: string, data: string, options?: any): Promise<void> {
      if (!self.pathFilter.shouldEncrypt(path)) {
        return await self.origWrite(path, data, options);
      }

      if (self.keyManager.isLocked) {
        throw new Error(`[MySecret] Cannot write while vault is locked (${path})`);
      }

      const vaultKey = self.keyManager.getVaultKey();
      if (!vaultKey) {
        throw new Error('[MySecret] Vault key unavailable in memory');
      }

      const plainBytes = stringToBytes(data);
      const encResult = await encryptAesGcm(
        plainBytes,
        vaultKey,
        self.pathFilter.normalizePath(path)
      );

      const armored = serializeArmored({
        version: 1,
        iv: encResult.iv,
        tag: encResult.tag,
        ciphertext: encResult.ciphertext
      });

      return await self.origWrite(path, armored, options);
    };

    // 3. Hook readBinary
    a.readBinary = async function (path: string): Promise<ArrayBuffer> {
      if (!self.pathFilter.shouldEncrypt(path)) {
        return await self.origReadBinary(path);
      }

      if (self.keyManager.isLocked) {
        throw new Error(`[MySecret] Access denied: Vault is locked (${path})`);
      }

      const rawBuffer = await self.origReadBinary(path);
      const rawBytes = new Uint8Array(rawBuffer);

      if (!isBinaryEncrypted(rawBytes)) {
        return rawBuffer;
      }

      const vaultKey = self.keyManager.getVaultKey();
      if (!vaultKey) {
        throw new Error('[MySecret] Vault key unavailable in memory');
      }

      try {
        const payload = deserializeBinary(rawBytes);
        const decrypted = await decryptAesGcm(
          payload.ciphertext,
          vaultKey,
          payload.iv,
          payload.tag,
          self.pathFilter.normalizePath(path)
        );
        return decrypted.buffer as ArrayBuffer;
      } catch (err) {
        console.error(`[MySecret] Failed to decrypt binary ${path}:`, err);
        throw new Error(`[MySecret] Binary decryption failed for ${path}`);
      }
    };

    // 4. Hook writeBinary
    a.writeBinary = async function (path: string, data: ArrayBuffer, options?: any): Promise<void> {
      if (!self.pathFilter.shouldEncrypt(path)) {
        return await self.origWriteBinary(path, data, options);
      }

      if (self.keyManager.isLocked) {
        throw new Error(`[MySecret] Cannot write binary while vault is locked (${path})`);
      }

      // Immediately cache plaintext media so pasted attachments display instantaneously
      if (self.mediaManager) {
        self.mediaManager.registerPlaintextMedia(path, data);
      }

      const vaultKey = self.keyManager.getVaultKey();
      if (!vaultKey) {
        throw new Error('[MySecret] Vault key unavailable in memory');
      }

      const plainBytes = new Uint8Array(data);
      const encResult = await encryptAesGcm(
        plainBytes,
        vaultKey,
        self.pathFilter.normalizePath(path)
      );

      const binaryEncrypted = serializeBinary({
        version: 1,
        iv: encResult.iv,
        tag: encResult.tag,
        ciphertext: encResult.ciphertext
      });

      return await self.origWriteBinary(path, binaryEncrypted.buffer as ArrayBuffer, options);
    };

    // 5. Hook append
    if (a.append) {
      a.append = async function (path: string, data: string, options?: any): Promise<void> {
        if (!self.pathFilter.shouldEncrypt(path)) {
          return await self.origAppend(path, data, options);
        }
        // Decrypt current, append in memory, and re-encrypt
        let existing = '';
        try {
          existing = await a.read(path);
        } catch {
          existing = '';
        }
        await a.write(path, existing + data, options);
      };
    }

    // 5b. Hook appendBinary
    //
    // SECURITY: without this hook `appendBinary` would append raw plaintext to
    // an encrypted attachment, silently corrupting it and leaking the appended
    // content in cleartext on disk.
    if (a.appendBinary) {
      a.appendBinary = async function (path: string, data: ArrayBuffer, options?: any): Promise<void> {
        if (!self.pathFilter.shouldEncrypt(path)) {
          return await self.origAppendBinary(path, data, options);
        }

        if (self.keyManager.isLocked) {
          throw new Error(`[MySecret] Cannot append binary while vault is locked (${path})`);
        }

        const vaultKey = self.keyManager.getVaultKey();
        if (!vaultKey) {
          throw new Error('[MySecret] Vault key unavailable in memory');
        }

        // Decrypt the current content, append, and re-encrypt everything.
        let existingBytes: Uint8Array = new Uint8Array(0);
        try {
          const rawBuffer = await self.origReadBinary(path);
          const rawBytes = new Uint8Array(rawBuffer);
          if (isBinaryEncrypted(rawBytes)) {
            const payload = deserializeBinary(rawBytes);
            existingBytes = await decryptAesGcm(
              payload.ciphertext,
              vaultKey,
              payload.iv,
              payload.tag,
              self.pathFilter.normalizePath(path)
            );
          } else {
            existingBytes = rawBytes;
          }
        } catch {
          // A missing or unreadable file starts empty.
          existingBytes = new Uint8Array(0);
        }

        const appended = new Uint8Array(data);
        const merged = new Uint8Array(existingBytes.length + appended.length);
        merged.set(existingBytes, 0);
        merged.set(appended, existingBytes.length);

        const encResult = await encryptAesGcm(
          merged,
          vaultKey,
          self.pathFilter.normalizePath(path)
        );

        const binaryEncrypted = serializeBinary({
          version: 1,
          iv: encResult.iv,
          tag: encResult.tag,
          ciphertext: encResult.ciphertext
        });

        return await self.origWriteBinary(path, binaryEncrypted.buffer as ArrayBuffer, options);
      };
    }

    // 6. Hook process
    if (a.process) {
      a.process = async function (
        path: string,
        fn: (data: string) => string,
        options?: any
      ): Promise<string> {
        if (!self.pathFilter.shouldEncrypt(path)) {
          return await self.origProcess(path, fn, options);
        }
        const currentText = await a.read(path);
        const processed = fn(currentText);
        await a.write(path, processed, options);
        return processed;
      };
    }

    // 7. Hook copy
    //
    // A copy must be re-encrypted with the *destination* path as AAD,
    // otherwise the duplicate could never be decrypted.
    //
    // NOTE: Obsidian's public API exposes no "copy" event, so the adapter
    // hook is the only available interception point for copies.
    if (a.copy) {
      a.copy = async function (path: string, newPath: string): Promise<void> {
        if (!self.origCopy) {
          return;
        }

        const oldNorm = self.pathFilter.normalizePath(path);
        const newNorm = self.pathFilter.normalizePath(newPath);

        await self.origCopy(path, newPath);

        try {
          await self.rebindAad(oldNorm, newNorm);
        } catch (err) {
          console.error(`[MySecret] Failed to re-bind encryption after copy (${path} -> ${newPath}):`, err);
          throw err;
        }
      };
    }

    this.isHooked = true;
  }

  /**
   * Re-binds the AAD after Obsidian reports a rename through the public
   * `vault.on('rename')` event.
   *
   * WHY AN EVENT AND NOT THE ADAPTER HOOK: `Vault.rename()` and
   * `FileManager.renameFile()` are the public entry points (drag & drop,
   * the file explorer, the "rename" command, sync plugins…). The
   * `DataAdapter.rename()` hook only fires if Obsidian happens to route the
   * operation through the adapter, which is an implementation detail and is
   * NOT part of the public contract. The `rename` event, in contrast, is
   * guaranteed to fire for every rename.
   *
   * The event fires *after* the file has already been moved, so the affected
   * subtree is enumerated from the NEW location and the old path of each
   * descendant is derived from it.
   *
   * @param file The renamed file or folder (at its NEW path)
   * @param oldPath Its previous vault path
   */
  public async handleVaultRename(file: TAbstractFile, oldPath: string): Promise<void> {
    try {
      const newPath = this.pathFilter.normalizePath(file.path);
      const oldNorm = this.pathFilter.normalizePath(oldPath);

      if (!newPath || !oldNorm || newPath === oldNorm) {
        return;
      }

      // Only files whose encryption policy applies need a re-bind.
      if (!this.pathFilter.shouldEncrypt(newPath) && !this.pathFilter.shouldEncrypt(oldNorm)) {
        return;
      }

      // Determine whether a folder was renamed.
      //
      // `instanceof TFolder` is used when possible, but a `stat` probe is
      // performed as well so the logic does not depend on the exact class
      // identity of the object delivered by the event (which is the more
      // robust signal, since the event fires after the move).
      let isFolder = file instanceof TFolder;
      if (!isFolder && this.origStat) {
        try {
          const stat = await this.origStat(newPath);
          isFolder = stat?.type === 'folder';
        } catch {
          isFolder = false;
        }
      }

      if (isFolder) {
        // A folder was renamed: every descendant moved with it. The event
        // fires only for the folder itself, so the subtree is enumerated
        // from its new location.
        const descendants = await this.collectSubtreeFiles(newPath);
        for (const descendant of descendants) {
          const fromAbs = oldNorm + descendant.slice(newPath.length);
          const toAbs = descendant;
          try {
            await this.rebindAad(fromAbs, toAbs);
          } catch (err) {
            console.error(`[MySecret] Failed to re-bind encryption after rename (${fromAbs} -> ${toAbs}):`, err);
          }
        }
      } else {
        await this.rebindAad(oldNorm, newPath);
      }

      this.mediaManager?.handleRename(oldNorm, newPath);
    } catch (err) {
      console.error('[MySecret] Failed to re-bind encryption after rename:', err);
    }
  }

  /**
   * Lists every file contained in `rootPath` (recursively).
   *
   * IMPORTANT: `DataAdapter.list()` returns **vault absolute paths** (the
   * documented contract of `ListedFiles.files` / `ListedFiles.folders`), NOT
   * bare names relative to the listed folder. The previous implementation
   * assumed they were relative and therefore built nonsense paths such as
   * `Notas/sub/Notes/sub/file.md`, which silently broke the AAD re-bind.
   *
   * @returns absolute vault paths of every file under `rootPath`.
   */
  private async collectSubtreeFiles(rootPath: string): Promise<string[]> {
    if (!this.origList) {
      // Without `list` we can only handle the root object itself.
      return [rootPath];
    }

    const results: string[] = [];
    const visited = new Set<string>();

    const walk = async (current: string): Promise<void> => {
      if (visited.has(current)) return;
      visited.add(current);

      let listing: { files: string[]; folders: string[] };
      try {
        listing = await this.origList(current);
      } catch {
        // Not a directory (it is a file) -> nothing to recurse into.
        return;
      }

      for (const file of listing.files || []) {
        results.push(file);
      }
      for (const folder of listing.folders || []) {
        await walk(folder);
      }
    };

    await walk(rootPath);
    return results;
  }

  /**
   * Re-binds the AES-GCM AAD of a file after it has been moved or copied.
   *
   * The file is read from disk in its *current* (encrypted with the old AAD)
   * form and rewritten using the new path as AAD. The content is only ever
   * rewritten through the raw (unintercepted) adapter so that no double
   * encryption happens.
   */
  private async rebindAad(fromAbs: string, toAbs: string): Promise<void> {
    const shouldEncryptOld = this.pathFilter.shouldEncrypt(fromAbs);
    const shouldEncryptNew = this.pathFilter.shouldEncrypt(toAbs);

    // Nothing to do when the encryption policy does not apply at all.
    if (!shouldEncryptOld && !shouldEncryptNew) {
      return;
    }

    if (this.keyManager.isLocked) {
      // Re-binding requires the vault key. If the vault is locked we cannot
      // safely rewrite the file: refuse instead of leaving it undecryptable.
      throw new Error('[MySecret] Cannot re-bind encryption while the vault is locked.');
    }
    const vaultKey = this.keyManager.getVaultKey();
    if (!vaultKey) {
      throw new Error('[MySecret] Vault key unavailable in memory');
    }

    const oldAad = this.pathFilter.normalizePath(fromAbs);
    const newAad = this.pathFilter.normalizePath(toAbs);

    // --- Text files ---
    const rawText = await this.origRead(toAbs);
    if (isArmoredEncrypted(rawText)) {
      const payload = deserializeArmored(rawText);
      const plain = await decryptAesGcm(payload.ciphertext, vaultKey, payload.iv, payload.tag, oldAad);
      if (!shouldEncryptNew) {
        await this.origWrite(toAbs, bytesToString(plain));
        return;
      }
      const enc = await encryptAesGcm(plain, vaultKey, newAad);
      await this.origWrite(toAbs, serializeArmored({
        version: 1,
        iv: enc.iv,
        tag: enc.tag,
        ciphertext: enc.ciphertext
      }));
      return;
    }

    // Plaintext file: encrypt it only if the new location requires it.
    if (shouldEncryptNew) {
      const enc = await encryptAesGcm(stringToBytes(rawText), vaultKey, newAad);
      await this.origWrite(toAbs, serializeArmored({
        version: 1,
        iv: enc.iv,
        tag: enc.tag,
        ciphertext: enc.ciphertext
      }));
    }

    // --- Binary files ---
    const rawBuffer = await this.origReadBinary(toAbs);
    const rawBytes = new Uint8Array(rawBuffer);
    if (isBinaryEncrypted(rawBytes)) {
      const payload = deserializeBinary(rawBytes);
      const plain = await decryptAesGcm(payload.ciphertext, vaultKey, payload.iv, payload.tag, oldAad);
      if (!shouldEncryptNew) {
        await this.origWriteBinary(toAbs, plain.buffer as ArrayBuffer);
        return;
      }
      const enc = await encryptAesGcm(plain, vaultKey, newAad);
      const binEnc = serializeBinary({
        version: 1,
        iv: enc.iv,
        tag: enc.tag,
        ciphertext: enc.ciphertext
      });
      await this.origWriteBinary(toAbs, binEnc.buffer as ArrayBuffer);
      return;
    }

    if (shouldEncryptNew) {
      const enc = await encryptAesGcm(rawBytes, vaultKey, newAad);
      const binEnc = serializeBinary({
        version: 1,
        iv: enc.iv,
        tag: enc.tag,
        ciphertext: enc.ciphertext
      });
      await this.origWriteBinary(toAbs, binEnc.buffer as ArrayBuffer);
    }
  }

  /**
   * Restores original DataAdapter methods (for uninstallation or rollback)
   */
  public uninstall(): void {
    if (!this.isHooked) return;

    const a = this.adapter as any;
    a.read = this.origRead;
    a.write = this.origWrite;
    a.readBinary = this.origReadBinary;
    a.writeBinary = this.origWriteBinary;
    if (this.origAppend) a.append = this.origAppend;
    if (this.origAppendBinary) a.appendBinary = this.origAppendBinary;
    if (this.origProcess) a.process = this.origProcess;
    if (this.origCopy) a.copy = this.origCopy;
    if (this.origGetResourcePath) a.getResourcePath = this.origGetResourcePath;

    this.isHooked = false;
  }

  /**
   * Access to raw underlying unintercepted read/write (for migrations)
   */
  public getRawAdapter() {
    return {
      read: this.origRead,
      write: this.origWrite,
      readBinary: this.origReadBinary,
      writeBinary: this.origWriteBinary,
      exists: this.adapter.exists ? this.adapter.exists.bind(this.adapter) : undefined
    };
  }
}
