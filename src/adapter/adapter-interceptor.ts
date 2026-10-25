/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Transparent DataAdapter Interceptor (VaultAdapter Hook)
 */

import { DataAdapter, TAbstractFile, TFile, TFolder, Vault } from 'obsidian';
import { PathFilter } from './path-filter';
import { KeyManager } from '../crypto/key-manager';
import { encryptAesGcm, decryptAesGcm } from '../crypto/aes';
import {
  isArmoredEncrypted,
  isArmoredBytesEncrypted,
  serializeArmored,
  deserializeArmored,
  isBinaryEncrypted,
  serializeBinary,
  deserializeBinary
} from '../crypto/envelope';
import { stringToBytes, bytesToString } from '../utils/buffer';
import {
  detectContainerFormat,
  decryptContainer,
  isAuthenticContainer,
  toArrayBuffer
} from './decrypt';
import { MetadataHashPatch } from './metadata-hash-patch';

import { MediaManager } from './media-manager';

export class AdapterInterceptor {
  private adapter: DataAdapter;
  private pathFilter: PathFilter;
  private keyManager: KeyManager;
  private mediaManager?: MediaManager;
  private isHooked: boolean = false;

  /**
   * The Obsidian `Vault` instance.
   *
   * It is required to intercept `Vault.readBinary()`, which is a DIFFERENT
   * entry point than `DataAdapter.readBinary()` (see the install() method for
   * the full rationale).
   */
  private vault?: Vault;

  /**
   * Keeps the hash of the metadata cache aligned with the hash that
   * Obsidian Sync computes (the hash of the ciphertext).
   */
  private metadataHashPatch?: MetadataHashPatch;

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

  /**
   * Original `Vault.readBinary`, restored on uninstall.
   */
  private origVaultReadBinary?: (file: TFile) => Promise<ArrayBuffer>;

  constructor(
    adapter: DataAdapter,
    pathFilter: PathFilter,
    keyManager: KeyManager,
    mediaManager?: MediaManager,
    vault?: Vault
  ) {
    this.adapter = adapter;
    this.pathFilter = pathFilter;
    this.keyManager = keyManager;
    this.mediaManager = mediaManager;
    this.vault = vault;
  }

  public setMediaManager(mediaManager: MediaManager): void {
    this.mediaManager = mediaManager;
  }

  /**
   * Attaches the patch that keeps the metadata cache hash aligned with the
   * hash that Obsidian Sync computes.
   */
  public setMetadataHashPatch(patch: MetadataHashPatch): void {
    this.metadataHashPatch = patch;
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

    // eslint-disable-next-line @typescript-eslint/no-this-alias -- Preserve interceptor instance context across patched methods
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

      // DATA INTEGRITY / ANTI DOUBLE-ENCRYPTION:
      //
      // Obsidian Sync writes back the ciphertext it downloaded. Encrypting it
      // again would produce a doubly encrypted note that could never be
      // decrypted. The payload is stored verbatim when it is a valid,
      // AUTHENTICATED MySecret container for that exact path.
      if (
        await isAuthenticContainer(
          stringToBytes(data),
          self.pathFilter.normalizePath(path),
          self.keyManager
        )
      ) {
        return await self.origWrite(path, data, options);
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
    //
    // SECURITY (confidentiality): this hook returns the RAW ON-DISK BYTES.
    //
    // The transparent decryption was originally implemented here because
    // Obsidian's metadata indexer reads notes through
    // `MetadataCache -> vault.readBinary(file) -> adapter.readBinary(path)`.
    // Decrypting in this hook therefore fixed the footnote indexing, but it
    // ALSO handed the cleartext to every other consumer of the raw adapter,
    // most importantly:
    //
    //   * Obsidian Sync  -> `app.vault.adapter.readBinary(path)` (direct call,
    //     it never goes through `vault.readBinary`). It would have uploaded
    //     the cleartext of every note to the cloud.
    //   * Obsidian Publish -> `vault.readBinary(file)`, which would have
    //     published the cleartext to a public website.
    //
    // The two consumers can be told apart WITHOUT relying on private APIs:
    // the indexer (and Publish) go through `Vault.readBinary(file)`, while Sync
    // calls the `DataAdapter` directly. Decryption is therefore moved to the
    // `Vault.readBinary` hook (see `installVaultHooks`), and this hook keeps
    // returning exactly what is on disk.
    //
    // This also fixes a silent data-corruption bug: Obsidian Sync downloads
    // the ciphertext and writes it back with `adapter.writeBinary`. With the
    // previous implementation the downloaded ciphertext was encrypted a SECOND
    // time, producing a doubly-encrypted file that could never be decrypted.
    a.readBinary = async function (path: string): Promise<ArrayBuffer> {
      return await self.origReadBinary(path);
    };

    // 4. Hook writeBinary
    a.writeBinary = async function (path: string, data: ArrayBuffer, options?: any): Promise<void> {
      if (!self.pathFilter.shouldEncrypt(path)) {
        return await self.origWriteBinary(path, data, options);
      }

      if (self.keyManager.isLocked) {
        throw new Error(`[MySecret] Cannot write binary while vault is locked (${path})`);
      }

      const vaultKey = self.keyManager.getVaultKey();
      if (!vaultKey) {
        throw new Error('[MySecret] Vault key unavailable in memory');
      }

      const plainBytes = new Uint8Array(data);

      // DATA INTEGRITY / ANTI DOUBLE-ENCRYPTION:
      //
      // Obsidian Sync downloads the ciphertext of a file and writes it back
      // verbatim through `vault.modifyBinary()` -> `adapter.writeBinary()`.
      // Encrypting that payload again would produce a DOUBLY encrypted file
      // that could never be decrypted (the outer layer would authenticate the
      // inner ciphertext instead of the note), silently destroying the vault.
      //
      // The payload is therefore stored verbatim when it is a valid,
      // AUTHENTICATED MySecret container for that exact path. The check is
      // cryptographic (it decrypts and verifies the GCM tag using the path as
      // AAD), so a file that merely looks like a container is still encrypted
      // normally and never leaks in cleartext.
      if (
        await isAuthenticContainer(
          plainBytes,
          self.pathFilter.normalizePath(path),
          self.keyManager
        )
      ) {
        return await self.origWriteBinary(path, toArrayBuffer(plainBytes), options);
      }

      // Immediately cache plaintext media so pasted attachments display instantaneously
      if (self.mediaManager) {
        self.mediaManager.registerPlaintextMedia(path, data);
      }

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

      return await self.origWriteBinary(path, toArrayBuffer(binaryEncrypted), options);
    };

    // 5. Hook append
    if (a.append) {
      a.append = async function (path: string, data: string, options?: any): Promise<void> {
        if (!self.pathFilter.shouldEncrypt(path)) {
          return await self.origAppend(path, data, options);
        }
        // Decrypt current, append in memory, and re-encrypt
        //
        // DATA INTEGRITY: a read failure must NEVER be swallowed here. If the
        // existing content cannot be read (locked vault, wrong AAD, corrupted
        // ciphertext), falling back to an empty string would silently REPLACE
        // the note with just the appended fragment, destroying the user's data.
        // The error is propagated instead.
        let existing: string;
        try {
          existing = await a.read(path);
        } catch (err: any) {
          // A genuinely missing file is the only case where starting from an
          // empty buffer is correct.
          let exists = false;
          if (typeof self.adapter.exists === 'function') {
            try {
              exists = await self.adapter.exists(path);
            } catch {
              exists = false;
            }
          }
          if (exists) {
            throw new Error(
              `[MySecret] Refusing to append to ${path}: the existing content could not be read (${err?.message || err}).`
            );
          }
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
        //
        // DATA INTEGRITY: as with `append`, a read failure must not be
        // swallowed. Swallowing it would silently truncate the attachment to
        // just the appended bytes.
        let existingBytes: Uint8Array = new Uint8Array(0);
        let fileExists = false;
        if (typeof self.adapter.exists === 'function') {
          try {
            fileExists = await self.adapter.exists(path);
          } catch {
            fileExists = false;
          }
        }

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
          } else if (isArmoredBytesEncrypted(rawBytes)) {
            // The target is an armored TEXT note (e.g. a Markdown file). The
            // binary envelope cannot be appended to it without destroying the
            // note, so it is rejected explicitly instead of being corrupted.
            throw new Error(
              `[MySecret] Refusing to append binary data to the text note ${path}.`
            );
          } else {
            existingBytes = rawBytes;
          }
        } catch (err: any) {
          if (fileExists) {
            throw new Error(
              `[MySecret] Refusing to append to ${path}: the existing content could not be read (${err?.message || err}).`
            );
          }
          // A genuinely missing file starts empty.
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
    a.process = async function (
      path: string,
      fn: (data: string) => string,
      options?: any
    ): Promise<string> {
      if (!self.pathFilter.shouldEncrypt(path)) {
        if (self.origProcess) {
          return await self.origProcess(path, fn, options);
        }
        let plain = '';
        try {
          plain = await self.origRead(path);
        } catch {
          plain = '';
        }
        const processed = fn(plain);
        await self.origWrite(path, processed, options);
        return processed;
      }

      // Check if file exists. If it exists, read MUST succeed; if read fails
      // (e.g. vault locked or decryption error), we MUST throw to prevent overwriting
      // existing user notes with empty text.
      let exists = false;
      if (typeof self.adapter.exists === 'function') {
        try {
          exists = await self.adapter.exists(path);
        } catch {
          exists = false;
        }
      }

      let currentText = '';
      if (exists) {
        currentText = await a.read(path);
      } else {
        try {
          currentText = await a.read(path);
        } catch {
          currentText = '';
        }
      }

      const processed = fn(currentText);
      await a.write(path, processed, options);
      return processed;
    };

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
   * Installs the `Vault.readBinary()` hook.
   *
   * WHY THIS HOOK EXISTS: the metadata indexer of Obsidian (which extracts
   * the footnotes, the links and the frontmatter) reads a note through
   * `MetadataCache.computeFileMetadataAsync()` ->
   * `vault.readBinary(file)` -> `adapter.readBinary(file.path)`.
   *
   * Because `Vault.readBinary` is a *different* entry point from
   * `DataAdapter.readBinary`, hooking it lets the plugin decrypt the notes
   * for the indexer while keeping the raw adapter (used by Obsidian Sync)
   * untouched. The cleartext is therefore never exposed to the sync engine.
   *
   * The hook is idempotent and it is safe to call it when the `Vault`
   * instance was not provided (e.g. in unit tests).
   */
  public installVaultHooks(): void {
    const vault = this.vault;
    if (!vault) return;

    const v = vault as any;
    if (!v.readBinary) return;

    if (!this.origVaultReadBinary) {
      this.origVaultReadBinary = v.readBinary.bind(vault);
    }

    // eslint-disable-next-line @typescript-eslint/no-this-alias -- Preserve interceptor instance context across patched methods
    const self = this;

    v.readBinary = async function (file: TFile): Promise<ArrayBuffer> {
      const path = file?.path;

      if (!path || !self.pathFilter.shouldEncrypt(path)) {
        return await self.origVaultReadBinary!(file);
      }

      if (self.keyManager.isLocked) {
        throw new Error(`[MySecret] Access denied: Vault is locked (${path})`);
      }

      const rawBuffer = await self.origVaultReadBinary!(file);
      const rawBytes = new Uint8Array(rawBuffer);

      // Files that are not encrypted on disk (e.g. before the initial
      // migration) are returned untouched.
      const format = detectContainerFormat(rawBytes);
      if (format === 'plain') {
        return rawBuffer;
      }

      try {
        // Keep the metadata cache hash aligned with the hash that Obsidian
        // Sync computes (the hash of the CIPHERTEXT). Without this, Sync
        // would detect a change on every file on every run.
        await self.metadataHashPatch?.recordCiphertextHashFromBytes(path, rawBytes);

        const outcome = await decryptContainer(
          rawBytes,
          self.pathFilter.normalizePath(path),
          self.keyManager
        );

        // The original `Vault.readBinary()` caches the RAW bytes it read in
        // the `TFile` object (`file.cache(decoded)`), so the CIPHERTEXT would
        // end up in the in-memory cache of the note. `Vault.cachedRead()`
        // would then return the armored content to the editor, and the user
        // would see the raw envelope instead of the note.
        //
        // The cache is therefore overwritten with the plaintext, so that
        // `cachedRead()` stays consistent with `read()`.
        if (typeof (file as any)?.cache === 'function') {
          try {
            (file as any).cache(new TextDecoder().decode(outcome.bytes));
          } catch (err) {
            // A failure to update the cache is not fatal: `cachedRead()` will
            // simply fall back to reading the file again.
            console.warn(`[MySecret] Could not refresh the in-memory cache of ${path}:`, err);
          }
        }

        return toArrayBuffer(outcome.bytes);
      } catch (err) {
        console.error(`[MySecret] Failed to decrypt ${path} for the metadata indexer:`, err);
        throw new Error(`[MySecret] Decryption failed for ${path}: Authentication check failed`);
      }
    };
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
   * Returns an ArrayBuffer that contains exactly the bytes of `data`.
   *
   * @deprecated Use the shared {@link toArrayBuffer} helper from `./decrypt`.
   */
  private toArrayBuffer(data: Uint8Array): ArrayBuffer {
    return toArrayBuffer(data);
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

    /*
     * DATA INTEGRITY: the container format is detected from the RAW BYTES, not
     * by reading the file as text first.
     *
     * The previous implementation read the file with `origRead()` (UTF-8) and
     * only then decided whether it was a text or a binary file. That was wrong
     * in two ways:
     *
     *  1. A *plaintext* Markdown note fell through to the binary branch (the
     *     text branch had no `return` after re-encrypting it), so the file was
     *     encrypted a second time as a binary container: the note became an
     *     unreadable blob.
     *  2. An *encrypted binary* attachment was decoded as UTF-8 (producing
     *     mojibake) and treated as plaintext, so the original bytes were
     *     replaced by corrupted data. The attachment was irrecoverably lost.
     */
    const rawBuffer = await this.origReadBinary(toAbs);
    const rawBytes = new Uint8Array(rawBuffer);

    // --- Encrypted BINARY container (attachments) ---
    if (isBinaryEncrypted(rawBytes)) {
      const payload = deserializeBinary(rawBytes);
      const plain = await decryptAesGcm(payload.ciphertext, vaultKey, payload.iv, payload.tag, oldAad);
      if (!shouldEncryptNew) {
        await this.origWriteBinary(toAbs, this.toArrayBuffer(plain));
        return;
      }
      const enc = await encryptAesGcm(plain, vaultKey, newAad);
      const binEnc = serializeBinary({
        version: 1,
        iv: enc.iv,
        tag: enc.tag,
        ciphertext: enc.ciphertext
      });
      await this.origWriteBinary(toAbs, this.toArrayBuffer(binEnc));
      return;
    }

    // --- Encrypted TEXT container (armored Markdown notes) ---
    if (isArmoredBytesEncrypted(rawBytes)) {
      const payload = deserializeArmored(bytesToString(rawBytes));
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

    // --- Plaintext file ---
    // Nothing to do when the destination does not require encryption.
    if (!shouldEncryptNew) {
      return;
    }

    const isTextNote = this.pathFilter.isTextNote(toAbs);
    if (isTextNote) {
      const enc = await encryptAesGcm(rawBytes, vaultKey, newAad);
      await this.origWrite(toAbs, serializeArmored({
        version: 1,
        iv: enc.iv,
        tag: enc.tag,
        ciphertext: enc.ciphertext
      }));
      return;
    }

    const enc = await encryptAesGcm(rawBytes, vaultKey, newAad);
    const binEnc = serializeBinary({
      version: 1,
      iv: enc.iv,
      tag: enc.tag,
      ciphertext: enc.ciphertext
    });
    await this.origWriteBinary(toAbs, this.toArrayBuffer(binEnc));
  }

  /**
   * Reads a file and returns its PLAINTEXT bytes.
   *
   * The raw `DataAdapter.readBinary()` intentionally returns the bytes as they
   * are on disk (so that Obsidian Sync never sees the cleartext). The
   * consumers that legitimately need the plaintext (the "decrypted" backup
   * export and the "decrypt everything" migration) must use this method
   * instead of the raw adapter.
   *
   * @param path The vault-relative path of the file.
   * @returns The decrypted bytes (or the original bytes when the file was not
   *          encrypted on disk).
   */
  public async readPlaintextBinary(path: string): Promise<Uint8Array> {
    const rawBuffer = await this.origReadBinary(path);
    const rawBytes = new Uint8Array(rawBuffer);

    if (!this.pathFilter.shouldEncrypt(path)) {
      return rawBytes;
    }

    const outcome = await decryptContainer(
      rawBytes,
      this.pathFilter.normalizePath(path),
      this.keyManager
    );
    return outcome.bytes;
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

    // Restore the original Vault.readBinary as well.
    if (this.vault && this.origVaultReadBinary) {
      (this.vault as any).readBinary = this.origVaultReadBinary;
      this.origVaultReadBinary = undefined;
    }

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
