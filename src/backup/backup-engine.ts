/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Backup & Export Engine (Local ZIP & Cloud Dispatch)
 */

import { zipSync, unzipSync, strToU8, strFromU8 } from 'fflate';
import MySecretPlugin from '../main';
import { BackupManifest, BackupStats, BackupSkippedFile, RestoreResult } from '../types';
import {
  VAULT_ENVELOPE_PATH,
  MAX_RESTORE_ENTRIES,
  MAX_RESTORE_ENTRY_BYTES,
  MAX_RESTORE_TOTAL_BYTES,
  MAX_RESTORE_ARCHIVE_BYTES
} from '../constants';
import { isArmoredEncrypted, isBinaryEncrypted, serializeArmored, serializeBinary } from '../crypto/envelope';
import { detectContainerFormat, isAuthenticContainer, decryptContainer } from '../adapter/decrypt';
import { encryptAesGcm } from '../crypto/aes';
import { stringToBytes, bytesToString, decodeUtf8Strict } from '../utils/buffer';
import { sanitizeVaultRelativePath, hasForbiddenSegment } from '../utils/path-sanitizer';

export interface CreateZipOptions {
  mode: 'encrypted' | 'decrypted';
  includeAttachments?: boolean;
  includeEnvelope?: boolean;
  /**
   * Key used to encrypt files that are still plaintext on disk. Needed by the
   * "on lock" auto-backup, which runs after the key was wiped from the
   * KeyManager. When omitted the KeyManager's key is used.
   */
  vaultKey?: CryptoKey;
}

export class BackupEngine {
  /**
   * Generates a compressed ZIP file containing vault notes and attachments
   */
  public static async createVaultZip(
    plugin: MySecretPlugin,
    options: CreateZipOptions,
    onProgress?: (currentFile: string, current: number, total: number) => void
  ): Promise<{ zipBytes: Uint8Array; filename: string; stats: BackupStats; manifest: BackupManifest }> {
    const startTime = Date.now();
    const mode = options.mode;
    const includeAttachments = options.includeAttachments ?? true;
    const includeEnvelope = options.includeEnvelope ?? (mode === 'encrypted');

    if (mode === 'decrypted' && plugin.keyManager.isLocked) {
      throw new Error('La bóveda está bloqueada. Debes desbloquearla para exportar notas descifradas.');
    }

    const rawAdapter = plugin.interceptor.getRawAdapter();
    const allFiles = plugin.app.vault.getFiles();

    // Filter candidate files based on settings
    const targets = allFiles.filter(file => {
      const isText = plugin.pathFilter.isTextNote(file.path);
      if (isText) {
        return plugin.pathFilter.shouldEncrypt(file.path);
      }
      // Attachment
      return includeAttachments && plugin.pathFilter.shouldEncrypt(file.path);
    });

    // The ZIP writer iterates this map with `for...in`, so a plain object is
    // used (a null-prototype object is not supported by the writer).
    // SECURITY: files whose path contains a prototype-polluting segment
    // ("__proto__", "constructor", ...) are skipped below, because assigning
    // such a key to a plain object would mutate its prototype instead of
    // creating a property.
    const zipData: Record<string, Uint8Array> = {};
    const manifestFiles: BackupManifest['files'] = [];
    let textNotesCount = 0;
    let attachmentsCount = 0;
    let totalBytes = 0;

    const vaultKey = options.vaultKey ?? plugin.keyManager.getVaultKey();
    const skipped: BackupSkippedFile[] = [];

    for (let i = 0; i < targets.length; i++) {
      const file = targets[i];
      const path = file.path;
      const isText = plugin.pathFilter.isTextNote(path);

      if (onProgress) {
        onProgress(path, i + 1, targets.length);
      }

      // SECURITY: a path segment such as "__proto__" or "constructor" cannot
      // be used as a key of the ZIP map without corrupting it. Such files are
      // skipped instead of breaking the whole backup.
      if (hasForbiddenSegment(path)) {
        console.warn(`[MySecret] Skipped unsafe file name in backup: ${path}`);
        continue;
      }

      try {
        if (mode === 'encrypted') {
          if (isText) {
            textNotesCount++;
            const diskContent = await rawAdapter.read(path);
            const diskIsArmored = isArmoredEncrypted(diskContent);
            if (!diskIsArmored && !vaultKey) {
              // Plaintext on disk and no key to encrypt it with: it must NOT
              // vanish silently from the archive.
              skipped.push({ path, reason: 'plaintext file and the vault key is not available' });
              continue;
            }
            if (!diskIsArmored && decodeUtf8Strict(new Uint8Array(await rawAdapter.readBinary(path))) === null) {
              skipped.push({ path, reason: 'not valid UTF-8; it would be altered by encryption' });
              continue;
            }
            if (diskIsArmored) {
              const fileBytes = strToU8(diskContent);
              zipData[path] = fileBytes;
              totalBytes += fileBytes.length;
              manifestFiles.push({ path, size: fileBytes.length, isEncrypted: true });
            } else if (vaultKey) {
              // Encrypt plain disk content on-the-fly
              const plainBytes = stringToBytes(diskContent);
              const enc = await encryptAesGcm(plainBytes, vaultKey, plugin.pathFilter.normalizePath(path));
              const armored = serializeArmored({
                version: 1,
                iv: enc.iv,
                tag: enc.tag,
                ciphertext: enc.ciphertext
              });
              const fileBytes = strToU8(armored);
              zipData[path] = fileBytes;
              totalBytes += fileBytes.length;
              manifestFiles.push({ path, size: fileBytes.length, isEncrypted: true });
            }
          } else {
            attachmentsCount++;
            const diskBuffer = await rawAdapter.readBinary(path);
            const diskBytes = new Uint8Array(diskBuffer);
            if (isBinaryEncrypted(diskBytes)) {
              zipData[path] = diskBytes;
              totalBytes += diskBytes.length;
              manifestFiles.push({ path, size: diskBytes.length, isEncrypted: true });
            } else if (!vaultKey) {
              skipped.push({ path, reason: 'plaintext file and the vault key is not available' });
            } else {
              const enc = await encryptAesGcm(diskBytes, vaultKey, plugin.pathFilter.normalizePath(path));
              const binEnc = serializeBinary({
                version: 1,
                iv: enc.iv,
                tag: enc.tag,
                ciphertext: enc.ciphertext
              });
              zipData[path] = binEnc;
              totalBytes += binEnc.length;
              manifestFiles.push({ path, size: binEnc.length, isEncrypted: true });
            }
          }
        } else {
          // Decrypted export (transparent plaintext)
          if (isText) {
            textNotesCount++;
            const plainText = await plugin.app.vault.adapter.read(path);
            const fileBytes = strToU8(plainText);
            zipData[path] = fileBytes;
            totalBytes += fileBytes.length;
            manifestFiles.push({ path, size: fileBytes.length, isEncrypted: false });
          } else {
            attachmentsCount++;
            // The raw adapter returns the bytes as they are on disk, so the
            // plaintext is obtained through the interceptor, which decrypts
            // explicitly.
            const plainBytes = await plugin.interceptor.readPlaintextBinary(path);
            const fileBytes = plainBytes;
            zipData[path] = fileBytes;
            totalBytes += fileBytes.length;
            manifestFiles.push({ path, size: fileBytes.length, isEncrypted: false });
          }
        }
      } catch (err: any) {
        console.warn(`[MySecret] Backup warning on ${path}:`, err);
        skipped.push({ path, reason: err?.message || String(err) });
      }
    }

    // Include vault-envelope.json if requested and in encrypted mode
    if (mode === 'encrypted' && includeEnvelope) {
      try {
        const envelopeExists = rawAdapter.exists
          ? await rawAdapter.exists(VAULT_ENVELOPE_PATH)
          : true;
        if (envelopeExists) {
          const envelopeStr = await rawAdapter.read(VAULT_ENVELOPE_PATH);
          zipData[VAULT_ENVELOPE_PATH] = strToU8(envelopeStr);
          zipData['vault-envelope.json'] = strToU8(envelopeStr); // Convenience root copy
        }
      } catch (err) {
        console.warn('[MySecret] Could not include envelope in backup:', err);
      }
    }

    // Build backup manifest
    const manifest: BackupManifest = {
      version: 1,
      plugin: 'MySecret',
      mode,
      createdAt: startTime,
      vaultName: plugin.app.vault.getName() || 'Obsidian_Vault',
      totalFiles: manifestFiles.length,
      files: manifestFiles
    };

    zipData['mysecret-manifest.json'] = strToU8(JSON.stringify(manifest, null, 2));

    // Compress with fflate
    const zipBytes = zipSync(zipData, { level: 6 });

    const stats: BackupStats = {
      skippedFiles: skipped,
      totalFiles: targets.length,
      totalBytes: zipBytes.length,
      textNotesCount,
      attachmentsCount,
      elapsedMs: Date.now() - startTime
    };

    const dateStr = new Date(startTime).toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const modeTag = mode === 'encrypted' ? 'Cifrado' : 'Descifrado';
    const filename = `MySecret_${manifest.vaultName}_${modeTag}_${dateStr}.zip`;

    return { zipBytes, filename, stats, manifest };
  }

  /**
   * Triggers a browser download of the generated ZIP file
   */
  public static triggerDownload(filename: string, zipBytes: Uint8Array): void {
    // Copy into a plain ArrayBuffer so the Blob never carries a
    // SharedArrayBuffer-typed view.
    const blob = new Blob([zipBytes.slice().buffer as ArrayBuffer], { type: 'application/zip' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    window.setTimeout(() => {
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
    }, 1500);
  }

  /**
   * Restores vault files from an unzipped backup.
   *
   * SECURITY: the archive is untrusted input. Every entry name is validated
   * with {@link sanitizeVaultRelativePath} before it is used, which blocks
   * "Zip Slip" (writing outside the vault via `../` segments or absolute
   * paths) and prevents an attacker from dropping a malicious plugin into
   * `.obsidian/plugins/`. The archive size, the number of entries and the
   * uncompressed payload are also bounded to mitigate ZIP bombs.
   */
  public static async restoreFromZip(
    plugin: MySecretPlugin,
    zipBytes: Uint8Array,
    onProgress?: (currentFile: string, current: number, total: number) => void
  ): Promise<RestoreResult> {
    const rawAdapter = plugin.interceptor.getRawAdapter();

    const result: RestoreResult = {
      restoredFiles: 0,
      skippedFiles: 0,
      errors: []
    };

    // SECURITY: the archive is untrusted. Every entry is judged by what it
    // CONTAINS, never by the `mode` its own manifest claims, and ciphertext is
    // only accepted when it authenticates with THIS vault's key. That needs
    // the key, hence an unlocked vault.
    if (!plugin.keyManager || plugin.keyManager.isLocked) {
      result.errors.push({
        path: '',
        error: 'Desbloquea la bóveda antes de restaurar: las entradas se validan con tu clave.'
      });
      return result;
    }

    if (!zipBytes || zipBytes.length === 0) {
      result.errors.push({ path: '', error: 'El archivo ZIP está vacío.' });
      return result;
    }
    if (zipBytes.length > MAX_RESTORE_ARCHIVE_BYTES) {
      result.errors.push({
        path: '',
        error: 'El archivo ZIP supera el tamaño máximo permitido.'
      });
      return result;
    }

    let unzipped: Record<string, Uint8Array>;
    try {
      // SECURITY: the `filter` callback receives the DECLARED uncompressed
      // size of every entry BEFORE it is inflated. Checking the total size
      // AFTER `unzipSync` is too late: a small ZIP can expand to gigabytes
      // and crash the renderer before any limit can be applied.
      const declaredSizes = new Map<string, number>();
      let declaredTotal = 0;
      let tooManyEntries = false;

      unzipped = unzipSync(zipBytes, {
        filter: (file) => {
          if (declaredSizes.size >= MAX_RESTORE_ENTRIES) {
            tooManyEntries = true;
            return false;
          }
          const size = Number(file.originalSize ?? 0);
          declaredSizes.set(file.name, size);
          declaredTotal += size;
          // Reject the entry as soon as the declared total exceeds the budget.
          return declaredTotal <= MAX_RESTORE_TOTAL_BYTES;
        }
      });

      if (tooManyEntries || declaredSizes.size > MAX_RESTORE_ENTRIES) {
        result.errors.push({
          path: '',
          error: 'El archivo ZIP contiene demasiadas entradas. Se aborta la restauración.'
        });
        return result;
      }
    } catch (err: any) {
      result.errors.push({
        path: '',
        error: 'No se pudo descomprimir el archivo ZIP: ' + (err?.message || String(err))
      });
      return result;
    }

    let manifest: BackupManifest | null = null;
    if (unzipped['mysecret-manifest.json']) {
      try {
        const manifestStr = strFromU8(unzipped['mysecret-manifest.json']);
        manifest = JSON.parse(manifestStr);
      } catch (err) {
        console.warn('[MySecret] Could not parse manifest:', err);
      }
    }

    const entries = Object.entries(unzipped);

    if (entries.length > MAX_RESTORE_ENTRIES) {
      result.errors.push({
        path: '',
        error: `El archivo ZIP contiene demasiadas entradas (${entries.length}). Se aborta la restauración.`
      });
      return result;
    }

    // Bound the total uncompressed payload (ZIP bomb protection).
    let totalUncompressed = 0;
    for (const [, data] of entries) {
      totalUncompressed += data.length;
      if (totalUncompressed > MAX_RESTORE_TOTAL_BYTES) {
        result.errors.push({
          path: '',
          error: 'El contenido descomprimido del ZIP supera el tamaño máximo permitido.'
        });
        return result;
      }
    }

    // `manifest` is informational only (shown in the UI); see the note above.
    void manifest;

    for (let i = 0; i < entries.length; i++) {
      const [entryPath, data] = entries[i];

      // Skip manifest or convenience duplicate
      if (entryPath === 'mysecret-manifest.json' || entryPath === 'vault-envelope.json') {
        continue;
      }

      // Skip directory entries
      if (entryPath.endsWith('/')) {
        continue;
      }

      if (onProgress) {
        onProgress(entryPath, i + 1, entries.length);
      }

      // SECURITY: reject any path that escapes the vault or targets a
      // system/hidden directory before touching the filesystem.
      const sanitized = sanitizeVaultRelativePath(entryPath);
      if (!sanitized.safe) {
        console.warn(`[MySecret] Blocked unsafe restore path "${entryPath}": ${sanitized.reason}`);
        result.skippedFiles++;
        result.errors.push({
          path: entryPath,
          error: `Ruta de archivo rechazada por seguridad: ${sanitized.reason}`
        });
        continue;
      }

      const safePath = sanitized.path;

      if (data.length > MAX_RESTORE_ENTRY_BYTES) {
        result.skippedFiles++;
        result.errors.push({
          path: safePath,
          error: 'El archivo supera el tamaño máximo permitido.'
        });
        continue;
      }

      try {
        // Ensure parent directories exist
        const lastSlash = safePath.lastIndexOf('/');
        if (lastSlash > 0) {
          const parentDir = safePath.slice(0, lastSlash);
          const dirExists = await plugin.app.vault.adapter.exists(parentDir);
          if (!dirExists) {
            await plugin.app.vault.adapter.mkdir(parentDir);
          }
        }

        const isText = plugin.pathFilter.isTextNote(safePath);
        const aad = plugin.pathFilter.normalizePath(safePath);
        const format = detectContainerFormat(data);
        const encryptsHere = plugin.pathFilter.shouldEncrypt(safePath);

        if (format !== 'plain') {
          // Ciphertext: it must belong to THIS vault and to THIS path.
          if (!(await isAuthenticContainer(data, aad, plugin.keyManager))) {
            result.skippedFiles++;
            result.errors.push({
              path: safePath,
              error: 'No se autentica con la clave de esta bóveda (copia de otra bóveda, ruta distinta o archivo alterado).'
            });
            continue;
          }
          if ((isText && format !== 'armored') || (!isText && format !== 'binary')) {
            result.skippedFiles++;
            result.errors.push({
              path: safePath,
              error: 'El formato del contenedor cifrado no corresponde al tipo de archivo.'
            });
            continue;
          }

          if (encryptsHere) {
            // Store verbatim: it is already encrypted for this path.
            if (format === 'armored') {
              await rawAdapter.write(safePath, bytesToString(data));
            } else {
              await rawAdapter.writeBinary(safePath, data.slice().buffer as ArrayBuffer);
            }
          } else {
            // The path is not encrypted by policy (excluded folder): restore
            // the plaintext, a ciphertext there would be unreadable.
            const outcome = await decryptContainer(data, aad, plugin.keyManager);
            if (format === 'armored') {
              await rawAdapter.write(safePath, bytesToString(outcome.bytes));
            } else {
              await rawAdapter.writeBinary(safePath, outcome.bytes.slice().buffer as ArrayBuffer);
            }
          }
        } else if (isText) {
          // Plaintext note: write through the intercepted adapter so it is
          // encrypted on the way in (never left as plaintext on disk).
          const textContent = decodeUtf8Strict(data);
          if (textContent === null) {
            if (encryptsHere) {
              result.skippedFiles++;
              result.errors.push({
                path: safePath,
                error: 'No es UTF-8 válido: cifrarlo lo alteraría.'
              });
              continue;
            }
            await rawAdapter.writeBinary(safePath, data.slice().buffer as ArrayBuffer);
          } else {
            await plugin.app.vault.adapter.write(safePath, textContent);
          }
        } else {
          await plugin.app.vault.adapter.writeBinary(safePath, data.slice().buffer as ArrayBuffer);
        }

        result.restoredFiles++;
      } catch (err: any) {
        console.error(`[MySecret] Failed to restore file ${safePath}:`, err);
        result.errors.push({
          path: safePath,
          error: err?.message || String(err)
        });
      }
    }

    return result;
  }

  /**
   * Restores vault files from a backup ZIP archive.
   *
   * Alias kept for API compatibility with the UI layer.
   */
  public static async restoreVaultZip(
    plugin: MySecretPlugin,
    zipBytes: Uint8Array,
    onProgress?: (currentFile: string, current: number, total: number) => void
  ): Promise<RestoreResult> {
    return BackupEngine.restoreFromZip(plugin, zipBytes, onProgress);
  }
}
