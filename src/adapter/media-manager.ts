/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Media & Attachment Decryption Manager
 *
 * Intercepts media/attachment loading in the Obsidian DOM so that
 * encrypted images (pasted or embedded) render seamlessly in memory via
 * secure Blob URLs while remaining fully encrypted on disk.
 */

import { App, TFile } from 'obsidian';
import { PathFilter } from './path-filter';
import { KeyManager } from '../crypto/key-manager';
import { decryptContainer, toArrayBuffer } from './decrypt';

const MIME_MAP: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  webp: 'image/webp',
  svg: 'image/svg+xml',
  bmp: 'image/bmp',
  ico: 'image/x-icon',
  mp3: 'audio/mpeg',
  wav: 'audio/wav',
  ogg: 'audio/ogg',
  m4a: 'audio/mp4',
  mp4: 'video/mp4',
  webm: 'video/webm',
  ogv: 'video/ogg',
  mov: 'video/quicktime',
  pdf: 'application/pdf'
};

export class MediaManager {
  private app: App;
  private pathFilter: PathFilter;
  private keyManager: KeyManager;
  private blobUrls: Map<string, string> = new Map(); // normalizedPath -> blobUrl
  private pendingResolutions: Map<string, Promise<string | null>> = new Map();
  private observer: MutationObserver | null = null;
  private globalErrorHandler: ((event: ErrorEvent) => void) | null = null;

  constructor(app: App, pathFilter: PathFilter, keyManager: KeyManager) {
    this.app = app;
    this.pathFilter = pathFilter;
    this.keyManager = keyManager;
    this.initListeners();
  }

  /**
   * Derives MIME type from file path extension
   */
  public getMimeType(path: string): string {
    const ext = (path.split('.').pop() || '').toLowerCase();
    return MIME_MAP[ext] || 'application/octet-stream';
  }

  /**
   * Registers plaintext binary data into an in-memory Blob URL immediately.
   * Called during writeBinary so pasted images render instantaneously.
   */
  public registerPlaintextMedia(path: string, data: ArrayBuffer | Uint8Array): string {
    const norm = this.pathFilter.normalizePath(path);
    const existing = this.blobUrls.get(norm);
    if (existing) {
      try {
        URL.revokeObjectURL(existing);
      } catch {
        // best effort
      }
    }

    const mime = this.getMimeType(norm);
    const blob = new Blob([data as any], { type: mime });
    const blobUrl = URL.createObjectURL(blob);
    this.blobUrls.set(norm, blobUrl);

    // Immediately patch any DOM img elements waiting for this path
    this.patchDomForPath(norm, blobUrl);

    return blobUrl;
  }

  /**
   * Synchronously returns a cached Blob URL for a normalized path if one exists.
   */
  public getCachedBlobUrl(path: string): string | null {
    const norm = this.pathFilter.normalizePath(path);
    return this.blobUrls.get(norm) || null;
  }

  /**
   * Resolves an attachment file into an in-memory decrypted Blob URL.
   * If not yet cached, reads the file via the Vault DataAdapter (which decrypts it).
   */
  public async getOrResolveMediaBlob(path: string): Promise<string | null> {
    const norm = this.pathFilter.normalizePath(path);

    if (this.blobUrls.has(norm)) {
      return this.blobUrls.get(norm)!;
    }

    if (this.keyManager.isLocked) {
      return null;
    }

    if (this.pendingResolutions.has(norm)) {
      return this.pendingResolutions.get(norm)!;
    }

    const resolutionPromise = (async () => {
      try {
        // The raw adapter returns the bytes as they are on disk, so the
        // decryption has to be performed explicitly here.
        //
        // SECURITY: `adapter.readBinary` intentionally does NOT decrypt,
        // because Obsidian Sync reads the files through the raw adapter and
        // would otherwise upload the cleartext to the cloud.
        const rawBuffer = await this.app.vault.adapter.readBinary(norm);
        if (!rawBuffer || rawBuffer.byteLength === 0) {
          return null;
        }

        const rawBytes = new Uint8Array(rawBuffer);
        const outcome = await decryptContainer(
          rawBytes,
          norm,
          this.keyManager
        );

        // The vault may have been locked while the file was being decrypted:
        // the plaintext must not be cached after a lock.
        if (this.keyManager.isLocked) {
          return null;
        }

        const decryptedBuffer = toArrayBuffer(outcome.bytes);
        const mime = this.getMimeType(norm);
        const blob = new Blob([decryptedBuffer], { type: mime });
        const blobUrl = URL.createObjectURL(blob);

        this.blobUrls.set(norm, blobUrl);
        this.patchDomForPath(norm, blobUrl);
        return blobUrl;
      } catch (err) {
        console.warn(`[MySecret] Could not resolve media blob for ${norm}:`, err);
        return null;
      } finally {
        this.pendingResolutions.delete(norm);
      }
    })();

    this.pendingResolutions.set(norm, resolutionPromise);
    return resolutionPromise;
  }

  /**
   * Patches all img elements in the DOM that reference a given path with the decrypted Blob URL
   */
  public patchDomForPath(normPath: string, blobUrl: string): void {
    const filename = normPath.split('/').pop() || normPath;

    const images = document.querySelectorAll('img');
    images.forEach(img => {
      const src = img.getAttribute('src') || '';
      const alt = img.getAttribute('alt') || '';
      const parent = img.closest('.internal-embed');
      const parentSrc = parent?.getAttribute('src') || '';

      // EXACT file name comparison. A substring test ("data.png" inside
      // "metadata.png") patched unrelated images with the wrong decrypted blob.
      if (
        MediaManager.lastSegment(src) === filename ||
        alt === filename ||
        parentSrc === filename ||
        parentSrc === normPath ||
        parentSrc.endsWith('/' + filename)
      ) {
        this.applyBlobToImage(img, blobUrl, normPath);
      }
    });
  }

  /**
   * Last path segment of a URL (query/fragment removed, percent-decoded).
   */
  private static lastSegment(rawUrl: string): string {
    try {
      const clean = rawUrl.split('?')[0].split('#')[0];
      const last = clean.split('/').pop() || '';
      return decodeURIComponent(last);
    } catch {
      return '';
    }
  }

  /**
   * Applies the Blob URL to an img element, clearing broken indicators and fixing display
   */
  private applyBlobToImage(img: HTMLImageElement, blobUrl: string, normPath: string): void {
    if (img.src === blobUrl) return;

    img.dataset.mysecretOriginalSrc = img.src;
    img.dataset.mysecretPath = normPath;
    img.dataset.mysecretPatched = 'true';
    img.src = blobUrl;

    const parent = img.closest('.internal-embed');
    if (parent) {
      parent.classList.remove('mod-empty', 'is-failed');
      parent.classList.add('is-loaded');
    }
  }

  /**
   * Inspects an img element and determines if it points to an encrypted vault attachment
   */
  public async patchImageElement(img: HTMLImageElement): Promise<void> {
    if (this.keyManager.isLocked) return;

    const currentSrc = img.getAttribute('src') || '';
    if (currentSrc.startsWith('blob:')) {
      return;
    }

    const matchedFile = this.resolveFileForImg(img);
    if (!matchedFile) return;

    if (!this.pathFilter.shouldEncrypt(matchedFile.path)) {
      return;
    }

    const cached = this.getCachedBlobUrl(matchedFile.path);
    if (cached) {
      this.applyBlobToImage(img, cached, matchedFile.path);
      return;
    }

    const resolvedUrl = await this.getOrResolveMediaBlob(matchedFile.path);
    if (resolvedUrl) {
      this.applyBlobToImage(img, resolvedUrl, matchedFile.path);
    }
  }

  /**
   * Resolves a DOM img element to its corresponding TFile in the vault
   */
  private resolveFileForImg(img: HTMLImageElement): TFile | null {
    const parentEmbed = img.closest('.internal-embed');
    const parentSrc = parentEmbed?.getAttribute('src') || '';
    const alt = img.getAttribute('alt') || '';
    const src = img.getAttribute('src') || '';

    // 1. Check parent embed src attribute (e.g. Pasted image 20261023205314.png)
    if (parentSrc) {
      const file = this.app.metadataCache.getFirstLinkpathDest(parentSrc, '');
      if (file instanceof TFile) return file;

      const direct = this.app.vault.getAbstractFileByPath(this.pathFilter.normalizePath(parentSrc));
      if (direct instanceof TFile) return direct;
    }

    // 2. Check alt attribute
    if (alt) {
      const file = this.app.metadataCache.getFirstLinkpathDest(alt, '');
      if (file instanceof TFile) return file;
    }

    // 3. Extract filename from app:// URL or relative src
    if (src) {
      try {
        const cleanUrl = src.split('?')[0].split('#')[0];
        const parts = cleanUrl.split('/');
        const rawFilename = parts[parts.length - 1];
        if (rawFilename) {
          const decoded = decodeURIComponent(rawFilename);
          const file = this.app.metadataCache.getFirstLinkpathDest(decoded, '');
          if (file instanceof TFile) return file;

          // Or try matching vault files by basename
          const allFiles = this.app.vault.getFiles();
          const match = allFiles.find(f => f.name === decoded);
          if (match) return match;
        }
      } catch {
        // ignore malformed URLs
      }
    }

    return null;
  }

  /**
   * Scans a DOM container and patches all encrypted image embeds
   */
  public scanAndPatch(container: HTMLElement): void {
    if (this.keyManager.isLocked) return;

    const images = container.querySelectorAll('img');
    images.forEach(img => {
      void this.patchImageElement(img);
    });
  }

  /**
   * Sets up global error capture listener and MutationObserver
   */
  private initListeners(): void {
    // 1. Global capture-phase error listener: catches broken img loads before Obsidian handles them
    this.globalErrorHandler = (event: ErrorEvent) => {
      const target = event.target;
      if (target instanceof HTMLImageElement) {
        void this.patchImageElement(target);
      }
    };
    window.addEventListener('error', this.globalErrorHandler, true);

    // 2. MutationObserver: watches for dynamically rendered images in Live Preview & views
    this.observer = new MutationObserver(mutations => {
      if (this.keyManager.isLocked) return;

      for (const mut of mutations) {
        if (mut.type === 'childList') {
          for (let i = 0; i < mut.addedNodes.length; i++) {
            const node = mut.addedNodes[i];
            if (node.nodeType === Node.ELEMENT_NODE) {
              const el = node as HTMLElement;
              if (el.tagName === 'IMG') {
                void this.patchImageElement(el as HTMLImageElement);
              } else if (el.querySelectorAll) {
                const imgs = el.querySelectorAll('img');
                imgs.forEach(img => void this.patchImageElement(img));
              }
            }
          }
        } else if (mut.type === 'attributes' && mut.attributeName === 'src') {
          const target = mut.target;
          if (target instanceof HTMLImageElement) {
            void this.patchImageElement(target);
          }
        }
      }
    });

    // Observe body for changes
    this.observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['src']
    });
  }

  /**
   * Handles vault file renames: updates cache keys accordingly
   */
  public handleRename(oldPath: string, newPath: string): void {
    const oldNorm = this.pathFilter.normalizePath(oldPath);
    const newNorm = this.pathFilter.normalizePath(newPath);

    if (this.blobUrls.has(oldNorm)) {
      const url = this.blobUrls.get(oldNorm)!;
      this.blobUrls.delete(oldNorm);
      this.blobUrls.set(newNorm, url);
      this.patchDomForPath(newNorm, url);
    }
  }

  /**
   * Revokes all active in-memory Blob URLs and wipes them from RAM.
   * Called whenever the vault is locked.
   */
  public revokeAll(): void {
    for (const url of this.blobUrls.values()) {
      try {
        URL.revokeObjectURL(url);
      } catch {
        // best effort
      }
    }
    this.blobUrls.clear();
    this.pendingResolutions.clear();

    // Reset patched images in DOM
    const images = document.querySelectorAll('img[data-mysecret-patched="true"]');
    images.forEach(img => {
      const htmlImg = img as HTMLImageElement;
      htmlImg.src = '';
      htmlImg.removeAttribute('data-mysecret-patched');
      htmlImg.removeAttribute('data-mysecret-path');
    });
  }

  /**
   * Cleanup on plugin unload
   */
  public destroy(): void {
    if (this.globalErrorHandler) {
      window.removeEventListener('error', this.globalErrorHandler, true);
      this.globalErrorHandler = null;
    }
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    this.revokeAll();
  }
}
