/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Obsidian Publish Guard
 */

import { App, Notice, TFile } from 'obsidian';
import { detectContainerFormat } from './decrypt';

/**
 * Internal plugin id of the Obsidian Publish core plugin.
 */
const PUBLISH_PLUGIN_ID = 'publish';

/**
 * Prevents Obsidian Publish from uploading the CLEARTEXT of the encrypted
 * notes.
 *
 * THE THREAT
 * -----------
 * Obsidian Publish uploads the notes to a **public website**. It reads them
 * through `vault.readBinary(file)`, which is exactly the entry point that
 * MySecret hooks to hand the PLAINTEXT to the metadata indexer. Without a
 * guard, every encrypted note would be published in cleartext, defeating the
 * whole purpose of the plugin.
 *
 * THE MITIGATION
 * --------------
 * The upload of an ENCRYPTED file is rejected with an actionable error. The
 * guard does NOT disable the Publish plugin (that would silently change the
 * user's configuration and depends on unstable internal APIs) and it does NOT
 * upload the ciphertext either (the published page would show an unreadable
 * envelope, and the hash that Publish computes over the plaintext would not
 * match the uploaded bytes, so the server would reject the upload).
 *
 * The user has an explicit escape hatch: the "Descifrar todo" action of
 * MySecret converts the notes to plaintext on disk, and Publish then works
 * normally with them.
 */
export class PublishGuard {
  private app: App;
  private publishInstance: any = null;
  private origApiUploadFile?: (file: TFile) => Promise<unknown>;
  private installed: boolean = false;
  private wrapper: ((file: TFile) => Promise<unknown>) | null = null;
  private noticeShown: boolean = false;

  constructor(app: App) {
    this.app = app;
  }

  /**
   * Detects whether Obsidian Publish is enabled and, if it is, blocks the
   * upload of the encrypted notes.
   *
   * @returns `true` when the guard was installed.
   */
  public install(): boolean {
    if (this.installed) return true;

    const internalPlugins = (this.app as any).internalPlugins;
    if (
      !internalPlugins ||
      typeof internalPlugins.getEnabledPluginById !== 'function'
    ) {
      return false;
    }

    let instance: any = null;
    try {
      instance = internalPlugins.getEnabledPluginById(PUBLISH_PLUGIN_ID);
    } catch {
      return false;
    }

    if (!instance || typeof instance.apiUploadFile !== 'function') {
      return false;
    }

    this.publishInstance = instance;
    this.origApiUploadFile = instance.apiUploadFile.bind(instance);

    // eslint-disable-next-line @typescript-eslint/no-this-alias -- Preserve the guard instance across the patched method
    const self = this;

    const wrapper = async function (file: TFile): Promise<unknown> {
      const blocked = await self.assertPublishable(file);
      if (!blocked) {
        return await self.origApiUploadFile!(file);
      }
      throw new Error(
        '[MySecret] Obsidian Publish no puede publicar "' +
        file.path +
        '" porque la nota está cifrada. Publicarla subiría el texto claro a ' +
        'un sitio web público. Usa "Descifrar todo" en MySecret antes de ' +
        'publicar, o excluye la nota de la publicación.'
      );
    };
    instance.apiUploadFile = wrapper;
    this.wrapper = wrapper;

    this.installed = true;

    console.warn(
      '[MySecret] Obsidian Publish is enabled: the upload of encrypted notes ' +
      'has been blocked to avoid publishing their cleartext.'
    );

    if (this.noticeShown) return true;
    this.noticeShown = true;

    try {
      new Notice(
        'MySecret: Obsidian Publish está activo. Se ha bloqueado la ' +
        'publicación de notas cifradas para no exponer su texto claro. ' +
        'Usa "Descifrar todo" si quieres publicarlas.',
        15000
      );
    } catch {
      // The Notice API may be unavailable in some environments.
    }

    return true;
  }

  /**
   * Re-checks the Publish plugin and (re)installs the guard when needed.
   *
   * Publish can be enabled AFTER MySecret has loaded, or disabled and enabled
   * again (which creates a NEW instance whose `apiUploadFile` is not wrapped).
   * Without this check the cleartext of the encrypted notes could be uploaded
   * to a public website in those cases.
   */
  public refresh(): void {
    let instance: any = null;
    try {
      const internalPlugins = (this.app as any).internalPlugins;
      instance = internalPlugins?.getEnabledPluginById?.(PUBLISH_PLUGIN_ID) ?? null;
    } catch {
      instance = null;
    }

    if (!instance) {
      // Publish was disabled: forget the stale instance.
      this.publishInstance = null;
      this.origApiUploadFile = undefined;
      this.wrapper = null;
      this.installed = false;
      return;
    }

    if (
      this.installed &&
      instance === this.publishInstance &&
      instance.apiUploadFile === this.wrapper
    ) {
      return;
    }

    this.installed = false;
    this.install();
  }

  /**
   * Checks whether the given file must NOT be published.
   *
   * A file is blocked when it is encrypted on disk. The detection is done on
   * the RAW bytes, exactly like the rest of the plugin, so a binary
   * attachment is never mistaken for a note (and vice versa).
   */
  private async assertPublishable(file: TFile): Promise<boolean> {
    const path = file?.path;
    if (!path) return false;

    try {
      const rawBuffer = await this.app.vault.adapter.readBinary(path);
      const rawBytes = new Uint8Array(rawBuffer);
      return detectContainerFormat(rawBytes) !== 'plain';
    } catch {
      // If the file cannot be read there is nothing to block here; the
      // upload itself will fail with its own error.
      return false;
    }
  }

  /**
   * Restores the original `apiUploadFile()` of the Publish plugin.
   */
  public uninstall(): void {
    if (!this.installed) return;

    if (this.publishInstance && this.origApiUploadFile) {
      this.publishInstance.apiUploadFile = this.origApiUploadFile;
    }

    this.publishInstance = null;
    this.origApiUploadFile = undefined;
    this.installed = false;
  }
}
