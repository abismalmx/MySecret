/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * RestoreModal: Restore Vault from Backup ZIP Archive
 */

import { App, Modal, Notice } from 'obsidian';
import { unzipSync, strFromU8 } from 'fflate';
import MySecretPlugin from '../main';
import { BackupEngine } from '../backup/backup-engine';
import { BackupManifest } from '../types';
import { MYSECRET_LOGO_DATA_URL } from './assets';
import {
  MAX_RESTORE_ENTRIES,
  MAX_RESTORE_TOTAL_BYTES,
  MAX_RESTORE_ARCHIVE_BYTES
} from '../constants';

function setCssStyles(el: HTMLElement, styles: Partial<CSSStyleDeclaration>): void {
  Object.assign(el.style, styles);
}
import { t } from '../i18n';

export class RestoreModal extends Modal {
  private plugin: MySecretPlugin;
  private selectedZipBytes: Uint8Array | null = null;
  private selectedFilename: string = '';
  private parsedManifest: BackupManifest | null = null;
  private isProcessing: boolean = false;

  private dropZone!: HTMLElement;
  private infoBox!: HTMLElement;
  private progressBar!: HTMLElement;
  private progressPercentEl!: HTMLElement;
  private progressStatusEl!: HTMLElement;
  private currentFileEl!: HTMLElement;
  private restoreBtn!: HTMLButtonElement;
  private cancelBtn!: HTMLButtonElement;

  constructor(app: App, plugin: MySecretPlugin) {
    super(app);
    this.plugin = plugin;
  }

  public override onOpen(): void {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    modalEl.addClass('mysecret-restore-modal');

    // Header & Logo
    const header = contentEl.createDiv({ cls: 'mysecret-migration-header' });
    const logoWrap = header.createDiv({ cls: 'mysecret-migration-logo-wrap' });
    logoWrap.createEl('img', {
      cls: 'mysecret-migration-logo',
      attr: {
        src: MYSECRET_LOGO_DATA_URL,
        alt: 'MySecret Logo',
        draggable: 'false'
      }
    });

    header.createEl('h2', {
      cls: 'mysecret-migration-title',
      text: t('restoreModal.title')
    });

    contentEl.createEl('p', {
      cls: 'mysecret-migration-desc',
      text: t('restoreModal.desc')
    });

    // Warning
    const warning = contentEl.createDiv({ cls: 'mysecret-migration-warning' });
    warning.createEl('strong', { text: `${t('common.warning')}: ` });
    warning.createSpan({
      text: t('restoreModal.warningOverwrite')
    });

    // Dropzone / File Picker
    this.dropZone = contentEl.createDiv({ cls: 'mysecret-restore-dropzone' });
    this.dropZone.createEl('div', { cls: 'mysecret-restore-dropzone-icon', text: '📥' });
    this.dropZone.createEl('div', {
      cls: 'mysecret-restore-dropzone-text',
      text: t('restoreModal.selectFileBtn')
    });

    const fileInput = this.dropZone.createEl('input', {
      type: 'file',
      attr: { accept: '.zip', style: 'display: none;' }
    });

    this.dropZone.addEventListener('click', () => fileInput.click());

    this.dropZone.addEventListener('dragover', e => {
      e.preventDefault();
      this.dropZone.addClass('is-dragover');
    });

    this.dropZone.addEventListener('dragleave', () => {
      this.dropZone.removeClass('is-dragover');
    });

    this.dropZone.addEventListener('drop', e => {
      e.preventDefault();
      this.dropZone.removeClass('is-dragover');
      if (e.dataTransfer && e.dataTransfer.files.length > 0) {
        this.loadFile(e.dataTransfer.files[0]);
      }
    });

    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files.length > 0) {
        this.loadFile(fileInput.files[0]);
      }
    });

    // Backup inspect summary box
    this.infoBox = contentEl.createDiv({ cls: 'mysecret-restore-info' });
    this.infoBox.hide();

    // Progress Section
    const progressContainer = contentEl.createDiv({ cls: 'mysecret-progress-section' });
    progressContainer.hide();

    const barWrapper = progressContainer.createDiv({ cls: 'mysecret-progress-bar-wrapper' });
    this.progressBar = barWrapper.createDiv({ cls: 'mysecret-progress-bar' });
    this.progressBar.createDiv({ cls: 'mysecret-progress-shimmer' });

    const progressHead = progressContainer.createDiv({ cls: 'mysecret-progress-head' });
    this.progressStatusEl = progressHead.createSpan({
      cls: 'mysecret-progress-counter',
      text: t('common.loading')
    });
    this.progressPercentEl = progressHead.createSpan({
      cls: 'mysecret-progress-percent',
      text: '0%'
    });

    this.currentFileEl = progressContainer.createDiv({
      cls: 'mysecret-progress-file',
      text: ''
    });

    // Actions
    const actions = contentEl.createDiv({ cls: 'mysecret-actions-group' });

    this.restoreBtn = actions.createEl('button', {
      cls: 'mod-cta',
      text: t('restoreModal.restoreBtn')
    });
    this.restoreBtn.disabled = true;

    this.cancelBtn = actions.createEl('button', {
      cls: 'mysecret-stop-btn',
      text: t('common.cancel')
    });

    this.restoreBtn.addEventListener('click', () => {
      if (!this.isProcessing && this.selectedZipBytes) {
        this.runRestore(progressContainer);
      }
    });

    this.cancelBtn.addEventListener('click', () => {
      this.close();
    });
  }

  private async loadFile(file: File): Promise<void> {
    try {
      this.selectedFilename = file.name;

      if (file.size > MAX_RESTORE_ARCHIVE_BYTES) {
        new Notice(t('common.error'));
        return;
      }

      const arrayBuffer = await file.arrayBuffer();
      this.selectedZipBytes = new Uint8Array(arrayBuffer);

      let declaredTotal = 0;
      let entryCount = 0;
      const unzipped = unzipSync(this.selectedZipBytes, {
        filter: (entry) => {
          entryCount++;
          declaredTotal += Number(entry.originalSize ?? 0);
          return entryCount <= MAX_RESTORE_ENTRIES &&
            declaredTotal <= MAX_RESTORE_TOTAL_BYTES;
        }
      });

      if (entryCount > MAX_RESTORE_ENTRIES || declaredTotal > MAX_RESTORE_TOTAL_BYTES) {
        new Notice(t('common.error'));
        return;
      }

      let manifest: BackupManifest | null = null;

      if (unzipped['mysecret-manifest.json']) {
        try {
          const manifestStr = strFromU8(unzipped['mysecret-manifest.json']);
          manifest = JSON.parse(manifestStr);
          this.parsedManifest = manifest;
        } catch {
          // ignore
        }
      }

      this.renderBackupInfo(Object.keys(unzipped).length, manifest);
      this.restoreBtn.disabled = false;
    } catch (err: any) {
      new Notice(`${t('common.error')}: ${err?.message || String(err)}`);
    }
  }

  private renderBackupInfo(totalEntries: number, manifest: BackupManifest | null): void {
    this.infoBox.empty();
    this.infoBox.show();

    this.infoBox.createEl('h4', { text: t('restoreModal.selectedFileLabel', { name: this.selectedFilename }) });
    const ul = this.infoBox.createEl('ul');

    if (manifest) {
      const modeText = manifest.mode === 'encrypted' ? `🔒 ${t('exportModal.modeEncrypted')}` : `📄 ${t('exportModal.modeDecrypted')}`;
      ul.createEl('li', { text: `${t('exportModal.modeLabel')}: ${modeText}` });
      ul.createEl('li', { text: `Vault: ${manifest.vaultName}` });
      ul.createEl('li', { text: `Date: ${new Date(manifest.createdAt).toLocaleString()}` });
      ul.createEl('li', { text: `Files: ${manifest.totalFiles}` });
    } else {
      ul.createEl('li', { text: `Total entries: ${totalEntries}` });
    }
  }

  private async runRestore(progressContainer: HTMLElement): Promise<void> {
    if (!this.selectedZipBytes) return;

    this.isProcessing = true;
    this.restoreBtn.disabled = true;
    this.cancelBtn.disabled = true;
    setCssStyles(this.dropZone, { pointerEvents: 'none' });
    progressContainer.show();

    try {
      this.progressStatusEl.setText(t('common.loading'));

      const result = await BackupEngine.restoreVaultZip(
        this.plugin,
        this.selectedZipBytes,
        (currentFile, current, total) => {
          const percent = total > 0 ? Math.round((current / total) * 100) : 0;
          setCssStyles(this.progressBar, { width: `${percent}%` });
          this.progressPercentEl.setText(`${percent}%`);
          this.progressStatusEl.setText(t('restoreModal.restoring', { processed: current, total }));
          this.currentFileEl.setText(`📄 ${currentFile}`);
        }
      );

      setCssStyles(this.progressBar, { width: '100%' });
      this.progressPercentEl.setText('100%');
      this.progressStatusEl.setText(t('notices.restoreSuccess', { count: result.restoredFiles }));
      this.currentFileEl.setText('');

      new Notice(`✅ ${t('notices.restoreSuccess', { count: result.restoredFiles })}`);

      this.cancelBtn.disabled = false;
      this.cancelBtn.setText(t('common.close'));
    } catch (err: any) {
      console.error('[MySecret] Restore error:', err);
      this.progressStatusEl.setText(`❌ ${t('common.error')}`);
      this.currentFileEl.setText(err?.message || String(err));
      new Notice(`❌ ${t('notices.restoreFailed', { error: err?.message || String(err) })}`);
      this.cancelBtn.disabled = false;
    } finally {
      this.isProcessing = false;
    }
  }

  public override onClose(): void {
    const { contentEl } = this;
    contentEl.empty();
  }
}
