/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * CloudBackupModal: Immediate Encrypted Cloud Backup Upload
 */

import { App, Modal, Notice } from 'obsidian';
import MySecretPlugin from '../main';
import { BackupEngine } from '../backup/backup-engine';
import { createCloudProvider } from '../backup/cloud';
import { MYSECRET_LOGO_DATA_URL } from './assets';
import { t } from '../i18n';

function setCssStyles(el: HTMLElement, styles: Partial<CSSStyleDeclaration>): void {
  Object.assign(el.style, styles);
}

export class CloudBackupModal extends Modal {
  private plugin: MySecretPlugin;
  private isProcessing: boolean = false;

  private progressBar!: HTMLElement;
  private progressPercentEl!: HTMLElement;
  private progressStatusEl!: HTMLElement;
  private currentFileEl!: HTMLElement;
  private backupBtn!: HTMLButtonElement;
  private cancelBtn!: HTMLButtonElement;

  /** Resolved lazily so the (encrypted) credentials are only decrypted on demand. */
  private providerInstance: any = null;

  constructor(app: App, plugin: MySecretPlugin) {
    super(app);
    this.plugin = plugin;
  }

  public override onOpen(): void {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    modalEl.addClass('mysecret-cloud-modal');

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
      text: t('cloudBackup.title')
    });

    const providerConfig = this.plugin.settings.backup;
    this.providerInstance = null;

    contentEl.createEl('p', {
      cls: 'mysecret-migration-desc',
      text: t('settings.backupSectionDesc')
    });

    // Cloud Provider status box
    const providerCard = contentEl.createDiv({ cls: 'mysecret-cloud-provider-card' });

    if (providerConfig.provider === 'none') {
      providerCard.addClass('is-unconfigured');
      providerCard.createDiv({ cls: 'mysecret-cloud-provider-icon', text: '⚠️' });
      const info = providerCard.createDiv({ cls: 'mysecret-cloud-provider-info' });
      info.createEl('div', {
        cls: 'mysecret-cloud-provider-name',
        text: t('cloudBackup.providerNone')
      });
      info.createEl('div', {
        cls: 'mysecret-cloud-provider-detail',
        text: t('settings.configureCloudDesc')
      });

      const configBtn = providerCard.createEl('button', {
        cls: 'mod-cta',
        text: t('settings.configureCloudBtn')
      });
      configBtn.addEventListener('click', () => {
        this.close();
        (this.app as any).setting.open();
        (this.app as any).setting.openTabById(this.plugin.manifest.id);
      });
      return;
    }

    // Active provider display
    const iconMap: Record<string, string> = {
      'google-drive': `📁 ${t('cloudBackup.providerGoogleDrive')}`,
      onedrive: `☁️ ${t('cloudBackup.providerOneDrive')}`,
      webdav: `🌐 ${t('cloudBackup.providerWebdav')}`,
      'local-sync': `💻 ${t('cloudBackup.providerLocalSync')}`
    };

    providerCard.createDiv({
      cls: 'mysecret-cloud-provider-icon',
      text: iconMap[providerConfig.provider] || '☁️'
    });
    const info = providerCard.createDiv({ cls: 'mysecret-cloud-provider-info' });
    info.createEl('div', {
      cls: 'mysecret-cloud-provider-name',
      text: `${t('cloudBackup.providerLabel')}: ${this.getProviderName()}`
    });

    let destinationSummary = '';
    if (providerConfig.provider === 'google-drive') {
      destinationSummary = providerConfig.googleDrive.folderId ? `Folder ID: ${providerConfig.googleDrive.folderId}` : 'Google Drive Root';
    } else if (providerConfig.provider === 'onedrive') {
      destinationSummary = `Path: ${providerConfig.oneDrive.folderPath}`;
    } else if (providerConfig.provider === 'webdav') {
      destinationSummary = `Server: ${providerConfig.webdav.serverUrl} (${providerConfig.webdav.remotePath})`;
    } else if (providerConfig.provider === 'local-sync') {
      destinationSummary = `Local Path: ${providerConfig.localSync.destinationPath}`;
    }

    info.createEl('div', {
      cls: 'mysecret-cloud-provider-detail',
      text: destinationSummary
    });

    // Security note
    const securityBox = contentEl.createDiv({ cls: 'mysecret-migration-warning' });
    securityBox.createEl('strong', { text: 'Zero-Knowledge: ' });
    securityBox.createSpan({
      text: t('settings.heroDesc')
    });

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

    this.backupBtn = actions.createEl('button', {
      cls: 'mod-cta',
      text: `🚀 ${t('settings.uploadCloudBtn')}`
    });

    this.cancelBtn = actions.createEl('button', {
      cls: 'mysecret-stop-btn',
      text: t('common.close')
    });

    this.backupBtn.addEventListener('click', () => {
      if (!this.isProcessing) {
        this.runCloudBackup(progressContainer);
      }
    });

    this.cancelBtn.addEventListener('click', () => {
      this.close();
    });
  }

  private async getProvider(): Promise<any | null> {
    if (this.providerInstance) {
      return this.providerInstance;
    }
    const resolved = await this.plugin.getDecryptedBackupSettings();
    if (!resolved) {
      return null;
    }
    this.providerInstance = createCloudProvider(resolved);
    return this.providerInstance;
  }

  private getProviderName(): string {
    const p = this.plugin.settings.backup.provider;
    switch (p) {
      case 'google-drive': return t('cloudBackup.providerGoogleDrive');
      case 'onedrive': return t('cloudBackup.providerOneDrive');
      case 'webdav': return t('cloudBackup.providerWebdav');
      case 'local-sync': return t('cloudBackup.providerLocalSync');
      default: return t('cloudBackup.providerNone');
    }
  }

  private async runCloudBackup(progressContainer: HTMLElement): Promise<void> {
    if (this.plugin.keyManager.isLocked) {
      new Notice(t('notices.vaultNotInitialized'));
      this.plugin.openLockScreen();
      return;
    }

    const provider = await this.getProvider();
    if (!provider) {
      new Notice(t('cloudBackup.providerNone'));
      return;
    }

    this.isProcessing = true;
    this.backupBtn.disabled = true;
    this.cancelBtn.disabled = true;
    progressContainer.show();

    try {
      this.progressStatusEl.setText(t('notices.backupStarted'));

      // Step 1: Generate encrypted zip in memory
      const zipResult = await BackupEngine.createVaultZip(
        this.plugin,
        { mode: 'encrypted', includeAttachments: true, includeEnvelope: true },
        (currentFile, current, total) => {
          const percent = total > 0 ? Math.round((current / total) * 50) : 0;
          setCssStyles(this.progressBar, { width: `${percent}%` });
          this.progressPercentEl.setText(`${percent}%`);
          this.progressStatusEl.setText(t('exportModal.exporting', { processed: current, total }));
          this.currentFileEl.setText(`📦 ${currentFile}`);
        }
      );


      const skippedByBackup = zipResult.stats.skippedFiles ?? [];
      if (skippedByBackup.length > 0) {
        console.warn('[MySecret] Backup skipped files:', skippedByBackup);
        new Notice(
          `⚠️ ${skippedByBackup.length} archivo(s) NO se incluyeron en la copia (p. ej. ${skippedByBackup[0].path}: ${skippedByBackup[0].reason}).`,
          12000
        );
      }

      // Step 2: Upload to cloud provider
      this.progressStatusEl.setText(`${provider.name}...`);
      this.currentFileEl.setText(zipResult.filename);

      const uploadResult = await provider.uploadBackup(
        zipResult.filename,
        zipResult.zipBytes,
        (uploaded: number, total: number) => {
          const ratio = total > 0 ? uploaded / total : 0;
          const percent = 50 + Math.round(ratio * 50);
          setCssStyles(this.progressBar, { width: `${percent}%` });
          this.progressPercentEl.setText(`${percent}%`);
          this.progressStatusEl.setText(`${(uploaded / (1024 * 1024)).toFixed(1)} / ${(total / (1024 * 1024)).toFixed(1)} MB`);
        }
      );

      if (!uploadResult.success) {
        throw new Error(uploadResult.error || 'Upload failed');
      }

      setCssStyles(this.progressBar, { width: '100%' });
      this.progressPercentEl.setText('100%');
      this.progressStatusEl.setText(`✅ ${t('notices.backupSuccess')}`);
      this.currentFileEl.setText(zipResult.filename);

      // Prune old backups
      try {
        await provider.pruneBackups(this.plugin.settings.backup.retentionCount || 5);
      } catch (pruneErr) {
        console.warn('[MySecret] Prune failed:', pruneErr);
      }

      this.plugin.settings.backup.lastBackupTimestamp = Date.now();
      await this.plugin.saveSettings();

      new Notice(`✅ ${t('notices.backupSuccess')}`);
      this.cancelBtn.disabled = false;
      this.cancelBtn.setText(t('common.close'));
    } catch (err: any) {
      console.error('[MySecret] Cloud backup error:', err);
      this.progressStatusEl.setText(`❌ ${t('common.error')}`);
      this.currentFileEl.setText(err?.message || String(err));
      new Notice(`❌ ${t('notices.backupFailed', { error: err?.message || String(err) })}`);
      this.cancelBtn.disabled = false;
      this.backupBtn.disabled = false;
    } finally {
      this.isProcessing = false;
    }
  }

  public override onClose(): void {
    const { contentEl } = this;
    contentEl.empty();
  }
}
