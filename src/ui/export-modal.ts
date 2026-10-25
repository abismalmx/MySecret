/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * ExportModal: Local Vault Export (Encrypted / Decrypted ZIP)
 */

import { App, Modal, Notice } from 'obsidian';
import MySecretPlugin from '../main';
import { BackupEngine } from '../backup/backup-engine';
import { MYSECRET_LOGO_DATA_URL } from './assets';
import { t } from '../i18n';

export class ExportModal extends Modal {
  private plugin: MySecretPlugin;
  private mode: 'encrypted' | 'decrypted' = 'encrypted';
  private includeAttachments: boolean = true;
  private includeEnvelope: boolean = true;
  private isProcessing: boolean = false;

  private progressBar!: HTMLElement;
  private progressPercentEl!: HTMLElement;
  private progressStatusEl!: HTMLElement;
  private currentFileEl!: HTMLElement;
  private exportBtn!: HTMLButtonElement;
  private cancelBtn!: HTMLButtonElement;

  constructor(app: App, plugin: MySecretPlugin) {
    super(app);
    this.plugin = plugin;
  }

  public override onOpen(): void {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    modalEl.addClass('mysecret-export-modal');

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
      text: t('exportModal.title')
    });

    contentEl.createEl('p', {
      cls: 'mysecret-migration-desc',
      text: t('exportModal.desc')
    });

    // Format selection cards
    const formatGroup = contentEl.createDiv({ cls: 'mysecret-export-format-group' });

    const encCard = formatGroup.createDiv({
      cls: `mysecret-export-card ${this.mode === 'encrypted' ? 'is-selected' : ''}`
    });
    encCard.createEl('div', { cls: 'mysecret-export-card-icon', text: '🔒' });
    encCard.createEl('div', { cls: 'mysecret-export-card-title', text: t('exportModal.modeEncrypted') });
    encCard.createEl('div', {
      cls: 'mysecret-export-card-desc',
      text: t('settings.exportArchiveDesc')
    });

    const decCard = formatGroup.createDiv({
      cls: `mysecret-export-card ${this.mode === 'decrypted' ? 'is-selected' : ''}`
    });
    decCard.createEl('div', { cls: 'mysecret-export-card-icon', text: '📄' });
    decCard.createEl('div', { cls: 'mysecret-export-card-title', text: t('exportModal.modeDecrypted') });
    decCard.createEl('div', {
      cls: 'mysecret-export-card-desc',
      text: t('exportModal.decryptedWarning')
    });

    encCard.addEventListener('click', () => {
      this.mode = 'encrypted';
      encCard.addClass('is-selected');
      decCard.removeClass('is-selected');
      envelopeSetting.style.display = 'flex';
    });

    decCard.addEventListener('click', () => {
      if (this.plugin.keyManager.isLocked) {
        new Notice(t('notices.vaultNotInitialized'));
        this.plugin.openLockScreen();
        return;
      }
      this.mode = 'decrypted';
      decCard.addClass('is-selected');
      encCard.removeClass('is-selected');
      envelopeSetting.style.display = 'none';
    });

    // Options container
    const optionsSection = contentEl.createDiv({ cls: 'mysecret-export-options' });

    // Include attachments toggle
    const attachSetting = optionsSection.createDiv({ cls: 'mysecret-checkbox-row' });
    const attachCheck = attachSetting.createEl('input', {
      type: 'checkbox',
      attr: { id: 'mysecret-export-attach' }
    });
    attachCheck.checked = this.includeAttachments;
    attachCheck.addEventListener('change', () => {
      this.includeAttachments = attachCheck.checked;
    });
    attachSetting.createEl('label', {
      attr: { for: 'mysecret-export-attach' },
      text: t('settings.encryptAttachmentsTitle')
    });

    // Include envelope toggle
    const envelopeSetting = optionsSection.createDiv({ cls: 'mysecret-checkbox-row' });
    const envelopeCheck = envelopeSetting.createEl('input', {
      type: 'checkbox',
      attr: { id: 'mysecret-export-env' }
    });
    envelopeCheck.checked = this.includeEnvelope;
    envelopeCheck.addEventListener('change', () => {
      this.includeEnvelope = envelopeCheck.checked;
    });
    envelopeSetting.createEl('label', {
      attr: { for: 'mysecret-export-env' },
      text: 'vault-envelope.json'
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

    // Action Buttons
    const actions = contentEl.createDiv({ cls: 'mysecret-actions-group' });

    this.exportBtn = actions.createEl('button', {
      cls: 'mod-cta',
      text: t('exportModal.exportBtn')
    });

    this.cancelBtn = actions.createEl('button', {
      cls: 'mysecret-stop-btn',
      text: t('common.close')
    });

    this.exportBtn.addEventListener('click', () => {
      if (!this.isProcessing) {
        this.runExport(progressContainer);
      }
    });

    this.cancelBtn.addEventListener('click', () => {
      this.close();
    });
  }

  private async runExport(progressContainer: HTMLElement): Promise<void> {
    if (this.mode === 'decrypted' && this.plugin.keyManager.isLocked) {
      new Notice(t('notices.vaultNotInitialized'));
      this.plugin.openLockScreen();
      return;
    }

    this.isProcessing = true;
    this.exportBtn.disabled = true;
    this.cancelBtn.disabled = true;
    progressContainer.show();

    try {
      this.progressStatusEl.setText(t('common.loading'));

      const result = await BackupEngine.createVaultZip(
        this.plugin,
        {
          mode: this.mode,
          includeAttachments: this.includeAttachments,
          includeEnvelope: this.includeEnvelope
        },
        (currentFile, current, total) => {
          const percent = total > 0 ? Math.round((current / total) * 100) : 0;
          this.progressBar.style.width = `${percent}%`;
          this.progressPercentEl.setText(`${percent}%`);
          this.progressStatusEl.setText(t('exportModal.exporting', { processed: current, total }));
          this.currentFileEl.setText(`📄 ${currentFile}`);
        }
      );

      this.progressBar.style.width = '100%';
      this.progressPercentEl.setText('100%');
      this.progressStatusEl.setText(
        `${t('common.success')} ${(result.stats.totalBytes / (1024 * 1024)).toFixed(2)} MB (${result.stats.totalFiles})`
      );
      this.currentFileEl.setText('');

      // Trigger automatic file download
      BackupEngine.triggerDownload(result.filename, result.zipBytes);

      new Notice(`✅ ${t('notices.exportSuccess')}: ${result.filename}`);
      this.cancelBtn.disabled = false;
      this.cancelBtn.setText(t('common.close'));
    } catch (err: any) {
      console.error('[MySecret] Export error:', err);
      this.progressStatusEl.setText(`❌ ${t('common.error')}`);
      this.currentFileEl.setText(err?.message || String(err));
      new Notice(`❌ ${t('notices.exportFailed', { error: err?.message || String(err) })}`);
      this.cancelBtn.disabled = false;
      this.exportBtn.disabled = false;
    } finally {
      this.isProcessing = false;
    }
  }

  public override onClose(): void {
    const { contentEl } = this;
    contentEl.empty();
  }
}
