/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * MigrationModal: Interactive Batch Encryption & Clean Full Decryption (Rollback)
 */

import { App, Modal, Notice, setCssStyles } from 'obsidian';
import MySecretPlugin from '../main';
import { isArmoredEncrypted, isBinaryEncrypted } from '../crypto/envelope';
import { MigrationProgress } from '../types';
import { MYSECRET_LOGO_DATA_URL } from './assets';
import { t } from '../i18n';

/**
 * How often the elapsed-time based ETA is refreshed (ms)
 */
const ETA_REFRESH_MS = 500;

export class MigrationModal extends Modal {
  private plugin: MySecretPlugin;
  private mode: 'encrypt' | 'decrypt';
  private isRunning: boolean = false;
  private isCancelled: boolean = false;

  /** Shared progress state (mirrors the MigrationProgress contract) */
  private progress: MigrationProgress = {
    totalFiles: 0,
    processedFiles: 0,
    currentFile: '',
    isComplete: false,
    isCancelled: false,
    errors: []
  };

  private progressContainer!: HTMLElement;
  private progressBar!: HTMLElement;
  private progressPercentEl!: HTMLElement;
  private statusText!: HTMLElement;
  private counterText!: HTMLElement;
  private etaText!: HTMLElement;
  private currentFileEl!: HTMLElement;
  private errorListEl!: HTMLElement;
  private errorCountEl!: HTMLElement;
  private preflightCountEl!: HTMLElement;

  private startBtn!: HTMLButtonElement;
  private cancelBtn!: HTMLButtonElement;

  /** Timestamp of the first processed file, used to estimate the remaining time */
  private startedAt: number = 0;
  private etaTimer: number | null = null;

  constructor(app: App, plugin: MySecretPlugin, mode: 'encrypt' | 'decrypt') {
    super(app);
    this.plugin = plugin;
    this.mode = mode;
  }

  public override onOpen(): void {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    modalEl.addClass('mysecret-migration-modal');

    const isEnc = this.mode === 'encrypt';

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
      text: isEnc ? t('migration.encryptTitle') : t('migration.decryptTitle')
    });

    contentEl.createEl('p', {
      cls: 'mysecret-migration-desc',
      text: isEnc ? t('migration.encryptDesc') : t('migration.decryptDesc')
    });

    // Warning alert box
    const warningBox = contentEl.createDiv({ cls: 'mysecret-migration-warning' });
    warningBox.createEl('strong', { text: `${t('common.warning')}: ` });
    warningBox.createSpan({
      text: t('common.warning')
    });

    // --- Preflight summary ---
    const preflight = contentEl.createDiv({ cls: 'mysecret-preflight' });
    preflight.createSpan({ cls: 'mysecret-preflight-label', text: 'Archivos candidatos: ' });
    this.preflightCountEl = preflight.createSpan({ cls: 'mysecret-preflight-value', text: 'Calculando…' });

    // --- Progress section ---
    this.progressContainer = contentEl.createDiv({ cls: 'mysecret-progress-section' });
    this.progressContainer.hide();

    const barWrapper = this.progressContainer.createDiv({ cls: 'mysecret-progress-bar-wrapper' });
    this.progressBar = barWrapper.createDiv({ cls: 'mysecret-progress-bar' });
    this.progressBar.createDiv({ cls: 'mysecret-progress-shimmer' });

    const progressHead = this.progressContainer.createDiv({ cls: 'mysecret-progress-head' });
    this.counterText = progressHead.createSpan({
      cls: 'mysecret-progress-counter',
      text: '0 de 0 procesados'
    });
    this.progressPercentEl = progressHead.createSpan({
      cls: 'mysecret-progress-percent',
      text: '0%'
    });

    this.statusText = this.progressContainer.createDiv({
      cls: 'mysecret-progress-status',
      text: 'Preparando lista de archivos…'
    });

    this.currentFileEl = this.progressContainer.createDiv({
      cls: 'mysecret-progress-file',
      text: ''
    });

    this.etaText = this.progressContainer.createDiv({
      cls: 'mysecret-progress-eta',
      text: ''
    });

    // --- Error list ---
    this.errorListEl = contentEl.createDiv({ cls: 'mysecret-migration-errors' });
    this.errorListEl.hide();
    this.errorCountEl = this.errorListEl.createSpan({
      cls: 'mysecret-migration-errors-count',
      text: '0 errores'
    });
    const errorsBody = this.errorListEl.createDiv({ cls: 'mysecret-migration-errors-body' });
    errorsBody.createEl('ul', { cls: 'mysecret-migration-errors-list' });

    // --- Buttons ---
    const actions = contentEl.createDiv({ cls: 'mysecret-actions-group' });

    this.startBtn = actions.createEl('button', {
      cls: isEnc ? 'mod-cta' : 'mod-warning',
      text: t('migration.startBtn'),
      attr: { 'data-mysecret-testid': 'migration-start-button' }
    });

    this.cancelBtn = actions.createEl('button', {
      cls: 'mysecret-stop-btn',
      text: t('common.cancel'),
      attr: { 'data-mysecret-testid': 'migration-cancel-button' }
    });

    this.startBtn.addEventListener('click', () => {
      this.runMigration();
    });

    this.cancelBtn.addEventListener('click', () => {
      if (this.isRunning) {
        this.stopMigration();
      } else {
        this.close();
      }
    });

    this.computePreflight();
  }

  /**
   * Counts the candidate files without touching them
   */
  private computePreflight(): void {
    try {
      const allFiles = this.app.vault.getFiles();
      const targets = allFiles.filter(f => this.plugin.pathFilter.shouldEncrypt(f.path));
      this.preflightCountEl.setText(String(targets.length));
    } catch (err: any) {
      this.preflightCountEl.setText('No disponible');
      console.error('[MySecret] Preflight failed:', err);
    }
  }

  /**
   * Runs the bulk migration over every candidate file
   */
  private async runMigration(): Promise<void> {
    this.isRunning = true;
    this.isCancelled = false;
    this.startedAt = Date.now();

    this.startBtn.disabled = true;
    this.cancelBtn.setText(`⛔ ${t('migration.stopBtn')}`);
    this.cancelBtn.addClass('mysecret-stop-btn-active');
    this.progressContainer.show();

    const rawAdapter = this.plugin.interceptor.getRawAdapter();
    const allFiles = this.app.vault.getFiles();
    const targets = allFiles.filter(f => this.plugin.pathFilter.shouldEncrypt(f.path));

    this.progress = {
      totalFiles: targets.length,
      processedFiles: 0,
      currentFile: '',
      isComplete: false,
      isCancelled: false,
      errors: []
    };

    if (targets.length === 0) {
      this.updateProgress(0, 0, '');
      this.finishMigration(0);
      return;
    }

    let modified = 0;
    this.startEtaTicker();

    for (const file of targets) {
      if (this.isCancelled) break;

      const path = file.path;
      const isText = this.plugin.pathFilter.isTextNote(path);
      this.updateProgress(this.progress.processedFiles, this.progress.totalFiles, path);

      try {
        if (this.mode === 'encrypt') {
          // Encrypt: only write files that are not encrypted on disk yet
          if (isText) {
            const diskContent = await rawAdapter.read(path);
            if (!isArmoredEncrypted(diskContent)) {
              await this.app.vault.adapter.write(path, diskContent);
              modified++;
            }
          } else {
            const diskBuffer = await rawAdapter.readBinary(path);
            const diskBytes = new Uint8Array(diskBuffer);
            if (!isBinaryEncrypted(diskBytes)) {
              await this.app.vault.adapter.writeBinary(path, diskBuffer);
              modified++;
            }
          }
        } else {
          // Decrypt: read the decrypted content and write it raw to disk
          if (isText) {
            const diskContent = await rawAdapter.read(path);
            if (isArmoredEncrypted(diskContent)) {
              const plainText = await this.app.vault.adapter.read(path);
              await rawAdapter.write(path, plainText);
              modified++;
            }
          } else {
            const diskBuffer = await rawAdapter.readBinary(path);
            const diskBytes = new Uint8Array(diskBuffer);
            if (isBinaryEncrypted(diskBytes)) {
              const plainBuffer = await this.app.vault.adapter.readBinary(path);
              await rawAdapter.writeBinary(path, plainBuffer);
              modified++;
            }
          }
        }
      } catch (err: any) {
        console.error(`[MySecret] Migration error on ${path}:`, err);
        this.progress.errors.push({ path, error: err?.message || String(err) });
      }

      this.progress.processedFiles++;
    }

    this.updateProgress(this.progress.processedFiles, this.progress.totalFiles, 'Completado');
    this.finishMigration(modified);
  }

  /**
   * Requests an emergency stop of the running migration
   */
  private stopMigration(): void {
    if (!this.isRunning) return;

    this.isCancelled = true;
    this.progress.isCancelled = true;
    this.cancelBtn.disabled = true;
    this.cancelBtn.setText('Deteniendo…');
    this.statusText.setText('Deteniendo el proceso de forma segura…');
  }

  /**
   * Starts the periodic ETA refresher
   */
  private startEtaTicker(): void {
    this.stopEtaTicker();
    this.etaTimer = window.setInterval(() => this.updateEta(), ETA_REFRESH_MS);
  }

  /**
   * Stops the periodic ETA refresher
   */
  private stopEtaTicker(): void {
    if (this.etaTimer !== null) {
      window.clearInterval(this.etaTimer);
      this.etaTimer = null;
    }
  }

  /**
   * Estimates the remaining time from the average throughput so far
   */
  private updateEta(): void {
    const processed = this.progress.processedFiles;
    const total = this.progress.totalFiles;

    if (processed <= 0 || total <= 0) {
      this.etaText.setText('Tiempo restante: estimating…');
      return;
    }

    const elapsed = Date.now() - this.startedAt;
    const perFile = elapsed / processed;
    const remaining = total - processed;
    const etaMs = perFile * remaining;

    this.etaText.setText(`Tiempo restante: ~${this.formatDuration(etaMs)}`);
  }

  /**
   * Formats a duration in milliseconds as a human readable string
   */
  private formatDuration(ms: number): string {
    if (!isFinite(ms) || ms < 0) return '—';
    if (ms < 1000) return '< 1 s';

    const totalSeconds = Math.round(ms / 1000);
    if (totalSeconds < 60) return `${totalSeconds} s`;

    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    if (minutes < 60) return `${minutes} min ${seconds} s`;

    const hours = Math.floor(minutes / 60);
    return `${hours} h ${minutes % 60} min`;
  }

  /**
   * Refreshes the progress bar, counter and current file
   */
  private updateProgress(current: number, total: number, currentPath: string): void {
    const percent = total === 0 ? 100 : Math.round((current / total) * 100);

    setCssStyles(this.progressBar, { width: `${percent}%` });
    this.progressPercentEl.setText(`${percent}%`);
    this.counterText.setText(`${current} de ${total} procesados`);
    this.currentFileEl.setText(currentPath ? `📄 ${currentPath}` : '');

    if (!this.isCancelled) {
      this.statusText.setText(
        this.mode === 'encrypt'
          ? 'Cifrando archivos de forma segura…'
          : 'Descifrando archivos de forma segura…'
      );
    }
  }

  /**
   * Renders the collected errors
   */
  private renderErrors(): void {
    const errors = this.progress.errors;

    if (errors.length === 0) {
      this.errorListEl.hide();
      return;
    }

    this.errorListEl.show();
    this.errorCountEl.setText(`${errors.length} ${errors.length === 1 ? 'error' : 'errores'}`);

    const list = this.errorListEl.querySelector('.mysecret-migration-errors-list');
    if (!list) return;

    list.empty();
    errors.slice(0, 50).forEach(item => {
      const li = list.createEl('li');
      li.createSpan({ cls: 'mysecret-error-path', text: item.path });
      li.createSpan({ cls: 'mysecret-error-message', text: item.error });
    });

    if (errors.length > 50) {
      list.createEl('li', {
        cls: 'mysecret-error-more',
        text: `… y ${errors.length - 50} errores más (revisa la consola de desarrollador).`
      });
    }
  }

  /**
   * Finalizes the migration and restores the UI state
   */
  private finishMigration(modified: number): void {
    this.isRunning = false;
    this.progress.isComplete = true;
    this.progress.isCancelled = this.isCancelled;

    this.stopEtaTicker();

    this.cancelBtn.disabled = false;
    this.cancelBtn.removeClass('mysecret-stop-btn-active');
    this.cancelBtn.setText(t('common.close'));
    this.startBtn.disabled = true;

    this.renderErrors();

    if (this.isCancelled) {
      this.statusText.setText(t('common.cancel'));
      this.etaText.setText('');
      new Notice(`⚠️ ${t('common.cancel')}`);
    } else {
      setCssStyles(this.progressBar, { width: '100%' });
      this.progressPercentEl.setText('100%');
      this.counterText.setText(`${this.progress.totalFiles} / ${this.progress.totalFiles}`);
      this.currentFileEl.setText('');
      this.etaText.setText('');
      this.statusText.setText(`¡${t('migration.complete')}! (${modified})`);

      if (this.progress.errors.length > 0) {
        this.statusText.setText(
          `${t('migration.complete')} (${this.progress.errors.length} errors, ${modified} files).`
        );
        new Notice(`⚠️ ${t('common.error')}`);
      } else {
        new Notice(`✅ ${t('migration.complete')}`);
      }
    }
  }

  public override onClose(): void {
    // Request a stop and clear the ETA ticker to avoid leaks
    this.isCancelled = true;
    this.progress.isCancelled = true;
    this.stopEtaTicker();

    const { contentEl } = this;
    contentEl.empty();
  }
}
