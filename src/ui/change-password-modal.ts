/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * ChangePasswordModal: Masked master-password change flow
 */

import { App, Modal, Notice } from 'obsidian';
import MySecretPlugin from '../main';
import { MIN_MASTER_PASSWORD_LENGTH } from '../constants';
import { estimatePasswordEntropy } from './setup-wizard';
import { MYSECRET_LOGO_DATA_URL } from './assets';
import { t } from '../i18n';

/**
 * Modal used to change the master password.
 */
export class ChangePasswordModal extends Modal {
  private plugin: MySecretPlugin;

  private passwordInput!: HTMLInputElement;
  private confirmInput!: HTMLInputElement;
  private errorEl!: HTMLElement;
  private submitBtn!: HTMLButtonElement;
  private isBusy: boolean = false;

  constructor(app: App, plugin: MySecretPlugin) {
    super(app);
    this.plugin = plugin;
  }

  public override onOpen(): void {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    modalEl.addClass('mysecret-change-password-modal');

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
      text: t('changePassword.title')
    });

    contentEl.createEl('p', {
      cls: 'mysecret-migration-desc',
      text: t('changePassword.subtitle')
    });

    this.errorEl = contentEl.createDiv({ cls: 'mysecret-error-banner' });
    this.errorEl.hide();

    const form = contentEl.createDiv({ cls: 'mysecret-wizard-form' });

    const p1Group = form.createDiv({ cls: 'mysecret-input-group' });
    p1Group.createEl('label', {
      cls: 'mysecret-input-label',
      text: t('changePassword.newPasswordLabel')
    });
    this.passwordInput = p1Group.createEl('input', {
      type: 'password',
      cls: 'mysecret-password-input',
      placeholder: `${t('notices.passwordTooShort')}`,
      attr: {
        spellcheck: 'false',
        autocomplete: 'new-password',
        'aria-label': t('changePassword.newPasswordLabel'),
        'data-mysecret-testid': 'change-password-input'
      }
    });

    const p2Group = form.createDiv({ cls: 'mysecret-input-group' });
    p2Group.createEl('label', {
      cls: 'mysecret-input-label',
      text: t('changePassword.confirmNewPasswordLabel')
    });
    this.confirmInput = p2Group.createEl('input', {
      type: 'password',
      cls: 'mysecret-password-input',
      placeholder: t('changePassword.confirmNewPasswordLabel'),
      attr: {
        spellcheck: 'false',
        autocomplete: 'new-password',
        'aria-label': t('changePassword.confirmNewPasswordLabel'),
        'data-mysecret-testid': 'change-password-confirm'
      }
    });

    const actions = contentEl.createDiv({ cls: 'mysecret-actions-group' });

    this.submitBtn = actions.createEl('button', {
      cls: 'mod-cta mysecret-wizard-btn',
      text: t('changePassword.submitBtn'),
      attr: { 'data-mysecret-testid': 'change-password-submit' }
    });

    const cancelBtn = actions.createEl('button', {
      cls: 'mysecret-wizard-btn',
      text: t('common.cancel')
    });

    this.submitBtn.addEventListener('click', () => {
      if (!this.isBusy) {
        this.handleSubmit();
      }
    });
    cancelBtn.addEventListener('click', () => this.close());

    // Enter submits the form.
    this.confirmInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        if (!this.isBusy) this.handleSubmit();
      }
    });

    window.setTimeout(() => this.passwordInput.focus(), 60);
  }

  private showError(message: string): void {
    this.errorEl.setText(message);
    this.errorEl.show();
  }

  private clearError(): void {
    this.errorEl.hide();
    this.errorEl.setText('');
  }

  /**
   * Wipes the sensitive inputs from the DOM.
   */
  private wipeInputs(): void {
    if (this.passwordInput) this.passwordInput.value = '';
    if (this.confirmInput) this.confirmInput.value = '';
  }

  private async handleSubmit(): Promise<void> {
    const newPass = this.passwordInput.value;
    const confirmPass = this.confirmInput.value;

    if (!newPass || newPass.length < MIN_MASTER_PASSWORD_LENGTH) {
      this.showError(t('notices.passwordTooShort'));
      this.wipeInputs();
      this.passwordInput.focus();
      return;
    }
    if (newPass !== confirmPass) {
      this.showError(t('notices.passwordsDoNotMatch'));
      this.wipeInputs();
      this.passwordInput.focus();
      return;
    }
    if (estimatePasswordEntropy(newPass).tier === 'weak') {
      this.showError(t('setupWizard.passwordHint'));
      this.wipeInputs();
      this.passwordInput.focus();
      return;
    }

    this.clearError();
    this.isBusy = true;
    this.submitBtn.disabled = true;
    this.submitBtn.setText(t('changePassword.updating'));

    try {
      const updatedEnvelope = await this.plugin.keyManager.changeMasterPassword(newPass);
      await this.plugin.saveVaultEnvelope(updatedEnvelope);
      new Notice(`✅ ${t('changePassword.success')}`);
      this.close();
    } catch (err: any) {
      this.showError(`❌ ${t('common.error')}: ${err?.message || String(err)}`);
    } finally {
      this.isBusy = false;
      this.submitBtn.disabled = false;
      this.submitBtn.setText(t('changePassword.submitBtn'));
      this.wipeInputs();
    }
  }

  public override onClose(): void {
    this.wipeInputs();
    const { contentEl } = this;
    contentEl.empty();
  }
}
