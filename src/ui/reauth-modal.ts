/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * ReauthModal: masked master-password prompt for sensitive actions
 *
 * Being unlocked is not proof that the person at the keyboard knows the
 * master password (the vault may have been opened through a biometric prompt
 * or the session may be unattended), so actions such as revealing the
 * recovery phrase, enrolling biometrics or exporting plaintext ask for it
 * again.
 */

import { App, Modal } from 'obsidian';
import MySecretPlugin from '../main';
import { t } from '../i18n';

export class ReauthModal extends Modal {
  private plugin: MySecretPlugin;
  private resolveFn: (ok: boolean) => void;
  private settled = false;
  private inputEl!: HTMLInputElement;
  private errorEl!: HTMLElement;
  private confirmBtn!: HTMLButtonElement;
  private busy = false;

  constructor(app: App, plugin: MySecretPlugin, resolve: (ok: boolean) => void) {
    super(app);
    this.plugin = plugin;
    this.resolveFn = resolve;
  }

  public override onOpen(): void {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    modalEl.addClass('mysecret-change-password-modal');

    contentEl.createEl('h2', { cls: 'mysecret-migration-title', text: t('reauth.title') });
    contentEl.createEl('p', { cls: 'mysecret-migration-desc', text: t('reauth.desc') });

    this.errorEl = contentEl.createDiv({ cls: 'mysecret-error-banner' });
    this.errorEl.hide();

    const group = contentEl.createDiv({ cls: 'mysecret-input-group' });
    this.inputEl = group.createEl('input', {
      type: 'password',
      cls: 'mysecret-password-input',
      attr: {
        spellcheck: 'false',
        autocomplete: 'current-password',
        'aria-label': t('reauth.title'),
        'data-mysecret-testid': 'reauth-password-input'
      }
    });

    const actions = contentEl.createDiv({ cls: 'mysecret-actions-group' });
    this.confirmBtn = actions.createEl('button', {
      cls: 'mod-cta mysecret-wizard-btn',
      text: t('reauth.confirmBtn'),
      attr: { 'data-mysecret-testid': 'reauth-confirm' }
    });
    const cancelBtn = actions.createEl('button', {
      cls: 'mysecret-wizard-btn',
      text: t('common.cancel')
    });

    this.confirmBtn.addEventListener('click', () => void this.submit());
    cancelBtn.addEventListener('click', () => this.close());
    this.inputEl.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        void this.submit();
      }
    });
    window.setTimeout(() => this.inputEl.focus(), 50);
  }

  private async submit(): Promise<void> {
    if (this.busy) return;
    const password = this.inputEl.value;
    if (!password) return;

    this.busy = true;
    this.confirmBtn.disabled = true;
    try {
      const ok = await this.plugin.keyManager.verifyPassword(password);
      if (ok) {
        this.settled = true;
        this.inputEl.value = '';
        this.resolveFn(true);
        this.close();
      } else {
        this.errorEl.setText(t('reauth.wrongPassword'));
        this.errorEl.show();
        this.inputEl.value = '';
        this.inputEl.focus();
      }
    } finally {
      this.busy = false;
      this.confirmBtn.disabled = false;
    }
  }

  public override onClose(): void {
    if (this.inputEl) this.inputEl.value = '';
    this.contentEl.empty();
    if (!this.settled) {
      this.settled = true;
      this.resolveFn(false);
    }
  }
}
