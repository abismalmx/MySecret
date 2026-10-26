/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * RecoveryPhraseModal: Displays the BIP-39 recovery phrase
 */

import { App, Modal, Notice } from 'obsidian';
import { MYSECRET_LOGO_DATA_URL } from './assets';
import { t } from '../i18n';

/**
 * Displays the 24-word BIP-39 recovery phrase of the current vault.
 */
export class RecoveryPhraseModal extends Modal {
  private mnemonic: string;
  private isConcealed: boolean = true;
  private clearTimer: number | null = null;

  constructor(app: App, mnemonic: string) {
    super(app);
    this.mnemonic = mnemonic;
  }

  public override onOpen(): void {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    modalEl.addClass('mysecret-recovery-modal');

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
      text: t('recoveryPhraseModal.title')
    });

    contentEl.createEl('p', {
      cls: 'mysecret-migration-desc',
      text: t('recoveryPhraseModal.desc')
    });

    const warning = contentEl.createDiv({ cls: 'mysecret-migration-warning' });
    warning.createSpan({ text: '⚠️ ' });
    warning.createSpan({
      text: t('recoveryPhraseModal.securityNotice')
    });

    const grid = contentEl.createDiv({ cls: 'mysecret-mnemonic-grid' });
    const words = this.mnemonic.split(' ').filter((w: string) => w.length > 0);
    words.forEach((word: string, idx: number) => {
      const card = grid.createDiv({ cls: 'mysecret-mnemonic-card' });
      card.createSpan({ cls: 'mysecret-mnemonic-num', text: `${idx + 1}.` });
      card.createSpan({ cls: 'mysecret-mnemonic-word', text: word });
    });
    grid.addClass('is-concealed');

    const toolbar = contentEl.createDiv({ cls: 'mysecret-mnemonic-toolbar' });

    const copyBtn = toolbar.createEl('button', {
      cls: 'mysecret-copy-btn',
      text: `📋 ${t('recoveryPhraseModal.copyMnemonic')}`
    });
    const concealBtn = toolbar.createEl('button', {
      cls: 'mysecret-copy-btn',
      text: `🙈 ${t('lockScreen.showPassword')}`
    });

    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(this.mnemonic);
        copyBtn.setText(`✅ ${t('common.copied')}`);
        new Notice(t('common.copied'));

        if (this.clearTimer !== null) window.clearTimeout(this.clearTimer);
        this.clearTimer = window.setTimeout(async () => {
          this.clearTimer = null;
          await this.wipeClipboard();
          copyBtn.setText(`📋 ${t('recoveryPhraseModal.copyMnemonic')}`);
        }, 30000);
      } catch {
        new Notice(t('common.error'));
      }
    });

    concealBtn.addEventListener('click', () => {
      this.isConcealed = !this.isConcealed;
      grid.toggleClass('is-concealed', this.isConcealed);
      concealBtn.setText(this.isConcealed ? `🙈 ${t('lockScreen.showPassword')}` : `🙉 ${t('lockScreen.hidePassword')}`);
    });

    const actions = contentEl.createDiv({ cls: 'mysecret-actions-group' });
    const closeBtn = actions.createEl('button', {
      cls: 'mod-cta mysecret-wizard-btn',
      text: t('common.close')
    });
    closeBtn.addEventListener('click', () => this.close());
  }

  /**
   * Removes the phrase from the clipboard. When the clipboard cannot be read
   * (permission, focus) it is cleared blindly: leaving 24 words behind is the
   * worse outcome.
   */
  private async wipeClipboard(): Promise<void> {
    try {
      const current = await navigator.clipboard.readText();
      if (current === this.mnemonic) {
        await navigator.clipboard.writeText('');
      }
    } catch {
      try {
        await navigator.clipboard.writeText('');
      } catch {
        // nothing else can be done
      }
    }
  }

  public override onClose(): void {
    if (this.clearTimer !== null) {
      // Closing must not cancel the promise made to the user: the copied
      // phrase is still cleared.
      window.clearTimeout(this.clearTimer);
      this.clearTimer = null;
      void this.wipeClipboard();
    }
    const { contentEl } = this;
    contentEl.empty();
  }
}
