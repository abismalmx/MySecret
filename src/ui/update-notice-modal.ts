/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * UpdateNoticeModal: one-time notice shown to existing users after the update
 * that fixed the language of the setup wizard.
 */

import { App, Modal } from 'obsidian';
import MySecretPlugin from '../main';
import { MYSECRET_LOGO_DATA_URL, GIDEON_FELT_AVATAR_DATA_URL } from './assets';
import { t } from '../i18n';

export class UpdateNoticeModal extends Modal {
  constructor(app: App, _plugin: MySecretPlugin) {
    super(app);
  }

  public override onOpen(): void {
    const { contentEl, modalEl } = this;
    contentEl.empty();
    modalEl.addClass('mysecret-update-notice-modal');

    const header = contentEl.createDiv({ cls: 'mysecret-migration-header' });
    const logoWrap = header.createDiv({ cls: 'mysecret-migration-logo-wrap' });
    logoWrap.createEl('img', {
      cls: 'mysecret-migration-logo',
      attr: { src: MYSECRET_LOGO_DATA_URL, alt: 'MySecret Logo', draggable: 'false' }
    });
    header.createEl('h2', { cls: 'mysecret-migration-title', text: t('updateNotice.title') });

    contentEl.createEl('p', { cls: 'mysecret-migration-desc', text: t('updateNotice.body') });
    contentEl.createEl('p', { cls: 'mysecret-migration-desc', text: t('updateNotice.noAction') });
    contentEl.createEl('p', { cls: 'mysecret-migration-desc', text: t('updateNotice.creditApology') });
    contentEl.createEl('p', { cls: 'mysecret-migration-desc', text: t('updateNotice.oneTime') });

    const actions = contentEl.createDiv({ cls: 'mysecret-actions-group' });
    const dismissBtn = actions.createEl('button', {
      cls: 'mod-cta mysecret-wizard-btn',
      text: t('updateNotice.dismissButton')
    });
    dismissBtn.addEventListener('click', () => this.close());

    const credit = contentEl.createDiv({ cls: 'mysecret-update-notice-credit' });
    const creditRow = credit.createDiv({ cls: 'mysecret-update-notice-credit-row' });
    creditRow.createEl('img', {
      cls: 'mysecret-update-notice-avatar',
      attr: { src: GIDEON_FELT_AVATAR_DATA_URL, alt: 'Gideon-Felt', draggable: 'false' }
    });
    const thanks = creditRow.createEl('p');
    thanks.appendText(t('updateNotice.creditPrefix'));
    thanks.createEl('a', {
      text: 'Gideon-Felt',
      href: 'https://github.com/Gideon-Felt',
      attr: { target: '_blank', rel: 'noopener noreferrer' }
    });
    thanks.appendText(t('updateNotice.creditSuffix'));
  }

  public override onClose(): void {
    this.contentEl.empty();
  }
}
