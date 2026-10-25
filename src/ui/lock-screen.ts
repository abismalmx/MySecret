/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * LockScreenModal: Fullscreen Lock Screen with Password & Recovery Phrase Unlock
 */

import { App, Modal, Notice, setIcon } from 'obsidian';
import MySecretPlugin from '../main';
import { validateMnemonic } from '../crypto/bip39';
import { BIP39_WORD_COUNT } from '../constants';
import { MYSECRET_LOGO_DATA_URL } from './assets';
import { zeroize } from '../utils/zeroize';
import { t } from '../i18n';

/**
 * Visual states of the lock indicator badge
 */
type LockStatus = 'locked' | 'working' | 'unlocked';

export class LockScreenModal extends Modal {
  private plugin: MySecretPlugin;
  private isRecoveryMode: boolean = false;
  private isBusy: boolean = false;
  private isClosed: boolean = false;
  private allowClose: boolean = false;

  private cardEl!: HTMLElement;
  private errorMessageEl!: HTMLElement;
  private statusEl!: HTMLElement;
  private statusTextEl!: HTMLElement;

  private passwordGroup!: HTMLElement;
  private passwordInput!: HTMLInputElement;
  private visibilityBtn!: HTMLButtonElement;

  private recoveryGroup!: HTMLElement;
  private recoveryInput!: HTMLTextAreaElement;
  private recoveryCounterEl!: HTMLElement;

  private unlockBtn!: HTMLButtonElement;
  private biometricBtn?: HTMLButtonElement;
  private toggleRecoveryLink!: HTMLAnchorElement;

  constructor(app: App, plugin: MySecretPlugin) {
    super(app);
    this.plugin = plugin;
  }

  public override onOpen(): void {
    const { contentEl, modalEl, containerEl } = this;
    contentEl.empty();

    modalEl.addClass('mysecret-lock-modal');
    containerEl.addClass('mysecret-lock-container-active');

    // The vault must stay locked: never allow closing the modal with Escape
    this.scope.register([], 'Escape', () => false);

    // Remove close button
    const closeBtn = modalEl.querySelector('.modal-close-button');
    if (closeBtn) closeBtn.remove();

    // Prevent clicking on background or outside from dismissing the modal
    containerEl.addEventListener('click', (e: MouseEvent) => {
      if (this.plugin.keyManager.isLocked) {
        if (!modalEl.contains(e.target as Node)) {
          e.stopPropagation();
          e.preventDefault();
          this.focusPasswordInput();
        }
      }
    }, true);

    this.cardEl = contentEl.createDiv({ cls: 'mysecret-lock-card' });
    this.renderHeader();
    this.renderBody();
    this.renderFooter();

    window.setTimeout(() => {
      this.passwordInput.focus();
      if (this.isBiometricsEnabled() && this.plugin.settings.biometrics?.autoPrompt !== false) {
        void this.handleBiometricUnlock();
      }
    }, 100);
  }

  /**
   * Header: brand icon, title, subtitle and the animated lock indicator
   */
  private renderHeader(): void {
    const header = this.cardEl.createDiv({ cls: 'mysecret-lock-header' });

    const iconWrap = header.createDiv({ cls: 'mysecret-lock-icon-wrap' });
    iconWrap.createEl('img', {
      cls: 'mysecret-lock-logo',
      attr: {
        src: MYSECRET_LOGO_DATA_URL,
        alt: 'MySecret Logo',
        draggable: 'false'
      }
    });

    header.createEl('h2', {
      cls: 'mysecret-lock-title',
      text: t('lockScreen.title')
    });

    header.createEl('p', {
      cls: 'mysecret-lock-subtitle',
      text: t('lockScreen.lockedDesc')
    });

    // --- Lock status indicator ---
    this.statusEl = header.createDiv({ cls: 'mysecret-lock-status' });
    this.statusEl.createSpan({ cls: 'mysecret-lock-status-dot' });
    this.statusTextEl = this.statusEl.createSpan({
      cls: 'mysecret-lock-status-text',
      text: t('lockScreen.statusLocked')
    });
    this.setStatus('locked');
  }

  /**
   * Body: password form, recovery form, error banner and action buttons
   */
  private renderBody(): void {
    const body = this.cardEl.createDiv({ cls: 'mysecret-lock-body' });

    // --- Error banner (hidden until needed) ---
    this.errorMessageEl = body.createDiv({ cls: 'mysecret-error-banner' });
    this.errorMessageEl.hide();

    // --- Biometric mode (if enrolled on this device) ---
    if (this.isBiometricsEnabled()) {
      const bioSection = body.createDiv({ cls: 'mysecret-bio-lock-section' });
      this.biometricBtn = bioSection.createEl('button', {
        cls: 'mysecret-bio-unlock-btn',
        attr: {
          type: 'button',
          'aria-label': t('lockScreen.biometricButton'),
          'data-mysecret-testid': 'lock-biometric-button'
        }
      });
      const bioIcon = this.biometricBtn.createSpan({ cls: 'mysecret-bio-icon' });
      setIcon(bioIcon, 'fingerprint');
      this.biometricBtn.createSpan({ text: t('lockScreen.biometricButton') });
      this.biometricBtn.addEventListener('click', () => {
        void this.handleBiometricUnlock();
      });

      const divider = body.createDiv({ cls: 'mysecret-lock-divider' });
      divider.createSpan({ text: t('lockScreen.orEnterPassword') });
    }

    // --- Password mode ---
    this.passwordGroup = body.createDiv({ cls: 'mysecret-lock-form' });

    const pGroup = this.passwordGroup.createDiv({ cls: 'mysecret-input-group' });
    pGroup.createEl('label', {
      cls: 'mysecret-input-label',
      text: t('lockScreen.passwordLabel')
    });

    const inputWrap = pGroup.createDiv({ cls: 'mysecret-input-wrap' });
    this.passwordInput = inputWrap.createEl('input', {
      type: 'password',
      cls: 'mysecret-password-input',
      placeholder: t('lockScreen.passwordPlaceholder'),
      attr: {
        spellcheck: 'false',
        autocomplete: 'off',
        'aria-label': t('lockScreen.passwordLabel'),
        'data-mysecret-testid': 'lock-password-input'
      }
    });

    // --- Password visibility toggle (eye button) ---
    this.visibilityBtn = inputWrap.createEl('button', {
      cls: 'mysecret-visibility-toggle',
      attr: {
        type: 'button',
        'aria-label': t('lockScreen.showPassword'),
        'aria-pressed': 'false',
        title: t('lockScreen.showPassword'),
        'data-mysecret-testid': 'lock-visibility-toggle'
      }
    });
    setIcon(this.visibilityBtn, 'eye');

    this.visibilityBtn.addEventListener('click', () => this.togglePasswordVisibility());

    this.passwordInput.addEventListener('keydown', (e: KeyboardEvent) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        this.handlePasswordUnlock();
      }
    });

    this.passwordInput.addEventListener('input', () => this.clearError());

    // --- Recovery mode (hidden by default) ---
    this.recoveryGroup = body.createDiv({ cls: 'mysecret-recovery-group' });
    this.recoveryGroup.hide();

    const rGroup = this.recoveryGroup.createDiv({ cls: 'mysecret-input-group' });
    rGroup.createEl('label', {
      cls: 'mysecret-input-label',
      text: t('lockScreen.recoveryLabel', { count: BIP39_WORD_COUNT })
    });

    this.recoveryInput = rGroup.createEl('textarea', {
      cls: 'mysecret-recovery-input',
      placeholder: t('lockScreen.recoveryPlaceholder'),
      attr: {
        spellcheck: 'false',
        autocomplete: 'off',
        'aria-label': t('lockScreen.recoveryLabel', { count: BIP39_WORD_COUNT }),
        'data-mysecret-testid': 'lock-recovery-input'
      }
    });

    this.recoveryCounterEl = rGroup.createDiv({
      cls: 'mysecret-recovery-counter',
      text: t('lockScreen.recoveryCounter', { count: 0, total: BIP39_WORD_COUNT })
    });

    this.recoveryInput.addEventListener('input', () => {
      this.updateRecoveryCounter();
      this.clearError();
    });

    this.recoveryInput.addEventListener('keydown', (e: KeyboardEvent) => {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
        e.preventDefault();
        this.handleRecoveryUnlock();
      }
    });

    // --- Actions ---
    const actions = body.createDiv({ cls: 'mysecret-actions-group' });

    this.unlockBtn = actions.createEl('button', {
      cls: 'mod-cta mysecret-unlock-btn',
      text: t('lockScreen.unlockButton'),
      attr: { 'data-mysecret-testid': 'lock-unlock-button' }
    });
    this.unlockBtn.addEventListener('click', () => {
      if (this.isRecoveryMode) {
        this.handleRecoveryUnlock();
      } else {
        this.handlePasswordUnlock();
      }
    });

    if (this.plugin.hasRecoveryPhrase()) {
      this.toggleRecoveryLink = body.createEl('a', {
        cls: 'mysecret-toggle-recovery-link',
        text: t('lockScreen.resetVaultWarning'),
        attr: { 'data-mysecret-testid': 'lock-toggle-recovery' }
      });
      this.toggleRecoveryLink.addEventListener('click', e => {
        e.preventDefault();
        this.toggleRecoveryMode();
      });
    } else {
      body.createDiv({
        cls: 'mysecret-lock-no-recovery-hint',
        text: t('lockScreen.onlyPasswordHint')
      });
    }
  }

  /**
   * Footer: technical details about the active cryptographic primitives
   */
  private renderFooter(): void {
    const footer = this.cardEl.createDiv({ cls: 'mysecret-lock-footer' });
    footer.createSpan({ text: 'AES-256-GCM' });
    footer.createSpan({ cls: 'mysecret-footer-sep', text: '•' });
    footer.createSpan({ text: 'Argon2id' });
    if (this.plugin.hasRecoveryPhrase()) {
      footer.createSpan({ cls: 'mysecret-footer-sep', text: '•' });
      footer.createSpan({ text: 'BIP-39' });
    }
    if (this.isBiometricsEnabled()) {
      footer.createSpan({ cls: 'mysecret-footer-sep', text: '•' });
      footer.createSpan({ text: 'Biometría' });
    }
  }

  // ---------------------------------------------------------------------
  // State helpers
  // ---------------------------------------------------------------------

  /**
   * Updates the lock indicator badge
   */
  private setStatus(status: LockStatus, message?: string): void {
    if (!this.statusEl) return;

    this.statusEl.removeClass('is-locked');
    this.statusEl.removeClass('is-working');
    this.statusEl.removeClass('is-unlocked');

    switch (status) {
      case 'working':
        this.statusEl.addClass('is-working');
        this.statusTextEl.setText(message || t('lockScreen.statusWorking'));
        break;
      case 'unlocked':
        this.statusEl.addClass('is-unlocked');
        this.statusTextEl.setText(message || t('lockScreen.statusUnlocked'));
        break;
      default:
        this.statusEl.addClass('is-locked');
        this.statusTextEl.setText(message || t('lockScreen.statusLocked'));
        break;
    }
  }

  /**
   * Toggles password visibility (eye button)
   */
  private togglePasswordVisibility(): void {
    const isHidden = this.passwordInput.type === 'password';
    this.passwordInput.type = isHidden ? 'text' : 'password';
    this.visibilityBtn.empty();
    setIcon(this.visibilityBtn, isHidden ? 'eye-off' : 'eye');
    this.visibilityBtn.setAttr('aria-pressed', String(isHidden));
    this.visibilityBtn.setAttr('aria-label', isHidden ? t('lockScreen.hidePassword') : t('lockScreen.showPassword'));
    this.visibilityBtn.setAttr('title', isHidden ? t('lockScreen.hidePassword') : t('lockScreen.showPassword'));
    this.visibilityBtn.toggleClass('is-visible', isHidden);
    this.passwordInput.focus();
  }

  /**
   * Switches between password and recovery phrase modes
   */
  private toggleRecoveryMode(): void {
    this.isRecoveryMode = !this.isRecoveryMode;
    this.clearError();

    if (this.isRecoveryMode) {
      this.passwordGroup.hide();
      this.recoveryGroup.show();
      this.toggleRecoveryLink.setText(t('lockScreen.backToPasswordLink'));
      this.unlockBtn.setText(t('lockScreen.recoverWithPhraseButton'));
      window.setTimeout(() => this.recoveryInput.focus(), 60);
    } else {
      this.recoveryGroup.hide();
      this.passwordGroup.show();
      this.toggleRecoveryLink.setText(t('lockScreen.resetVaultWarning'));
      this.unlockBtn.setText(t('lockScreen.unlockButton'));
      window.setTimeout(() => this.passwordInput.focus(), 60);
    }
  }

  /**
   * Updates the "X / 24 palabras" counter of the recovery input
   */
  private updateRecoveryCounter(): void {
    const words = this.recoveryInput.value.trim().split(/\s+/).filter(w => w.length > 0);
    const count = words.length;

    this.recoveryCounterEl.setText(t('lockScreen.recoveryCounter', { count, total: BIP39_WORD_COUNT }));
    this.recoveryCounterEl.toggleClass('is-complete', count === BIP39_WORD_COUNT);
  }

  /**
   * Shows an error message and triggers the shake animation
   */
  private showError(message: string): void {
    if (!this.errorMessageEl) return;

    this.errorMessageEl.setText(message);
    this.errorMessageEl.show();
    this.shakeCard();
  }

  /**
   * Hides the current error message
   */
  private clearError(): void {
    if (this.errorMessageEl) {
      this.errorMessageEl.hide();
    }
  }

  /**
   * Animated shake feedback for invalid attempts
   */
  private shakeCard(): void {
    if (!this.cardEl) return;

    this.cardEl.removeClass('mysecret-shake');
    // Force reflow so the animation can be replayed consecutively
    void this.cardEl.offsetWidth;
    this.cardEl.addClass('mysecret-shake');

    window.setTimeout(() => this.cardEl.removeClass('mysecret-shake'), 520);
  }

  /**
   * Enables / disables the UI while a cryptographic operation is running
   */
  private setBusy(busy: boolean): void {
    // The modal may already be closed: its DOM has been detached
    if (this.isClosed) return;

    this.isBusy = busy;
    this.unlockBtn.disabled = busy;
    this.passwordInput.disabled = busy;
    this.recoveryInput.disabled = busy;
    this.visibilityBtn.disabled = busy;
    if (this.biometricBtn) {
      this.biometricBtn.disabled = busy;
    }

    if (busy) {
      this.setStatus('working', t('lockScreen.derivingKey'));
      this.unlockBtn.setText(t('lockScreen.decrypting'));
    } else {
      this.setStatus('locked');
      this.unlockBtn.setText(this.isRecoveryMode ? t('lockScreen.recoverWithPhraseButton') : t('lockScreen.unlockButton'));
    }
  }

  /**
   * Puts the UI in the "waiting for the browser" state.
   *
   * SECURITY / UX: the biometric ceremony happens in the EXTERNAL browser and
   * can take up to 75 seconds. The password input and the unlock button MUST
   * stay usable during that window: disabling them left the app frozen with
   * no way to fall back to the master password (the very bug the Android
   * bridge was supposed to fix).
   */
  private setBiometricWaiting(waiting: boolean): void {
    if (this.isClosed) return;

    this.isBusy = waiting;
    // The password path is deliberately NOT blocked.
    this.passwordInput.disabled = false;
    this.recoveryInput.disabled = false;
    this.visibilityBtn.disabled = false;
    this.unlockBtn.disabled = waiting;
    if (this.biometricBtn) {
      this.biometricBtn.disabled = waiting;
    }
  }

  public async handleBiometricUnlock(): Promise<void> {
    if (this.isBusy || this.isClosed) return;

    this.clearError();
    this.setBiometricWaiting(true);
    this.setStatus('working', t('lockScreen.bioWaiting'));

    const cancelBio = () => {
      this.plugin.biometricManager.cancelPendingSession();
    };
    this.statusEl.addEventListener('click', cancelBio, { once: true });

    let rawKey: Uint8Array | null = null;
    try {
      const vaultId = this.plugin.getVaultId();
      rawKey = await this.plugin.biometricManager.unlockWithBiometrics(vaultId);

      if (rawKey) {
        const success = await this.plugin.keyManager.unlockWithRawVaultKey(rawKey);
        // `unlockWithRawVaultKey` takes ownership of the buffer and wipes it,
        // so it must not be wiped twice nor used afterwards.
        rawKey = null;
        if (success) {
          this.setStatus('unlocked', t('lockScreen.accessGranted'));
          this.forceClose();
          this.plugin.unlockVaultSuccess();
          return;
        }
      }

      this.setStatus('locked');
      this.showError(t('lockScreen.bioFailed'));
      this.passwordInput.focus();
    } catch (err: any) {
      this.setStatus('locked');
      this.showError(err?.message || t('lockScreen.bioFailed'));
      this.passwordInput.focus();
    } finally {
      this.statusEl.removeEventListener('click', cancelBio);
      // SECURITY: wipe the key if the unlock did not consume it.
      if (rawKey) zeroize(rawKey);
      this.setBiometricWaiting(false);
    }
  }

  /**
   * Whether the biometric unlock is usable on this device.
   *
   * It requires BOTH the user setting and an enrollment that matches the
   * currently active provider, so a stale envelope never shows a button that
   * cannot work.
   */
  private isBiometricsEnabled(): boolean {
    return Boolean(
      this.plugin.settings.biometrics?.enabled &&
      this.plugin.biometricManager.isBiometricsEnrolled(this.plugin.getVaultId())
    );
  }

  // ---------------------------------------------------------------------
  // Unlock flows
  // ---------------------------------------------------------------------

  /**
   * Unlocks the vault using the master password
   */
  private async handlePasswordUnlock(): Promise<void> {
    if (this.isBusy) return;

    const password = this.passwordInput.value;
    if (!password) {
      this.showError(t('lockScreen.emptyPasswordError'));
      return;
    }

    this.clearError();
    this.setBusy(true);

    try {
      const success = await this.plugin.keyManager.unlockWithPassword(password);

      if (success) {
        this.setStatus('unlocked', t('lockScreen.accessGranted'));
        this.passwordInput.value = '';
        this.forceClose();
        this.plugin.unlockVaultSuccess();
      } else {
        this.showError(t('lockScreen.invalidPassword'));
        this.passwordInput.value = '';
        this.passwordInput.focus();
      }
    } catch (err: any) {
      this.showError(err?.message || t('common.unknownError'));
    } finally {
      this.setBusy(false);
    }
  }

  /**
   * Unlocks the vault using the 24-word BIP-39 recovery phrase
   */
  private async handleRecoveryUnlock(): Promise<void> {
    if (this.isBusy) return;

    const phrase = this.recoveryInput.value.trim();

    if (!phrase) {
      this.showError(t('lockScreen.emptyPhraseError'));
      return;
    }

    const wordCount = phrase.split(/\s+/).filter(w => w.length > 0).length;
    if (wordCount !== BIP39_WORD_COUNT) {
      this.showError(t('lockScreen.phraseWordCountError', { expected: BIP39_WORD_COUNT, actual: wordCount }));
      return;
    }

    if (!validateMnemonic(phrase)) {
      this.showError(t('lockScreen.invalidPhraseError'));
      return;
    }

    this.clearError();
    this.setBusy(true);

    try {
      const success = await this.plugin.keyManager.unlockWithRecoveryPhrase(phrase);

      if (success) {
        this.setStatus('unlocked', t('lockScreen.accessGranted'));
        this.recoveryInput.value = '';
        this.forceClose();
        this.plugin.unlockVaultSuccess();
        new Notice(t('lockScreen.vaultRecoveredNotice'));
      } else {
        this.showError(t('lockScreen.invalidPhraseError'));
        this.recoveryInput.value = '';
      }
    } catch (err: any) {
      this.showError(err?.message || t('common.unknownError'));
    } finally {
      this.setBusy(false);
    }
  }

  public isModalClosed(): boolean {
    return this.isClosed;
  }

  public forceClose(): void {
    this.allowClose = true;
    super.close();
  }

  public override close(): void {
    if (!this.allowClose && this.plugin.keyManager.isLocked) {
      this.focusPasswordInput();
      return;
    }
    super.close();
  }

  public focusPasswordInput(): void {
    if (this.isClosed) return;
    if (this.isRecoveryMode && this.recoveryInput) {
      this.recoveryInput.focus();
    } else if (this.passwordInput) {
      this.passwordInput.focus();
    }
    this.shakeCard();
  }

  public override onClose(): void {
    this.isClosed = true;
    this.plugin.onLockModalClosed(this);

    // Wipe any secret material still present in the DOM
    if (this.passwordInput) {
      this.passwordInput.value = '';
      this.passwordInput.setAttribute('type', 'password');
    }
    if (this.recoveryInput) {
      this.recoveryInput.value = '';
    }
    if (this.visibilityBtn) {
      this.visibilityBtn.empty();
      setIcon(this.visibilityBtn, 'eye');
    }

    const { contentEl } = this;
    contentEl.empty();

    // If modal was dismissed unexpectedly while vault is still locked, reopen immediately
    if (this.plugin.keyManager.isLocked && !this.allowClose) {
      window.setTimeout(() => {
        if (this.plugin.keyManager.isLocked) {
          this.plugin.openLockScreen();
        }
      }, 20);
    }
  }
}
