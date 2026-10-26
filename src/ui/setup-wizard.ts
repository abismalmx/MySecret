/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * SetupWizardModal: First-Run Onboarding, Master Password & BIP-39 Recovery Cards
 */

import { App, Modal, Notice, setIcon } from 'obsidian';
import MySecretPlugin from '../main';
import { BIP39_WORD_COUNT, MIN_MASTER_PASSWORD_LENGTH } from '../constants';
import { MYSECRET_LOGO_DATA_URL } from './assets';
import { zeroize } from '../utils/zeroize';
import { t } from '../i18n';

/**
 * Minimum accepted length for the master password.
 *
 * It is sourced from the shared constant so that the setup wizard and the
 * password-change flow always enforce exactly the same policy.
 */
const MIN_PASSWORD_LENGTH = MIN_MASTER_PASSWORD_LENGTH;

/**
 * Entropy quality tiers rendered by the strength meter
 */
type EntropyTier = 'empty' | 'weak' | 'fair' | 'good' | 'strong';

interface EntropyResult {
  /** Estimated entropy in bits */
  bits: number;
  /** Quality tier derived from the entropy estimate */
  tier: EntropyTier;
  /** Human readable label */
  label: string;
}

/**
 * Estimates the entropy of a candidate password.
 *
 * The estimate follows the pattern used by well known password strength meters:
 * a base contribution of log2(poolSize) per character, minus a penalty for
 * repeated characters and minus a penalty for sequential runs (abc, 123, ...).
 */
export function estimatePasswordEntropy(password: string): EntropyResult {
  if (!password.length) {
    return { bits: 0, tier: 'empty', label: 'Sin contraseña' };
  }

  // Character pool size
  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^A-Za-z0-9]/.test(password)) poolSize += 33;

  let bits = password.length * Math.log2(Math.max(poolSize, 2));

  // Penalty: repeated characters (-1 bit each)
  const seen = new Map<string, number>();
  for (const ch of password) {
    const count = (seen.get(ch) || 0) + 1;
    seen.set(ch, count);
    if (count > 1) {
      bits -= 1;
    }
  }

  // Penalty: sequential runs of 3+ characters (-2 bits per extra char)
  let runLength = 1;
  for (let i = 1; i < password.length; i++) {
    const delta = password.charCodeAt(i) - password.charCodeAt(i - 1);
    if (delta === 1 || delta === -1) {
      runLength++;
      if (runLength > 2) {
        bits -= 2;
      }
    } else {
      runLength = 1;
    }
  }

  bits = Math.max(0, Math.round(bits));

  let tier: EntropyTier;
  let label: string;
  if (bits < 40) {
    tier = 'weak';
    label = 'Muy débil';
  } else if (bits < 60) {
    tier = 'fair';
    label = 'Débil';
  } else if (bits < 80) {
    tier = 'good';
    label = 'Buena';
  } else {
    tier = 'strong';
    label = 'Excelente';
  }

  return { bits, tier, label };
}

export class SetupWizardModal extends Modal {
  private plugin: MySecretPlugin;
  private currentStep: number = 1;
  private enableRecoveryPhrase: boolean = true;
  private generatedPassword: string = '';
  private generatedMnemonic: string = '';
  private pendingBulkEncrypt: boolean = false;

  /** Random word indices used by the Step 3 backup challenge */
  private challengeIndices: number[] = [];
  private challengeAnswered: boolean = false;

  /** Guards against rendering into a detached DOM after the modal was closed */
  private isClosed: boolean = false;

  constructor(app: App, plugin: MySecretPlugin) {
    super(app);
    this.plugin = plugin;
  }

  public override onOpen(): void {
    const { modalEl } = this;
    modalEl.addClass('mysecret-wizard-modal');
    // Prevent closing modal with Escape during setup to protect initialization integrity
    this.scope.register([], 'Escape', () => false);
    this.renderStep();
  }

  /**
   * Renders the stepper header shared by every step
   */
  private renderStepper(container: HTMLElement): void {
    const stepper = container.createDiv({ cls: 'mysecret-stepper' });

    const steps = this.enableRecoveryPhrase
      ? [
          { index: 1, label: 'Contraseña y modo' },
          { index: 2, label: 'Frase de auxilio' },
          { index: 3, label: 'Verificación' },
          { index: 4, label: 'Huella digital' }
        ]
      : [
          { index: 1, label: 'Contraseña y modo' },
          { index: 2, label: 'Bóveda protegida' },
          { index: 3, label: 'Huella digital' }
        ];

    steps.forEach((step, i) => {
      const item = stepper.createDiv({ cls: 'mysecret-step' });

      if (step.index < this.currentStep) {
        item.addClass('is-completed');
      } else if (step.index === this.currentStep) {
        item.addClass('is-current');
      }

      const bullet = item.createSpan({ cls: 'mysecret-step-bullet' });
      bullet.setText(step.index < this.currentStep ? '✓' : String(step.index));

      item.createSpan({ cls: 'mysecret-step-label', text: step.label });

      if (i < steps.length - 1) {
        item.createSpan({ cls: 'mysecret-step-line' });
      }
    });
  }

  private renderStep(): void {
    if (this.isClosed) return;

    const { contentEl } = this;
    contentEl.empty();

    const container = contentEl.createDiv({ cls: 'mysecret-wizard-container' });
    const brandWrap = container.createDiv({ cls: 'mysecret-wizard-brand' });
    brandWrap.createEl('img', {
      cls: 'mysecret-wizard-brand-logo',
      attr: {
        src: MYSECRET_LOGO_DATA_URL,
        alt: 'MySecret Logo',
        draggable: 'false'
      }
    });

    this.renderStepper(container);

    if (this.currentStep === 1) {
      this.renderStep1Password(container);
    } else if (this.enableRecoveryPhrase) {
      if (this.currentStep === 2) {
        this.renderStep2Mnemonic(container);
      } else if (this.currentStep === 3) {
        this.renderStep3Confirm(container);
      } else {
        void this.renderBiometricEnrollmentStep(container);
      }
    } else {
      if (this.currentStep === 2) {
        this.renderDirectFinish(container);
      } else {
        void this.renderBiometricEnrollmentStep(container);
      }
    }
  }

  /**
   * STEP 1: Set Master Password (with visual entropy meter)
   */
  private renderStep1Password(container: HTMLElement): void {
    container.createEl('h2', { cls: 'mysecret-wizard-title', text: `🛡️ ${t('setupWizard.title')}` });
    container.createEl('p', {
      cls: 'mysecret-wizard-desc',
      text: t('setupWizard.subtitle')
    });

    const errorEl = container.createDiv({ cls: 'mysecret-error-banner' });
    errorEl.hide();

    const form = container.createDiv({ cls: 'mysecret-wizard-form' });

    // --- Password field ---
    const p1Group = form.createDiv({ cls: 'mysecret-input-group' });
    p1Group.createEl('label', { cls: 'mysecret-input-label', text: t('setupWizard.passwordLabel') });

    const p1Wrap = p1Group.createDiv({ cls: 'mysecret-input-wrap' });
    const p1 = p1Wrap.createEl('input', {
      type: 'password',
      cls: 'mysecret-password-input',
      placeholder: t('setupWizard.passwordPlaceholder'),
      attr: {
        spellcheck: 'false',
        autocomplete: 'new-password',
        'aria-label': t('setupWizard.passwordLabel'),
        'data-mysecret-testid': 'wizard-password-input'
      }
    });

    const p1Toggle = p1Wrap.createEl('button', {
      cls: 'mysecret-visibility-toggle',
      attr: {
        type: 'button',
        'aria-label': 'Mostrar contraseña',
        'aria-pressed': 'false',
        title: 'Mostrar contraseña'
      }
    });
    setIcon(p1Toggle, 'eye');
    p1Toggle.addEventListener('click', () => {
      const isHidden = p1.type === 'password';
      p1.type = isHidden ? 'text' : 'password';
      p1Toggle.empty();
      setIcon(p1Toggle, isHidden ? 'eye-off' : 'eye');
      p1Toggle.setAttr('aria-pressed', String(isHidden));
      p1Toggle.setAttr('aria-label', isHidden ? 'Ocultar contraseña' : 'Mostrar contraseña');
      p1.focus();
    });

    // --- Entropy meter ---
    const meter = form.createDiv({ cls: 'mysecret-entropy-meter' });

    const meterHead = meter.createDiv({ cls: 'mysecret-entropy-head' });
    meterHead.createSpan({ cls: 'mysecret-entropy-label', text: 'Fuerza de la contraseña' });

    const meterValue = meterHead.createSpan({
      cls: 'mysecret-entropy-value',
      text: 'Sin contraseña'
    });

    const bars = meter.createDiv({ cls: 'mysecret-entropy-bars' });
    const barEls: HTMLElement[] = [];
    for (let i = 0; i < 5; i++) {
      barEls.push(bars.createDiv({ cls: 'mysecret-entropy-bar' }));
    }

    const hints = meter.createDiv({ cls: 'mysecret-entropy-hints' });
    const hintEls: HTMLElement[] = [];
    const hintTexts = [
      'Al menos 12 caracteres',
      'Mezcla mayúsculas y minúsculas',
      'Incluye números',
      'Incluye símbolos',
      'Evita secuencias y repeticiones'
    ];
    for (const text of hintTexts) {
      const hint = hints.createDiv({ cls: 'mysecret-entropy-hint' });
      hint.createSpan({ cls: 'mysecret-hint-icon', text: '○' });
      hint.createSpan({ text });
      hintEls.push(hint);
    }

    // --- Confirmation field ---
    const p2Group = form.createDiv({ cls: 'mysecret-input-group' });
    p2Group.createEl('label', { cls: 'mysecret-input-label', text: 'Confirma la contraseña maestra' });

    const p2 = p2Group.createEl('input', {
      type: 'password',
      cls: 'mysecret-password-input',
      placeholder: 'Repite la contraseña maestra…',
      attr: {
        spellcheck: 'false',
        autocomplete: 'new-password',
        'aria-label': 'Confirma la contraseña maestra',
        'data-mysecret-testid': 'wizard-confirm-input'
      }
    });

    // --- Live meter update ---
    const updateMeter = (): void => {
      const value = p1.value;
      const result = estimatePasswordEntropy(value);

      meter.setAttribute('data-tier', result.tier);
      meterValue.setText(value.length ? `${result.label} · ${result.bits} bits` : 'Sin contraseña');

      const activeBars =
        result.tier === 'empty' ? 0 :
        result.tier === 'weak' ? 1 :
        result.tier === 'fair' ? 2 :
        result.tier === 'good' ? 4 : 5;

      barEls.forEach((bar, i) => {
        bar.toggleClass('is-active', i < activeBars);
      });

      // Live checklist
      hintEls[0].toggleClass('is-met', value.length >= MIN_PASSWORD_LENGTH);
      hintEls[1].toggleClass('is-met', /[a-z]/.test(value) && /[A-Z]/.test(value));
      hintEls[2].toggleClass('is-met', /[0-9]/.test(value));
      hintEls[3].toggleClass('is-met', /[^A-Za-z0-9]/.test(value));

      const hasSequence = /(.)\1{2,}|(?:abc|123|qwe|asd|zxc)/i.test(value);
      hintEls[4].toggleClass('is-met', value.length > 0 && !hasSequence && !/(.)\1/.test(value));
    };

    p1.addEventListener('input', updateMeter);
    updateMeter();

    // --- Recovery Option Selection ---
    const recoveryChoiceWrap = form.createDiv({ cls: 'mysecret-recovery-choice-wrap' });
    recoveryChoiceWrap.createEl('div', {
      cls: 'mysecret-recovery-choice-title',
      text: 'Opciones de recuperación de la bóveda:'
    });

    const choiceStandard = recoveryChoiceWrap.createDiv({
      cls: `mysecret-choice-card ${this.enableRecoveryPhrase ? 'is-selected' : ''}`
    });
    choiceStandard.createEl('div', { cls: 'mysecret-choice-radio', text: this.enableRecoveryPhrase ? '●' : '○' });
    const choiceStandardInfo = choiceStandard.createDiv({ cls: 'mysecret-choice-info' });
    choiceStandardInfo.createEl('strong', { text: 'Generar frase de recuperación de 24 palabras (Recomendado)' });
    choiceStandardInfo.createEl('p', {
      text: 'Podrás recuperar el acceso a tus notas si alguna vez olvidas la contraseña maestra.'
    });

    const choiceParanoid = recoveryChoiceWrap.createDiv({
      cls: `mysecret-choice-card ${!this.enableRecoveryPhrase ? 'is-selected' : ''}`
    });
    choiceParanoid.createEl('div', { cls: 'mysecret-choice-radio', text: !this.enableRecoveryPhrase ? '●' : '○' });
    const choiceParanoidInfo = choiceParanoid.createDiv({ cls: 'mysecret-choice-info' });
    choiceParanoidInfo.createEl('strong', { text: 'Solo contraseña maestra (Máxima seguridad / Sin auxilio)' });
    choiceParanoidInfo.createEl('p', {
      text: 'No se guardará ninguna puerta de auxilio en disco. Si olvidas tu contraseña, la pérdida será permanente.'
    });

    choiceStandard.addEventListener('click', () => {
      this.enableRecoveryPhrase = true;
      choiceStandard.addClass('is-selected');
      choiceParanoid.removeClass('is-selected');
      choiceStandard.querySelector('.mysecret-choice-radio')!.setText('●');
      choiceParanoid.querySelector('.mysecret-choice-radio')!.setText('○');
      nextBtn.setText('Continuar a Frase de Recuperación →');
      const stepperEl = container.querySelector('.mysecret-stepper');
      if (stepperEl) {
        stepperEl.remove();
        const brand = container.querySelector('.mysecret-wizard-brand');
        if (brand) {
          const newStepperWrap = container.createDiv({ cls: 'mysecret-temp-stepper-wrap' });
          this.renderStepper(newStepperWrap);
          brand.insertAdjacentElement('afterend', newStepperWrap.firstElementChild!);
          newStepperWrap.remove();
        }
      }
    });

    choiceParanoid.addEventListener('click', () => {
      this.enableRecoveryPhrase = false;
      choiceParanoid.addClass('is-selected');
      choiceStandard.removeClass('is-selected');
      choiceParanoid.querySelector('.mysecret-choice-radio')!.setText('●');
      choiceStandard.querySelector('.mysecret-choice-radio')!.setText('○');
      nextBtn.setText('Finalizar Configuración (Solo Contraseña) →');
      const stepperEl = container.querySelector('.mysecret-stepper');
      if (stepperEl) {
        stepperEl.remove();
        const brand = container.querySelector('.mysecret-wizard-brand');
        if (brand) {
          const newStepperWrap = container.createDiv({ cls: 'mysecret-temp-stepper-wrap' });
          this.renderStepper(newStepperWrap);
          brand.insertAdjacentElement('afterend', newStepperWrap.firstElementChild!);
          newStepperWrap.remove();
        }
      }
    });

    // --- Actions ---
    const actions = container.createDiv({ cls: 'mysecret-actions-group' });

    const nextBtn = actions.createEl('button', {
      cls: 'mod-cta mysecret-wizard-btn',
      text: this.enableRecoveryPhrase ? 'Continuar a Frase de Recuperación →' : 'Finalizar Configuración (Solo Contraseña) →',
      attr: { 'data-mysecret-testid': 'wizard-continue-button' }
    });

    nextBtn.addEventListener('click', () => {
      const pass = p1.value;
      const confirm = p2.value;

      if (!pass || pass.length < MIN_PASSWORD_LENGTH) {
        errorEl.setText(`La contraseña debe tener al menos ${MIN_PASSWORD_LENGTH} caracteres.`);
        errorEl.show();
        return;
      }
      if (pass !== confirm) {
        errorEl.setText('Las contraseñas no coinciden.');
        errorEl.show();
        return;
      }

      const result = estimatePasswordEntropy(pass);
      if (result.tier === 'weak') {
        errorEl.setText('La contraseña es demasiado débil. Añade variedad de caracteres para continuar.');
        errorEl.show();
        return;
      }

      errorEl.hide();
      this.generatedPassword = pass;
      this.currentStep = 2;
      this.renderStep();
    });

    window.setTimeout(() => p1.focus(), 100);
  }

  /**
   * STEP 2: Show the 24 BIP-39 recovery words as styled cards
   */
  private renderStep2Mnemonic(container: HTMLElement): void {
    container.createEl('h2', { cls: 'mysecret-wizard-title', text: '🔑 Tu Frase de Rescate' });
    container.createEl('p', {
      cls: 'mysecret-wizard-desc',
      text: `Estas ${BIP39_WORD_COUNT} palabras son el ÚNICO modo de recuperar tus notas si olvidas la contraseña maestra. Anótalas en papel o guárdalas en un gestor de claves seguro.`
    });

    const errorEl = container.createDiv({ cls: 'mysecret-error-banner' });
    errorEl.hide();

    // Generate the vault keys and the mnemonic
    const loadingEl = container.createDiv({ cls: 'mysecret-loading' });
    loadingEl.createSpan({ cls: 'mysecret-spinner' });
    loadingEl.createSpan({ text: 'Generando entropía criptográfica (Argon2id + BIP-39)…' });

    // SECURITY / DATA INTEGRITY: the wizard must never overwrite an existing
    // vault. A second `initializeVault()` generates a NEW random vault key;
    // anything encrypted with the previous one becomes unreadable forever.
    if (this.plugin.keyManager.isInitialized) {
      loadingEl.remove();
      errorEl.setText('Ya existe una bóveda configurada: el asistente no puede crear otra clave encima.');
      errorEl.show();
      return;
    }

    this.plugin.keyManager.initializeVault(this.generatedPassword).then(async ({ mnemonic, envelope, commit }) => {
      // ATOMIC GUARANTEE: persist the envelope to disk BEFORE unlocking in RAM
      await this.plugin.saveVaultEnvelope(envelope);
      await commit();

      const safeMnemonic = mnemonic || '';
      this.generatedMnemonic = safeMnemonic;

      // The modal may have been closed while the KDF was running
      if (this.isClosed) return;

      loadingEl.remove();

      // --- Warning banner ---
      const warning = container.createDiv({ cls: 'mysecret-wizard-warning' });
      warning.createSpan({ text: '⚠️ ' });
      warning.createSpan({ text: 'Esta frase nunca volverá a mostrarse. Asegúrate de copiarla antes de continuar.' });

      // --- Toolbar ---
      const toolbar = container.createDiv({ cls: 'mysecret-mnemonic-toolbar' });

      const copyBtn = toolbar.createEl('button', {
        cls: 'mysecret-copy-btn',
        text: '📋 Copiar frase',
        attr: { 'data-mysecret-testid': 'wizard-copy-button' }
      });

      const concealBtn = toolbar.createEl('button', {
        cls: 'mysecret-copy-btn',
        text: '🙈 Ocultar palabras',
        attr: { 'data-mysecret-testid': 'wizard-conceal-button' }
      });

      // --- Mnemonic grid ---
      const words: string[] = safeMnemonic ? safeMnemonic.split(' ').filter((w: string) => w.length > 0) : [];
      const grid = container.createDiv({ cls: 'mysecret-mnemonic-grid' });

      words.forEach((word, idx) => {
        const card = grid.createDiv({ cls: 'mysecret-mnemonic-card' });
        card.createSpan({ cls: 'mysecret-mnemonic-num', text: `${idx + 1}.` });
        card.createSpan({ cls: 'mysecret-mnemonic-word', text: word });
      });

      // --- Secure copy: clears the clipboard after a delay ---
      let clearTimer: number | null = null;

      copyBtn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(safeMnemonic);
          copyBtn.setText('✅ Copiada');
          new Notice('Frase de rescate copiada al portapapeles.');

          // Auto-clear the clipboard so the secret does not linger
          if (clearTimer !== null) window.clearTimeout(clearTimer);
          clearTimer = window.setTimeout(async () => {
            try {
              const current = await navigator.clipboard.readText();
              if (current === safeMnemonic) {
                await navigator.clipboard.writeText('');
              }
              copyBtn.setText('📋 Copiar frase');
            } catch {
              // Clipboard read may be denied: the copy still succeeded
              copyBtn.setText('📋 Copiar frase');
            }
          }, 30000);
        } catch {
          errorEl.setText('No se pudo acceder al portapapeles. Anota las palabras manualmente.');
          errorEl.show();
        }
      });

      // --- Conceal / reveal toggle ---
      let concealed = false;
      concealBtn.addEventListener('click', () => {
        concealed = !concealed;
        grid.toggleClass('is-concealed', concealed);
        concealBtn.setText(concealed ? '👁️ Mostrar palabras' : '🙈 Ocultar palabras');
      });

      // --- Navigation ---
      const actions = container.createDiv({ cls: 'mysecret-actions-group' });

      const nextBtn = actions.createEl('button', {
        cls: 'mod-cta mysecret-wizard-btn',
        text: 'He guardado mi frase de auxilio →',
        attr: { 'data-mysecret-testid': 'wizard-mnemonic-continue' }
      });

      nextBtn.addEventListener('click', () => {
        this.currentStep = 3;
        this.renderStep();
      });
    }).catch((err: any) => {
      if (this.isClosed) return;

      loadingEl.remove();
      errorEl.setText('Error al inicializar la bóveda: ' + (err?.message || 'error desconocido'));
      errorEl.show();
    });
  }

  /**
   * STEP 3: Confirm the backup with a 2-word random challenge
   */
  private renderStep3Confirm(container: HTMLElement): void {
    container.createEl('h2', { cls: 'mysecret-wizard-title', text: '🎉 ¡Bóveda Protegida!' });
    container.createEl('p', {
      cls: 'mysecret-wizard-desc',
      text: 'MySecret ha inicializado el cifrado transparente. A partir de ahora, cada nota que guardes se cifrará automáticamente con AES-256-GCM.'
    });

    const errorEl = container.createDiv({ cls: 'mysecret-error-banner' });
    errorEl.hide();

    const words = this.generatedMnemonic.split(' ').filter(w => w.length > 0);

    // --- Pick 2 distinct random word indices ---
    if (this.challengeIndices.length !== 2 || words.length === 0) {
      this.challengeIndices = this.pickChallengeIndices(words.length);
    }

    const challenge = container.createDiv({ cls: 'mysecret-challenge' });
    challenge.createEl('h3', {
      cls: 'mysecret-challenge-title',
      text: 'Demuestra que guardaste tu frase'
    });
    challenge.createEl('p', {
      cls: 'mysecret-challenge-desc',
      text: 'Introduce las dos palabras que te solicitamos para confirmar que tu respaldo es correcto.'
    });

    const inputs: HTMLInputElement[] = [];

    this.challengeIndices.forEach((wordIndex, i) => {
      const group = challenge.createDiv({ cls: 'mysecret-input-group' });
      group.createEl('label', {
        cls: 'mysecret-input-label',
        text: `Palabra ${this.challengeIndices[i] + 1} de ${BIP39_WORD_COUNT}`
      });

      const input = group.createEl('input', {
        type: 'text',
        cls: 'mysecret-password-input',
        placeholder: 'Introduce la palabra…',
        attr: {
          spellcheck: 'false',
          autocomplete: 'off',
          'aria-label': `Palabra ${wordIndex + 1}`,
          'data-mysecret-testid': `wizard-challenge-input-${i}`
        }
      });
      inputs.push(input);
    });

    const feedback = challenge.createDiv({ cls: 'mysecret-challenge-feedback' });

    const validateChallenge = (): boolean => {
      let allCorrect = true;

      inputs.forEach((input, i) => {
        const expected = words[this.challengeIndices[i]];
        const given = input.value.trim().toLowerCase();
        const correct = given === expected;

        input.toggleClass('is-correct', correct && given.length > 0);
        input.toggleClass('is-wrong', !correct && given.length > 0);
        if (!correct) allCorrect = false;
      });

      this.challengeAnswered = allCorrect;
      return allCorrect;
    };

    inputs.forEach((input) => {
      input.addEventListener('input', () => {
        validateChallenge();
        errorEl.hide();
      });
      input.addEventListener('keydown', (e: KeyboardEvent) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          if (validateChallenge()) {
            this.handleChallengePassed();
          }
        }
      });
    });

    // --- Actions ---
    const actions = container.createDiv({ cls: 'mysecret-actions-group' });

    const verifyBtn = actions.createEl('button', {
      cls: 'mod-cta mysecret-wizard-btn',
      text: 'Verificar palabras',
      attr: { 'data-mysecret-testid': 'wizard-verify-button' }
    });

    verifyBtn.addEventListener('click', () => {
      if (validateChallenge()) {
        this.handleChallengePassed();
      } else {
        errorEl.setText('Las palabras no coinciden. Vuelve a consultar tu frase de rescate.');
        errorEl.show();
        feedback.setText('Verificación fallida');
        feedback.addClass('is-error');
      }
    });

    const finishBtn = actions.createEl('button', {
      cls: 'mysecret-wizard-btn',
      text: 'Comenzar a usar Obsidian',
      attr: { 'data-mysecret-testid': 'wizard-finish-button' }
    });

    finishBtn.addEventListener('click', () => {
      if (!this.challengeAnswered) {
        errorEl.setText('Verifica las dos palabras antes de finalizar la configuración.');
        errorEl.show();
        return;
      }
      this.currentStep = 4;
      this.renderStep();
    });
  }

  /**
   * Handles a successful backup verification
   */
  private handleChallengePassed(): void {
    const errorEl = this.modalEl.querySelector('.mysecret-error-banner');
    if (errorEl) {
      (errorEl as HTMLElement).hide();
    }

    const feedback = this.modalEl.querySelector('.mysecret-challenge-feedback');
    if (feedback) {
      feedback.setText('✓ Respaldo verificado correctamente');
      feedback.removeClass('is-error');
      feedback.addClass('is-success');
    }

    // Avoid duplicating the action button when the user verifies twice
    if (this.modalEl.querySelector('[data-mysecret-testid="wizard-encrypt-all-button"]')) {
      return;
    }

    new Notice('✅ Frase de rescate verificada. Ya puedes configurar la huella o continuar.');

    // Offer the bulk encryption of pre-existing notes
    const actions = this.modalEl.querySelector('.mysecret-actions-group');
    if (!actions) return;

    const encryptAllBtn = actions.createEl('button', {
      cls: 'mod-cta mysecret-wizard-btn',
      text: '🔒 Cifrar notas existentes ahora',
      attr: { 'data-mysecret-testid': 'wizard-encrypt-all-button' }
    });

    encryptAllBtn.addEventListener('click', () => {
      this.pendingBulkEncrypt = true;
      this.currentStep = 4;
      this.renderStep();
    });
  }

  /**
   * DIRECT FINISH: For users who opt out of recovery phrase (Password-Only / Maximum Paranoia)
   */
  private renderDirectFinish(container: HTMLElement): void {
    container.createEl('h2', { cls: 'mysecret-wizard-title', text: '🛡️ Máxima Seguridad Activada' });
    container.createEl('p', {
      cls: 'mysecret-wizard-desc',
      text: 'Protegiendo tu bóveda con cifrado AES-256-GCM y Argon2id exclusivamente con tu contraseña maestra.'
    });

    const loadingEl = container.createDiv({ cls: 'mysecret-loading' });
    loadingEl.createSpan({ cls: 'mysecret-spinner' });
    loadingEl.createSpan({ text: 'Generando claves y cifrando configuración…' });

    if (this.plugin.keyManager.isInitialized) {
      loadingEl.remove();
      container.createDiv({
        cls: 'mysecret-error-banner',
        text: 'Ya existe una bóveda configurada: el asistente no puede crear otra clave encima.'
      });
      return;
    }

    this.plugin.keyManager
      .initializeVault(this.generatedPassword, false)
      .then(async ({ envelope, commit }) => {
        await this.plugin.saveVaultEnvelope(envelope);
        await commit();

        if (this.isClosed) return;
        loadingEl.remove();

        const successCard = container.createDiv({ cls: 'mysecret-challenge-feedback is-success' });
        successCard.setText('✓ Bóveda configurada con éxito en modo de solo contraseña');

        const noteBox = container.createDiv({ cls: 'mysecret-migration-warning' });
        noteBox.createEl('strong', { text: 'Importante: ' });
        noteBox.createSpan({
          text: 'No se generó frase de auxilio. Tu contraseña maestra es el único medio para acceder a tus notas.'
        });

        const actions = container.createDiv({ cls: 'mysecret-actions-group' });

        const startBtn = actions.createEl('button', {
          cls: 'mysecret-wizard-btn',
          text: 'Continuar a Huella Digital →'
        });
        startBtn.addEventListener('click', () => {
          this.currentStep = 3;
          this.renderStep();
        });

        const encryptAllBtn = actions.createEl('button', {
          cls: 'mod-cta mysecret-wizard-btn',
          text: '🔒 Cifrar notas existentes ahora'
        });
        encryptAllBtn.addEventListener('click', () => {
          this.pendingBulkEncrypt = true;
          this.currentStep = 3;
          this.renderStep();
        });
      })
      .catch(err => {
        loadingEl.setText(`Error al inicializar la bóveda: ${err?.message || String(err)}`);
      });
  }

  /**
   * STEP 4: Biometric Enrollment Prompt
   */
  private async renderBiometricEnrollmentStep(container: HTMLElement): Promise<void> {
    container.createEl('h2', { cls: 'mysecret-wizard-title', text: '👆 Desbloqueo Rápido con Huella Digital' });
    container.createEl('p', {
      cls: 'mysecret-wizard-desc',
      text: 'Puedes desbloquear tu bóveda al instante usando el sensor biométrico de este dispositivo sin tener que teclear tu contraseña cada vez.'
    });

    const statusEl = container.createDiv({ cls: 'mysecret-loading' });
    statusEl.createSpan({ cls: 'mysecret-spinner' });
    statusEl.createSpan({ text: 'Comprobando hardware biométrico de este equipo…' });

    const vaultId = this.plugin.getVaultId();
    const capabilities = await this.plugin.biometricManager.checkBiometricAvailability(vaultId);

    if (this.isClosed) return;
    statusEl.remove();

    const finishSetup = (): void => {
      this.close();
      this.plugin.unlockVaultSuccess();
      new Notice('Bóveda lista y protegida. 🔒');
      if (this.pendingBulkEncrypt) {
        this.plugin.openMigrationModal('encrypt');
      }
    };

    const card = container.createDiv({ cls: 'mysecret-choice-card is-selected' });

    if (capabilities.supported) {
      const info = card.createDiv({ cls: 'mysecret-choice-info' });
      info.createEl('strong', { text: `Hardware disponible: ${capabilities.label}` });
      info.createEl('p', {
        text: 'Al activarlo, se guardará un sobre seguro vinculado exclusivamente a este equipo. Cada dispositivo que uses conserva su propia configuración de huella.'
      });

      const feedback = container.createDiv({ cls: 'mysecret-challenge-feedback' });
      feedback.hide();

      const actions = container.createDiv({ cls: 'mysecret-actions-group' });

      const enrollBtn = actions.createEl('button', {
        cls: 'mod-cta mysecret-wizard-btn',
        text: 'Activar Huella en este Dispositivo',
        attr: { 'data-mysecret-testid': 'wizard-enroll-bio-button' }
      });

      const skipBtn = actions.createEl('button', {
        cls: 'mysecret-wizard-btn',
        text: 'Omitir por ahora',
        attr: { 'data-mysecret-testid': 'wizard-skip-bio-button' }
      });

      enrollBtn.addEventListener('click', async () => {
        const rawVaultKey = this.plugin.keyManager.getRawVaultKey();
        if (!rawVaultKey) {
          feedback.setText('La bóveda debe estar cargada en RAM para enrolar la huella.');
          feedback.addClass('is-error');
          feedback.show();
          return;
        }

        enrollBtn.disabled = true;
        enrollBtn.setText('Escaneando huella…');
        feedback.setText('Coloca tu dedo en el sensor o confirma en el diálogo del sistema…');
        feedback.removeClass('is-error');
        feedback.show();

        try {
          const success = await this.plugin.biometricManager.enrollBiometrics(rawVaultKey, vaultId);
          if (success) {
            // Keep the other biometric settings (the Android bridge URL, for one).
            this.plugin.settings.biometrics = {
              ...this.plugin.settings.biometrics,
              enabled: true,
              autoPrompt: true
            };
            await this.plugin.saveSettings();

            feedback.setText('✓ Huella digital activada correctamente en este equipo');
            feedback.removeClass('is-error');
            feedback.addClass('is-success');
            enrollBtn.remove();
            skipBtn.setText('Comenzar a usar Obsidian →');
            skipBtn.addClass('mod-cta');
            new Notice('👆 Desbloqueo con huella habilitado.');
          }
        } catch (err: any) {
          enrollBtn.disabled = false;
          enrollBtn.setText('Reintentar Activación');
          feedback.setText(err?.message || 'Error en la verificación biométrica.');
          feedback.addClass('is-error');
        } finally {
          // SECURITY: the copy of the vault key must never linger in the heap.
          zeroize(rawVaultKey);
        }
      });

      skipBtn.addEventListener('click', finishSetup);
    } else {
      const info = card.createDiv({ cls: 'mysecret-choice-info' });
      info.createEl('strong', { text: 'Hardware Biométrico no configurado en este equipo' });
      info.createEl('p', {
        text: 'No se detectó un lector biométrico directo o la URL del puente de Cloudflare Pages aún no está configurada. Tu bóveda se desbloqueará con tu contraseña maestra (puedes activar la huella más tarde en Ajustes > MySecret).'
      });

      const actions = container.createDiv({ cls: 'mysecret-actions-group' });
      const finishBtn = actions.createEl('button', {
        cls: 'mod-cta mysecret-wizard-btn',
        text: 'Comenzar a usar Obsidian',
        attr: { 'data-mysecret-testid': 'wizard-finish-button' }
      });

      finishBtn.addEventListener('click', finishSetup);
    }
  }

  /**
   * Picks 2 distinct random indices for the backup challenge
   */
  private pickChallengeIndices(wordCount: number): number[] {
    if (wordCount === 0) return [];
    if (wordCount === 1) return [0];

    const first = Math.floor(Math.random() * wordCount);
    let second = Math.floor(Math.random() * wordCount);
    while (second === first) {
      second = Math.floor(Math.random() * wordCount);
    }

    return [first, second].sort((a, b) => a - b);
  }

  public override onClose(): void {
    this.isClosed = true;

    // Remove the secret from memory
    this.generatedPassword = '';
    this.generatedMnemonic = '';

    const { contentEl } = this;
    contentEl.empty();
  }
}
