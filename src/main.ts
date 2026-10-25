/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Main Plugin Entrypoint & Lifecycle Controller
 */

import { Plugin, Notice, TFile, TFolder } from 'obsidian';
import { PluginSettings, VaultEnvelopeConfig, CloudBackupSettings } from './types';
import { PLUGIN_ID, VAULT_ENVELOPE_PATH, VAULT_ENVELOPE_FILENAME } from './constants';
import { PathFilter } from './adapter/path-filter';
import { KeyManager } from './crypto/key-manager';
import { AdapterInterceptor } from './adapter/adapter-interceptor';
import { MediaManager } from './adapter/media-manager';
import { MySecretSettingTab } from './ui/settings-tab';
import { LockScreenModal } from './ui/lock-screen';
import { SetupWizardModal } from './ui/setup-wizard';
import { MigrationModal } from './ui/migration-modal';
import { ExportModal } from './ui/export-modal';
import { CloudBackupModal } from './ui/cloud-backup-modal';
import { RestoreModal } from './ui/restore-modal';
import { ChangePasswordModal } from './ui/change-password-modal';
import { RecoveryPhraseModal } from './ui/recovery-phrase-modal';
import { BackupEngine } from './backup/backup-engine';
import { createCloudProvider } from './backup/cloud';
import {
  encryptCredential,
  decryptCredential,
  isEncryptedCredential
} from './utils/credential-store';
import { BiometricManager } from './biometrics/biometric-manager';
import { sha256HexSync } from './utils/sha256';
import { initI18n, t, setI18nLanguage } from './i18n';

const DEFAULT_SETTINGS: PluginSettings = {
  autoLockMinutes: 5,
  lockOnBlur: false,
  excludedFolders: [],
  encryptAttachments: true,
  isInitialized: false,
  language: 'auto',
  biometrics: {
    enabled: false,
    autoPrompt: true,
    bridgeUrl: ''
  },
  backup: {
    provider: 'none',
    googleDrive: { accessToken: '', folderId: '' },
    oneDrive: { accessToken: '', folderPath: 'MySecretBackups' },
    webdav: { serverUrl: '', username: '', password: '', remotePath: 'MySecretBackups' },
    localSync: { destinationPath: '' },
    autoBackup: false,
    autoBackupTrigger: 'both',
    autoBackupIntervalHours: 24,
    lastBackupTimestamp: 0,
    retentionCount: 5
  }
};

export default class MySecretPlugin extends Plugin {
  public settings!: PluginSettings;
  public pathFilter!: PathFilter;
  public keyManager!: KeyManager;
  public biometricManager!: BiometricManager;
  public interceptor!: AdapterInterceptor;
  public mediaManager!: MediaManager;

  private inactivityTimer: any = null;
  private autoBackupIntervalTimer: any = null;
  private isAutoBackupRunning: boolean = false;
  private ribbonIconEl!: HTMLElement;
  public currentLockModal: LockScreenModal | null = null;
  private savedOpenLeaves: Array<{ path: string; state: any; eState: any }> = [];

  public async onload(): Promise<void> {
    console.log('[MySecret] Loading transparent encryption plugin...');

    await this.loadSettings();
    initI18n(this.settings.language);

    // 1. Initialize Filters, Media Manager, and Cryptographic Key Manager
    this.pathFilter = new PathFilter(
      this.settings.excludedFolders,
      this.settings.encryptAttachments
    );
    this.keyManager = new KeyManager();
    this.biometricManager = new BiometricManager(this.settings.biometrics?.bridgeUrl);
    this.mediaManager = new MediaManager(this.app, this.pathFilter, this.keyManager);

    // 1b. Register custom protocol handler for external biometric bridge: obsidian://mysecret-auth
    this.registerObsidianProtocolHandler('mysecret-auth', async (params) => {
      console.log('[MySecret] Protocol handler callback received for mysecret-auth');
      try {
        const handled = await this.biometricManager.handleProtocolCallback(params);
        if (handled && !this.keyManager.isLocked && this.currentLockModal) {
          this.currentLockModal.forceClose();
          this.currentLockModal = null;
        }
      } catch (err: any) {
        console.warn('[MySecret] Error en callback de autenticación externa:', err);
        new Notice(`Error biométrico: ${err?.message || String(err)}`);
      }
    });

    // 2. Check if Vault is already configured with an envelope
    await this.loadVaultEnvelope();

    // 3. Install transparent VaultAdapter interception
    this.interceptor = new AdapterInterceptor(
      this.app.vault.adapter,
      this.pathFilter,
      this.keyManager,
      this.mediaManager
    );
    this.interceptor.install();

    // 3b. Transparent media rendering in Reading View and markdown cards
    this.registerMarkdownPostProcessor((element) => {
      this.mediaManager.scanAndPatch(element);
    });

    // 3c. Re-bind the encryption AAD when Obsidian renames a file or folder.
    //
    // SECURITY / DATA INTEGRITY: the AES-GCM additional authenticated data is
    // bound to the normalized vault path. If a file is renamed and the AAD is
    // not re-bound, its content becomes permanently undecryptable (silent
    // data loss). The public `rename` event is used because it is the only
    // interception point guaranteed to fire for every rename (drag & drop,
    // file explorer, rename command, sync plugins…).
    this.registerEvent(
      this.app.vault.on('rename', (file, oldPath) => {
        void this.interceptor.handleVaultRename(file, oldPath);
      })
    );

    // 4. Ribbon Icon for Lock State & Quick Actions
    this.ribbonIconEl = this.addRibbonIcon('lock', t('ribbon.lockedTooltip'), () => {
      if (this.keyManager.isLocked) {
        this.openLockScreen();
      } else {
        this.lockVault();
      }
    });
    this.updateRibbonIcon();

    // 5. Register Commands
    this.addCommand({
      id: 'mysecret-lock-vault',
      name: t('commands.lockVault'),
      checkCallback: (checking: boolean) => {
        if (!this.keyManager.isLocked) {
          if (!checking) this.lockVault();
          return true;
        }
        return false;
      }
    });

    this.addCommand({
      id: 'mysecret-unlock-vault',
      name: t('commands.unlockVault'),
      checkCallback: (checking: boolean) => {
        if (this.keyManager.isLocked) {
          if (!checking) this.openLockScreen();
          return true;
        }
        return false;
      }
    });

    this.addCommand({
      id: 'mysecret-change-password',
      name: t('commands.changePassword'),
      callback: () => this.promptChangePassword()
    });

    this.addCommand({
      id: 'mysecret-bulk-encrypt',
      name: t('settings.encryptAllFilesBtn'),
      callback: () => this.openMigrationModal('encrypt')
    });

    this.addCommand({
      id: 'mysecret-export-zip',
      name: t('commands.exportBackup'),
      callback: () => new ExportModal(this.app, this).open()
    });

    this.addCommand({
      id: 'mysecret-cloud-backup',
      name: t('commands.cloudBackup'),
      callback: () => new CloudBackupModal(this.app, this).open()
    });

    this.addCommand({
      id: 'mysecret-restore-backup',
      name: t('commands.restoreBackup'),
      callback: () => new RestoreModal(this.app, this).open()
    });

    // 6. Settings Tab
    this.addSettingTab(new MySecretSettingTab(this.app, this));

    // 7. Security: Activity Tracking for Auto-Lock
    this.registerDomEvent(window, 'keydown', () => this.resetInactivityTimer());
    this.registerDomEvent(window, 'mousemove', () => this.resetInactivityTimer());
    this.registerDomEvent(window, 'mousedown', () => this.resetInactivityTimer());
    this.registerDomEvent(window, 'touchstart', () => this.resetInactivityTimer());

    // Window Blur (minimize/app switch)
    this.registerDomEvent(window, 'blur', () => {
      if (this.settings.lockOnBlur && !this.keyManager.isLocked) {
        this.lockVault();
      }
    });

    // 7b. File Explorer context menu (App de archivos) to exclude/include folders
    this.registerEvent(
      this.app.workspace.on('file-menu', (menu, file) => {
        if (
          file instanceof TFolder &&
          (typeof file.isRoot !== 'function' || !file.isRoot()) &&
          file.path.trim().length > 0 &&
          file.path !== '/'
        ) {
          const isDirectlyExcluded = this.isFolderExcluded(file.path);
          const isInheritedExcluded = !isDirectlyExcluded && this.pathFilter.isUserExcluded(file.path);

          if (isInheritedExcluded) {
            menu.addItem(item => {
              item
                .setTitle('MySecret: Ya excluida (heredada de carpeta superior)')
                .setIcon('folder-check')
                .setDisabled(true);
            });
          } else {
            menu.addItem(item => {
              item
                .setTitle(
                  isDirectlyExcluded
                    ? 'MySecret: Quitar de carpetas excluidas (Cifrar)'
                    : 'MySecret: Excluir carpeta del cifrado'
                )
                .setIcon(isDirectlyExcluded ? 'lock' : 'folder-minus')
                .onClick(async () => {
                  await this.toggleFolderExclusion(file.path);
                });
            });
          }
        }
      })
    );

    // 8. Auto-Backup Periodic Timer
    this.initAutoBackupTimer();

    // 9. Boot Evaluation: Setup Wizard vs Immediate Lock
    this.app.workspace.onLayoutReady(() => {
      if (!this.keyManager.isInitialized) {
        // Vault has never been initialized with MySecret
        this.openSetupWizard();
      } else {
        // Vault is configured: strictly enforce lock screen at startup
        this.preserveAndCloseOpenNotes();
        document.body.classList.add('is-mysecret-locked');
        this.openLockScreen();
      }
    });
  }

  public onunload(): void {
    console.log('[MySecret] Unloading transparent encryption plugin...');
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
    }
    if (this.autoBackupIntervalTimer) {
      clearInterval(this.autoBackupIntervalTimer);
      this.autoBackupIntervalTimer = null;
    }
    if (this.mediaManager) {
      this.mediaManager.destroy();
    }
    document.body.classList.remove('is-mysecret-locked');
    // Securely wipe RAM and uninstall hooks
    this.keyManager.lock();
    this.interceptor.uninstall();
  }

  public async loadSettings(): Promise<void> {
    const loaded = await this.loadData();
    this.settings = Object.assign({}, DEFAULT_SETTINGS, loaded);
    if (loaded && loaded.backup) {
      this.settings.backup = Object.assign({}, DEFAULT_SETTINGS.backup, loaded.backup);
    } else {
      this.settings.backup = Object.assign({}, DEFAULT_SETTINGS.backup);
    }
    if (loaded && loaded.biometrics) {
      this.settings.biometrics = Object.assign({}, DEFAULT_SETTINGS.biometrics, loaded.biometrics);
    } else {
      this.settings.biometrics = Object.assign({}, DEFAULT_SETTINGS.biometrics);
    }
  }

  /**
   * Returns a persistent identifier for this vault to scope device-local
   * biometric envelopes.
   *
   * SECURITY: the identifier MUST be unique per vault. The previous fallback
   * was `app.appId`, which is a CONSTANT shared by every vault opened with
   * the same Obsidian installation: two different vaults would then share the
   * same biometric envelope slot (and the same keyring entry), so unlocking
   * vault A would also unlock vault B.
   *
   * The Argon2 salt is the preferred source because it is unique, random and
   * already persisted inside `vault-envelope.json`. When the envelope is not
   * loaded yet, a hash of the absolute vault path is used instead of the
   * shared `appId`.
   */
  public getVaultId(): string {
    const envelope = this.keyManager.getEnvelope();
    if (envelope && envelope.argon2 && envelope.argon2.salt) {
      return envelope.argon2.salt;
    }
    return this.getVaultPathFingerprint();
  }

  /**
   * Stable fingerprint of the vault location.
   *
   * It is derived from the absolute vault path so it stays constant across
   * restarts but differs between two distinct vaults. SHA-256 is used so the
   * identifier can safely take part in the AES-GCM AAD of the biometric
   * envelope (a 32-bit hash would make collisions realistic, and a collision
   * would break the vault binding).
   */
  private getVaultPathFingerprint(): string {
    const rawPath = (this.app as any)?.vault?.adapter?.basePath || (this.app as any)?.appId || '';
    const path = String(rawPath);

    try {
      const nodeCrypto = (window as any).require('crypto');
      if (nodeCrypto && typeof nodeCrypto.createHash === 'function') {
        return nodeCrypto.createHash('sha256').update(path, 'utf8').digest('hex');
      }
    } catch {
      // Fall through to the pure-JS fallback below.
    }

    // Pure-JS SHA-256 fallback (FIPS 180-4). Used only when Node's crypto
    // module is unreachable (e.g. a restricted mobile WebView).
    return sha256HexSync(path);
  }

  public async saveSettings(): Promise<void> {
    // Encrypt the sensitive credentials *before* they hit the disk.
    // `this.settings` keeps the encrypted representation so that the values
    // are never persisted in cleartext.
    await this.encryptCredentialsInSettings();
    await this.saveData(this.settings);
  }

  /**
   * Stores a new cloud credential, encrypting it before it is persisted.
   *
   * @param field Which credential is being set
   * @param plaintext The plaintext credential value
   */
  public async setEncryptedCredential(
    field: 'googleDriveAccessToken' | 'oneDriveAccessToken' | 'webdavPassword',
    plaintext: string
  ): Promise<void> {
    const backup = this.settings.backup;

    if (!plaintext) {
      if (field === 'googleDriveAccessToken') backup.googleDrive.accessToken = '';
      else if (field === 'oneDriveAccessToken') backup.oneDrive.accessToken = '';
      else backup.webdav.password = '';
      await this.saveSettings();
      return;
    }

    const vaultKey = this.keyManager.getVaultKey();
    if (!vaultKey) {
      new Notice('Desbloquea la bóveda para guardar las credenciales de forma cifrada.');
      return;
    }

    try {
      const encrypted = await encryptCredential(vaultKey, plaintext);
      if (field === 'googleDriveAccessToken') backup.googleDrive.accessToken = encrypted;
      else if (field === 'oneDriveAccessToken') backup.oneDrive.accessToken = encrypted;
      else backup.webdav.password = encrypted;
      await this.saveSettings();
    } catch (err: any) {
      new Notice('❌ No se pudo guardar la credencial: ' + (err?.message || String(err)));
    }
  }

  /**
   * Returns a display-safe representation of a stored credential.
   *
   * Encrypted values are never shown in cleartext in the settings UI; an
   * empty string is returned instead so the field looks "unset".
   */
  public getCredentialDisplayValue(stored: string | undefined): string {
    if (!stored) return '';
    if (isEncryptedCredential(stored)) return '';
    return stored;
  }

  /**
   * Encrypts the sensitive cloud credentials before they are written to disk.
   *
   * SECURITY: `data.json` is plain JSON inside the vault. OAuth tokens and
   * WebDAV passwords must not be stored there in cleartext.
   */
  private async encryptCredentialsInSettings(): Promise<void> {
    const vaultKey = this.keyManager.getVaultKey();
    if (!vaultKey) {
      // The vault is locked: the vault key is unavailable, so the credentials
      // cannot be encrypted. They are left untouched (they stay encrypted from
      // a previous session) rather than being written in cleartext.
      return;
    }

    const backup = this.settings.backup;
    const secrets: Array<{ current: string; apply: (v: string) => void }> = [
      {
        current: backup.googleDrive.accessToken,
        apply: v => { backup.googleDrive.accessToken = v; }
      },
      {
        current: backup.oneDrive.accessToken,
        apply: v => { backup.oneDrive.accessToken = v; }
      },
      {
        current: backup.webdav.password,
        apply: v => { backup.webdav.password = v; }
      }
    ];

    for (const secret of secrets) {
      if (!secret.current) continue;
      if (isEncryptedCredential(secret.current)) continue;
      try {
        const encrypted = await encryptCredential(vaultKey, secret.current);
        secret.apply(encrypted);
      } catch (err) {
        console.error('[MySecret] Could not encrypt a cloud credential:', err);
      }
    }
  }

  /**
   * Returns a copy of the backup settings with the cloud credentials
   * decrypted, ready to be handed to a cloud provider.
   *
   * @returns null when the vault is locked (the credentials cannot be used).
   */
  public async getDecryptedBackupSettings(): Promise<CloudBackupSettings | null> {
    const vaultKey = this.keyManager.getVaultKey();
    if (!vaultKey) {
      return null;
    }

    const backup = this.settings.backup;
    const resolved: CloudBackupSettings = JSON.parse(JSON.stringify(backup));

    const secrets: Array<{ stored: string; apply: (v: string) => void }> = [
      {
        stored: backup.googleDrive.accessToken,
        apply: v => { resolved.googleDrive.accessToken = v; }
      },
      {
        stored: backup.oneDrive.accessToken,
        apply: v => { resolved.oneDrive.accessToken = v; }
      },
      {
        stored: backup.webdav.password,
        apply: v => { resolved.webdav.password = v; }
      }
    ];

    for (const secret of secrets) {
      if (!secret.stored) continue;
      if (!isEncryptedCredential(secret.stored)) {
        // Legacy plain-text credential: keep it as-is (and let the migration
        // below encrypt it on the next save).
        secret.apply(secret.stored);
        continue;
      }
      try {
        const plain = await decryptCredential(vaultKey, secret.stored);
        if (plain === null) {
          throw new Error('the credential envelope could not be decrypted');
        }
        secret.apply(plain);
      } catch (err) {
        console.error('[MySecret] Could not decrypt a cloud credential:', err);
        secret.apply('');
      }
    }

    return resolved;
  }

  public async loadVaultEnvelope(): Promise<boolean> {
    try {
      const rawAdapter = this.app.vault.adapter;
      const candidatePaths = [VAULT_ENVELOPE_PATH];
      if (this.manifest?.dir) {
        const manifestEnvPath = `${this.manifest.dir}/${VAULT_ENVELOPE_FILENAME}`;
        if (!candidatePaths.includes(manifestEnvPath)) {
          candidatePaths.unshift(manifestEnvPath);
        }
      }

      for (const envPath of candidatePaths) {
        const exists = await rawAdapter.exists(envPath);
        if (exists) {
          const rawContent = await rawAdapter.read(envPath);
          const parsed: VaultEnvelopeConfig = JSON.parse(rawContent);
          this.keyManager.setEnvelope(parsed);
          this.settings.isInitialized = true;
          await this.saveSettings();
          return true;
        }
      }
    } catch (err) {
      console.warn('[MySecret] Could not load vault-envelope.json:', err);
    }
    return false;
  }

  public async saveVaultEnvelope(config?: VaultEnvelopeConfig): Promise<void> {
    const envelopeToSave = config || this.keyManager.getEnvelope();
    if (!envelopeToSave) {
      throw new Error('[MySecret] No hay configuración de sobre (envelope) para guardar');
    }
    const rawAdapter = this.app.vault.adapter;
    const targetDir = this.manifest?.dir || `.obsidian/plugins/${PLUGIN_ID}`;
    const targetPath = `${targetDir}/${VAULT_ENVELOPE_FILENAME}`;

    if (!(await rawAdapter.exists(targetDir))) {
      await rawAdapter.mkdir(targetDir);
    }
    await rawAdapter.write(targetPath, JSON.stringify(envelopeToSave, null, 2));

    // Also keep fallback path in sync if targetDir is different
    if (targetPath !== VAULT_ENVELOPE_PATH) {
      try {
        const fallbackDir = `.obsidian/plugins/${PLUGIN_ID}`;
        if (!(await rawAdapter.exists(fallbackDir))) {
          await rawAdapter.mkdir(fallbackDir);
        }
        await rawAdapter.write(VAULT_ENVELOPE_PATH, JSON.stringify(envelopeToSave, null, 2));
      } catch {
        // Fallback sync is best effort
      }
    }

    this.keyManager.setEnvelope(envelopeToSave);
    this.settings.isInitialized = true;
    await this.saveSettings();
  }

  // --- Auto-Backup Engine & Timers ---

  public initAutoBackupTimer(): void {
    if (this.autoBackupIntervalTimer) {
      clearInterval(this.autoBackupIntervalTimer);
      this.autoBackupIntervalTimer = null;
    }

    // Check periodically (every 15 minutes) if an interval auto-backup is due
    this.autoBackupIntervalTimer = setInterval(() => {
      if (
        this.settings.backup.autoBackup &&
        (this.settings.backup.autoBackupTrigger === 'interval' || this.settings.backup.autoBackupTrigger === 'both')
      ) {
        this.runBackgroundAutoBackup('interval');
      }
    }, 15 * 60 * 1000);
  }

  public async runBackgroundAutoBackup(
    triggerReason: 'on-lock' | 'interval',
    preResolved?: CloudBackupSettings | null
  ): Promise<void> {
    if (this.isAutoBackupRunning) return;
    if (!this.settings.backup.autoBackup || this.settings.backup.provider === 'none') return;

    if (triggerReason === 'interval') {
      const minIntervalMs = this.settings.backup.autoBackupIntervalHours * 60 * 60 * 1000;
      const elapsed = Date.now() - (this.settings.backup.lastBackupTimestamp || 0);
      if (elapsed < minIntervalMs) {
        return;
      }
    }

    // SECURITY: the credentials are encrypted with the vault key, so they can
    // only be decrypted while the vault is unlocked. When the trigger is
    // "on-lock" the caller resolves them BEFORE wiping the keys.
    const resolvedConfig = preResolved !== undefined
      ? preResolved
      : await this.getDecryptedBackupSettings();

    if (!resolvedConfig) {
      console.warn('[MySecret] Auto-backup skipped: the vault must be unlocked to use the cloud credentials.');
      return;
    }
    const provider = createCloudProvider(resolvedConfig);
    if (!provider) return;

    this.isAutoBackupRunning = true;
    console.log(`[MySecret] Triggering background auto-backup (${triggerReason}) to ${provider.name}...`);

    try {
      const result = await BackupEngine.createVaultZip(this, {
        mode: 'encrypted',
        includeAttachments: this.settings.encryptAttachments,
        includeEnvelope: true
      });

      const uploadResult = await provider.uploadBackup(result.filename, result.zipBytes);
      if (uploadResult.success) {
        this.settings.backup.lastBackupTimestamp = Date.now();
        await this.saveSettings();
        console.log(`[MySecret] Auto-backup succeeded: ${result.filename}`);
        new Notice(`☁️ MySecret: Copia de seguridad automática subida a ${provider.name}.`);
      } else {
        console.warn(`[MySecret] Auto-backup upload warning:`, uploadResult.message);
      }
    } catch (err) {
      console.error('[MySecret] Auto-backup error:', err);
    } finally {
      this.isAutoBackupRunning = false;
    }
  }

  // --- Workspace Leaves Preservation on Lock ---

  public preserveAndCloseOpenNotes(): void {
    this.savedOpenLeaves = [];
    const leafTypes = ['markdown', 'image', 'canvas', 'pdf'];
    const leaves: any[] = [];
    for (const type of leafTypes) {
      leaves.push(...this.app.workspace.getLeavesOfType(type));
    }

    for (const leaf of leaves) {
      const view = leaf.view;
      const file = (view as any)?.file;
      if (file instanceof TFile) {
        this.savedOpenLeaves.push({
          path: file.path,
          state: leaf.getViewState(),
          eState: typeof leaf.getEphemeralState === 'function' ? leaf.getEphemeralState() : undefined
        });
      }
      leaf.detach();
    }
  }

  public async restoreSavedOpenNotes(): Promise<void> {
    if (!this.savedOpenLeaves || this.savedOpenLeaves.length === 0) return;
    const leavesToRestore = [...this.savedOpenLeaves];
    this.savedOpenLeaves = [];

    for (const saved of leavesToRestore) {
      const file = this.app.vault.getAbstractFileByPath(saved.path);
      if (file instanceof TFile) {
        try {
          const leaf = this.app.workspace.getLeaf('tab');
          await leaf.openFile(file, saved.state);
          if (saved.eState && typeof leaf.setEphemeralState === 'function') {
            leaf.setEphemeralState(saved.eState);
          }
        } catch (err) {
          console.warn(`[MySecret] Could not restore open note: ${saved.path}`, err);
        }
      }
    }
  }

  // --- Vault Locking & Unlocking ---

  public lockVault(): void {
    if (this.keyManager.isLocked) return;

    // 1. Wipe media cache and revoke all in-memory Blob URLs
    if (this.mediaManager) {
      this.mediaManager.revokeAll();
    }

    // 2. Preserve and close all open notes and editor leaves
    this.preserveAndCloseOpenNotes();

    // 3. Cloak entire workspace against visual inspection
    document.body.classList.add('is-mysecret-locked');

    // SECURITY: the cloud credentials are encrypted with the vault key. The
    // "on-lock" auto-backup must therefore resolve them BEFORE the key is
    // wiped from RAM, otherwise the upload could never authenticate.
    const needsBackupOnLock =
      this.settings.backup.autoBackup &&
      (this.settings.backup.autoBackupTrigger === 'on-lock' ||
        this.settings.backup.autoBackupTrigger === 'both');

    let pendingBackup: Promise<void> | null = null;
    if (needsBackupOnLock) {
      pendingBackup = (async () => {
        const resolved = await this.getDecryptedBackupSettings();
        await this.runBackgroundAutoBackup('on-lock', resolved);
      })();
    }

    this.keyManager.lock();
    this.updateRibbonIcon();
    new Notice(`🔒 ${t('notices.vaultLocked')}`);
    this.openLockScreen();

    if (pendingBackup) {
      pendingBackup.catch(err => {
        console.error('[MySecret] Auto-backup on lock failed:', err);
      });
    }
  }

  public unlockVaultSuccess(): void {
    document.body.classList.remove('is-mysecret-locked');
    this.updateRibbonIcon();
    this.resetInactivityTimer();
    new Notice(`🔓 ${t('notices.vaultUnlocked')}`);
    if (this.currentLockModal) {
      const modal = this.currentLockModal;
      this.currentLockModal = null;
      modal.forceClose();
    }
    // Restore notes that were open before locking
    void this.restoreSavedOpenNotes();
  }

  public onLockModalClosed(modal: LockScreenModal): void {
    if (this.currentLockModal === modal) {
      this.currentLockModal = null;
    }
  }

  public updateRibbonIcon(): void {
    if (!this.ribbonIconEl) return;
    if (this.keyManager.isLocked) {
      this.ribbonIconEl.setAttribute('aria-label', t('ribbon.lockedTooltip'));
      this.ribbonIconEl.classList.add('mysecret-locked');
      this.ribbonIconEl.classList.remove('mysecret-unlocked');
    } else {
      this.ribbonIconEl.setAttribute('aria-label', t('ribbon.unlockedTooltip'));
      this.ribbonIconEl.classList.remove('mysecret-locked');
      this.ribbonIconEl.classList.add('mysecret-unlocked');
    }
  }

  public resetInactivityTimer(): void {
    if (this.inactivityTimer) {
      clearTimeout(this.inactivityTimer);
      this.inactivityTimer = null;
    }

    if (this.keyManager.isLocked || this.settings.autoLockMinutes <= 0) {
      return;
    }

    const timeoutMs = this.settings.autoLockMinutes * 60 * 1000;
    this.inactivityTimer = setTimeout(() => {
      console.log(`[MySecret] Auto-lock fired after ${this.settings.autoLockMinutes} minutes of inactivity.`);
      this.lockVault();
    }, timeoutMs);
  }

  // --- Modals & User Prompts ---

  public openLockScreen(): void {
    if (this.currentLockModal) {
      if (this.currentLockModal.isModalClosed() || !document.contains(this.currentLockModal.containerEl)) {
        this.currentLockModal = null;
      } else {
        this.currentLockModal.focusPasswordInput();
        return;
      }
    }
    this.currentLockModal = new LockScreenModal(this.app, this);
    this.currentLockModal.open();
  }

  public openSetupWizard(): void {
    const wizard = new SetupWizardModal(this.app, this);
    wizard.open();
  }

  public openMigrationModal(mode: 'encrypt' | 'decrypt'): void {
    if (this.keyManager.isLocked) {
      new Notice('Debes desbloquear la bóveda antes de realizar operaciones de migración.');
      this.openLockScreen();
      return;
    }
    const modal = new MigrationModal(this.app, this, mode);
    modal.open();
  }

  public promptChangePassword(): void {
    if (this.keyManager.isLocked) {
      new Notice('Debes desbloquear la bóveda antes de cambiar la contraseña.');
      this.openLockScreen();
      return;
    }
    // Trigger password change prompt.
    // SECURITY: `window.prompt` renders the master password in cleartext and
    // cannot be masked, so a dedicated masked modal is used instead.
    const newPassModal = new ChangePasswordModal(this.app, this);
    newPassModal.open();
  }

  public hasRecoveryPhrase(): boolean {
    return Boolean(this.keyManager.hasRecoveryEnvelope());
  }

  public promptShowRecoveryPhrase(): void {
    if (this.keyManager.isLocked) {
      new Notice('Debes desbloquear la bóveda primero.');
      this.openLockScreen();
      return;
    }

    if (!this.hasRecoveryPhrase()) {
      new Notice('Esta bóveda está en modo de máxima seguridad: la frase de recuperación está desactivada.');
      return;
    }

    // The phrase is kept in RAM (never on disk) so the user can display it
    // again if the setup wizard was closed before it was written down.
    const mnemonic = this.keyManager.getRecoveryMnemonic();
    if (!mnemonic) {
      new Notice('La frase de recuperación no está en memoria en esta sesión. Si la anotaste al configurar la bóveda, sigue usándola.');
      return;
    }
    new RecoveryPhraseModal(this.app, mnemonic).open();
  }

  public async enableRecoveryPhrase(): Promise<string | null> {
    if (this.keyManager.isLocked) {
      new Notice('Debes desbloquear la bóveda primero.');
      this.openLockScreen();
      return null;
    }
    const result = await this.keyManager.addRecoveryPhrase();
    await this.saveVaultEnvelope(result.envelope);
    new Notice('✅ Frase de recuperación activada.');
    return result.mnemonic;
  }

  public async disableRecoveryPhrase(): Promise<boolean> {
    if (this.keyManager.isLocked) {
      new Notice('Debes desbloquear la bóveda primero.');
      this.openLockScreen();
      return false;
    }
    const updatedEnvelope = this.keyManager.removeRecoveryPhrase();
    await this.saveVaultEnvelope(updatedEnvelope);
    new Notice('🛡️ Frase de recuperación eliminada. Solo podrás acceder con tu contraseña.');
    return true;
  }

  // --- Folder Exclusion Management ---

  public isFolderExcluded(folderPath: string): boolean {
    const normalized = this.pathFilter.normalizePath(folderPath);
    return this.settings.excludedFolders.some(
      f => this.pathFilter.normalizePath(f) === normalized
    );
  }

  public async addExcludedFolder(folderPath: string): Promise<boolean> {
    const normalized = this.pathFilter.normalizePath(folderPath);
    if (!normalized) {
      new Notice('Introduce una ruta de carpeta válida.');
      return false;
    }

    if (this.isFolderExcluded(normalized)) {
      new Notice(`La carpeta "${normalized}" ya está en la lista de exclusiones.`);
      return false;
    }

    if (this.pathFilter.isUserExcluded(normalized)) {
      new Notice(`La carpeta "${normalized}" ya está excluida por una carpeta superior.`);
      return false;
    }

    this.settings.excludedFolders.push(normalized);
    await this.saveSettings();
    this.pathFilter.updateConfig(
      this.settings.excludedFolders,
      this.settings.encryptAttachments
    );
    new Notice(`Carpeta "${normalized}" excluida del cifrado.`);
    return true;
  }

  public async removeExcludedFolder(folderPath: string): Promise<boolean> {
    const normalized = this.pathFilter.normalizePath(folderPath);
    const initialLen = this.settings.excludedFolders.length;
    this.settings.excludedFolders = this.settings.excludedFolders.filter(
      f => this.pathFilter.normalizePath(f) !== normalized
    );

    if (this.settings.excludedFolders.length !== initialLen) {
      await this.saveSettings();
      this.pathFilter.updateConfig(
        this.settings.excludedFolders,
        this.settings.encryptAttachments
      );
      new Notice(`Carpeta "${normalized}" eliminada de exclusiones.`);
      return true;
    }
    return false;
  }

  public async toggleFolderExclusion(folderPath: string): Promise<boolean> {
    const normalized = this.pathFilter.normalizePath(folderPath);
    if (this.isFolderExcluded(normalized)) {
      await this.removeExcludedFolder(normalized);
      return false;
    } else {
      await this.addExcludedFolder(normalized);
      return true;
    }
  }
}

