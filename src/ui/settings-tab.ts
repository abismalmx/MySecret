/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Settings Tab: Configuration, Auto-lock timer, Exclusions & Vault Management
 */

import { App, PluginSettingTab, Setting, Notice, setIcon, Platform } from 'obsidian';
import MySecretPlugin from '../main';
import { MYSECRET_LOGO_DATA_URL } from './assets';
import { ExportModal } from './export-modal';
import { CloudBackupModal } from './cloud-backup-modal';
import { RestoreModal } from './restore-modal';
import { FolderPickerModal } from './folder-picker-modal';
import { createCloudProvider } from '../backup/cloud';
import { zeroize } from '../utils/zeroize';
import { validateBridgeUrl } from '../biometrics/bridge-url';
import { t, setI18nLanguage } from '../i18n';

/**
 * Delays a function until the user stops typing. Credential fields used to
 * encrypt and write `data.json` on every single keystroke.
 */
function debounce<A extends unknown[]>(fn: (...args: A) => void | Promise<void>, ms: number): (...args: A) => void {
  let timer: number | null = null;
  return (...args: A) => {
    if (timer !== null) window.clearTimeout(timer);
    timer = window.setTimeout(() => {
      timer = null;
      void fn(...args);
    }, ms);
  };
}

export class MySecretSettingTab extends PluginSettingTab {
  private plugin: MySecretPlugin;

  constructor(app: App, plugin: MySecretPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  public display(): void {
    const { containerEl } = this;
    containerEl.empty();

    // Brand Hero Banner with Logo
    const hero = containerEl.createDiv({ cls: 'mysecret-settings-hero' });
    const logoWrap = hero.createDiv({ cls: 'mysecret-settings-logo-wrap' });
    logoWrap.createEl('img', {
      cls: 'mysecret-settings-logo',
      attr: {
        src: MYSECRET_LOGO_DATA_URL,
        alt: 'MySecret Logo',
        draggable: 'false'
      }
    });

    const heroInfo = hero.createDiv({ cls: 'mysecret-settings-hero-info' });
    heroInfo.createDiv({ cls: 'mysecret-settings-hero-title', text: t('settings.heroTitle') });
    heroInfo.createEl('p', {
      cls: 'mysecret-settings-hero-desc',
      text: t('settings.heroDesc')
    });
    heroInfo.createEl('div', {
      text: t('settings.heroAuthor'),
      cls: 'mysecret-hero-author'
    });

    // =========================================================================
    // Section 1: Auto-Lock & Encryption
    // =========================================================================
    new Setting(containerEl).setName(t('settings.autoLockSectionTitle')).setHeading();
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: t('settings.autoLockSectionDesc')
    });

    // 1. Auto-Lock Timer
    new Setting(containerEl)
      .setName(t('settings.inactivityTimerTitle'))
      .setDesc(t('settings.inactivityTimerDesc'))
      .addDropdown(dropdown => {
        dropdown
          .addOption('0', t('settings.inactivityDisabled'))
          .addOption('1', t('settings.inactivity1Min'))
          .addOption('5', t('settings.inactivity5Min'))
          .addOption('15', t('settings.inactivity15Min'))
          .addOption('30', t('settings.inactivity30Min'))
          .setValue(String(this.plugin.settings.autoLockMinutes))
          .onChange(async value => {
            this.plugin.settings.autoLockMinutes = parseInt(value, 10);
            await this.plugin.saveSettings();
            this.plugin.resetInactivityTimer();
          });
      });

    // 2. Lock on blur
    new Setting(containerEl)
      .setName(t('settings.lockOnBlurTitle'))
      .setDesc(t('settings.lockOnBlurDesc'))
      .addToggle(toggle => {
        toggle
          .setValue(this.plugin.settings.lockOnBlur)
          .onChange(async value => {
            this.plugin.settings.lockOnBlur = value;
            await this.plugin.saveSettings();
          });
      });

    // 3. Encrypt Attachments
    new Setting(containerEl)
      .setName(t('settings.encryptAttachmentsTitle'))
      .setDesc(t('settings.encryptAttachmentsDesc'))
      .addToggle(toggle => {
        toggle
          .setValue(this.plugin.settings.encryptAttachments)
          .onChange(async value => {
            // Turning attachment encryption OFF first converts the already
            // encrypted attachments back to plaintext, otherwise they would be
            // served as raw ciphertext and corrupted by the next save.
            const applied = await this.plugin.setEncryptAttachments(value);
            if (!applied) {
              toggle.setValue(!value);
            }
          });
      });

    // =========================================================================
    // Section 1b: Biometrics
    // =========================================================================
    new Setting(containerEl).setName(t('settings.biometricsSectionTitle')).setHeading();
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: t('settings.biometricsSectionDesc')
    });

    const isAndroid = Platform.isAndroidApp;
    const vaultId = this.plugin.getVaultId();
    const isEnrolled = this.plugin.biometricManager.isBiometricsEnrolled(vaultId);
    const isEnabled = Boolean(this.plugin.settings.biometrics?.enabled && isEnrolled);

    if (isAndroid) {
      const androidInfo = containerEl.createDiv({ cls: 'setting-item-description mysecret-android-bridge-notice' });
      androidInfo.setText(t('settings.androidBridgeNotice'));

      new Setting(containerEl)
        .setName(t('settings.androidBridgeUrlTitle'))
        .setDesc(t('settings.androidBridgeUrlDesc'))
        .addText(text => {
          text
            .setPlaceholder(t('settings.androidBridgePlaceholder'))
            .setValue(this.plugin.settings.biometrics?.bridgeUrl || '')
            .onChange(async val => {
              const trimmed = (val || '').trim();
              let normalized = '';
              if (trimmed) {
                const validation = validateBridgeUrl(trimmed);
                if (!validation.valid) {
                  new Notice(`⚠️ ${validation.reason}`);
                  return;
                }
                normalized = validation.url;
              }
              if (!this.plugin.settings.biometrics) {
                this.plugin.settings.biometrics = { enabled: false, autoPrompt: true, bridgeUrl: normalized };
              } else {
                this.plugin.settings.biometrics.bridgeUrl = normalized;
              }
              this.plugin.biometricManager.setBridgeUrl(normalized);
              await this.plugin.saveSettings();
            });
        })
        .addButton(btn => {
          btn.setButtonText(t('settings.testBridgeBtn')).onClick(() => {
            const url = this.plugin.settings.biometrics?.bridgeUrl;
            if (!url) {
              new Notice(t('settings.bridgeInvalidError'));
              return;
            }
            const validation = validateBridgeUrl(url);
            if (!validation.valid) {
              new Notice(`⚠️ ${validation.reason}`);
              return;
            }
            window.open(validation.url, '_system');
          });
        });
    }

    new Setting(containerEl)
      .setName(t('settings.enableBiometricsTitle'))
      .setDesc(
        isEnrolled
          ? t('settings.biometricsEnrolledDevice')
          : t('settings.biometricsNotEnrolledDevice')
      )
      .addToggle(toggle => {
        toggle.setValue(isEnabled).onChange(async value => {
          if (value) {
            if (isAndroid) {
              const url = this.plugin.settings.biometrics?.bridgeUrl;
              if (!url) {
                new Notice(t('settings.androidBridgeNotice'));
                toggle.setValue(false);
                return;
              }
            }
            // Enable / enroll: the master password is asked again, because
            // enrolling hands the vault key to a device-local unlock path.
            if (!(await this.plugin.requireReauth())) {
              toggle.setValue(false);
              return;
            }
            const rawKey = this.plugin.keyManager.getRawVaultKey();
            if (!rawKey) {
              new Notice(t('notices.vaultNotInitialized'));
              toggle.setValue(false);
              return;
            }
            try {
              new Notice(isAndroid ? t('settings.enrollBiometricPrompt') : t('settings.testBiometricsWaiting'));
              const success = await this.plugin.biometricManager.enrollBiometrics(rawKey, vaultId);
              if (success) {
                if (!this.plugin.settings.biometrics) {
                  this.plugin.settings.biometrics = {
                    enabled: true,
                    autoPrompt: true,
                    bridgeUrl: this.plugin.biometricManager.getBridgeUrl()
                  };
                } else {
                  this.plugin.settings.biometrics.enabled = true;
                }
                await this.plugin.saveSettings();
                new Notice(t('settings.biometricsActiveNotice'));
                this.display();
              } else {
                toggle.setValue(false);
              }
            } catch (err: any) {
              new Notice(`${t('common.error')}: ${err?.message || String(err)}`);
              toggle.setValue(false);
            } finally {
              zeroize(rawKey);
            }
          } else {
            // Disable
            this.plugin.biometricManager.disableBiometrics(vaultId);
            if (this.plugin.settings.biometrics) {
              this.plugin.settings.biometrics.enabled = false;
            }
            await this.plugin.saveSettings();
            new Notice(t('settings.biometricsRemovedNotice'));
            this.display();
          }
        });
      });

    if (isEnrolled) {
      new Setting(containerEl)
        .setName(t('settings.autoPromptBiometricsTitle'))
        .setDesc(t('settings.autoPromptBiometricsDesc'))
        .addToggle(toggle => {
          toggle
            .setValue(this.plugin.settings.biometrics?.autoPrompt !== false)
            .onChange(async val => {
              if (!this.plugin.settings.biometrics) {
                this.plugin.settings.biometrics = { enabled: true, autoPrompt: val };
              } else {
                this.plugin.settings.biometrics.autoPrompt = val;
              }
              await this.plugin.saveSettings();
            });
        });

      new Setting(containerEl)
        .setName(t('settings.testBiometricsTitle'))
        .setDesc(t('settings.testBiometricsDesc'))
        .addButton(btn => {
          btn.setButtonText(t('settings.testBiometricsBtn')).onClick(async () => {
            btn.setDisabled(true);
            btn.setButtonText(t('settings.testBiometricsWaiting'));
            let decryptedKey: Uint8Array | null = null;
            try {
              decryptedKey = await this.plugin.biometricManager.unlockWithBiometrics(vaultId);
              if (decryptedKey && decryptedKey.length === 32) {
                new Notice(t('settings.testBiometricsSuccess'));
              } else {
                new Notice(t('settings.testBiometricsFailed'));
              }
            } catch (err: any) {
              new Notice(`${t('common.error')}: ${err?.message || String(err)}`);
            } finally {
              if (decryptedKey) zeroize(decryptedKey);
              btn.setDisabled(false);
              btn.setButtonText(t('settings.testBiometricsBtn'));
            }
          });
        });
    }

    // =========================================================================
    // Section 2: Excluded Folders
    // =========================================================================
    new Setting(containerEl).setName(t('settings.exclusionsSectionTitle')).setHeading();
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: t('settings.exclusionsSectionDesc')
    });

    new Setting(containerEl)
      .setName(t('settings.addFolderExclusionBtn'))
      .setDesc(t('settings.addFolderExclusionDesc'))
      .addButton(btn => {
        btn
          .setButtonText(t('settings.chooseFolderBtn'))
          .setIcon('folder-search')
          .setCta()
          .setTooltip(t('settings.chooseFolderTooltip'))
          .onClick(() => {
            new FolderPickerModal(
              this.app,
              this.plugin.settings.excludedFolders,
              async folder => {
                await this.plugin.addExcludedFolder(folder.path);
                renderFolderList();
              }
            ).open();
          });
      });

    // Visual container for excluded folders
    const foldersContainer = containerEl.createDiv({ cls: 'mysecret-excluded-folders-wrap' });

    // Secondary action: manual folder path input
    const manualWrap = foldersContainer.createDiv({ cls: 'mysecret-manual-folder-input-wrap' });
    const manualInput = manualWrap.createEl('input', {
      type: 'text',
      cls: 'mysecret-manual-input',
      placeholder: t('settings.manualPathPlaceholder')
    });
    const addManualBtn = manualWrap.createEl('button', {
      cls: 'mod-cta mysecret-manual-add-btn',
      text: t('settings.addBtn')
    });

    const handleAddManual = async () => {
      const val = manualInput.value.trim();
      if (!val) {
        new Notice(t('folderPicker.emptyText'));
        return;
      }
      const added = await this.plugin.addExcludedFolder(val);
      if (added) {
        manualInput.value = '';
        renderFolderList();
      }
    };

    addManualBtn.addEventListener('click', handleAddManual);
    manualInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleAddManual();
      }
    });

    // Chips list
    const listEl = foldersContainer.createDiv({ cls: 'mysecret-excluded-list' });

    const renderFolderList = () => {
      listEl.empty();
      const current = this.plugin.settings.excludedFolders;

      if (!current || current.length === 0) {
        const emptyEl = listEl.createDiv({ cls: 'mysecret-excluded-empty' });
        const iconSpan = emptyEl.createSpan({ cls: 'mysecret-excluded-empty-icon' });
        setIcon(iconSpan, 'shield-check');
        emptyEl.createSpan({
          text: t('settings.noExclusions')
        });
        return;
      }

      for (const folder of current) {
        const chip = listEl.createDiv({ cls: 'mysecret-folder-chip' });

        const folderIcon = chip.createSpan({ cls: 'mysecret-folder-chip-icon' });
        setIcon(folderIcon, 'folder');

        chip.createSpan({ cls: 'mysecret-folder-chip-path', text: folder });

        const removeBtn = chip.createSpan({
          cls: 'mysecret-folder-chip-remove',
          attr: {
            'aria-label': t('settings.removeExclusionAria', { folder }),
            title: t('common.delete')
          }
        });
        setIcon(removeBtn, 'x');

        removeBtn.addEventListener('click', async e => {
          e.stopPropagation();
          await this.plugin.removeExcludedFolder(folder);
          renderFolderList();
        });
      }
    };

    renderFolderList();

    // =========================================================================
    // Section 3: Password & Recovery Phrase
    // =========================================================================
    new Setting(containerEl).setName(t('settings.recoverySectionTitle')).setHeading();
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: t('settings.recoverySectionDesc')
    });

    // Change Master Password
    new Setting(containerEl)
      .setName(t('settings.changePasswordTitle'))
      .setDesc(t('settings.changePasswordDesc'))
      .addButton(button => {
        button
          .setButtonText(t('settings.changePasswordBtn'))
          .setCta()
          .onClick(() => {
            this.plugin.promptChangePassword();
          });
      });

    // Recovery Phrase management
    if (this.plugin.hasRecoveryPhrase()) {
      new Setting(containerEl)
        .setName(t('settings.viewRecoveryTitle'))
        .setDesc(t('settings.viewRecoveryDesc'))
        .addButton(button => {
          button
            .setButtonText(t('settings.showPhraseBtn'))
            .onClick(() => {
              void this.plugin.promptShowRecoveryPhrase();
            });
        });

      new Setting(containerEl)
        .setName(t('settings.deleteRecoveryTitle'))
        .setDesc(t('settings.deleteRecoveryDesc'))
        .addButton(button => {
          button
            .setButtonText(t('settings.deletePhraseBtn'))
            .setWarning()
            .onClick(async () => {
              const confirmed = window.confirm(t('settings.deletePhraseConfirm'));
              if (confirmed) {
                await this.plugin.disableRecoveryPhrase();
                this.display();
              }
            });
        });
    } else {
      new Setting(containerEl)
        .setName(t('commands.showRecoveryPhrase'))
        .setDesc(t('settings.recoveryDisabledDesc'))
        .addButton(button => {
          button
            .setButtonText(t('settings.enableRecoveryBtn'))
            .setCta()
            .onClick(async () => {
              const mnemonic = await this.plugin.enableRecoveryPhrase();
              this.display();
              if (mnemonic) {
                void this.plugin.promptShowRecoveryPhrase();
              }
            });
        });
    }

    // =========================================================================
    // Section 4: Cloud Backups
    // =========================================================================
    new Setting(containerEl).setName(t('settings.backupSectionTitle')).setHeading();
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: t('settings.backupSectionDesc')
    });

    // Active Cloud Provider
    new Setting(containerEl)
      .setName(t('settings.storageProviderTitle'))
      .setDesc(t('settings.storageProviderDesc'))
      .addDropdown(dropdown => {
        dropdown
          .addOption('none', t('settings.providerNone'))
          .addOption('google-drive', t('settings.providerGoogleDrive'))
          .addOption('onedrive', t('settings.providerOneDrive'))
          .addOption('webdav', t('settings.providerWebdav'))
          .addOption('local-sync', t('settings.providerLocalSync'))
          .setValue(this.plugin.settings.backup.provider)
          .onChange(async value => {
            this.plugin.settings.backup.provider = value as any;
            await this.plugin.saveSettings();
            this.display();
          });
      });

    // Dynamic Provider Inputs Container
    const providerContainer = containerEl.createDiv({ cls: 'mysecret-provider-settings-wrap' });

    if (this.plugin.settings.backup.provider === 'google-drive') {
      new Setting(providerContainer)
        .setName(t('settings.gdriveTokenTitle'))
        .setDesc(t('settings.gdriveTokenDesc'))
        .addText(text => {
          text
            .setPlaceholder('ya29.a0AfH6SM...')
            .setValue(this.plugin.getCredentialDisplayValue(this.plugin.settings.backup.googleDrive.accessToken))
            .onChange(debounce(async (val: string) => {
              await this.plugin.setEncryptedCredential('googleDriveAccessToken', val);
            }, 600));
          text.inputEl.type = 'password';
        });

      new Setting(providerContainer)
        .setName(t('settings.gdriveFolderTitle'))
        .setDesc(t('settings.gdriveFolderDesc'))
        .addText(text => {
          text
            .setPlaceholder('1AbCdEfGhIjKlMnOpQrStUvWxYz')
            .setValue(this.plugin.settings.backup.googleDrive.folderId)
            .onChange(async val => {
              this.plugin.settings.backup.googleDrive.folderId = val;
              await this.plugin.saveSettings();
            });
        });
    } else if (this.plugin.settings.backup.provider === 'onedrive') {
      new Setting(providerContainer)
        .setName(t('settings.onedriveTokenTitle'))
        .setDesc(t('settings.onedriveTokenDesc'))
        .addText(text => {
          text
            .setPlaceholder('EwBoA8l6BAAU...')
            .setValue(this.plugin.getCredentialDisplayValue(this.plugin.settings.backup.oneDrive.accessToken))
            .onChange(debounce(async (val: string) => {
              await this.plugin.setEncryptedCredential('oneDriveAccessToken', val);
            }, 600));
          text.inputEl.type = 'password';
        });

      new Setting(providerContainer)
        .setName(t('settings.onedriveFolderTitle'))
        .setDesc(t('settings.onedriveFolderDesc'))
        .addText(text => {
          text
            .setPlaceholder('MySecretBackups')
            .setValue(this.plugin.settings.backup.oneDrive.folderPath)
            .onChange(async val => {
              this.plugin.settings.backup.oneDrive.folderPath = val;
              await this.plugin.saveSettings();
            });
        });
    } else if (this.plugin.settings.backup.provider === 'webdav') {
      new Setting(providerContainer)
        .setName(t('settings.webdavUrlTitle'))
        .setDesc(t('settings.webdavUrlDesc'))
        .addText(text => {
          text
            .setPlaceholder('https://nextcloud.ejemplo.com/remote.php/webdav')
            .setValue(this.plugin.settings.backup.webdav.serverUrl)
            .onChange(async val => {
              this.plugin.settings.backup.webdav.serverUrl = val;
              await this.plugin.saveSettings();
            });
        });

      new Setting(providerContainer)
        .setName(t('settings.webdavUserTitle'))
        .setDesc(t('settings.webdavUserDesc'))
        .addText(text => {
          text
            .setPlaceholder('mi_usuario')
            .setValue(this.plugin.settings.backup.webdav.username)
            .onChange(async val => {
              this.plugin.settings.backup.webdav.username = val;
              await this.plugin.saveSettings();
            });
        });

      new Setting(providerContainer)
        .setName(t('settings.webdavPassTitle'))
        .setDesc(t('settings.webdavPassDesc'))
        .addText(text => {
          text
            .setPlaceholder('••••••••••••')
            .setValue(this.plugin.getCredentialDisplayValue(this.plugin.settings.backup.webdav.password))
            .onChange(debounce(async (val: string) => {
              await this.plugin.setEncryptedCredential('webdavPassword', val);
            }, 600));
          text.inputEl.type = 'password';
        });

      new Setting(providerContainer)
        .setName(t('settings.webdavFolderTitle'))
        .setDesc(t('settings.webdavFolderDesc'))
        .addText(text => {
          text
            .setPlaceholder('MySecretBackups')
            .setValue(this.plugin.settings.backup.webdav.remotePath)
            .onChange(async val => {
              this.plugin.settings.backup.webdav.remotePath = val;
              await this.plugin.saveSettings();
            });
        });
    } else if (this.plugin.settings.backup.provider === 'local-sync') {
      new Setting(providerContainer)
        .setName(t('settings.localSyncTitle'))
        .setDesc(t('settings.localSyncDesc'))
        .addText(text => {
          text
            .setPlaceholder('/home/usuario/Backups')
            .setValue(this.plugin.settings.backup.localSync.destinationPath)
            .onChange(async val => {
              this.plugin.settings.backup.localSync.destinationPath = val;
              await this.plugin.saveSettings();
            });
        });
    }

    // Test Connection Button (if a provider is chosen)
    if (this.plugin.settings.backup.provider !== 'none') {
      new Setting(containerEl)
        .setName(t('settings.testConnectionTitle'))
        .setDesc(t('settings.testConnectionDesc'))
        .addButton(button => {
          button
            .setButtonText(t('settings.testConnectionBtn'))
            .onClick(async () => {
              button.setDisabled(true);
              button.setButtonText(t('settings.testConnectionTesting'));
              try {
                const resolved = await this.plugin.getDecryptedBackupSettings();
                if (!resolved) {
                  new Notice(t('notices.vaultNotInitialized'));
                  return;
                }
                const provider = createCloudProvider(resolved);
                if (!provider) {
                  new Notice(t('settings.providerNone'));
                  return;
                }
                const result = await provider.testConnection();
                if (result.success) {
                  new Notice(`✅ ${result.message}`);
                } else {
                  new Notice(`❌ ${result.message}`);
                }
              } catch (err: any) {
                new Notice(`❌ ${t('common.error')}: ${err?.message || String(err)}`);
              } finally {
                button.setDisabled(false);
                button.setButtonText(t('settings.testConnectionBtn'));
              }
            });
        });

      // Auto-backup configuration
      new Setting(containerEl)
        .setName(t('settings.autoBackupTitle'))
        .setDesc(t('settings.autoBackupDesc'))
        .addToggle(toggle => {
          toggle
            .setValue(this.plugin.settings.backup.autoBackup)
            .onChange(async val => {
              this.plugin.settings.backup.autoBackup = val;
              await this.plugin.saveSettings();
              this.display();
            });
        });

      if (this.plugin.settings.backup.autoBackup) {
        new Setting(containerEl)
          .setName(t('settings.autoBackupTriggerTitle'))
          .setDesc(t('settings.autoBackupTriggerDesc'))
          .addDropdown(dropdown => {
            dropdown
              .addOption('on-lock', t('settings.triggerOnLock'))
              .addOption('interval', t('settings.triggerInterval'))
              .addOption('both', t('settings.triggerBoth'))
              .setValue(this.plugin.settings.backup.autoBackupTrigger)
              .onChange(async val => {
                this.plugin.settings.backup.autoBackupTrigger = val as any;
                await this.plugin.saveSettings();
              });
          });

        new Setting(containerEl)
          .setName(t('settings.frequencyTitle'))
          .setDesc(t('settings.frequencyDesc'))
          .addDropdown(dropdown => {
            dropdown
              .addOption('1', t('settings.freq1h'))
              .addOption('6', t('settings.freq6h'))
              .addOption('12', t('settings.freq12h'))
              .addOption('24', t('settings.freq24h'))
              .addOption('72', t('settings.freq72h'))
              .setValue(String(this.plugin.settings.backup.autoBackupIntervalHours))
              .onChange(async val => {
                this.plugin.settings.backup.autoBackupIntervalHours = parseInt(val, 10);
                await this.plugin.saveSettings();
              });
          });
      }
    }

    // =========================================================================
    // Section 5: Export & Restore
    // =========================================================================
    new Setting(containerEl).setName(t('settings.manualSectionTitle')).setHeading();
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: t('settings.manualSectionDesc')
    });

    // Local ZIP Export Modal trigger
    new Setting(containerEl)
      .setName(t('settings.exportZipTitle'))
      .setDesc(t('settings.exportZipDesc'))
      .addButton(button => {
        button
          .setButtonText(t('settings.exportZipBtn'))
          .setCta()
          .onClick(() => {
            new ExportModal(this.app, this.plugin).open();
          });
      });

    // Cloud Backup Modal trigger
    new Setting(containerEl)
      .setName(t('settings.uploadCloudTitle'))
      .setDesc(t('settings.uploadCloudDesc'))
      .addButton(button => {
        button
          .setButtonText(t('settings.uploadCloudBtn'))
          .onClick(() => {
            new CloudBackupModal(this.app, this.plugin).open();
          });
      });

    // Restore Backup Modal trigger
    new Setting(containerEl)
      .setName(t('settings.restoreZipTitle'))
      .setDesc(t('settings.restoreZipDesc'))
      .addButton(button => {
        button
          .setButtonText(t('settings.restoreZipBtn'))
          .onClick(() => {
            new RestoreModal(this.app, this.plugin).open();
          });
      });

    // =========================================================================
    // Section 6: Maintenance & Migration
    // =========================================================================
    new Setting(containerEl).setName(t('settings.maintenanceTitle')).setHeading();
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: t('settings.maintenanceDesc')
    });

    new Setting(containerEl)
      .setName(t('settings.bulkEncryptTitle'))
      .setDesc(t('settings.bulkEncryptDesc'))
      .addButton(button => {
        button
          .setButtonText(t('settings.bulkEncryptBtn'))
          .onClick(() => {
            this.plugin.openMigrationModal('encrypt');
          });
      });

    new Setting(containerEl)
      .setName(t('settings.bulkDecryptTitle'))
      .setDesc(t('settings.bulkDecryptDesc'))
      .addButton(button => {
        button
          .setButtonText(t('settings.bulkDecryptBtn'))
          .setWarning()
          .onClick(() => {
            this.plugin.openMigrationModal('decrypt');
          });
      });

    // =========================================================================
    // Section 7: Language Settings (ALWAYS IN ENGLISH)
    // =========================================================================
    new Setting(containerEl).setName('Language').setHeading();
    containerEl.createEl('p', {
      cls: 'setting-item-description',
      text: 'Select the display language for the plugin interface.'
    });

    new Setting(containerEl)
      .setName('Plugin Interface Language')
      .setDesc('Choose your preferred language (changes apply immediately to this settings tab).')
      .addDropdown(dropdown => {
        dropdown
          .addOption('auto', 'Auto (Follow Obsidian)')
          .addOption('en', 'English')
          .addOption('es', 'Español')
          .addOption('ru', 'Русский')
          .addOption('zh', '简体中文')
          .setValue(this.plugin.settings.language || 'auto')
          .onChange(async val => {
            this.plugin.settings.language = val as any;
            await this.plugin.saveSettings();
            setI18nLanguage(this.plugin.settings.language);
            this.plugin.updateRibbonIcon();
            this.display();
          });
      });
  }
}
