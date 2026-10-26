/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Type Definitions & Contracts
 */

export interface VaultEnvelopeConfig {
  version: number;
  /**
   * Stable identifier of the vault (hex). It is used to scope device-local
   * secrets (biometric envelopes, keyring entries). It MUST NOT change when
   * the master password changes (the Argon2 salt does), otherwise the
   * biometric enrollment would be silently orphaned.
   *
   * Envelopes created before this field existed fall back to the Argon2
   * salt that was current when the field was first introduced.
   */
  vaultId?: string;
  argon2: {
    memory: number;
    iterations: number;
    parallelism: number;
    salt: string; // Hex string (16 bytes)
  };
  vaultKeyEnvelope: {
    iv: string; // Hex string (12 bytes)
    tag: string; // Hex string (16 bytes)
    ciphertext: string; // Hex string (32 bytes AES-256 key encrypted)
  };
  recoveryEnvelope?: {
    salt: string; // Hex string (16 bytes)
    iv: string; // Hex string (12 bytes)
    tag: string; // Hex string (16 bytes)
    ciphertext: string; // Hex string (32 bytes AES-256 key encrypted)
  };
  createdAt: number;
  updatedAt: number;
}

export interface InitializeVaultResult {
  mnemonic: string | null;
  envelope: VaultEnvelopeConfig;
  commit: () => Promise<void>;
}

export interface EncryptedPayload {
  version: number;
  iv: Uint8Array;
  tag: Uint8Array;
  ciphertext: Uint8Array;
}

export type CloudProviderType = 'none' | 'google-drive' | 'onedrive' | 'webdav' | 'local-sync';

export interface CloudBackupSettings {
  provider: CloudProviderType;
  googleDrive: {
    accessToken: string;
    folderId: string;
  };
  oneDrive: {
    accessToken: string;
    folderPath: string;
  };
  webdav: {
    serverUrl: string;
    username: string;
    password: string;
    remotePath: string;
  };
  localSync: {
    destinationPath: string;
  };
  autoBackup: boolean;
  autoBackupTrigger: 'on-lock' | 'interval' | 'both';
  autoBackupIntervalHours: number;
  lastBackupTimestamp: number;
  retentionCount: number;
}

export interface BackupManifest {
  version: number;
  plugin: string;
  mode: 'encrypted' | 'decrypted';
  createdAt: number;
  vaultName: string;
  totalFiles: number;
  files: Array<{
    path: string;
    size: number;
    isEncrypted: boolean;
  }>;
}

export interface BackupSkippedFile {
  path: string;
  reason: string;
}

export interface BackupStats {
  /** Files that could NOT be included in the archive, with the reason. */
  skippedFiles?: BackupSkippedFile[];
  totalFiles: number;
  totalBytes: number;
  textNotesCount: number;
  attachmentsCount: number;
  elapsedMs: number;
}

export interface RestoreResult {
  restoredFiles: number;
  skippedFiles: number;
  errors: Array<{ path: string; error: string }>;
}

export interface PluginSettings {
  autoLockMinutes: number; // 0 = disabled, 1, 5, 15, 30, etc.
  lockOnBlur: boolean;
  excludedFolders: string[]; // List of user-excluded relative paths, e.g. ["Public", "Shared"]
  encryptAttachments: boolean;
  isInitialized: boolean;
  language?: 'auto' | 'en' | 'es' | 'ru' | 'zh';
  backup: CloudBackupSettings;
  /**
   * Renames/copies whose AAD re-binding could not be completed (vault locked,
   * crash...). They are replayed on the next unlock so no note stays bound to
   * a path it no longer has.
   */
  pendingRebinds?: Array<{ from: string; to: string }>;
  biometrics?: {
    enabled: boolean;
    autoPrompt: boolean;
    bridgeUrl?: string;
  };
}

export interface KeyManagerState {
  isLocked: boolean;
  isInitialized: boolean;
  hasVaultKey: boolean;
}

export interface MigrationProgress {
  totalFiles: number;
  processedFiles: number;
  currentFile: string;
  isComplete: boolean;
  isCancelled: boolean;
  errors: Array<{ path: string; error: string }>;
}
