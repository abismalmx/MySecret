/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Cloud Provider Interface & Common Contracts
 */

import { CloudProviderType } from '../../types';

export interface CloudUploadResult {
  success: boolean;
  remoteId?: string;
  remotePath?: string;
  message?: string;
  bytesUploaded?: number;
}

export interface CloudTestResult {
  success: boolean;
  message: string;
  details?: Record<string, any>;
}

export interface CloudPruneResult {
  /** Backups removed (or already gone). */
  deleted: number;
  /** Backups that should have been removed but could not be. */
  failed: number;
  message?: string;
}

export interface CloudProvider {
  readonly id: CloudProviderType;
  readonly name: string;

  /**
   * Tests connectivity, credentials and permissions with the cloud service
   */
  testConnection(): Promise<CloudTestResult>;

  /**
   * Uploads an encrypted backup zip payload to the cloud service
   */
  uploadBackup(filename: string, data: Uint8Array): Promise<CloudUploadResult>;

  /**
   * Removes the backups of this vault beyond the newest `keep`.
   *
   * `filenamePrefix` (`MySecret_<vault>_Cifrado_`) restricts the candidates
   * to this vault's files; see `retention.ts` for the selection rules.
   */
  pruneBackups(filenamePrefix: string, keep: number): Promise<CloudPruneResult>;
}
