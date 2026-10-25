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
}
