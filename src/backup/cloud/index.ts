/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Cloud Provider Registry & Factory
 */

import { CloudBackupSettings } from '../../types';
import { CloudProvider } from './provider-interface';
import { GoogleDriveProvider } from './google-drive';
import { OneDriveProvider } from './onedrive';
import { WebDAVProvider } from './webdav';
import { LocalSyncProvider } from './local-sync';

export * from './provider-interface';
export * from './google-drive';
export * from './onedrive';
export * from './webdav';
export * from './local-sync';

export function createCloudProvider(settings: CloudBackupSettings): CloudProvider | null {
  switch (settings.provider) {
    case 'google-drive':
      return new GoogleDriveProvider(
        settings.googleDrive.accessToken,
        settings.googleDrive.folderId
      );
    case 'onedrive':
      return new OneDriveProvider(
        settings.oneDrive.accessToken,
        settings.oneDrive.folderPath
      );
    case 'webdav':
      return new WebDAVProvider(
        settings.webdav.serverUrl,
        settings.webdav.username,
        settings.webdav.password,
        settings.webdav.remotePath
      );
    case 'local-sync':
      return new LocalSyncProvider(
        settings.localSync.destinationPath
      );
    case 'none':
    default:
      return null;
  }
}
