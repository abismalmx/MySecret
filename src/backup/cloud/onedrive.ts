/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Microsoft OneDrive Cloud Provider (Microsoft Graph API)
 */

import { requestHttp, toExactArrayBuffer } from '../../utils/http';
import { CloudProvider, CloudPruneResult, CloudTestResult, CloudUploadResult } from './provider-interface';
import { selectBackupsToDelete } from './retention';

export class OneDriveProvider implements CloudProvider {
  public readonly id = 'onedrive';
  public readonly name = 'Microsoft OneDrive';

  private accessToken: string;
  private folderPath: string;

  constructor(accessToken: string, folderPath: string = 'MySecretBackups') {
    this.accessToken = accessToken.trim();
    this.folderPath = folderPath.trim().replace(/^\/+|\/+$/g, '') || 'MySecretBackups';
  }

  public async testConnection(): Promise<CloudTestResult> {
    if (!this.accessToken) {
      return {
        success: false,
        message: 'No se ha configurado un Token de Acceso para Microsoft OneDrive.'
      };
    }

    try {
      const response = await requestHttp({
        url: 'https://graph.microsoft.com/v1.0/me/drive',
        method: 'GET',
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          Accept: 'application/json'
        }
      });

      if (response.status === 200) {
        const data = response.json;
        const owner = data.owner?.user?.displayName || 'Usuario de OneDrive';
        const driveType = data.driveType || 'Personal';
        return {
          success: true,
          message: `Conexión exitosa con Microsoft OneDrive (${owner} - Tipo: ${driveType}).`,
          details: data
        };
      } else {
        return {
          success: false,
          message: `Error de OneDrive (Código ${response.status}): ${response.text}`
        };
      }
    } catch (err: any) {
      return {
        success: false,
        message: `Fallo al conectar con Microsoft OneDrive: ${err?.message || String(err)}`
      };
    }
  }

  public async uploadBackup(filename: string, data: Uint8Array): Promise<CloudUploadResult> {
    if (!this.accessToken) {
      return {
        success: false,
        message: 'Token de acceso no configurado.'
      };
    }

    try {
      // Clean path encoding for Microsoft Graph API
      const safeFolder = encodeURIComponent(this.folderPath).replace(/%2F/g, '/');
      const safeFilename = encodeURIComponent(filename);
      const uploadUrl = `https://graph.microsoft.com/v1.0/me/drive/root:/${safeFolder}/${safeFilename}:/content`;

      const response = await requestHttp({
        url: uploadUrl,
        method: 'PUT',
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'Content-Type': 'application/zip'
        },
        body: toExactArrayBuffer(data)
      });

      if (response.status === 200 || response.status === 201) {
        const resJson = response.json;
        return {
          success: true,
          remoteId: resJson.id,
          remotePath: `${this.folderPath}/${filename}`,
          bytesUploaded: data.length,
          message: `Copia de seguridad subida correctamente a OneDrive (${this.folderPath}/${filename}).`
        };
      } else {
        return {
          success: false,
          message: `Error al subir a OneDrive (Código ${response.status}): ${response.text}`
        };
      }
    } catch (err: any) {
      return {
        success: false,
        message: `Error de red al subir a OneDrive: ${err?.message || String(err)}`
      };
    }
  }

  /**
   * OneDrive sends deleted items to the recycle bin (recoverable).
   */
  public async pruneBackups(filenamePrefix: string, keep: number): Promise<CloudPruneResult> {
    if (!this.accessToken) return { deleted: 0, failed: 0, message: 'Token de acceso no configurado.' };
    const auth = { Authorization: `Bearer ${this.accessToken}`, Accept: 'application/json' };
    const safeFolder = encodeURIComponent(this.folderPath).replace(/%2F/g, '/');

    const items: Array<{ id: string; name: string }> = [];
    let url: string | null =
      `https://graph.microsoft.com/v1.0/me/drive/root:/${safeFolder}:/children?$select=id,name&$top=200`;
    while (url) {
      const res = await requestHttp({ url, method: 'GET', headers: auth });
      if (res.status !== 200 || !res.json) {
        return { deleted: 0, failed: 0, message: `No se pudo listar OneDrive (Código ${res.status}).` };
      }
      for (const f of res.json.value || []) {
        if (f && typeof f.id === 'string' && typeof f.name === 'string') items.push(f);
      }
      const next: unknown = res.json['@odata.nextLink'];
      // Only follow pagination links that stay on Microsoft Graph.
      url = typeof next === 'string' && next.startsWith('https://graph.microsoft.com/') ? next : null;
    }

    let deleted = 0;
    let failed = 0;
    for (const item of selectBackupsToDelete(items, filenamePrefix, keep)) {
      try {
        const res = await requestHttp({
          url: `https://graph.microsoft.com/v1.0/me/drive/items/${encodeURIComponent(item.id)}`,
          method: 'DELETE',
          headers: auth
        });
        if (res.status === 204 || res.status === 200 || res.status === 404) deleted++;
        else failed++;
      } catch {
        failed++;
      }
    }
    return { deleted, failed };
  }
}
