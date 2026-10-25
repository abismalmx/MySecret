/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Microsoft OneDrive Cloud Provider (Microsoft Graph API)
 */

import { requestHttp, toExactArrayBuffer } from '../../utils/http';
import { CloudProvider, CloudTestResult, CloudUploadResult } from './provider-interface';

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
}
