/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Google Drive Cloud Provider (Direct API v3 Integration)
 */

import { requestHttp, toExactArrayBuffer } from '../../utils/http';
import { CloudProvider, CloudTestResult, CloudUploadResult } from './provider-interface';

/**
 * Generates a cryptographically random multipart boundary.
 *
 * SECURITY: `Math.random()` is NOT cryptographically secure. A predictable
 * boundary can be crafted by an attacker so that the boundary string appears
 * inside the uploaded payload, which would allow the payload to be reinterpreted
 * as an extra MIME part (multipart injection). We use the Web Crypto CSPRNG.
 */
function generateMultipartBoundary(): string {
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return `-------MySecretBackupBoundary${hex}`;
}

export class GoogleDriveProvider implements CloudProvider {
  public readonly id = 'google-drive';
  public readonly name = 'Google Drive';

  private accessToken: string;
  private folderId: string;

  constructor(accessToken: string, folderId: string = '') {
    this.accessToken = accessToken.trim();
    this.folderId = folderId.trim();
  }

  public async testConnection(): Promise<CloudTestResult> {
    if (!this.accessToken) {
      return {
        success: false,
        message: 'No se ha introducido un Token de Acceso (OAuth Bearer) para Google Drive.'
      };
    }

    try {
      const response = await requestHttp({
        url: 'https://www.googleapis.com/drive/v3/about?fields=user,storageQuota',
        method: 'GET',
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          Accept: 'application/json'
        }
      });

      if (response.status === 200) {
        const data = response.json;
        const userName = data.user?.displayName || 'Usuario de Google';
        const userEmail = data.user?.emailAddress || '';
        return {
          success: true,
          message: `Conexión exitosa con Google Drive (${userName}${userEmail ? ' - ' + userEmail : ''}).`,
          details: data
        };
      } else {
        return {
          success: false,
          message: `Error de Google Drive (Código ${response.status}): ${response.text}`
        };
      }
    } catch (err: any) {
      return {
        success: false,
        message: `Fallo al conectar con Google Drive: ${err?.message || String(err)}`
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
      const boundary = generateMultipartBoundary();
      const metadata: Record<string, any> = {
        name: filename,
        mimeType: 'application/zip',
        description: 'Copia de seguridad cifrada de bóveda Obsidian MySecret (AES-256-GCM)'
      };

      if (this.folderId) {
        metadata.parents = [this.folderId];
      }

      // Build multipart body
      const metadataStr = JSON.stringify(metadata);
      const headerPart = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${metadataStr}\r\n--${boundary}\r\nContent-Type: application/zip\r\n\r\n`;
      const footerPart = `\r\n--${boundary}--`;

      const encoder = new TextEncoder();
      const headerBytes = encoder.encode(headerPart);
      const footerBytes = encoder.encode(footerPart);

      // Concatenate header + binary data + footer
      const fullBody = new Uint8Array(headerBytes.length + data.length + footerBytes.length);
      fullBody.set(headerBytes, 0);
      fullBody.set(data, headerBytes.length);
      fullBody.set(footerBytes, headerBytes.length + data.length);

      const response = await requestHttp({
        url: 'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart',
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          'Content-Type': `multipart/related; boundary=${boundary}`
        },
        body: toExactArrayBuffer(fullBody)
      });

      if (response.status === 200 || response.status === 201) {
        const resJson = response.json;
        return {
          success: true,
          remoteId: resJson.id,
          bytesUploaded: data.length,
          message: `Copia de seguridad subida correctamente a Google Drive (ID: ${resJson.id}).`
        };
      } else {
        return {
          success: false,
          message: `Error al subir a Google Drive (Código ${response.status}): ${response.text}`
        };
      }
    } catch (err: any) {
      return {
        success: false,
        message: `Error de red al subir a Google Drive: ${err?.message || String(err)}`
      };
    }
  }
}
