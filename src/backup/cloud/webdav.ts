/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * WebDAV Universal Cloud Provider (Nextcloud, ownCloud, Box, pCloud, NAS, Rclone)
 */

import { requestHttp, assertSafeUrl, toExactArrayBuffer } from '../../utils/http';
import { CloudProvider, CloudTestResult, CloudUploadResult } from './provider-interface';

export class WebDAVProvider implements CloudProvider {
  public readonly id = 'webdav';
  public readonly name = 'WebDAV (Nextcloud / Box / pCloud / NAS)';

  private serverUrl: string;
  private username: string;
  private password: string;
  private remotePath: string;

  constructor(serverUrl: string, username: string = '', password: string = '', remotePath: string = 'MySecretBackups') {
    this.serverUrl = serverUrl.trim().replace(/\/+$/, '');
    this.username = username.trim();
    this.password = password.trim();
    this.remotePath = remotePath.trim().replace(/^\/+|\/+$/g, '') || 'MySecretBackups';
  }

  /**
   * SECURITY: the Basic `Authorization` header carries the WebDAV password in
   * base64 (i.e. effectively in cleartext). It must never travel over plain
   * HTTP, so an insecure server URL is rejected outright.
   */
  private assertSecureTransport(): void {
    assertSafeUrl(this.serverUrl, true);
  }

  private getAuthHeader(): string {
    if (!this.username) return '';
    try {
      const creds = `${this.username}:${this.password}`;
      // Cross-platform base64 encoding
      if (typeof window !== 'undefined' && window.btoa) {
        return `Basic ${window.btoa(unescape(encodeURIComponent(creds)))}`;
      }
      return `Basic ${Buffer.from(creds).toString('base64')}`;
    } catch {
      return '';
    }
  }

  public async testConnection(): Promise<CloudTestResult> {
    if (!this.serverUrl) {
      return {
        success: false,
        message: 'No se ha configurado la URL del servidor WebDAV.'
      };
    }

    try {
      this.assertSecureTransport();
    } catch (err: any) {
      return {
        success: false,
        message: err?.message || String(err)
      };
    }

    try {
      const headers: Record<string, string> = {};
      const auth = this.getAuthHeader();
      if (auth) headers['Authorization'] = auth;

      // Send PROPFIND (standard WebDAV) or fallback to OPTIONS/GET
      let response;
      try {
        response = await requestHttp({
          url: this.serverUrl,
          method: 'PROPFIND',
          headers: {
            ...headers,
            Depth: '0'
          }
        });
      } catch {
        // Fallback to OPTIONS if PROPFIND is filtered by proxy
        response = await requestHttp({
          url: this.serverUrl,
          method: 'OPTIONS',
          headers
        });
      }

      if (response.status >= 200 && response.status < 400) {
        return {
          success: true,
          message: `Conexión exitosa con el servidor WebDAV (${this.serverUrl}).`
        };
      } else {
        return {
          success: false,
          message: `Servidor WebDAV respondió con código ${response.status}: ${response.text}`
        };
      }
    } catch (err: any) {
      return {
        success: false,
        message: `Fallo de conexión al servidor WebDAV: ${err?.message || String(err)}`
      };
    }
  }

  public async uploadBackup(filename: string, data: Uint8Array): Promise<CloudUploadResult> {
    if (!this.serverUrl) {
      return {
        success: false,
        message: 'URL del servidor WebDAV no configurada.'
      };
    }

    try {
      this.assertSecureTransport();
    } catch (err: any) {
      return {
        success: false,
        message: err?.message || String(err)
      };
    }

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/zip'
      };
      const auth = this.getAuthHeader();
      if (auth) headers['Authorization'] = auth;

      // Attempt to ensure target collection (directory) exists
      const targetDirUrl = `${this.serverUrl}/${encodeURIComponent(this.remotePath)}`;
      try {
        await requestHttp({
          url: targetDirUrl,
          method: 'MKCOL',
          headers: auth ? { Authorization: auth } : {}
        });
      } catch {
        // MKCOL will return 405 or 409 if collection already exists, which is normal
      }

      const fileUrl = `${targetDirUrl}/${encodeURIComponent(filename)}`;
      const response = await requestHttp({
        url: fileUrl,
        method: 'PUT',
        headers,
        body: toExactArrayBuffer(data)
      });

      if (response.status === 200 || response.status === 201 || response.status === 204) {
        return {
          success: true,
          remotePath: `${this.remotePath}/${filename}`,
          bytesUploaded: data.length,
          message: `Copia de seguridad subida correctamente a WebDAV (${this.remotePath}/${filename}).`
        };
      } else {
        return {
          success: false,
          message: `Error al subir a WebDAV (Código ${response.status}): ${response.text}`
        };
      }
    } catch (err: any) {
      return {
        success: false,
        message: `Error de red al subir a WebDAV: ${err?.message || String(err)}`
      };
    }
  }
}
