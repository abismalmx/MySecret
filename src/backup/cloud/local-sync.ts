/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Local Sync Cloud Provider (MEGA, Google Drive Desktop, OneDrive Desktop, Dropbox, USB)
 */

import { CloudProvider, CloudTestResult, CloudUploadResult } from './provider-interface';
import { sanitizeVaultRelativePath } from '../../utils/path-sanitizer';

export class LocalSyncProvider implements CloudProvider {
  public readonly id = 'local-sync';
  public readonly name = 'Carpeta Sincronizada (MEGA / Drive / OneDrive de Escritorio)';

  private destinationPath: string;

  constructor(destinationPath: string) {
    this.destinationPath = destinationPath.trim();
  }

  private getFs(): any {
    try {
      // Available on Obsidian Desktop (Electron)
      // eslint-disable-next-line @typescript-eslint/no-require-imports -- Dynamic import of Node.js fs module in Electron environment
      return (window as any).require ? (window as any).require('fs') : require('fs');
    } catch {
      return null;
    }
  }

  private getPathModule(): any {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports -- Dynamic import of Node.js path module in Electron environment
      return (window as any).require ? (window as any).require('path') : require('path');
    } catch {
      return null;
    }
  }

  public async testConnection(): Promise<CloudTestResult> {
    if (!this.destinationPath) {
      return {
        success: false,
        message: 'No se ha especificado la ruta de la carpeta de sincronización.'
      };
    }

    const fs = this.getFs();
    if (!fs) {
      return {
        success: false,
        message: 'La escritura directa en carpetas locales solo está disponible en Obsidian para Escritorio.'
      };
    }

    try {
      if (!fs.existsSync(this.destinationPath)) {
        // Attempt to create directory recursively if it doesn't exist
        fs.mkdirSync(this.destinationPath, { recursive: true });
      }

      // Check write permissions
      const testFile = this.getPathModule()?.join(this.destinationPath, '.mysecret_write_test') || `${this.destinationPath}/.mysecret_write_test`;
      fs.writeFileSync(testFile, 'test');
      fs.unlinkSync(testFile);

      return {
        success: true,
        message: `Ruta accesible y con permisos de escritura: ${this.destinationPath}`
      };
    } catch (err: any) {
      return {
        success: false,
        message: `Error al acceder a la carpeta '${this.destinationPath}': ${err?.message || String(err)}`
      };
    }
  }

  public async uploadBackup(filename: string, data: Uint8Array): Promise<CloudUploadResult> {
    if (!this.destinationPath) {
      return {
        success: false,
        message: 'Ruta de destino no configurada.'
      };
    }

    const fs = this.getFs();
    if (!fs) {
      return {
        success: false,
        message: 'Esta función requiere Obsidian de escritorio para acceder a carpetas del sistema.'
      };
    }

    try {
      if (!fs.existsSync(this.destinationPath)) {
        fs.mkdirSync(this.destinationPath, { recursive: true });
      }

      const pathMod = this.getPathModule();

      // SECURITY: the backup filename is derived from the vault name, which is
      // user-controlled. Reject any name that could escape the destination
      // directory (e.g. "../../../etc/cron.d/evil") before joining the paths.
      const safeName = sanitizeVaultRelativePath(filename);
      if (!safeName.safe || safeName.path.includes('/')) {
        return {
          success: false,
          message: `Nombre de archivo de copia de seguridad no válido: ${safeName.reason || 'la ruta contiene separadores'}`
        };
      }

      const targetFilePath = pathMod ? pathMod.join(this.destinationPath, safeName.path) : `${this.destinationPath}/${safeName.path}`;

      // Convert Uint8Array to Buffer for node fs
      const buffer = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
      fs.writeFileSync(targetFilePath, buffer);

      return {
        success: true,
        remotePath: targetFilePath,
        bytesUploaded: data.length,
        message: `Copia de seguridad guardada exitosamente en: ${targetFilePath}`
      };
    } catch (err: any) {
      return {
        success: false,
        message: `Error al escribir en la carpeta local: ${err?.message || String(err)}`
      };
    }
  }
}
