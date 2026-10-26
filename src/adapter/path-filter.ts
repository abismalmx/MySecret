/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Path Filtering & File Exclusion Logic
 */

import { SYSTEM_EXCLUDED_PREFIXES } from '../constants';

export class PathFilter {
  private excludedFolders: string[] = [];
  private encryptAttachments: boolean = true;

  constructor(excludedFolders: string[] = [], encryptAttachments: boolean = true) {
    this.updateConfig(excludedFolders, encryptAttachments);
  }

  public updateConfig(excludedFolders: string[], encryptAttachments: boolean): void {
    this.excludedFolders = excludedFolders.map(f => this.normalizePath(f));
    this.encryptAttachments = encryptAttachments;
  }

  /**
   * Normalizes a vault relative path (removing leading/trailing slashes)
   */
  public normalizePath(path: string): string {
    return (path || '').normalize('NFC').replace(/^[/\\]+/, '').replace(/[/\\]+$/, '').replace(/\\/g, '/');
  }

  /**
   * Checks if a path should NEVER be encrypted (e.g. system files, plugins, git)
   */
  public isSystemExcluded(path: string): boolean {
    const normalized = this.normalizePath(path);
    for (const prefix of SYSTEM_EXCLUDED_PREFIXES) {
      if (normalized.startsWith(prefix) || normalized === prefix.replace('/', '')) {
        return true;
      }
    }
    const segments = normalized.split('/');
    const baseName = segments[segments.length - 1] || '';

    // Hidden DIRECTORIES at any depth (e.g. `Projects/.git/`, `Notes/.cache/`)
    // are never user content: Obsidian does not index them.
    for (let i = 0; i < segments.length - 1; i++) {
      if (segments[i].startsWith('.')) {
        return true;
      }
    }

    if (baseName.startsWith('.')) {
      // Dotfiles at the root of the vault (.DS_Store, .gitignore...) are never
      // encrypted. A hidden TEXT NOTE inside a folder (`Notes/.private.md`) IS
      // user content and must not be silently left in cleartext; any other
      // nested dotfile (`.gitkeep`, `.DS_Store`...) stays excluded.
      if (segments.length === 1 || !this.isTextNote(normalized)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks if a path is excluded by user settings
   */
  public isUserExcluded(path: string): boolean {
    const normalized = this.normalizePath(path);
    for (const folder of this.excludedFolders) {
      if (folder && (normalized.startsWith(folder + '/') || normalized === folder)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Determines if a file is a text note (e.g. Markdown or Canvas)
   */
  public isTextNote(path: string): boolean {
    const lower = path.toLowerCase();
    return lower.endsWith('.md') || lower.endsWith('.canvas') || lower.endsWith('.txt');
  }

  /**
   * Decides whether the file at `path` should be encrypted
   */
  public shouldEncrypt(path: string): boolean {
    if (this.isSystemExcluded(path)) {
      return false;
    }
    if (this.isUserExcluded(path)) {
      return false;
    }

    // If it's a markdown or text note, always encrypt
    if (this.isTextNote(path)) {
      return true;
    }

    // If it's a binary attachment (image, pdf, etc.), check user setting
    return this.encryptAttachments;
  }
}
