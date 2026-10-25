/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Folder Picker Modal: Interactive Vault Folder Selection
 */

import { App, FuzzySuggestModal, FuzzyMatch, TFolder, setIcon } from 'obsidian';
import { t } from '../i18n';

export class FolderPickerModal extends FuzzySuggestModal<TFolder> {
  private folders: TFolder[];
  private onChooseCallback: (folder: TFolder) => void;

  constructor(app: App, excludedFolders: string[], onChoose: (folder: TFolder) => void) {
    super(app);
    this.onChooseCallback = onChoose;
    this.setPlaceholder(t('folderPicker.placeholder'));

    const normalize = (p: string) =>
      p.replace(/^[/\\]+/, '').replace(/[/\\]+$/, '').replace(/\\/g, '/');

    // Normalized set of currently excluded folders
    const currentExcludedSet = new Set(excludedFolders.map(f => normalize(f)));

    // Collect all loaded folders from the active Obsidian vault
    const allFiles = this.app.vault.getAllLoadedFiles();
    this.folders = allFiles
      .filter((file): file is TFolder => {
        if (!(file instanceof TFolder)) return false;
        // Avoid root folder whether marked by isRoot() or by path
        if (typeof file.isRoot === 'function' && file.isRoot()) return false;
        const norm = normalize(file.path);
        return norm.length > 0 && norm !== '/';
      })
      .filter(folder => !currentExcludedSet.has(normalize(folder.path)))
      .sort((a, b) => a.path.localeCompare(b.path));

    this.emptyStateText = t('folderPicker.emptyText');
  }

  public getItems(): TFolder[] {
    return this.folders;
  }

  public getItemText(folder: TFolder): string {
    return folder.path;
  }

  public renderSuggestion(item: FuzzyMatch<TFolder>, el: HTMLElement): void {
    super.renderSuggestion(item, el);
    const iconSpan = el.createSpan({ cls: 'mysecret-folder-suggestion-icon' });
    setIcon(iconSpan, 'folder');
    el.prepend(iconSpan);
    el.addClass('mysecret-folder-suggestion-item');
  }

  public onChooseItem(folder: TFolder, _evt: MouseEvent | KeyboardEvent): void {
    this.onChooseCallback(folder);
  }
}
