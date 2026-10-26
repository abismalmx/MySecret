/**
 * Runtime stub of the `obsidian` module for the Node.js test environment.
 *
 * The real `obsidian` package only ships TypeScript declarations (no runtime
 * code), so the modules that import it cannot be bundled and executed under
 * Node. This stub provides the minimal runtime surface needed by the
 * security regression tests.
 */

export class TAbstractFile {
  constructor(path) {
    this.path = path;
    this.name = path.split('/').pop() || path;
  }
}

export class TFile extends TAbstractFile {
  constructor(path, stat = {}) {
    super(path);
    this.stat = { ctime: 0, mtime: 0, size: 0, type: 'file', ...stat };
    this.cachedContent = null;
  }
  basename() {
    return this.name;
  }
  extension() {
    const idx = this.name.lastIndexOf('.');
    return idx === -1 ? '' : this.name.slice(idx + 1);
  }
  /**
   * Reproduces the in-memory cache of the real `TFile`.
   *
   * @param content The text to cache, or `null` to invalidate the cache.
   */
  cache(content) {
    this.cachedContent = content === null ? null : content;
  }
}

export class TFolder extends TAbstractFile {
  constructor(path) {
    super(path);
    this.children = [];
  }
  isRoot() {
    return this.path === '/' || this.path === '';
  }
}

/**
 * Minimal `Vault` stub.
 *
 * It reproduces the two behaviours of the real Obsidian `Vault` that matter
 * for the encryption hooks:
 *
 *   * `readBinary(file)` delegates to `adapter.readBinary(file.path)` and
 *     caches the RAW bytes in the `TFile` (the real implementation calls
 *     `file.cache(new TextDecoder().decode(bytes))`).
 *   * `cachedRead(file)` returns the cached text when available.
 */
export class Vault {
  constructor(adapter) {
    this.adapter = adapter;
  }

  async readBinary(file) {
    const bytes = await this.adapter.readBinary(file.path);
    if (file && typeof file.cache === 'function' && file.extension === 'md') {
      file.cache(new TextDecoder().decode(new Uint8Array(bytes)));
    }
    return bytes;
  }

  async cachedRead(file) {
    if (file && typeof file.cachedContent === 'string') {
      return file.cachedContent;
    }
    const bytes = await this.readBinary(file);
    return new TextDecoder().decode(new Uint8Array(bytes));
  }
}

export class Notice {
  constructor(message) {
    this.message = message;
  }
  hide() {}
}

export class Modal {
  constructor(app) {
    this.app = app;
    this.contentEl = createStubElement();
    this.modalEl = createStubElement();
    this.scope = { register: () => {} };
  }
  open() {}
  close() {}
  onOpen() {}
  onClose() {}
}

export class Plugin {
  constructor(app, manifest) {
    this.app = app;
    this.manifest = manifest;
  }
  addCommand() {}
  addRibbonIcon() { return createStubElement(); }
  registerEvent() {}
  registerInterval() {}
  async loadData() { return null; }
  async saveData() {}
}

export class PluginSettingTab {
  constructor(app, plugin) {
    this.app = app;
    this.plugin = plugin;
    this.containerEl = createStubElement();
  }
  display() {}
  hide() {}
}

export class Setting {
  constructor() {}
  setName() { return this; }
  setDesc() { return this; }
  addText() { return this; }
  addToggle() { return this; }
  addDropdown() { return this; }
  addButton() { return this; }
  addButton2() { return this; }
  setHeading() { return this; }
}

export class Component {}
export class Events {}
export class MarkdownView {}
export class WorkspaceLeaf {}
export class Menu { addItem() {} }
export class Editor {}

/**
 * Minimal DOM-ish element stub. The interceptor only relies on the adapter
 * and the vault, not on the DOM, so this is intentionally simple.
 */
function createStubElement() {
  const el = {
    children: [],
    classList: {
      add() {}, remove() {}, toggle() {}, contains: () => false
    },
    style: {},
    value: '',
    textContent: '',
    innerHTML: '',
    empty() {},
    show() {},
    hide() {},
    setText() {},
    setAttr() {},
    setAttribute() {},
    addClass() {},
    removeClass() {},
    toggleClass() {},
    createDiv: () => createStubElement(),
    createSpan: () => createStubElement(),
    createEl: () => createStubElement(),
    addEventListener() {},
    querySelector: () => null,
    querySelectorAll: () => [],
    appendChild() {},
    removeChild() {},
  };
  return el;
}

export function normalizePath(path) {
  return path.replace(/\\/g, '/').replace(/\/+/g, '/').replace(/^\/|\/$/g, '');
}

export const Platform = {
  isDesktop: true,
  isMobile: false,
  isMacOS: false,
  isWin: false,
  isLinux: true,
  isAndroidApp: false,
  isIosApp: false
};

// Needed only so `src/main.ts` (which pulls in every modal) can be bundled.
export class FuzzySuggestModal extends Modal {}
export function setIcon() {}
