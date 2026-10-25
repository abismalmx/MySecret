import { SupportedLanguage, TranslationDictionary } from './types';
import { en } from './locales/en';
import { es } from './locales/es';
import { ru } from './locales/ru';
import { zh } from './locales/zh';

const dictionaries: Record<SupportedLanguage, TranslationDictionary> = {
  en,
  es,
  ru,
  zh
};

let userSettingLocale: 'auto' | SupportedLanguage = 'auto';
let currentActiveLocale: SupportedLanguage = 'en';

export function detectObsidianLocale(): SupportedLanguage {
  try {
    // 1. Try Obsidian stored language in localStorage
    const storedLang = window?.localStorage?.getItem('language');
    if (storedLang) {
      const lower = storedLang.toLowerCase();
      if (lower.startsWith('es')) return 'es';
      if (lower.startsWith('ru')) return 'ru';
      if (lower.startsWith('zh')) return 'zh';
      if (lower.startsWith('en')) return 'en';
    }

    // 2. Try window.moment if available
    const momentLang = (window as any)?.moment?.locale?.();
    if (typeof momentLang === 'string') {
      const lower = momentLang.toLowerCase();
      if (lower.startsWith('es')) return 'es';
      if (lower.startsWith('ru')) return 'ru';
      if (lower.startsWith('zh')) return 'zh';
      if (lower.startsWith('en')) return 'en';
    }

    // 3. Try navigator.language
    if (typeof navigator !== 'undefined' && navigator.language) {
      const lower = navigator.language.toLowerCase();
      if (lower.startsWith('es')) return 'es';
      if (lower.startsWith('ru')) return 'ru';
      if (lower.startsWith('zh')) return 'zh';
      if (lower.startsWith('en')) return 'en';
    }
  } catch {
    // ignore
  }

  return 'en';
}

export function initI18n(savedPreference: 'auto' | SupportedLanguage = 'auto'): void {
  setI18nLanguage(savedPreference);
}

export function setI18nLanguage(preference: 'auto' | SupportedLanguage = 'auto'): void {
  userSettingLocale = preference;
  if (preference === 'auto') {
    currentActiveLocale = detectObsidianLocale();
  } else if (dictionaries[preference]) {
    currentActiveLocale = preference;
  } else {
    currentActiveLocale = 'en';
  }
}

export function getCurrentLocale(): SupportedLanguage {
  return currentActiveLocale;
}

export function getUserLanguageSetting(): 'auto' | SupportedLanguage {
  return userSettingLocale;
}

/**
 * Access nested translations using dot notation, e.g. t('settings.heroTitle')
 * Supports parameter interpolation, e.g. t('notices.restoreSuccess', { count: 12 })
 */
export function t(path: string, params?: Record<string, string | number>): string {
  const segments = path.split('.');
  
  let target: any = dictionaries[currentActiveLocale];
  for (const seg of segments) {
    if (target && typeof target === 'object' && seg in target) {
      target = target[seg];
    } else {
      target = undefined;
      break;
    }
  }

  // Fallback to English if key was not found in current locale
  if (typeof target !== 'string') {
    let fallback: any = dictionaries.en;
    for (const seg of segments) {
      if (fallback && typeof fallback === 'object' && seg in fallback) {
        fallback = fallback[seg];
      } else {
        fallback = undefined;
        break;
      }
    }
    if (typeof fallback === 'string') {
      target = fallback;
    } else {
      // Key does not exist even in English fallback
      return path;
    }
  }

  let text = target as string;
  if (params) {
    for (const [key, val] of Object.entries(params)) {
      text = text.replace(new RegExp(`\\{${key}\\}`, 'g'), String(val));
    }
  }

  return text;
}
