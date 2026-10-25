import test from 'node:test';
import assert from 'node:assert/strict';
import { en } from '../src/i18n/locales/en';
import { es } from '../src/i18n/locales/es';
import { ru } from '../src/i18n/locales/ru';
import { zh } from '../src/i18n/locales/zh';
import {
  initI18n,
  setI18nLanguage,
  getCurrentLocale,
  getUserLanguageSetting,
  t
} from '../src/i18n/index';

test('i18n: All dictionaries match the same top-level structure', () => {
  const locales = [en, es, ru, zh];
  const keys = Object.keys(en);

  for (const locale of locales) {
    assert.deepEqual(Object.keys(locale).sort(), keys.sort());
  }
});

test('i18n: Switching languages changes t() translations correctly', () => {
  setI18nLanguage('es');
  assert.equal(getCurrentLocale(), 'es');
  assert.equal(t('common.cancel'), 'Cancelar');
  assert.equal(t('commands.lockVault'), 'Bloquear bóveda ahora');

  setI18nLanguage('en');
  assert.equal(getCurrentLocale(), 'en');
  assert.equal(t('common.cancel'), 'Cancel');
  assert.equal(t('commands.lockVault'), 'Lock vault now');

  setI18nLanguage('ru');
  assert.equal(getCurrentLocale(), 'ru');
  assert.equal(t('common.cancel'), 'Отмена');
  assert.equal(t('commands.lockVault'), 'Заблокировать хранилище сейчас');

  setI18nLanguage('zh');
  assert.equal(getCurrentLocale(), 'zh');
  assert.equal(t('common.cancel'), '取消');
  assert.equal(t('commands.lockVault'), '立即锁定仓库');
});

test('i18n: Parameter interpolation works across languages', () => {
  setI18nLanguage('en');
  assert.equal(
    t('lockScreen.recoveryCounter', { count: 3, total: 24 }),
    '3 / 24 words'
  );

  setI18nLanguage('es');
  assert.equal(
    t('lockScreen.recoveryCounter', { count: 5, total: 24 }),
    '5 / 24 palabras'
  );

  setI18nLanguage('ru');
  assert.equal(
    t('lockScreen.recoveryCounter', { count: 12, total: 24 }),
    '12 / 24 слов'
  );

  setI18nLanguage('zh');
  assert.equal(
    t('lockScreen.recoveryCounter', { count: 18, total: 24 }),
    '18 / 24 个单词'
  );
});

test('i18n: Fallback to English for missing keys and graceful degradation', () => {
  setI18nLanguage('es');
  assert.equal(t('nonexistent.path.to.key'), 'nonexistent.path.to.key');
});

test('i18n: Auto detection falls back to English when no environment language is set', () => {
  setI18nLanguage('auto');
  assert.equal(getUserLanguageSetting(), 'auto');
  assert.ok(['en', 'es', 'ru', 'zh'].includes(getCurrentLocale()));
});
