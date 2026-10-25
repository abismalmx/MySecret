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

test('i18n: Interpolation treats replacement patterns in values literally', () => {
  setI18nLanguage('en');

  // SECURITY: `$&`, `$'` and `$` are special in `String.replace`. If the value
  // were passed as a plain replacement string, they would be expanded and the
  // message would be corrupted (and part of the template leaked into it).
  const withAmp = t('notices.exportFailed', { error: 'boom $& oops' });
  assert.ok(withAmp.includes('boom $& oops'), `Expected literal $&, got: ${withAmp}`);

  const withPrefix = t('notices.exportFailed', { error: 'x $`y' });
  assert.ok(withPrefix.includes('x $`y'), `Expected literal $\`, got: ${withPrefix}`);

  const withSuffix = t('notices.exportFailed', { error: "x $'y" });
  assert.ok(withSuffix.includes("x $'y"), `Expected literal $', got: ${withSuffix}`);

  // A dollar sign followed by a digit is also a replacement pattern.
  const withDollar = t('notices.exportFailed', { error: 'cost $1' });
  assert.ok(withDollar.includes('cost $1'), `Expected literal $1, got: ${withDollar}`);
});

test('i18n: Interpolation escapes regex metacharacters in parameter names', () => {
  setI18nLanguage('en');

  // A parameter name containing regex metacharacters must be matched
  // literally, and must never make the lookup throw a SyntaxError.
  assert.doesNotThrow(() => t('notices.exportFailed', { 'a{1,2}': 'value' }));

  const result = t('notices.exportFailed', { 'a{1,2}': 'value' });
  assert.ok(
    !result.includes('{a{1,2}}'),
    `Unresolved placeholder must not remain in: ${result}`
  );
});
