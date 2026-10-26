/**
 * Automated Test Suite for MySecret Cryptographic & Core Modules
 */

import assert from 'node:assert';
import test from 'node:test';
import { webcrypto } from 'node:crypto';
import { argon2id } from 'hash-wasm';

// Polyfill window.crypto for Node test environment if needed
if (!globalThis.window) {
  globalThis.window = {
    crypto: webcrypto,
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    setInterval: globalThis.setInterval.bind(globalThis),
    clearInterval: globalThis.clearInterval.bind(globalThis)
  };
}

// 1. BIP-39 Tests
import { generateMnemonic, validateMnemonic, mnemonicToKey } from '../src/crypto/bip39.ts';
import { BIP39_WORDLIST } from '../src/crypto/wordlist-english.ts';

test('BIP-39: Wordlist contains exactly 2048 words', () => {
  assert.strictEqual(BIP39_WORDLIST.length, 2048);
  assert.strictEqual(BIP39_WORDLIST[0], 'abandon');
  assert.strictEqual(BIP39_WORDLIST[2047], 'zoo');
});

test('BIP-39: Generates valid 24-word mnemonic', () => {
  const mnemonic = generateMnemonic();
  const words = mnemonic.split(' ');
  assert.strictEqual(words.length, 24);
  assert.strictEqual(validateMnemonic(mnemonic), true);
});

test('BIP-39: Rejects corrupted or invalid mnemonics', () => {
  const valid = generateMnemonic();
  const words = valid.split(' ');

  // Invalid word
  const invalidWord = [...words];
  invalidWord[0] = 'notawordxyz';
  assert.strictEqual(validateMnemonic(invalidWord.join(' ')), false);

  // Wrong count
  assert.strictEqual(validateMnemonic(words.slice(0, 23).join(' ')), false);

  // Checksum mismatch (corrupt the last word containing the checksum bits)
  const corrupted = [...words];
  corrupted[23] = corrupted[23] === 'zoo' ? 'abandon' : 'zoo';
  assert.strictEqual(validateMnemonic(corrupted.join(' ')), false);
});

test('BIP-39: Key derivation produces deterministic 32-byte key', async () => {
  const mnemonic = generateMnemonic();
  const salt = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

  const key1 = await mnemonicToKey(mnemonic, salt);
  const key2 = await mnemonicToKey(mnemonic, salt);

  assert.strictEqual(key1.length, 32);
  assert.deepStrictEqual(key1, key2);
});

// 2. Envelope Tests
import {
  isArmoredEncrypted,
  isArmoredBytesEncrypted,
  serializeArmored,
  deserializeArmored,
  isBinaryEncrypted,
  serializeBinary,
  deserializeBinary
} from '../src/crypto/envelope.ts';

test('Envelope: Armored text round-trip and header detection', () => {
  const payload = {
    version: 1,
    iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
    tag: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]),
    ciphertext: new TextEncoder().encode('Hello Encrypted World!')
  };

  const armored = serializeArmored(payload);
  assert.strictEqual(isArmoredEncrypted(armored), true);
  assert.strictEqual(isArmoredEncrypted('# Just a plain note'), false);

  const parsed = deserializeArmored(armored);
  assert.strictEqual(parsed.version, 1);
  assert.deepStrictEqual(parsed.iv, payload.iv);
  assert.deepStrictEqual(parsed.tag, payload.tag);
  assert.deepStrictEqual(parsed.ciphertext, payload.ciphertext);

  // CRLF line ending resilience
  const crlfArmored = armored.replace(/\n/g, '\r\n');
  const parsedCrlf = deserializeArmored(crlfArmored);
  assert.deepStrictEqual(parsedCrlf.ciphertext, payload.ciphertext);
});

test('Envelope: Empty payload (0-byte ciphertext) armored round-trip', () => {
  const emptyPayload = {
    version: 1,
    iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
    tag: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]),
    ciphertext: new Uint8Array(0)
  };

  const armored = serializeArmored(emptyPayload);
  assert.strictEqual(isArmoredEncrypted(armored), true);

  const parsed = deserializeArmored(armored);
  assert.strictEqual(parsed.version, 1);
  assert.deepStrictEqual(parsed.iv, emptyPayload.iv);
  assert.deepStrictEqual(parsed.tag, emptyPayload.tag);
  assert.strictEqual(parsed.ciphertext.length, 0);

  // CRLF resilience with empty body
  const crlfArmored = armored.replace(/\n/g, '\r\n');
  const parsedCrlf = deserializeArmored(crlfArmored);
  assert.strictEqual(parsedCrlf.ciphertext.length, 0);
});

test('Envelope: isArmoredBytesEncrypted detects armored header with BOM and whitespace', () => {
  const encText = '-----BEGIN MYSECRET ENCRYPTED FILE-----\nVersion: 1';
  const normalBytes = new TextEncoder().encode(encText);
  assert.strictEqual(isArmoredBytesEncrypted(normalBytes), true);

  // With leading whitespace
  const spaceBytes = new TextEncoder().encode('  \n\t' + encText);
  assert.strictEqual(isArmoredBytesEncrypted(spaceBytes), true);

  // With UTF-8 BOM
  const bomBytes = new Uint8Array([0xEF, 0xBB, 0xBF, ...normalBytes]);
  assert.strictEqual(isArmoredBytesEncrypted(bomBytes), true);

  // Plaintext markdown or random binary
  assert.strictEqual(isArmoredBytesEncrypted(new TextEncoder().encode('# Regular Markdown Note')), false);
  assert.strictEqual(isArmoredBytesEncrypted(new Uint8Array([1, 2, 3])), false);
  assert.strictEqual(isArmoredBytesEncrypted(new Uint8Array(0)), false);
});


test('Envelope: Deserializing note without body separator (empty note on disk)', () => {
  const rawDiskNote = `-----BEGIN MYSECRET ENCRYPTED FILE-----
Version: 1
IV: hxis9HT6Z+sE7Ce8
Tag: LlLbF6eyaaS8prx3vQVOAA==


-----END MYSECRET ENCRYPTED FILE-----
`;

  const parsed = deserializeArmored(rawDiskNote);
  assert.strictEqual(parsed.version, 1);
  assert.strictEqual(parsed.iv.length, 12);
  assert.strictEqual(parsed.tag.length, 16);
  assert.strictEqual(parsed.ciphertext.length, 0);
});

test('Envelope: Binary compact round-trip and magic header detection', () => {
  const payload = {
    version: 1,
    iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
    tag: new Uint8Array([10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]),
    ciphertext: new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03])
  };

  const binary = serializeBinary(payload);
  assert.strictEqual(isBinaryEncrypted(binary), true);
  assert.strictEqual(isBinaryEncrypted(new Uint8Array([1, 2, 3, 4])), false);

  const parsed = deserializeBinary(binary);
  assert.strictEqual(parsed.version, 1);
  assert.deepStrictEqual(parsed.iv, payload.iv);
  assert.deepStrictEqual(parsed.tag, payload.tag);
  assert.deepStrictEqual(parsed.ciphertext, payload.ciphertext);
});

// 3. AES-256-GCM Cryptographic Tests
import { importAesKey, encryptAesGcm, decryptAesGcm } from '../src/crypto/aes.ts';

test('AES-256-GCM: Hardware accelerated encryption and decryption with AAD', async () => {
  const rawKey = new Uint8Array(32);
  webcrypto.getRandomValues(rawKey);
  const key = await importAesKey(rawKey);

  const plainText = 'My deeply confidential personal journal entry.';
  const plainBytes = new TextEncoder().encode(plainText);
  const aad = 'Folder/SecretNote.md';

  const enc = await encryptAesGcm(plainBytes, key, aad);
  assert.strictEqual(enc.iv.length, 12);
  assert.strictEqual(enc.tag.length, 16);

  const decrypted = await decryptAesGcm(enc.ciphertext, key, enc.iv, enc.tag, aad);
  assert.strictEqual(new TextDecoder().decode(decrypted), plainText);
});

test('AES-256-GCM: Tamper detection (AEAD integrity)', async () => {
  const rawKey = new Uint8Array(32);
  webcrypto.getRandomValues(rawKey);
  const key = await importAesKey(rawKey);

  const plainBytes = new TextEncoder().encode('Unchanged secret data');
  const enc = await encryptAesGcm(plainBytes, key, 'Note.md');

  // Alter 1 byte of ciphertext
  const tamperedCipher = new Uint8Array(enc.ciphertext);
  tamperedCipher[0] ^= 0xff;

  await assert.rejects(
    async () => {
      await decryptAesGcm(tamperedCipher, key, enc.iv, enc.tag, 'Note.md');
    },
    /operation failed|tag mismatch|mac check in gcm failed/i
  );

  // Alter AAD (renaming or path swap attack)
  await assert.rejects(
    async () => {
      await decryptAesGcm(enc.ciphertext, key, enc.iv, enc.tag, 'DifferentPath.md');
    },
    /operation failed|tag mismatch|mac check in gcm failed/i
  );
});

// 4. Zeroize Tests
import { zeroize } from '../src/utils/zeroize.ts';

test('Zeroize: Overwrites buffer memory completely with zeros', () => {
  const secretBuffer = new Uint8Array([42, 99, 123, 255, 17, 88]);
  zeroize(secretBuffer);
  for (let i = 0; i < secretBuffer.length; i++) {
    assert.strictEqual(secretBuffer[i], 0);
  }
});

// 5. Path Filter Tests
import { PathFilter } from '../src/adapter/path-filter.ts';

test('PathFilter: System files, dotfiles and excluded folders', () => {
  const filter = new PathFilter(['Public', 'Shared'], true);

  // System exclusions
  assert.strictEqual(filter.shouldEncrypt('.obsidian/plugins/mysecret/data.json'), false);
  assert.strictEqual(filter.shouldEncrypt('.git/HEAD'), false);
  assert.strictEqual(filter.shouldEncrypt('.trash/old.md'), false);
  assert.strictEqual(filter.shouldEncrypt('.DS_Store'), false);

  // User excluded folders
  assert.strictEqual(filter.shouldEncrypt('Public/readme.md'), false);
  assert.strictEqual(filter.shouldEncrypt('Shared/collab.md'), false);

  // Protected files
  assert.strictEqual(filter.shouldEncrypt('Secret.md'), true);
  assert.strictEqual(filter.shouldEncrypt('Work/Finances.md'), true);
  assert.strictEqual(filter.shouldEncrypt('Canvas/diagram.canvas'), true);
  assert.strictEqual(filter.shouldEncrypt('Attachments/passport.pdf'), true);
  assert.strictEqual(filter.shouldEncrypt('Photos/id.png'), true);
});

test('PathFilter: Unicode NFC normalization for accented paths', () => {
  const filter = new PathFilter([], true);
  // NFC (precomposed í = \u00ED) vs NFD (decomposed i + acute = \u0069\u0301)
  const nfcPath = 'Diario personal/Sin t\u00EDtulo.md';
  const nfdPath = 'Diario personal/Sin t\u0069\u0301tulo.md';

  assert.notStrictEqual(nfcPath, nfdPath); // Preconditions: different byte sequences
  assert.strictEqual(filter.normalizePath(nfcPath), filter.normalizePath(nfdPath));
  assert.strictEqual(filter.normalizePath(nfdPath), 'Diario personal/Sin título.md');
});

test('AES-256-GCM: Empty plaintext note round-trip with accented path and NFC/NFD AAD equivalence', async () => {
  const rawKey = new Uint8Array(32);
  webcrypto.getRandomValues(rawKey);
  const key = await importAesKey(rawKey);

  const filter = new PathFilter([], true);
  const nfcPath = 'Diario personal/Sin t\u00EDtulo.md';
  const nfdPath = 'Diario personal/Sin t\u0069\u0301tulo.md';

  const plainBytes = new Uint8Array(0); // empty note
  const aad = filter.normalizePath(nfcPath);

  const enc = await encryptAesGcm(plainBytes, key, aad);
  assert.strictEqual(enc.ciphertext.length, 0);
  assert.strictEqual(enc.tag.length, 16);

  // Decrypt using NFD path normalized via PathFilter
  const decrypted = await decryptAesGcm(
    enc.ciphertext,
    key,
    enc.iv,
    enc.tag,
    filter.normalizePath(nfdPath)
  );
  assert.strictEqual(decrypted.length, 0);
});

// 6. Zip Packaging & Manifest Tests
import { zipSync, unzipSync, strToU8, strFromU8 } from 'fflate';
import { createCloudProvider } from '../src/backup/cloud/index.ts';

test('Backup & Zip: Packaging files and reading manifest round-trip', () => {
  const noteContent = '-----BEGIN MYSECRET ENCRYPTED FILE-----\nversion: 1\n...\n-----END MYSECRET ENCRYPTED FILE-----';
  const binaryContent = new Uint8Array([0x4d, 0x59, 0x53, 0x45, 0x01, 0x02, 0x03]);
  const envelopeContent = JSON.stringify({ version: 1, vaultKeyEnvelope: { ciphertext: 'abcd' } });

  const manifest = {
    version: 1,
    plugin: 'MySecret',
    mode: 'encrypted',
    createdAt: Date.now(),
    vaultName: 'TestVault',
    totalFiles: 2,
    files: [
      { path: 'Notes/Secret.md', size: noteContent.length, isEncrypted: true },
      { path: 'Images/photo.png', size: binaryContent.length, isEncrypted: true }
    ]
  };

  const zipEntries = {
    'Notes/Secret.md': strToU8(noteContent),
    'Images/photo.png': binaryContent,
    'vault-envelope.json': strToU8(envelopeContent),
    'mysecret-manifest.json': strToU8(JSON.stringify(manifest))
  };

  const zipBytes = zipSync(zipEntries, { level: 6 });
  assert.ok(zipBytes.length > 0);

  const unzipped = unzipSync(zipBytes);
  assert.strictEqual(strFromU8(unzipped['Notes/Secret.md']), noteContent);
  assert.deepStrictEqual(unzipped['Images/photo.png'], binaryContent);
  assert.strictEqual(strFromU8(unzipped['vault-envelope.json']), envelopeContent);

  const parsedManifest = JSON.parse(strFromU8(unzipped['mysecret-manifest.json']));
  assert.strictEqual(parsedManifest.plugin, 'MySecret');
  assert.strictEqual(parsedManifest.mode, 'encrypted');
  assert.strictEqual(parsedManifest.totalFiles, 2);
});

// 7. Cloud Providers Contract Tests
test('Cloud Providers: Factory resolves valid provider instances', () => {
  const gDrive = createCloudProvider({
    provider: 'google-drive',
    googleDrive: { accessToken: 'token123', folderId: 'folder456' },
    oneDrive: { accessToken: '', folderPath: '' },
    webdav: { serverUrl: '', username: '', password: '', remotePath: '' },
    localSync: { destinationPath: '' },
    autoBackup: false,
    autoBackupTrigger: 'both',
    autoBackupIntervalHours: 24,
    lastBackupTimestamp: 0,
    retentionCount: 5
  });
  assert.ok(gDrive);
  assert.strictEqual(gDrive.id, 'google-drive');

  const oneDrive = createCloudProvider({
    provider: 'onedrive',
    googleDrive: { accessToken: '', folderId: '' },
    oneDrive: { accessToken: 'ms_token', folderPath: 'Backups' },
    webdav: { serverUrl: '', username: '', password: '', remotePath: '' },
    localSync: { destinationPath: '' },
    autoBackup: false,
    autoBackupTrigger: 'both',
    autoBackupIntervalHours: 24,
    lastBackupTimestamp: 0,
    retentionCount: 5
  });
  assert.ok(oneDrive);
  assert.strictEqual(oneDrive.id, 'onedrive');

  const webdav = createCloudProvider({
    provider: 'webdav',
    googleDrive: { accessToken: '', folderId: '' },
    oneDrive: { accessToken: '', folderPath: '' },
    webdav: { serverUrl: 'https://cloud.example.com/dav', username: 'usr', password: 'pwd', remotePath: 'Notes' },
    localSync: { destinationPath: '' },
    autoBackup: false,
    autoBackupTrigger: 'both',
    autoBackupIntervalHours: 24,
    lastBackupTimestamp: 0,
    retentionCount: 5
  });
  assert.ok(webdav);
  assert.strictEqual(webdav.id, 'webdav');

  const localSync = createCloudProvider({
    provider: 'local-sync',
    googleDrive: { accessToken: '', folderId: '' },
    oneDrive: { accessToken: '', folderPath: '' },
    webdav: { serverUrl: '', username: '', password: '', remotePath: '' },
    localSync: { destinationPath: '/tmp/mysecret-test-backups' },
    autoBackup: false,
    autoBackupTrigger: 'both',
    autoBackupIntervalHours: 24,
    lastBackupTimestamp: 0,
    retentionCount: 5
  });
  assert.ok(localSync);
  assert.strictEqual(localSync.id, 'local-sync');
});

// 8. KeyManager Optional Recovery Phrase Tests
import { KeyManager } from '../src/crypto/key-manager.ts';

test('KeyManager: Optional recovery phrase initialization and toggle', async () => {
  const km = new KeyManager();

  // 1. Initialize WITHOUT recovery phrase
  const result = await km.initializeVault('MySecretPassword123!', false);
  assert.strictEqual(result.mnemonic, null);
  assert.strictEqual(result.envelope.recoveryEnvelope, undefined);
  await result.commit();

  assert.strictEqual(km.hasRecoveryEnvelope(), false);
  assert.strictEqual(km.isLocked, false);

  // 2. Lock and unlock with password
  km.lock();
  assert.strictEqual(km.isLocked, true);

  const unlocked = await km.unlockWithPassword('MySecretPassword123!');
  assert.strictEqual(unlocked, true);
  assert.strictEqual(km.isLocked, false);

  // 3. Trying recovery unlock throws error because envelope has no recovery slot
  await assert.rejects(
    async () =>
      km.unlockWithRecoveryPhrase(
        'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art'
      ),
    /Recovery envelope configuration is missing/
  );

  // 4. Dynamically add recovery phrase
  const added = await km.addRecoveryPhrase();
  assert.ok(added.mnemonic);
  assert.strictEqual(km.hasRecoveryEnvelope(), true);
  assert.ok(km.getRecoveryMnemonic());

  // 5. Remove recovery phrase
  km.removeRecoveryPhrase();
  assert.strictEqual(km.hasRecoveryEnvelope(), false);
  assert.strictEqual(km.getRecoveryMnemonic(), null);
});

test('KeyManager: Password change preserves note encryption/decryption integrity and rejects old password', async () => {
  const km = new KeyManager();
  const initialPassword = 'InitialMasterPassword123!';
  const newPassword = 'NewUltraMasterPassword456!';

  // 1. Initialize vault with initial password (with recovery phrase)
  const initResult = await km.initializeVault(initialPassword, true);
  await initResult.commit();
  const mnemonic = initResult.mnemonic;
  assert.ok(mnemonic);

  // 2. Encrypt a mock note with the initial vault key
  const noteContent = 'Este es mi diario personal altamente confidencial con MySecret.';
  const noteBytes = new TextEncoder().encode(noteContent);
  const notePath = 'Diario/2026-10-23.md';
  const initialSalt = initResult.envelope.argon2.salt;

  const vaultKey = km.getVaultKey();
  assert.ok(vaultKey);
  const encryptedNote = await encryptAesGcm(noteBytes, vaultKey, notePath);

  // 3. Change master password
  const updatedEnvelope = await km.changeMasterPassword(newPassword, initialPassword);
  assert.ok(updatedEnvelope);
  assert.notStrictEqual(updatedEnvelope.argon2.salt, initialSalt);

  // 4. Verify note is still decryptable while unlocked
  const currentKey = km.getVaultKey();
  assert.ok(currentKey);
  const decrypted1 = await decryptAesGcm(
    encryptedNote.ciphertext,
    currentKey,
    encryptedNote.iv,
    encryptedNote.tag,
    notePath
  );
  assert.strictEqual(new TextDecoder().decode(decrypted1), noteContent);

  // 5. Lock vault
  km.lock();
  assert.strictEqual(km.isLocked, true);
  assert.strictEqual(km.getVaultKey(), null);

  // 6. Old password must fail
  const oldUnlockSuccess = await km.unlockWithPassword(initialPassword);
  assert.strictEqual(oldUnlockSuccess, false);
  assert.strictEqual(km.isLocked, true);

  // 7. New password must succeed
  const newUnlockSuccess = await km.unlockWithPassword(newPassword);
  assert.strictEqual(newUnlockSuccess, true);
  assert.strictEqual(km.isLocked, false);

  // 8. Decrypt note after unlocking with new password
  const restoredKey = km.getVaultKey();
  assert.ok(restoredKey);
  const decrypted2 = await decryptAesGcm(
    encryptedNote.ciphertext,
    restoredKey,
    encryptedNote.iv,
    encryptedNote.tag,
    notePath
  );
  assert.strictEqual(new TextDecoder().decode(decrypted2), noteContent);

  // 9. Verify recovery phrase still unlocks and recovers the same note
  km.lock();
  assert.strictEqual(km.isLocked, true);
  const recoveryUnlockSuccess = await km.unlockWithRecoveryPhrase(mnemonic);
  assert.strictEqual(recoveryUnlockSuccess, true);
  assert.strictEqual(km.isLocked, false);

  const keyAfterRecovery = km.getVaultKey();
  assert.ok(keyAfterRecovery);
  const decrypted3 = await decryptAesGcm(
    encryptedNote.ciphertext,
    keyAfterRecovery,
    encryptedNote.iv,
    encryptedNote.tag,
    notePath
  );
  assert.strictEqual(new TextDecoder().decode(decrypted3), noteContent);
});

