/**
 * Compatibility tests for the out-of-plugin recovery tools.
 *
 * A vault is generated with the REAL plugin code (KeyManager + the same
 * encryption the adapter hooks use) and then decrypted with
 * `tools/offline-decryptor.html` and `tools/standalone-decryptor.py`.
 *
 * Before the fix both tools used a different key derivation and envelope
 * format and could not decrypt a single real file.
 *
 * The Python tool needs `cryptography` (and `argon2-cffi` for --password);
 * those tests are skipped, loudly, when they are not installed. Set
 * MYSECRET_TEST_PYTHON to point at an interpreter that has them.
 */

import assert from 'node:assert';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { spawnSync } from 'node:child_process';
import { webcrypto } from 'node:crypto';

if (!globalThis.window) {
  globalThis.window = {
    crypto: webcrypto,
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis)
  };
}

import { KeyManager } from '../src/crypto/key-manager.ts';
import { encryptAesGcm } from '../src/crypto/aes.ts';
import { serializeArmored, serializeBinary } from '../src/crypto/envelope.ts';

const ROOT = path.resolve(import.meta.dirname, '..');
const PASSWORD = 'Correct-Horse-Battery-Staple-42';
const NOTE_PATH = 'Notas/Diario Ñandú.md';
const NOTE_TEXT = '# Diario\n\nContenido secreto con acentos: áéíóú ñ 🔐\n';
const IMG_PATH = 'Adjuntos/foto.png';
const IMG_BYTES = Uint8Array.from({ length: 300 }, (_, i) => (i * 7) & 0xff);

async function buildVault() {
  const km = new KeyManager();
  const { mnemonic, envelope, commit } = await km.initializeVault(PASSWORD, true);
  await commit();

  const vault = fs.mkdtempSync(path.join(os.tmpdir(), 'mysecret-vault-'));
  const write = (rel, data) => {
    const full = path.join(vault, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, data);
  };

  write('.obsidian/plugins/mysecret/vault-envelope.json', JSON.stringify(envelope, null, 2));

  const noteEnc = await encryptAesGcm(new TextEncoder().encode(NOTE_TEXT), km.getVaultKey(), NOTE_PATH.normalize('NFC'));
  const armored = serializeArmored({ version: 1, ...noteEnc });
  write(NOTE_PATH, armored);

  const imgEnc = await encryptAesGcm(IMG_BYTES, km.getVaultKey(), IMG_PATH);
  write(IMG_PATH, serializeBinary({ version: 1, ...imgEnc }));

  write('Publico/libre.md', 'esta nota nunca se cifro');
  return { vault, mnemonic, envelope, armored };
}

// ---------------------------------------------------------------------------
// offline-decryptor.html — executed in a vm with a minimal DOM
// ---------------------------------------------------------------------------

function loadHtmlTool() {
  const html = fs.readFileSync(path.join(ROOT, 'tools', 'offline-decryptor.html'), 'utf8');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const sandbox = {
    crypto: webcrypto,
    TextEncoder,
    TextDecoder,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
    Uint8Array,
    URL,
    Blob,
    setTimeout,
    document: undefined // the UI wiring is skipped; only the pure functions are used
  };
  vm.createContext(sandbox);
  vm.runInContext(
    script + '\n;globalThis.__tool = { recoverVaultKey, parseArmored, parseBinary, decryptContainer };',
    sandbox
  );
  return sandbox.__tool;
}

test('Recovery tool (HTML): decrypts a real note with the recovery phrase', async () => {
  const { vault, mnemonic, envelope, armored } = await buildVault();
  try {
    const tool = loadHtmlTool();
    const vaultKey = await tool.recoverVaultKey(JSON.stringify(envelope), mnemonic);
    const plain = await tool.decryptContainer(vaultKey, NOTE_PATH, tool.parseArmored(armored));
    assert.strictEqual(new TextDecoder().decode(plain), NOTE_TEXT);
  } finally {
    fs.rmSync(vault, { recursive: true, force: true });
  }
});

test('Recovery tool (HTML): decrypts a real binary attachment', async () => {
  const { vault, mnemonic, envelope } = await buildVault();
  try {
    const tool = loadHtmlTool();
    const vaultKey = await tool.recoverVaultKey(JSON.stringify(envelope), mnemonic);
    const raw = new Uint8Array(fs.readFileSync(path.join(vault, IMG_PATH)));
    const plain = await tool.decryptContainer(vaultKey, IMG_PATH, tool.parseBinary(raw));
    assert.deepStrictEqual([...plain], [...IMG_BYTES]);
  } finally {
    fs.rmSync(vault, { recursive: true, force: true });
  }
});

test('Recovery tool (HTML): wrong phrase and wrong path fail with clear errors', async () => {
  const { vault, mnemonic, envelope, armored } = await buildVault();
  try {
    const tool = loadHtmlTool();
    const wrong = mnemonic.split(' ').reverse().join(' ');
    await assert.rejects(() => tool.recoverVaultKey(JSON.stringify(envelope), wrong), /incorrecta/i);

    const vaultKey = await tool.recoverVaultKey(JSON.stringify(envelope), mnemonic);
    await assert.rejects(
      () => tool.decryptContainer(vaultKey, 'Otra/ruta.md', tool.parseArmored(armored)),
      /ruta indicada no coincide/i
    );
    await assert.rejects(() => tool.recoverVaultKey('{not json', mnemonic), /JSON/i);
  } finally {
    fs.rmSync(vault, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// standalone-decryptor.py
// ---------------------------------------------------------------------------

const PYTHON = process.env.MYSECRET_TEST_PYTHON || 'python3';
const hasPython = (mods) =>
  spawnSync(PYTHON, ['-c', `import ${mods}`], { encoding: 'utf8' }).status === 0;
const TOOL = path.join(ROOT, 'tools', 'standalone-decryptor.py');

function runTool(args, input) {
  return spawnSync(PYTHON, [TOOL, ...args], { encoding: 'buffer', input });
}

test('Recovery tool (Python): decrypts a whole real vault with the recovery phrase', { skip: !hasPython('cryptography') && 'python "cryptography" not installed' }, async () => {
  const { vault, mnemonic } = await buildVault();
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'mysecret-out-'));
  try {
    const r = runTool(['--vault', vault, '--mnemonic', mnemonic, '--output', out]);
    assert.strictEqual(r.status, 0, r.stdout.toString() + r.stderr.toString());

    assert.strictEqual(fs.readFileSync(path.join(out, NOTE_PATH), 'utf8'), NOTE_TEXT);
    assert.deepStrictEqual([...fs.readFileSync(path.join(out, IMG_PATH))], [...IMG_BYTES]);
    assert.strictEqual(fs.readFileSync(path.join(out, 'Publico/libre.md'), 'utf8'), 'esta nota nunca se cifro');
    assert.strictEqual(fs.existsSync(path.join(out, '.obsidian')), false, 'hidden folders are not copied');
  } finally {
    fs.rmSync(vault, { recursive: true, force: true });
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test('Recovery tool (Python): decrypts with the master password (Argon2id)', { skip: !hasPython('cryptography, argon2') && 'python "cryptography"/"argon2-cffi" not installed' }, async () => {
  const { vault } = await buildVault();
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'mysecret-out-'));
  try {
    const r = runTool(['--vault', vault, '--password', PASSWORD, '--output', out]);
    assert.strictEqual(r.status, 0, r.stdout.toString() + r.stderr.toString());
    assert.strictEqual(fs.readFileSync(path.join(out, NOTE_PATH), 'utf8'), NOTE_TEXT);

    const bad = runTool(['--vault', vault, '--password', 'wrong-password-123', '--output', out + '-x']);
    assert.notStrictEqual(bad.status, 0);
    assert.match(bad.stderr.toString(), /Wrong password/i);
  } finally {
    fs.rmSync(vault, { recursive: true, force: true });
    fs.rmSync(out, { recursive: true, force: true });
  }
});

test('Recovery tool (Python): single file needs the right relative path', { skip: !hasPython('cryptography') && 'python "cryptography" not installed' }, async () => {
  const { vault, mnemonic } = await buildVault();
  try {
    const envelope = path.join(vault, '.obsidian/plugins/mysecret/vault-envelope.json');
    const file = path.join(vault, NOTE_PATH);

    const ok = runTool(['--envelope', envelope, '--mnemonic', mnemonic, '--file', file, '--relative-path', NOTE_PATH]);
    assert.strictEqual(ok.status, 0, ok.stderr.toString());
    assert.strictEqual(ok.stdout.toString('utf8'), NOTE_TEXT);

    const wrong = runTool(['--envelope', envelope, '--mnemonic', mnemonic, '--file', file, '--relative-path', 'x/y.md']);
    assert.notStrictEqual(wrong.status, 0);
    assert.match(wrong.stderr.toString(), /Authentication failed/i);
  } finally {
    fs.rmSync(vault, { recursive: true, force: true });
  }
});

test('Recovery tool (Python): refuses an output directory inside the vault', { skip: !hasPython('cryptography') && 'python "cryptography" not installed' }, async () => {
  const { vault, mnemonic } = await buildVault();
  try {
    const r = runTool(['--vault', vault, '--mnemonic', mnemonic, '--output', path.join(vault, 'decrypted')]);
    assert.notStrictEqual(r.status, 0);
    assert.match(r.stderr.toString(), /OUTSIDE the vault/i);
  } finally {
    fs.rmSync(vault, { recursive: true, force: true });
  }
});
