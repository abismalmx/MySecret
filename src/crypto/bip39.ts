/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Pure TypeScript BIP-39 Implementation (24-word Mnemonic & Key Derivation)
 */

import { BIP39_WORDLIST } from './wordlist-english';
import { stringToBytes } from '../utils/buffer';

// Map for O(1) lookup
const WORD_MAP = new Map<string, number>();
for (let i = 0; i < BIP39_WORDLIST.length; i++) {
  WORD_MAP.set(BIP39_WORDLIST[i], i);
}


/**
 * Generates a 24-word BIP-39 mnemonic phrase from 256 bits of entropy
 */
export function generateMnemonic(customEntropy?: Uint8Array): string {
  // 256 bits = 32 bytes entropy
  const entropy = customEntropy || new Uint8Array(32);
  if (!customEntropy) {
    window.crypto.getRandomValues(entropy);
  }

  if (entropy.length !== 32) {
    throw new Error('Entropy must be exactly 32 bytes (256 bits) for 24-word mnemonic');
  }

  // Synchronous SHA-256 for entropy checksum calculation
  // To avoid async in basic generator, we can calculate checksum with a simple pure implementation or digest:
  return entropyToMnemonicSync(entropy);
}

/**
 * Pure bit conversion of 256-bit entropy + 8-bit checksum -> 24 words
 */
function entropyToMnemonicSync(entropy: Uint8Array): string {
  // Simple pure JS SHA-256 for the 32-byte entropy block to get the 8-bit checksum
  const checksumByte = computeSha256FirstByte(entropy);

  // Combine 32 bytes (256 bits) + 1 byte checksum (take first 8 bits) = 264 bits
  // 264 bits / 11 bits = 24 words
  const bits: number[] = [];
  for (let i = 0; i < entropy.length; i++) {
    for (let j = 7; j >= 0; j--) {
      bits.push((entropy[i] >> j) & 1);
    }
  }
  // Append 8 bits of checksum
  for (let j = 7; j >= 0; j--) {
    bits.push((checksumByte >> j) & 1);
  }

  const words: string[] = [];
  for (let i = 0; i < 24; i++) {
    let wordIndex = 0;
    for (let j = 0; j < 11; j++) {
      wordIndex = (wordIndex << 1) | bits[i * 11 + j];
    }
    words.push(BIP39_WORDLIST[wordIndex]);
  }

  return words.join(' ');
}

/**
 * Validates a BIP-39 mnemonic phrase (word count, wordlist check, and SHA-256 checksum)
 */
export function validateMnemonic(mnemonic: string): boolean {
  if (!mnemonic) return false;
  const words = mnemonic.trim().toLowerCase().split(/\s+/);
  if (words.length !== 24) return false;

  const bits: number[] = [];
  for (const word of words) {
    const index = WORD_MAP.get(word);
    if (index === undefined) return false;
    for (let j = 10; j >= 0; j--) {
      bits.push((index >> j) & 1);
    }
  }

  // 264 bits = 256 bits entropy + 8 bits checksum
  const entropy = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    let byteVal = 0;
    for (let j = 0; j < 8; j++) {
      byteVal = (byteVal << 1) | bits[i * 8 + j];
    }
    entropy[i] = byteVal;
  }

  let expectedChecksum = 0;
  for (let j = 0; j < 8; j++) {
    expectedChecksum = (expectedChecksum << 1) | bits[256 + j];
  }

  const actualChecksum = computeSha256FirstByte(entropy);
  return expectedChecksum === actualChecksum;
}

/**
 * Derives a 256-bit (32 bytes) master recovery key from a BIP-39 mnemonic and salt using PBKDF2
 */
export async function mnemonicToKey(mnemonic: string, salt: Uint8Array): Promise<Uint8Array> {
  const cleanMnemonic = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');
  const passphraseBytes = stringToBytes(cleanMnemonic);

  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    passphraseBytes as BufferSource,
    'PBKDF2',
    false,
    ['deriveBits']
  );

  // PBKDF2 with HMAC-SHA512, 2048 iterations (BIP-39 standard specification)
  const derivedBits = await window.crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: 2048,
      hash: 'SHA-512'
    },
    baseKey,
    256 // 32 bytes
  );

  return new Uint8Array(derivedBits);
}

/**
 * Compact pure-JS single-block SHA-256 implementation to extract the first byte checksum
 * (BIP-39 checksum is just the first ENT/32 bits of SHA-256(entropy)).
 */
function computeSha256FirstByte(data: Uint8Array): number {
  let h0 = 0x6a09e667;
  const h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  const h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  // Pad the 32-byte input to 64 bytes (512-bit block)
  const block = new Uint8Array(64);
  block.set(data, 0);
  block[32] = 0x80;
  // Length is 256 bits (32 bytes * 8) -> 0x0000000000000100
  block[62] = 0x01;
  block[63] = 0x00;

  const w = new Uint32Array(64);
  for (let i = 0; i < 16; i++) {
    w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
  }

  for (let i = 16; i < 64; i++) {
    const s0 = (rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3)) >>> 0;
    const s1 = (rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10)) >>> 0;
    w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
  }

  let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;

  for (let i = 0; i < 64; i++) {
    const s1 = (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) >>> 0;
    const ch = ((e & f) ^ (~e & g)) >>> 0;
    const temp1 = (h + s1 + ch + K[i] + w[i]) >>> 0;
    const s0 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) >>> 0;
    const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
    const temp2 = (s0 + maj) >>> 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  h0 = (h0 + a) >>> 0;
  // First byte of h0 is the first byte of SHA-256
  return (h0 >>> 24) & 0xff;
}

function rotr(x: number, n: number): number {
  return (x >>> n) | (x << (32 - n));
}
