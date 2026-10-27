/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

// Password-based JSON Web Encryption (RFC 7516) in the flattened JSON
// serialization, with "PBES2-HS512+A256KW" key wrapping and "A256GCM" content
// encryption (RFC 7518 sections 4.8 and 5.3). Any JOSE library can open these
// files with the password.

const ALG = 'PBES2-HS512+A256KW';
const ENC = 'A256GCM';
// OWASP recommends at least 210,000 iterations of PBKDF2-HMAC-SHA512.
const ITERATIONS = 600_000;
// Bounds for files from elsewhere, so a hostile file can't stall the app.
const MIN_ITERATIONS = 1_000;
const MAX_ITERATIONS = 10_000_000;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class WrongPasswordError extends Error {
  constructor() {
    super('That password doesn’t open this vault.');
    this.name = 'WrongPasswordError';
  }
}

export function toBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(text) {
  return Uint8Array.from(atob(text.replace(/\s/g, '')), (char) =>
    char.charCodeAt(0),
  );
}

export function toBase64Url(bytes) {
  return toBase64(bytes)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function fromBase64Url(text) {
  return fromBase64(text.replace(/-/g, '+').replace(/_/g, '/'));
}

export function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function isJwe(value) {
  return (
    typeof value?.protected === 'string' &&
    typeof value.ciphertext === 'string' &&
    typeof value.encrypted_key === 'string'
  );
}

async function deriveWrappingKey(password, p2s, iterations) {
  // RFC 7518 section 4.8.1.1: the salt is the algorithm name, a zero byte,
  // and the "p2s" bytes.
  const salt = new Uint8Array([...encoder.encode(ALG), 0, ...p2s]);
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-512', salt, iterations },
    passwordKey,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  );
}

/**
 * Creates a vault key for `password`: a random content encryption key, kept
 * as a non-extractable `CryptoKey`, plus the protected header and wrapped key
 * that every file sealed with it carries.
 */
export async function createKey(password) {
  const p2s = randomBytes(16);
  const header = { alg: ALG, enc: ENC, p2s: toBase64Url(p2s), p2c: ITERATIONS };
  const wrappingKey = await deriveWrappingKey(password, p2s, ITERATIONS);
  const extractable = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
  const wrapped = await crypto.subtle.wrapKey(
    'raw',
    extractable,
    wrappingKey,
    'AES-KW',
  );
  const raw = await crypto.subtle.exportKey('raw', extractable);
  const cek = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
  return {
    cek,
    protected: toBase64Url(encoder.encode(JSON.stringify(header))),
    encryptedKey: toBase64Url(new Uint8Array(wrapped)),
  };
}

/** Unwraps the key of `jwe` with `password`. */
export async function unlockKey(jwe, password) {
  if (!isJwe(jwe)) {
    throw new Error('This is not an encrypted vault.');
  }
  const cek = await unwrapContentKey(jwe, password, false);
  return { cek, protected: jwe.protected, encryptedKey: jwe.encrypted_key };
}

/**
 * Wraps the content key of `key`, a vault key or a JWE, with `wrappingKey`,
 * so `unlockWithWrappedKey()` can unlock the vault without the password,
 * which this needs once to reach the key.
 */
export async function wrapKeyWith(key, password, wrappingKey) {
  const jwe = {
    protected: key.protected,
    encrypted_key: key.encrypted_key ?? key.encryptedKey,
  };
  const cek = await unwrapContentKey(jwe, password, true);
  return toBase64Url(
    new Uint8Array(
      await crypto.subtle.wrapKey('raw', cek, wrappingKey, 'AES-KW'),
    ),
  );
}

/** Unlocks the key of `jwe` from a key wrapped by `wrapKeyWith()`. */
export async function unlockWithWrappedKey(jwe, wrapped, wrappingKey) {
  const cek = await crypto.subtle.unwrapKey(
    'raw',
    fromBase64Url(wrapped),
    wrappingKey,
    'AES-KW',
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  );
  return { cek, protected: jwe.protected, encryptedKey: jwe.encrypted_key };
}

async function unwrapContentKey(jwe, password, extractable) {
  const header = JSON.parse(decoder.decode(fromBase64Url(jwe.protected)));
  if (header.alg !== ALG || header.enc !== ENC) {
    throw new Error(
      `Unsupported encryption: ${header.alg} with ${header.enc}.`,
    );
  }
  if (
    !Number.isInteger(header.p2c) ||
    header.p2c < MIN_ITERATIONS ||
    header.p2c > MAX_ITERATIONS
  ) {
    throw new Error('The file’s key derivation settings are out of range.');
  }
  const wrappingKey = await deriveWrappingKey(
    password,
    fromBase64Url(header.p2s),
    header.p2c,
  );
  try {
    // AES key wrap has an integrity check, so a wrong password fails here.
    return await crypto.subtle.unwrapKey(
      'raw',
      fromBase64Url(jwe.encrypted_key),
      wrappingKey,
      'AES-KW',
      'AES-GCM',
      extractable,
      ['encrypt', 'decrypt'],
    );
  } catch {
    throw new WrongPasswordError();
  }
}

/** Whether `jwe` was sealed with `key`, so `open()` can skip the password. */
export function sealedWith(jwe, key) {
  return (
    isJwe(jwe) &&
    jwe.protected === key.protected &&
    jwe.encrypted_key === key.encryptedKey
  );
}

function additionalData(jwe) {
  // RFC 7516 section 5.1: the protected header as base64url, then "." and
  // the "aad" member when there is one.
  return encoder.encode(
    jwe.aad === undefined ? jwe.protected : `${jwe.protected}.${jwe.aad}`,
  );
}

/** Decrypts `jwe` with an unlocked `key` and returns the plaintext string. */
export async function open(jwe, key) {
  const ciphertext = fromBase64Url(jwe.ciphertext);
  const tag = fromBase64Url(jwe.tag);
  const data = new Uint8Array(ciphertext.length + tag.length);
  data.set(ciphertext);
  data.set(tag, ciphertext.length);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: fromBase64Url(jwe.iv),
      additionalData: additionalData(jwe),
      tagLength: 128,
    },
    key.cek,
    data,
  );
  return decoder.decode(plaintext);
}

/** Encrypts `plaintext` with `key` under a fresh IV. */
export async function seal(key, plaintext) {
  const iv = randomBytes(12);
  const jwe = { protected: key.protected, encrypted_key: key.encryptedKey };
  const output = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: additionalData(jwe),
        tagLength: 128,
      },
      key.cek,
      encoder.encode(plaintext),
    ),
  );
  return {
    ...jwe,
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(output.subarray(0, -16)),
    tag: toBase64Url(output.subarray(-16)),
  };
}
