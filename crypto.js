/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const HASHES = { SHA1: 'SHA-1', SHA256: 'SHA-256', SHA512: 'SHA-512' };

export function normalizeSecret(secret) {
  return String(secret)
    .replace(/[\s=-]/g, '')
    .toUpperCase();
}

export function isBase32(secret) {
  return /^[A-Z2-7]+$/.test(secret);
}

/** Returns `'SHA1'`, `'SHA256'`, or `'SHA512'`, or `null` for anything else. */
export function parseAlgorithm(algorithm) {
  const name = String(algorithm || 'SHA1')
    .toUpperCase()
    .replace('-', '');
  return name in HASHES ? name : null;
}

export function normalizeAlgorithm(algorithm) {
  return parseAlgorithm(algorithm) ?? 'SHA1';
}

export function base32Decode(secret) {
  const clean = normalizeSecret(secret);
  if (!isBase32(clean)) {
    throw new Error('The secret is not valid Base32.');
  }
  const bytes = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let bits = 0;
  let value = 0;
  let index = 0;
  for (const char of clean) {
    value = ((value << 5) | BASE32_ALPHABET.indexOf(char)) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bytes[index++] = (value >>> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return bytes;
}

export function importHmacKey(secret, algorithm = 'SHA1') {
  return crypto.subtle.importKey(
    'raw',
    base32Decode(secret),
    { name: 'HMAC', hash: HASHES[normalizeAlgorithm(algorithm)] },
    false,
    ['sign'],
  );
}

/** RFC 6238 TOTP for an HMAC key from `importHmacKey()`. */
export async function totp(
  key,
  { digits = 6, period = 30, time = Date.now() },
) {
  const counter = Math.floor(time / 1000 / period);
  const message = new DataView(new ArrayBuffer(8));
  message.setUint32(0, Math.floor(counter / 2 ** 32));
  message.setUint32(4, counter >>> 0);
  const mac = new Uint8Array(
    await crypto.subtle.sign('HMAC', key, message.buffer),
  );
  const offset = mac[mac.length - 1] & 0xf;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** Parses an otpauth://totp/ link from the Google Authenticator Key URI Format. */
export function parseOtpauth(uri) {
  const url = new URL(uri.trim());
  if (url.protocol !== 'otpauth:') {
    throw new Error('This is not an otpauth:// link.');
  }
  if (url.host.toLowerCase() !== 'totp') {
    throw new Error('Only time-based (TOTP) links are supported.');
  }
  const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
  const separator = label.indexOf(':');
  const labelIssuer = separator >= 0 ? label.slice(0, separator).trim() : '';
  const account = (separator >= 0 ? label.slice(separator + 1) : label).trim();
  const params = url.searchParams;
  const secret = normalizeSecret(params.get('secret') || '');
  if (!isBase32(secret)) {
    throw new Error('The link has no valid secret.');
  }
  const issuer = params.get('issuer')?.trim() || labelIssuer;
  return {
    issuer,
    // A label that only repeats the issuer names no account.
    account: separator < 0 && account === issuer ? '' : account,
    secret,
    digits: Number(params.get('digits')) || 6,
    period: Number(params.get('period')) || 30,
    algorithm: normalizeAlgorithm(params.get('algorithm')),
  };
}

export function buildOtpauth({
  issuer = '',
  account = '',
  secret,
  digits = 6,
  period = 30,
  algorithm = 'SHA1',
}) {
  const label =
    issuer && account
      ? `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`
      : encodeURIComponent(issuer || account || 'Token');
  const params = [`secret=${normalizeSecret(secret)}`];
  if (issuer) {
    params.push(`issuer=${encodeURIComponent(issuer)}`);
  }
  params.push(
    `algorithm=${normalizeAlgorithm(algorithm)}`,
    `digits=${digits}`,
    `period=${period}`,
  );
  return `otpauth://totp/${label}?${params.join('&')}`;
}
