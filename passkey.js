/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

import { fromBase64Url, randomBytes, toBase64Url } from './jwe.js';

// Fingerprint unlock. A passkey with the WebAuthn PRF extension returns a
// secret that's fixed for the passkey and a salt, and that it only releases
// after user verification, such as a fingerprint. The app derives an AES key
// from that secret and stores the vault key wrapped with it, so unlocking
// takes the fingerprint and no stored password.

const encoder = new TextEncoder();

/** Whether this browser may support passkeys with PRF on this device. */
export async function passkeysSupported() {
  if (!window.PublicKeyCredential) {
    return false;
  }
  try {
    const capabilities = await PublicKeyCredential.getClientCapabilities?.();
    if (capabilities && 'extension:prf' in capabilities) {
      return (
        capabilities['extension:prf'] &&
        capabilities.userVerifyingPlatformAuthenticator !== false
      );
    }
  } catch {
    // Fall through to the older check.
  }
  return PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
}

async function wrappingKeyFrom(secret) {
  const base = await crypto.subtle.importKey('raw', secret, 'HKDF', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(32),
      info: encoder.encode('TOTP Vault key wrapping'),
    },
    base,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  );
}

async function evaluate(credentialId, salt) {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [{ type: 'public-key', id: credentialId }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const secret = credential.getClientExtensionResults().prf?.results?.first;
  if (!secret) {
    throw new Error('The passkey didn’t return its secret.');
  }
  return secret;
}

/**
 * Creates a passkey for fingerprint unlock. Returns the record to store,
 * without the wrapped key, and the key to wrap the vault key with.
 */
export async function createPasskey() {
  const salt = randomBytes(32);
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: 'TOTP Vault' },
      user: {
        id: randomBytes(16),
        name: 'TOTP Vault',
        displayName: 'TOTP Vault',
      },
      challenge: randomBytes(32),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'preferred',
        userVerification: 'required',
      },
      extensions: { prf: { eval: { first: salt } } },
    },
  });
  const prf = credential.getClientExtensionResults().prf;
  if (!prf?.enabled && !prf?.results) {
    throw new Error(
      'This device’s passkeys can’t unlock the vault, because they lack the PRF extension.',
    );
  }
  const credentialId = new Uint8Array(credential.rawId);
  // Some authenticators only return the secret when asked for it again.
  const secret = prf.results?.first ?? (await evaluate(credentialId, salt));
  return {
    record: {
      credentialId: toBase64Url(credentialId),
      salt: toBase64Url(salt),
    },
    wrappingKey: await wrappingKeyFrom(secret),
  };
}

/** Asks for the fingerprint and returns the record's wrapping key. */
export async function passkeyWrappingKey(record) {
  return wrappingKeyFrom(
    await evaluate(
      fromBase64Url(record.credentialId),
      fromBase64Url(record.salt),
    ),
  );
}
