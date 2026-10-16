/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  buildOtpauth,
  isBase32,
  normalizeSecret,
  parseOtpauth,
} from './crypto.js';
import { hostOf } from './icons.js';
import { isJwe } from './jwe.js';
import { createToken, displayName, fromCxf, isCxf, toCxf } from './vault.js';

/**
 * Reads an import file. Returns `{ kind: 'encrypted', jwe }` for a vault that
 * needs its password, or `{ kind, vault }` with the tokens of a plaintext
 * format, where `kind` is `'cxf'`, `'bitwarden'`, or `'otpauth'`.
 */
export async function readImportFile(file) {
  const text = (await file.text()).replace(/^﻿/, '').trim();
  if (text.startsWith('{')) {
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      throw new Error(`${file.name} isn’t valid JSON.`);
    }
    if (isJwe(json)) {
      return { kind: 'encrypted', jwe: json };
    }
    if (isCxf(json)) {
      return { kind: 'cxf', vault: fromCxf(json) };
    }
    if (Array.isArray(json.items)) {
      return { kind: 'bitwarden', vault: fromBitwarden(json) };
    }
  } else if (text.includes('otpauth://')) {
    return { kind: 'otpauth', vault: fromOtpauthList(text) };
  }
  throw new Error(
    `${file.name} isn’t a vault, CXF, Bitwarden, or otpauth:// file.`,
  );
}

function vaultOf(tokens) {
  return { accountId: '', tokens, deleted: [] };
}

export function fromOtpauthList(text) {
  const tokens = [];
  for (const line of text.split(/\s+/)) {
    if (line.startsWith('otpauth://totp/')) {
      tokens.push(createToken(parseOtpauth(line)));
    }
  }
  return vaultOf(tokens);
}

export function fromBitwarden(json) {
  if (json.encrypted) {
    throw new Error(
      'This Bitwarden export is password protected. Export it as unencrypted JSON.',
    );
  }
  const tokens = [];
  for (const item of json.items) {
    const totp = item?.login?.totp?.trim();
    if (!totp) {
      continue;
    }
    const username = item.login.username ?? '';
    let details;
    if (totp.startsWith('otpauth://totp/')) {
      details = parseOtpauth(totp);
    } else if (isBase32(normalizeSecret(totp))) {
      details = { secret: normalizeSecret(totp) };
    } else {
      // Steam and HOTP codes use schemes the app can't generate.
      continue;
    }
    tokens.push(
      createToken({
        ...details,
        issuer: details.issuer || item.name || '',
        account: details.account || username,
        url: hostOf(item.login.uris?.[0]?.uri),
      }),
    );
  }
  return vaultOf(tokens);
}

export function toOtpauthList(vault) {
  return vault.tokens.map(buildOtpauth).join('\n') + '\n';
}

export function toBitwarden(vault) {
  return {
    encrypted: false,
    folders: [],
    items: vault.tokens.map((token) => ({
      type: 1,
      name: displayName(token),
      notes: null,
      favorite: false,
      reprompt: 0,
      folderId: null,
      fields: [],
      login: {
        username: token.account || null,
        password: null,
        totp: buildOtpauth(token),
        uris: token.url ? [{ match: null, uri: `https://${token.url}` }] : [],
      },
    })),
  };
}

export function toPlainCxf(vault) {
  return toCxf(vault, { deletions: false });
}
