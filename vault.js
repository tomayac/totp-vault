/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

import { isBase32, normalizeSecret, parseAlgorithm } from './crypto.js';
import { hostOf } from './icons.js';
import { randomBytes, toBase64Url } from './jwe.js';

// The vault is a FIDO Credential Exchange Format (CXF) 1.0 document. CXF has
// no place for icons or deletions, so the app adds two extensions, named
// `<exporterRpId>/<name>` as CXF requires. Other importers ignore them.
export const RP_ID = 'tomayac.github.io';
const ICON_EXTENSION = 'totp-vault-icon';
const DELETED_EXTENSION = 'totp-vault-deleted';

/**
 * A token in memory:
 * `{ id, issuer, account, secret, digits, period, algorithm, url, icon,
 * createdAt, modifiedAt }`, with times in UNIX seconds as in CXF, `url` a
 * host name, and `icon` a data URL.
 */
export function newId() {
  return toBase64Url(randomBytes(16));
}

export function now() {
  return Math.floor(Date.now() / 1000);
}

export function emptyVault() {
  return { accountId: newId(), tokens: [], deleted: [] };
}

/** Fills in the fields a token from an import may lack. */
export function createToken(fields) {
  const time = now();
  return {
    id: newId(),
    issuer: '',
    account: '',
    digits: 6,
    period: 30,
    algorithm: 'SHA1',
    url: '',
    createdAt: time,
    modifiedAt: time,
    ...fields,
    secret: normalizeSecret(fields.secret),
  };
}

export function displayName(token) {
  return token.issuer || token.account || 'Unnamed token';
}

function extensionName(name) {
  return `${RP_ID}/${name}`;
}

function findExtension(extensions, name) {
  // Matching the suffix keeps files readable if the app moves to another host.
  return (Array.isArray(extensions) ? extensions : []).find(
    (extension) =>
      typeof extension?.name === 'string' &&
      extension.name.endsWith(`/${name}`),
  );
}

function iconExtension(icon) {
  const match = /^data:([^;,]+);base64,(.*)$/.exec(icon ?? '');
  return match
    ? [
        {
          name: extensionName(ICON_EXTENSION),
          mediaType: match[1],
          data: match[2],
        },
      ]
    : [];
}

function toItem(token) {
  const extensions = iconExtension(token.icon);
  return {
    id: token.id,
    creationAt: token.createdAt,
    modifiedAt: token.modifiedAt,
    title: displayName(token),
    ...(token.issuer && token.account ? { subtitle: token.account } : {}),
    ...(token.url
      ? { scope: { urls: [`https://${token.url}`], androidApps: [] } }
      : {}),
    credentials: [
      {
        type: 'totp',
        secret: token.secret,
        period: token.period,
        digits: token.digits,
        algorithm: token.algorithm.toLowerCase(),
        ...(token.account ? { username: token.account } : {}),
        ...(token.issuer ? { issuer: token.issuer } : {}),
      },
    ],
    ...(extensions.length ? { extensions } : {}),
  };
}

/**
 * Serializes `vault` as a CXF header. `deletions` keeps the record of deleted
 * tokens that syncing needs, which a plain export leaves out.
 */
export function toCxf(vault, { deletions = true } = {}) {
  return {
    version: { major: 1, minor: 0 },
    exporterRpId: RP_ID,
    exporterDisplayName: 'TOTP Vault',
    timestamp: now(),
    accounts: [
      {
        id: vault.accountId,
        username: '',
        email: '',
        collections: [],
        items: vault.tokens.map(toItem),
        extensions:
          deletions && vault.deleted.length
            ? [{ name: extensionName(DELETED_EXTENSION), items: vault.deleted }]
            : [],
      },
    ],
  };
}

export function isCxf(value) {
  return (
    Number.isInteger(value?.version?.major) && Array.isArray(value.accounts)
  );
}

function isId(value) {
  // CXF ids are base64url of at most 64 bytes.
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,86}$/.test(value);
}

/** Reads the TOTP credentials of a CXF document, from this app or another. */
export function fromCxf(document) {
  if (!isCxf(document) || document.version.major !== 1) {
    throw new Error('Unsupported CXF version.');
  }
  const vault = { accountId: '', tokens: [], deleted: [] };
  const seen = new Set();
  for (const account of document.accounts) {
    vault.accountId ||= isId(account?.id) ? account.id : '';
    for (const item of account?.items ?? []) {
      const credentials = (item?.credentials ?? []).filter(
        (credential) => credential?.type === 'totp',
      );
      for (const credential of credentials) {
        const secret = normalizeSecret(credential.secret ?? '');
        // CXF requires importers to skip unknown algorithms.
        const algorithm = parseAlgorithm(credential.algorithm);
        if (!isBase32(secret) || !algorithm) {
          continue;
        }
        const id = isId(item.id) && !seen.has(item.id) ? item.id : newId();
        seen.add(id);
        const icon = findExtension(item.extensions, ICON_EXTENSION);
        const createdAt = Number(item.creationAt) || now();
        vault.tokens.push({
          id,
          issuer: String(credential.issuer ?? item.title ?? '').trim(),
          account: String(credential.username ?? item.subtitle ?? '').trim(),
          secret,
          digits: Number(credential.digits) || 6,
          period: Number(credential.period) || 30,
          algorithm,
          url: hostOf(item.scope?.urls?.[0]),
          ...(/^image\/[\w.+-]+$/.test(icon?.mediaType) &&
          typeof icon.data === 'string'
            ? { icon: `data:${icon.mediaType};base64,${icon.data}` }
            : {}),
          createdAt,
          modifiedAt: Number(item.modifiedAt) || createdAt,
        });
      }
    }
    const deleted = findExtension(account?.extensions, DELETED_EXTENSION);
    for (const entry of deleted?.items ?? []) {
      if (isId(entry?.id) && Number.isFinite(entry.deletedAt)) {
        vault.deleted.push({ id: entry.id, deletedAt: entry.deletedAt });
      }
    }
  }
  vault.accountId ||= newId();
  return vault;
}

/**
 * Merges two copies of a vault. Per token, the later edit wins, and a
 * deletion wins over edits made before it.
 */
export function mergeVaults(local, remote) {
  const deleted = new Map();
  for (const { id, deletedAt } of [...local.deleted, ...remote.deleted]) {
    deleted.set(id, Math.max(deleted.get(id) ?? 0, deletedAt));
  }
  const tokens = new Map(local.tokens.map((token) => [token.id, token]));
  for (const token of remote.tokens) {
    const mine = tokens.get(token.id);
    if (!mine || token.modifiedAt > mine.modifiedAt) {
      tokens.set(token.id, token);
    }
  }
  for (const [id, deletedAt] of deleted) {
    if (tokens.get(id)?.modifiedAt <= deletedAt) {
      tokens.delete(id);
    }
  }
  return {
    accountId: local.accountId,
    tokens: [...tokens.values()],
    deleted: [...deleted].map(([id, deletedAt]) => ({ id, deletedAt })),
  };
}

/** A string that's equal for two vaults with the same content. */
export function fingerprint(vault) {
  const byId = (a, b) => (a.id < b.id ? -1 : 1);
  return JSON.stringify({
    tokens: [...vault.tokens]
      .sort(byId)
      .map((token) => Object.fromEntries(Object.entries(token).sort())),
    deleted: [...vault.deleted].sort(byId),
  });
}
