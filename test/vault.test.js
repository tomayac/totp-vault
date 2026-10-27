/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  fromBitwarden,
  fromOtpauthList,
  readImportFile,
  toBitwarden,
  toOtpauthList,
  toPlainCxf,
} from '../formats.js';
import {
  WrongPasswordError,
  createKey,
  open,
  seal,
  sealedWith,
  unlockKey,
} from '../jwe.js';
import {
  createToken,
  emptyVault,
  fingerprint,
  fromCxf,
  mergeVaults,
  toCxf,
} from '../vault.js';

const ICON = 'data:image/png;base64,iVBORw0KGgo=';

function sampleVault() {
  const vault = emptyVault();
  vault.tokens.push(
    createToken({
      issuer: 'GitHub',
      account: 'octocat',
      secret: 'JBSWY3DPEHPK3PXP',
      url: 'github.com',
      icon: ICON,
    }),
    createToken({
      issuer: 'Example',
      secret: 'GEZDGNBVGY3TQOJQ',
      digits: 8,
      period: 60,
      algorithm: 'SHA256',
    }),
  );
  return vault;
}

function file(name, content) {
  return { name, text: async () => content };
}

test('a sealed vault opens with its password and nothing else', async () => {
  const key = await createKey('correct horse battery');
  const jwe = await seal(key, 'plaintext ✓');
  assert.equal(
    JSON.parse(atob(jwe.protected.replace(/-/g, '+').replace(/_/g, '/'))).alg,
    'PBES2-HS512+A256KW',
  );
  assert.equal(
    await open(jwe, await unlockKey(jwe, 'correct horse battery')),
    'plaintext ✓',
  );
  await assert.rejects(
    unlockKey(jwe, 'wrong horse battery'),
    WrongPasswordError,
  );
  assert.ok(sealedWith(jwe, key));
  const tampered = {
    ...jwe,
    ciphertext: jwe.ciphertext.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')),
  };
  await assert.rejects(open(tampered, key));
});

test('CXF keeps every token field, icons, and deletions', () => {
  const vault = sampleVault();
  vault.deleted.push({ id: 'gone', deletedAt: 1700000000 });
  const cxf = toCxf(vault);
  const item = cxf.accounts[0].items[0];
  assert.equal(item.credentials[0].type, 'totp');
  assert.equal(item.credentials[0].algorithm, 'sha1');
  assert.deepEqual(item.scope, {
    urls: ['https://github.com'],
    androidApps: [],
  });
  assert.equal(item.extensions[0].name, 'tomayac.github.io/totp-vault-icon');
  assert.equal(
    fingerprint(fromCxf(JSON.parse(JSON.stringify(cxf)))),
    fingerprint(vault),
  );
  assert.deepEqual(toPlainCxf(vault).accounts[0].extensions, []);
});

test('fromCxf() reads other exporters and skips unknown algorithms', () => {
  const cxf = {
    version: { major: 1, minor: 0 },
    exporterRpId: 'manager.example',
    exporterDisplayName: 'Manager',
    timestamp: 1700000000,
    accounts: [
      {
        id: 'acc',
        username: '',
        email: '',
        collections: [],
        items: [
          {
            id: 'item1',
            title: 'Shop',
            credentials: [
              {
                type: 'basic-auth',
                username: { fieldType: 'string', value: 'me' },
              },
              {
                type: 'totp',
                secret: 'jbsw y3dp ehpk 3pxp',
                period: 30,
                digits: 6,
                algorithm: 'sha1',
                username: 'me',
              },
              {
                type: 'totp',
                secret: 'GEZDGNBVGY3TQOJQ',
                period: 30,
                digits: 6,
                algorithm: 'md5',
              },
            ],
            extensions: [{ name: 'manager.example/whatever', x: 1 }],
            futureField: true,
          },
        ],
      },
    ],
  };
  const { tokens } = fromCxf(cxf);
  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].issuer, 'Shop');
  assert.equal(tokens[0].account, 'me');
  assert.equal(tokens[0].secret, 'JBSWY3DPEHPK3PXP');
});

test('mergeVaults() keeps the later edit and honors deletions', () => {
  const base = sampleVault();
  const [github, example] = base.tokens;
  const local = structuredClone(base);
  const remote = structuredClone(base);
  local.tokens[0] = {
    ...github,
    account: 'local',
    modifiedAt: github.modifiedAt + 5,
  };
  remote.tokens[0] = {
    ...github,
    account: 'remote',
    modifiedAt: github.modifiedAt + 9,
  };
  remote.tokens = remote.tokens.filter((token) => token.id !== example.id);
  remote.deleted.push({ id: example.id, deletedAt: example.modifiedAt + 1 });
  const added = createToken({ issuer: 'New', secret: 'MFRGGZDFMZTWQ2LK' });
  local.tokens.push(added);
  const merged = mergeVaults(local, remote);
  assert.deepEqual(
    merged.tokens.map((token) => token.account || token.issuer),
    ['remote', 'New'],
  );
  assert.equal(merged.deleted.length, 1);
  // Editing after the deletion brings a token back.
  const revived = mergeVaults(
    { ...remote, tokens: [], deleted: [] },
    {
      ...base,
      tokens: [{ ...example, modifiedAt: example.modifiedAt + 2 }],
      deleted: remote.deleted,
    },
  );
  assert.equal(revived.tokens.length, 1);
});

test('Bitwarden and otpauth exports import back', async () => {
  const vault = sampleVault();
  const bitwarden = fromBitwarden(
    JSON.parse(JSON.stringify(toBitwarden(vault))),
  );
  assert.deepEqual(
    bitwarden.tokens.map(
      ({ issuer, account, secret, digits, period, algorithm, url }) => ({
        issuer,
        account,
        secret,
        digits,
        period,
        algorithm,
        url,
      }),
    ),
    vault.tokens.map(
      ({ issuer, account, secret, digits, period, algorithm, url }) => ({
        issuer,
        account,
        secret,
        digits,
        period,
        algorithm,
        url,
      }),
    ),
  );
  const links = fromOtpauthList(toOtpauthList(vault));
  assert.deepEqual(
    links.tokens.map((token) => token.secret),
    vault.tokens.map((token) => token.secret),
  );
  assert.throws(
    () => fromBitwarden({ encrypted: true, items: [] }),
    /password protected/,
  );
});

test('readImportFile() recognizes every export format', async () => {
  const vault = sampleVault();
  const key = await createKey('correct horse battery');
  const formats = {
    encrypted: JSON.stringify(await seal(key, JSON.stringify(toCxf(vault)))),
    cxf: JSON.stringify(toPlainCxf(vault)),
    bitwarden: JSON.stringify(toBitwarden(vault)),
    otpauth: toOtpauthList(vault),
  };
  for (const [kind, content] of Object.entries(formats)) {
    const result = await readImportFile(file(`x.${kind}`, content));
    assert.equal(result.kind, kind);
  }
  await assert.rejects(readImportFile(file('x.txt', 'hello')), /isn’t a vault/);
});

test('a wrapped vault key unlocks the vault without the password', async () => {
  const { unlockWithWrappedKey, wrapKeyWith } = await import('../jwe.js');
  const key = await createKey('correct horse battery');
  const jwe = await seal(key, 'secret codes');
  const wrappingKey = await crypto.subtle.generateKey(
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  );
  const wrapped = await wrapKeyWith(jwe, 'correct horse battery', wrappingKey);
  const unwrapped = await unlockWithWrappedKey(jwe, wrapped, wrappingKey);
  assert.equal(await open(jwe, unwrapped), 'secret codes');
  assert.ok(sealedWith(jwe, unwrapped));
  // Wrapping proves the password first.
  await assert.rejects(
    wrapKeyWith(jwe, 'wrong horse battery', wrappingKey),
    WrongPasswordError,
  );
  const otherKey = await crypto.subtle.generateKey(
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey'],
  );
  await assert.rejects(unlockWithWrappedKey(jwe, wrapped, otherKey));
});
