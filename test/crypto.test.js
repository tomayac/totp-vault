/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { buildOtpauth, importHmacKey, parseOtpauth, totp } from '../crypto.js';
import { guessDomain, hostOf } from '../icons.js';

// RFC 6238 appendix B: the ASCII seeds "1234567890" repeated, in Base32.
const SEEDS = {
  SHA1: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
  SHA256: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  SHA512:
    'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA',
};
const VECTORS = [
  [59, { SHA1: '94287082', SHA256: '46119246', SHA512: '90693936' }],
  [1111111109, { SHA1: '07081804', SHA256: '68084774', SHA512: '25091201' }],
  [1234567890, { SHA1: '89005924', SHA256: '91819424', SHA512: '93441116' }],
  [2000000000, { SHA1: '69279037', SHA256: '90698825', SHA512: '38618901' }],
];

test('totp() matches the RFC 6238 test vectors', async () => {
  for (const [seconds, expected] of VECTORS) {
    for (const [algorithm, code] of Object.entries(expected)) {
      const key = await importHmacKey(SEEDS[algorithm], algorithm);
      assert.equal(
        await totp(key, { digits: 8, period: 30, time: seconds * 1000 }),
        code,
        `${algorithm} at ${seconds}`,
      );
    }
  }
});

test('otpauth links round-trip', () => {
  const details = {
    issuer: 'Example Co',
    account: 'me@example.com',
    secret: 'JBSWY3DPEHPK3PXP',
    digits: 8,
    period: 60,
    algorithm: 'SHA256',
  };
  assert.deepEqual(parseOtpauth(buildOtpauth(details)), details);
  assert.equal(
    parseOtpauth('otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP')
      .issuer,
    'GitHub',
  );
  assert.throws(() => parseOtpauth('otpauth://hotp/X?secret=JBSWY3DP'));
});

test('guessDomain() finds a website for an issuer', () => {
  const cases = [
    [{ issuer: 'GitHub' }, 'github.com'],
    [{ issuer: 'Lemon Squeezy' }, 'lemonsqueezy.com'],
    [{ issuer: 'masto.host' }, 'masto.host'],
    [{ issuer: 'Home Assistant' }, 'home-assistant.io'],
    [{ issuer: '1&1 IONOS' }, 'ionos.com'],
    [{ issuer: 'Slack (Chromium)' }, 'slack.com'],
    [{ issuer: 'GitHub', url: 'https://ghe.example.com/x' }, 'ghe.example.com'],
    [{ issuer: '' }, ''],
  ];
  for (const [token, domain] of cases) {
    assert.equal(guessDomain(token), domain, JSON.stringify(token));
  }
  assert.equal(hostOf('not a url'), '');
});
