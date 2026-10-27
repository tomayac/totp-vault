/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { rememberChoice, screenSignature } from '../screens.js';

test('screenSignature() tells display setups apart', () => {
  const laptop = screenSignature({
    width: 1512,
    height: 982,
    devicePixelRatio: 2,
    isExtended: false,
  });
  const clamshell = screenSignature({
    width: 2560,
    height: 1440,
    devicePixelRatio: 1,
    isExtended: false,
  });
  const besideTheLaptop = screenSignature({
    width: 2560,
    height: 1440,
    devicePixelRatio: 1,
    isExtended: true,
  });
  assert.equal(laptop, '1512x982@2');
  assert.equal(clamshell, '2560x1440@1');
  assert.equal(besideTheLaptop, '2560x1440@1+');
  assert.equal(
    screenSignature({ width: 1, height: 1, devicePixelRatio: 1.25000001 }),
    '1x1@1.25',
  );
});

test('rememberChoice() keeps the latest choice per setup, and only so many', () => {
  let choices = rememberChoice(null, 'a', 'password');
  choices = rememberChoice(choices, 'b', 'fingerprint');
  choices = rememberChoice(choices, 'a', 'fingerprint');
  assert.deepEqual(choices, { b: 'fingerprint', a: 'fingerprint' });
  for (let i = 0; i < 30; i++) {
    choices = rememberChoice(choices, `setup${i}`, 'password');
  }
  assert.equal(Object.keys(choices).length, 20);
  assert.equal(choices.setup29, 'password');
  assert.equal(choices.a, undefined);
});
