/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { byUsage, recordUse, scoreAt } from '../usage.js';

const DAY = 24 * 60 * 60 * 1000;
const byName = (a, b) => a.id.localeCompare(b.id);

test('more used tokens sort first, the rest by name', () => {
  const ids = new Set(['a', 'b', 'c']);
  let usage = {};
  usage = recordUse(usage, 'c', 0, ids);
  usage = recordUse(usage, 'c', 0, ids);
  usage = recordUse(usage, 'b', 0, ids);
  const tokens = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
  assert.deepEqual(
    tokens.sort(byUsage(usage, 0, byName)).map((token) => token.id),
    ['c', 'b', 'a'],
  );
});

test('uses count half after 30 days, so recent habits win', () => {
  const ids = new Set(['old', 'new']);
  let usage = {};
  for (let i = 0; i < 3; i++) {
    usage = recordUse(usage, 'old', 0, ids);
  }
  assert.equal(scoreAt(usage.old, 30 * DAY), 1.5);
  usage = recordUse(usage, 'new', 90 * DAY, ids);
  usage = recordUse(usage, 'new', 90 * DAY, ids);
  const tokens = [{ id: 'old' }, { id: 'new' }];
  assert.equal(tokens.sort(byUsage(usage, 90 * DAY, byName))[0].id, 'new');
});

test('recordUse() drops deleted tokens', () => {
  const usage = recordUse(
    { gone: { score: 5, at: 0 } },
    'a',
    0,
    new Set(['a']),
  );
  assert.deepEqual(Object.keys(usage), ['a']);
});
