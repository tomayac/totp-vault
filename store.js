/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

// Everything stored is either encrypted or harmless: the vault and the GitHub
// settings are JWEs, the sync state holds only a commit hash and a flag, the
// usage counts are keyed by random token IDs, and the passkey record holds a
// vault key that only the passkey's secret unwraps.
export const KEYS = {
  vault: 'totp-vault.vault',
  github: 'totp-vault.github',
  sync: 'totp-vault.sync',
  usage: 'totp-vault.usage',
  passkey: 'totp-vault.passkey',
};

// Keeps the values that couldn't be saved, for this page load, for example in
// a private window that blocks storage or when storage is full. Storage
// stays the source of truth for everything else, since other windows of the
// app change it too.
const unsaved = new Map();

export function load(key) {
  if (unsaved.has(key)) {
    return unsaved.get(key);
  }
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : null;
  } catch {
    // Unreadable or blocked storage.
    return null;
  }
}

/** Returns whether `value` reached persistent storage. */
export function save(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    unsaved.delete(key);
    return true;
  } catch {
    unsaved.set(key, value);
    return false;
  }
}

export function remove(key) {
  unsaved.delete(key);
  try {
    localStorage.removeItem(key);
  } catch {
    // Nothing to remove.
  }
}
