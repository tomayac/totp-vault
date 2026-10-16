/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

// Everything stored is either encrypted or harmless: the vault and the GitHub
// settings are JWEs, and the sync state holds only a commit hash and a flag.
export const KEYS = {
  vault: 'totp-vault.vault',
  github: 'totp-vault.github',
  sync: 'totp-vault.sync',
};

// Keeps values for this page load when storage is unavailable, for example
// in a private window that blocks it.
const fallback = new Map();

export function load(key) {
  try {
    const raw = localStorage.getItem(key);
    if (raw) {
      return JSON.parse(raw);
    }
  } catch {
    // Unreadable or blocked storage: fall through.
  }
  return fallback.get(key) ?? null;
}

/** Returns whether `value` reached persistent storage. */
export function save(key, value) {
  fallback.set(key, value);
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

export function remove(key) {
  fallback.delete(key);
  try {
    localStorage.removeItem(key);
  } catch {
    // Nothing to remove.
  }
}
