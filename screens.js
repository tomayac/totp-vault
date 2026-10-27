/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

// Without the Window Management API's `isInternal`, a page can't tell the
// built-in screen from an external one. It can tell display setups apart,
// though, by the size and pixel density of the screen the window is on, and
// whether more than one display is on. The app remembers how the user last
// unlocked on each setup: a closed laptop on an external monitor gets a
// different signature than its own screen.

const MAX_SETUPS = 20;

/** A short signature of the display setup, like `2560x1440@1+`. */
export function screenSignature({
  width,
  height,
  devicePixelRatio,
  isExtended,
}) {
  const density = Math.round(devicePixelRatio * 100) / 100;
  return `${width}x${height}@${density}${isExtended ? '+' : ''}`;
}

/**
 * Returns `choices` with `choice` (`'password'` or `'fingerprint'`) for
 * `signature`, keeping the most recently used setups.
 */
export function rememberChoice(choices, signature, choice) {
  const entries = Object.entries(choices ?? {}).filter(
    ([key]) => key !== signature,
  );
  entries.push([signature, choice]);
  return Object.fromEntries(entries.slice(-MAX_SETUPS));
}
