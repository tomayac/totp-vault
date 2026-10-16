/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

// Counts how often each token's code gets copied on this device, so the list
// can put the most used first. A use counts half as much after 30 days, so
// the order follows current habits. Usage maps token IDs to
// `{ score, at }`, the score as of the time `at` in milliseconds.

const HALF_LIFE_MS = 30 * 24 * 60 * 60 * 1000;

/** The score of `entry` at `time`, after decay. */
export function scoreAt(entry, time) {
  return entry ? entry.score * 0.5 ** ((time - entry.at) / HALF_LIFE_MS) : 0;
}

/**
 * Returns `usage` with one use of `id` at `time` added, keeping only the
 * IDs in `ids`, so deleted tokens don't linger.
 */
export function recordUse(usage, id, time, ids) {
  const kept = Object.fromEntries(
    Object.entries(usage ?? {}).filter(([key]) => ids.has(key)),
  );
  kept[id] = { score: scoreAt(kept[id], time) + 1, at: time };
  return kept;
}

/** A comparator that puts more used tokens first, then defers to `fallback`. */
export function byUsage(usage, time, fallback) {
  return (a, b) =>
    scoreAt(usage?.[b.id], time) - scoreAt(usage?.[a.id], time) ||
    fallback(a, b);
}
