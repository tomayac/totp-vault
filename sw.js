/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

// Bump `CACHE` whenever any of `ASSETS` changes, so installed copies update.
const CACHE = 'totp-vault-v7';
const ASSETS = [
  './',
  './index.html',
  './style.css',
  './app.js',
  './crypto.js',
  './formats.js',
  './github.js',
  './icons.js',
  './jwe.js',
  './scanner.js',
  './store.js',
  './vault.js',
  './vendor/jsQR.js',
  './manifest.webmanifest',
  './icon.svg',
  './icon-192.png',
  './icon-512.png',
  './icon-maskable-512.png',
  './apple-touch-icon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(ASSETS))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (
    request.method !== 'GET' ||
    new URL(request.url).origin !== location.origin
  ) {
    return;
  }
  event.respondWith(
    caches
      .match(request, { ignoreSearch: true })
      .then(
        (cached) =>
          cached ??
          fetch(request).catch(() =>
            request.mode === 'navigate'
              ? caches.match('./index.html')
              : Response.error(),
          ),
      ),
  );
});
