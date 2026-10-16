/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

// icon.horse serves high-resolution favicons with CORS, which lets the app
// shrink an icon on a canvas and store it with its token for offline use.
const ICON_SERVICE = 'https://icon.horse/icon/';
const ICON_SIZE = 96;

// Services whose domain is something other than `<issuer>.com`, keyed by the
// issuer in lowercase with everything but letters and digits removed.
const DOMAINS = {
  '11ionos': 'ionos.com',
  ajax: 'ajax.systems',
  bugzillamozilla: 'bugzilla.mozilla.org',
  chromium: 'chromium.org',
  chromiumslack: 'slack.com',
  firefox: 'firefox.com',
  gatehub: 'gatehub.net',
  globalentry: 'ttp.cbp.dhs.gov',
  homeassistant: 'home-assistant.io',
  interledger: 'interledger.org',
  npm: 'npmjs.com',
  slackchromium: 'slack.com',
  twitter: 'x.com',
};

/** Returns the host name in a URL or bare domain, or `''`. */
export function hostOf(value) {
  const text = String(value ?? '').trim();
  if (!text) {
    return '';
  }
  try {
    return new URL(text.includes('://') ? text : `https://${text}`).hostname;
  } catch {
    return '';
  }
}

/** Returns the token's website, or a best guess from its issuer. */
export function guessDomain({ url = '', issuer = '' }) {
  const host = hostOf(url);
  if (host) {
    return host;
  }
  const name = issuer.trim().toLowerCase();
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(name)) {
    return name;
  }
  const key = name.replace(/[^a-z0-9]/g, '');
  return key ? (DOMAINS[key] ?? `${key}.com`) : '';
}

/** Scales any image `Blob` to fit a square PNG data URL. */
export async function imageToDataUrl(blob) {
  const url = URL.createObjectURL(blob);
  try {
    const image = new Image();
    image.src = url;
    await image.decode();
    // SVGs without intrinsic dimensions report 0.
    const width = image.naturalWidth || ICON_SIZE;
    const height = image.naturalHeight || ICON_SIZE;
    const scale = Math.min(ICON_SIZE / width, ICON_SIZE / height);
    const canvas = document.createElement('canvas');
    canvas.width = canvas.height = ICON_SIZE;
    const context = canvas.getContext('2d');
    context.imageSmoothingQuality = 'high';
    context.drawImage(
      image,
      (ICON_SIZE - width * scale) / 2,
      (ICON_SIZE - height * scale) / 2,
      width * scale,
      height * scale,
    );
    return canvas.toDataURL('image/png');
  } finally {
    URL.revokeObjectURL(url);
  }
}

/** Fetches the favicon for `domain` as a data URL. */
export async function fetchIcon(domain) {
  const response = await fetch(ICON_SERVICE + encodeURIComponent(domain), {
    credentials: 'omit',
    referrerPolicy: 'no-referrer',
  });
  if (!response.ok) {
    throw new Error(`icon.horse answered ${response.status}`);
  }
  return imageToDataUrl(await response.blob());
}

/** Fills `element` with the token's icon, or a colored initial. */
export function renderIcon(element, { icon, issuer, account }) {
  const name = (issuer || account || '?').trim();
  element.replaceChildren();
  element.classList.toggle('letter', !icon);
  if (icon) {
    const image = new Image();
    image.alt = '';
    image.src = icon;
    element.append(image);
    return;
  }
  let hue = 0;
  for (const char of name) {
    hue = (hue * 31 + char.codePointAt(0)) % 360;
  }
  element.style.setProperty('--hue', hue);
  element.textContent = [...name][0].toUpperCase();
}
