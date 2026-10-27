/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  buildOtpauth,
  importHmacKey,
  isBase32,
  normalizeAlgorithm,
  normalizeSecret,
  parseOtpauth,
  totp,
} from './crypto.js';
import {
  readImportFile,
  toBitwarden,
  toOtpauthList,
  toPlainCxf,
} from './formats.js';
import { readFile, writeFile } from './github.js';
import {
  fetchIcon,
  guessDomain,
  hostOf,
  imageToDataUrl,
  renderIcon,
} from './icons.js';
import {
  createKey,
  open,
  seal,
  sealedWith,
  unlockKey,
  unlockWithWrappedKey,
  wrapKeyWith,
} from './jwe.js';
import {
  createPasskey,
  passkeyWrappingKey,
  passkeysSupported,
} from './passkey.js';
import { Scanner, saveCamera, scanImage } from './scanner.js';
import { KEYS, load, remove, save } from './store.js';
import { byUsage, recordUse } from './usage.js';
import {
  createToken,
  displayName,
  emptyVault,
  fingerprint,
  fromCxf,
  mergeVaults,
  newId,
  now,
  toCxf,
} from './vault.js';

const IDLE_LOCK_MS = 5 * 60 * 1000;
const HIDDEN_LOCK_MS = 60 * 1000;
const EXPIRING_SECONDS = 5;
// icon.horse rate limits clients that ask too fast.
const ICON_INTERVAL_MS = 1000;
const ICON_BACKOFF_MS = 2000;
const ICON_RETRIES = 4;
// Waiting a moment batches quick successive edits into one commit.
const SYNC_DELAY_MS = 1500;
const MIN_PASSWORD_LENGTH = 8;
const ICONS_DISMISSED_KEY = 'totp-vault.icons-dismissed';
// Fingerprint unlock is offered once per vault, then lives in Settings.
const PASSKEY_OFFERED_KEY = 'totp-vault.passkey-offered';
const DEFAULT_GITHUB = {
  owner: '',
  repo: 'totp-vault-data',
  path: 'vault.jwe.json',
  branch: '',
  token: '',
};

const $ = (selector) => document.querySelector(selector);

const views = {
  welcome: $('#welcome-view'),
  unlock: $('#unlock-view'),
  vault: $('#vault-view'),
};
const tokenList = $('#token-list');
const tokenTemplate = $('#token-template');
const searchInput = $('#search');
const fileInput = $('#file-input');
const imageInput = $('#image-input');
const addDialog = $('#add-dialog');
const addForm = $('#add-form');
const editDialog = $('#edit-dialog');
const editForm = $('#edit-form');
const exportDialog = $('#export-dialog');
const scanDialog = $('#scan-dialog');
const passwordDialog = $('#password-dialog');
const passwordForm = $('#password-form');
const githubDialog = $('#github-dialog');
const githubForm = $('#github-form');
const settingsDialog = $('#settings-dialog');
const cameraSelect = $('#camera-select');
const scanStatus = $('#scan-status');
const syncStatus = $('#sync-status');
const toast = $('#toast');
const dialogs = [
  passwordDialog,
  githubDialog,
  scanDialog,
  addDialog,
  editDialog,
  exportDialog,
  settingsDialog,
];

// The unlocked vault. `key` is the vault key from `jwe.js`, `vault` holds the
// decrypted tokens, `hmacKeys` caches a key per token, `github` holds the
// backup settings, and `oldKeys` lets syncing read backups saved before a
// password change. `lock()` drops all of it.
let session = null;
// Rendered tokens by ID: their elements and the counter `value` belongs to.
let rendered = new Map();
let lastActivity = Date.now();
let hiddenAt = 0;
let toastTimer = 0;
// The icon the edit dialog will save: `undefined` keeps the current one, and
// `''` removes it.
let pendingIcon;
// Where an image picked through `imageInput` goes: `'scan'` or `'icon'`.
let imagePurpose = 'scan';
// Counts local changes, so a sync can tell whether edits arrived meanwhile.
let revision = 0;
let syncTimer = 0;
let syncRunning = null;
let syncAgain = false;

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('visible'), 5000);
}

function plural(count, one, many = `${one}s`) {
  return `${count} ${count === 1 ? one : many}`;
}

function findToken(id) {
  return session.vault.tokens.find((token) => token.id === id);
}

function formatCode(code) {
  const split = Math.floor(code.length / 2);
  return `${code.slice(0, split)} ${code.slice(split)}`;
}

function hmacKeyFor(token) {
  const cached = session.hmacKeys.get(token.id);
  if (cached?.secret === token.secret && cached.algorithm === token.algorithm) {
    return cached.key;
  }
  const key = importHmacKey(token.secret, token.algorithm);
  session.hmacKeys.set(token.id, {
    secret: token.secret,
    algorithm: token.algorithm,
    key,
  });
  return key;
}

// Rendering.

function render() {
  const stored = Boolean(load(KEYS.vault));
  views.welcome.hidden = Boolean(session) || stored;
  views.unlock.hidden = Boolean(session) || !stored;
  views.vault.hidden = !session;
  renderUnlockView();
  for (const id of [
    'add-button',
    'import-button',
    'export-button',
    'settings-button',
    'lock-button',
  ]) {
    $(`#${id}`).hidden = !session;
  }
  renderList();
  renderSyncStatus();
}

function renderList() {
  tokenList.replaceChildren();
  rendered = new Map();
  if (!session) {
    return;
  }
  const query = searchInput.value.trim().toLowerCase();
  const tokens = [...session.vault.tokens].sort(
    byUsage(
      load(KEYS.usage),
      Date.now(),
      (a, b) =>
        displayName(a).localeCompare(displayName(b), undefined, {
          sensitivity: 'base',
        }) || a.account.localeCompare(b.account),
    ),
  );
  for (const token of tokens) {
    if (
      query &&
      !`${token.issuer} ${token.account}`.toLowerCase().includes(query)
    ) {
      continue;
    }
    const item = tokenTemplate.content.firstElementChild.cloneNode(true);
    item.dataset.id = token.id;
    renderIcon(item.querySelector('.icon'), token);
    item.querySelector('.issuer').textContent = displayName(token);
    item.querySelector('.account').textContent = token.issuer
      ? token.account
      : '';
    tokenList.append(item);
    rendered.set(token.id, {
      token,
      item,
      code: item.querySelector('.code'),
      progress: item.querySelector('.progress'),
      counter: -1,
      value: '',
    });
  }
  const missingIcons = session.vault.tokens.filter(
    (token) => !token.icon,
  ).length;
  $('#icon-banner').hidden =
    missingIcons === 0 || Boolean(load(ICONS_DISMISSED_KEY));
  $('#icon-banner-count').textContent =
    `${plural(missingIcons, 'token has', 'tokens have')} no icon yet.`;
  $('#empty-note').hidden = session.vault.tokens.length > 0;
  $('#copy-hint').hidden = session.vault.tokens.length === 0;
  tick();
}

function tick() {
  if (!session) {
    return;
  }
  const time = Date.now();
  if (time - lastActivity > IDLE_LOCK_MS) {
    lock();
    return;
  }
  for (const entry of rendered.values()) {
    const { digits, period } = entry.token;
    const counter = Math.floor(time / 1000 / period);
    const remaining = period - ((time / 1000) % period);
    entry.progress.style.setProperty('--remaining', remaining / period);
    entry.item.classList.toggle('expiring', remaining <= EXPIRING_SECONDS);
    if (counter === entry.counter) {
      continue;
    }
    entry.counter = counter;
    const current = session;
    hmacKeyFor(entry.token)
      .then((key) => totp(key, { digits, period, time }))
      .then((value) => {
        if (session === current && entry.counter === counter) {
          entry.value = value;
          entry.code.textContent = formatCode(value);
        }
      });
  }
}

setInterval(tick, 250);

// Storage.

function syncState() {
  return load(KEYS.sync) ?? { sha: null, dirty: false };
}

/** Encrypts the vault into storage and schedules a backup. */
async function persist({ backup = true } = {}) {
  const jwe = await seal(session.key, JSON.stringify(toCxf(session.vault)));
  if (!save(KEYS.vault, jwe)) {
    showToast(
      'This browser blocked storage. Your tokens are kept until you close the page, so export the vault.',
    );
  }
  if (backup) {
    revision++;
    save(KEYS.sync, { ...syncState(), dirty: true });
    scheduleSync();
  }
}

async function saveGitHubSettings() {
  if (session.github) {
    save(KEYS.github, await seal(session.key, JSON.stringify(session.github)));
  } else {
    remove(KEYS.github);
  }
}

async function startSession(key, vault, github = null) {
  // Unlocked some other way, a fingerprint prompt has nothing left to do.
  passkeyAbort?.abort();
  session = { key, vault, hmacKeys: new Map(), github, oldKeys: [] };
  if (!github) {
    const sealed = load(KEYS.github);
    if (sealed && sealedWith(sealed, key)) {
      session.github = JSON.parse(await open(sealed, key));
    }
  }
  lastActivity = Date.now();
  searchInput.value = '';
  render();
  focusSearch();
  if (session.github) {
    sync();
  }
}

/**
 * Focuses the search field, so typing filters right away. Touch devices are
 * left alone, where focusing would raise a keyboard over the codes.
 */
function focusSearch() {
  if (matchMedia('(pointer: fine)').matches) {
    searchInput.focus();
  }
}

/** Replaces whatever is stored on this device with `vault`. */
async function createVault(key, vault) {
  remove(KEYS.github);
  remove(KEYS.sync);
  remove(KEYS.passkey);
  remove(PASSKEY_OFFERED_KEY);
  remove(ICONS_DISMISSED_KEY);
  session = { key, vault, hmacKeys: new Map(), github: null, oldKeys: [] };
  await persist({ backup: false });
  await startSession(key, vault);
}

async function lock() {
  // Finish a pending backup while the settings are still decrypted.
  if (syncTimer) {
    clearTimeout(syncTimer);
    syncTimer = 0;
    await sync();
  }
  session = null;
  for (const dialog of dialogs) {
    dialog.close();
  }
  render();
  if (!passkeyCurrent() || matchMedia('(pointer: fine)').matches) {
    $('#password').focus();
  }
}

function forgetDevice() {
  if (
    !confirm(
      'Remove the vault from this device? Tokens that aren’t in your GitHub backup or an export are lost.',
    )
  ) {
    return;
  }
  for (const key of [
    ...Object.values(KEYS),
    ICONS_DISMISSED_KEY,
    PASSKEY_OFFERED_KEY,
  ]) {
    remove(key);
  }
  session = null;
  for (const dialog of dialogs) {
    dialog.close();
  }
  render();
}

// Prompts.

/**
 * Asks for a password. `verify(password)` may throw to show an error and keep
 * the dialog open. Resolves with its result, or `null` when canceled.
 */
function askPassword({
  title,
  message,
  submitLabel = 'Continue',
  confirm = false,
  verify = (password) => password,
}) {
  return new Promise((resolve) => {
    const error = passwordForm.querySelector('.error');
    const submit = $('#password-submit');
    passwordForm.reset();
    $('#password-title').textContent = title;
    $('#password-message').textContent = message;
    submit.textContent = submitLabel;
    error.textContent = '';
    $('#confirm-label').hidden = !confirm;
    passwordForm.confirm.required = confirm;
    passwordForm.password.autocomplete = confirm
      ? 'new-password'
      : 'current-password';

    const finish = (value) => {
      passwordForm.removeEventListener('submit', onSubmit);
      passwordDialog.removeEventListener('close', onClose);
      passwordDialog.close();
      passwordForm.reset();
      resolve(value);
    };
    // `close` fires asynchronously, so when one prompt follows another, the
    // first prompt's event arrives while the dialog is open again. Only a
    // `close` that leaves the dialog closed is a cancel.
    const onClose = () => {
      if (!passwordDialog.open) {
        finish(null);
      }
    };
    const onSubmit = async (event) => {
      event.preventDefault();
      const password = passwordForm.password.value;
      if (confirm && password.length < MIN_PASSWORD_LENGTH) {
        error.textContent = `Use at least ${MIN_PASSWORD_LENGTH} characters.`;
        return;
      }
      if (confirm && password !== passwordForm.confirm.value) {
        error.textContent = 'The passwords don’t match.';
        return;
      }
      submit.disabled = true;
      const label = submit.textContent;
      submit.textContent = 'Working…';
      try {
        finish(await verify(password));
      } catch (problem) {
        error.textContent = problem.message;
        passwordForm.password.select();
      } finally {
        submit.disabled = false;
        submit.textContent = label;
      }
    };
    passwordForm.addEventListener('submit', onSubmit);
    passwordDialog.addEventListener('close', onClose);
    passwordDialog.showModal();
  });
}

/** Asks for GitHub settings, like `askPassword()`. */
function askGitHub({ title, submitLabel, verify }) {
  return new Promise((resolve) => {
    const error = githubForm.querySelector('.error');
    const submit = $('#github-submit');
    const initial = session?.github ?? DEFAULT_GITHUB;
    for (const [name, value] of Object.entries(initial)) {
      githubForm[name].value = value;
    }
    $('#github-title').textContent = title;
    submit.textContent = submitLabel;
    error.textContent = '';

    const finish = (value) => {
      githubForm.removeEventListener('submit', onSubmit);
      githubDialog.removeEventListener('close', onClose);
      githubDialog.close();
      githubForm.token.value = '';
      resolve(value);
    };
    // See `askPassword()`.
    const onClose = () => {
      if (!githubDialog.open) {
        finish(null);
      }
    };
    const onSubmit = async (event) => {
      event.preventDefault();
      const settings = Object.fromEntries(
        Object.keys(DEFAULT_GITHUB).map((name) => [
          name,
          githubForm[name].value.trim(),
        ]),
      );
      submit.disabled = true;
      error.textContent = '';
      try {
        finish(await verify(settings));
      } catch (problem) {
        error.textContent = problem.message;
      } finally {
        submit.disabled = false;
      }
    };
    githubForm.addEventListener('submit', onSubmit);
    githubDialog.addEventListener('close', onClose);
    githubDialog.showModal();
  });
}

function askNewPassword(message) {
  return askPassword({
    title: 'Choose a vault password',
    message,
    submitLabel: 'Save',
    confirm: true,
    verify: async (password) => ({ key: await createKey(password), password }),
  });
}

// GitHub backup.

function scheduleSync() {
  if (!session?.github) {
    return;
  }
  clearTimeout(syncTimer);
  syncTimer = setTimeout(() => {
    syncTimer = 0;
    sync();
  }, SYNC_DELAY_MS);
  setSyncStatus('pending');
}

let syncStatusState = { state: 'idle' };

function setSyncStatus(state, message = '') {
  syncStatusState = { state, message, at: new Date() };
  renderSyncStatus();
}

function renderSyncStatus() {
  const { state, message, at } = syncStatusState;
  syncStatus.hidden = !session?.github;
  syncStatus.classList.toggle('error', state === 'error');
  syncStatus.textContent = {
    idle: 'Backed up to GitHub',
    pending: 'Backing up to GitHub…',
    syncing: 'Backing up to GitHub…',
    done: `Backed up to GitHub at ${at?.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`,
    error: `Backup failed: ${message} Tap to retry.`,
  }[state];
  const summary = $('#settings-github-summary');
  if (summary) {
    summary.textContent = session?.github
      ? `Every change goes to ${session.github.path} in ${session.github.owner}/${session.github.repo}. ${syncStatus.textContent}`
      : 'Not set up. Every change can go to a private repository, encrypted.';
  }
}

/**
 * Reads the backup's vault and merges it into the session. Returns whether
 * the backup now matches this device, so no upload is needed.
 */
async function pullRemote(text) {
  const jwe = JSON.parse(text);
  let key = [session.key, ...session.oldKeys].find((candidate) =>
    sealedWith(jwe, candidate),
  );
  let password = null;
  if (!key) {
    const answer = await askPassword({
      title: 'The backup has another password',
      message:
        'The vault on GitHub was saved with a different password, probably from another device. Enter that password to merge it. This device switches to it too.',
      submitLabel: 'Merge',
      verify: async (candidate) => ({
        key: await unlockKey(jwe, candidate),
        password: candidate,
      }),
    });
    if (!answer) {
      throw new Error('The backup needs its password.');
    }
    ({ key, password } = answer);
    session.oldKeys.push(session.key);
    session.key = key;
    await saveGitHubSettings();
  }
  const remote = fromCxf(JSON.parse(await open(jwe, key)));
  const merged = mergeVaults(session.vault, remote);
  // A new password needs saving too, so this device unlocks with it.
  if (password || fingerprint(merged) !== fingerprint(session.vault)) {
    session.vault = merged;
    await persist({ backup: false });
    renderList();
  }
  if (password) {
    await refreshPasskey(password);
  }
  return fingerprint(merged) === fingerprint(remote) && key === session.key;
}

/** Merges with the backup and uploads local changes. */
async function sync() {
  if (!session?.github) {
    return;
  }
  if (syncRunning) {
    syncAgain = true;
    return syncRunning;
  }
  const current = session;
  setSyncStatus('syncing');
  syncRunning = (async () => {
    try {
      for (let attempt = 1; ; attempt++) {
        const state = syncState();
        const remote = await readFile(current.github);
        if (session !== current) {
          return;
        }
        const startRevision = revision;
        const upToDate = remote
          ? remote.sha === state.sha
            ? !state.dirty
            : await pullRemote(remote.text)
          : false;
        if (upToDate) {
          save(KEYS.sync, {
            sha: remote.sha,
            dirty: revision !== startRevision,
          });
          break;
        }
        try {
          const sha = await writeFile(
            current.github,
            JSON.stringify(load(KEYS.vault), null, 2) + '\n',
            remote?.sha,
          );
          save(KEYS.sync, { sha, dirty: revision !== startRevision });
          break;
        } catch (error) {
          // Another device wrote in between: read and merge again.
          if ([409, 422].includes(error.status) && attempt < 3) {
            continue;
          }
          throw error;
        }
      }
      setSyncStatus('done');
    } catch (error) {
      setSyncStatus('error', error.message);
    } finally {
      syncRunning = null;
      if (syncAgain && session === current) {
        syncAgain = false;
        sync();
      }
    }
  })();
  return syncRunning;
}

syncStatus.addEventListener('click', () => sync());
addEventListener('online', () => {
  if (syncState().dirty) {
    sync();
  }
});

// Importing.

/** Reads files into vaults, asking for the password of encrypted ones. */
async function readFiles(files) {
  const vaults = [];
  const problems = [];
  let encrypted = false;
  for (const file of files) {
    try {
      const result = await readImportFile(file);
      if (result.kind !== 'encrypted') {
        vaults.push(result.vault);
        continue;
      }
      const vault = await askPassword({
        title: 'Open the encrypted vault',
        message: `Enter the password of ${file.name}.`,
        submitLabel: 'Open',
        verify: async (password) =>
          fromCxf(
            JSON.parse(
              await open(result.jwe, await unlockKey(result.jwe, password)),
            ),
          ),
      });
      if (vault) {
        vaults.push(vault);
        encrypted = true;
      }
    } catch (problem) {
      problems.push(problem.message);
    }
  }
  return { vaults, problems, encrypted };
}

/** Adds the tokens whose secrets `vault` doesn't have yet. */
function addTokens(vault, tokens) {
  const secrets = new Set(vault.tokens.map((token) => token.secret));
  const ids = new Set(vault.tokens.map((token) => token.id));
  let added = 0;
  for (const token of tokens) {
    if (secrets.has(token.secret)) {
      continue;
    }
    secrets.add(token.secret);
    const unique = ids.has(token.id) ? { ...token, id: newId() } : token;
    ids.add(unique.id);
    vault.tokens.push(unique);
    added++;
  }
  return added;
}

async function importIntoNewVault(files) {
  const { vaults, problems, encrypted } = await readFiles(files);
  if (!vaults.length) {
    if (problems.length) {
      showToast(problems.join(' '));
    }
    return;
  }
  // A single vault keeps its identity, so its ids keep matching a backup.
  const [first, ...rest] = vaults;
  const vault = first.accountId
    ? { ...first, tokens: [], deleted: first.deleted }
    : emptyVault();
  addTokens(vault, first.tokens);
  for (const other of rest) {
    addTokens(vault, other.tokens);
  }
  const answer = await askNewPassword(
    `${plural(vault.tokens.length, 'token')} ready. This password encrypts your vault on this device and in your GitHub backup.` +
      (encrypted ? ' It may differ from the file’s password.' : ''),
  );
  if (!answer) {
    return;
  }
  await createVault(answer.key, vault);
  showToast(
    [`Imported ${plural(vault.tokens.length, 'token')}.`, ...problems].join(
      ' ',
    ),
  );
  await offerPasskey(answer.password);
}

async function importIntoVault(files) {
  const { vaults, problems } = await readFiles(files);
  let added = 0;
  for (const vault of vaults) {
    added += addTokens(session.vault, vault.tokens);
  }
  if (added) {
    await persist();
    renderList();
  }
  const summary = added
    ? `Imported ${plural(added, 'token')}.`
    : vaults.length
      ? 'All these tokens are already in the vault.'
      : '';
  showToast([summary, ...problems].filter(Boolean).join(' '));
}

function importFiles(files) {
  if (!files.length) {
    return;
  }
  return session ? importIntoVault(files) : importIntoNewVault(files);
}

fileInput.addEventListener('change', async () => {
  const files = [...fileInput.files];
  fileInput.value = '';
  await importFiles(files);
});

$('#welcome-import').addEventListener('click', () => fileInput.click());
$('#import-button').addEventListener('click', () => fileInput.click());

document.addEventListener('dragover', (event) => event.preventDefault());
document.addEventListener('drop', (event) => {
  event.preventDefault();
  const files = [...event.dataTransfer.files];
  if (scanDialog.open) {
    const image = files.find((file) => file.type.startsWith('image/'));
    if (image) {
      scanFile(image);
    }
  } else if (session || !views.welcome.hidden) {
    importFiles(files);
  }
});

// Onboarding, unlocking, and locking.

$('#welcome-empty').addEventListener('click', async () => {
  const answer = await askNewPassword(
    'This password encrypts your vault on this device and in your GitHub backup. You need it on every device.',
  );
  if (answer) {
    await createVault(answer.key, emptyVault());
    await offerPasskey(answer.password);
  }
});

$('#welcome-github').addEventListener('click', async () => {
  const found = await askGitHub({
    title: 'Restore from GitHub',
    submitLabel: 'Find backup',
    verify: async (settings) => {
      const remote = await readFile(settings);
      if (!remote) {
        throw new Error(`There’s no ${settings.path} in that repository yet.`);
      }
      return { settings, remote, jwe: JSON.parse(remote.text) };
    },
  });
  if (!found) {
    return;
  }
  const answer = await askPassword({
    title: 'Unlock your backup',
    message: `Enter the password of the vault in ${found.settings.owner}/${found.settings.repo}.`,
    submitLabel: 'Unlock',
    verify: async (password) => ({
      key: await unlockKey(found.jwe, password),
      password,
    }),
  });
  if (!answer) {
    return;
  }
  const { key, password } = answer;
  const vault = fromCxf(JSON.parse(await open(found.jwe, key)));
  save(KEYS.vault, found.jwe);
  save(KEYS.sync, { sha: found.remote.sha, dirty: false });
  remove(KEYS.passkey);
  remove(PASSKEY_OFFERED_KEY);
  remove(ICONS_DISMISSED_KEY);
  await startSession(key, vault, found.settings);
  await saveGitHubSettings();
  showToast(`Restored ${plural(vault.tokens.length, 'token')}.`);
  await offerPasskey(password);
});

$('#unlock-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const password = $('#password');
  const button = event.submitter ?? $('#unlock-form button');
  const error = $('#unlock-error');
  error.textContent = '';
  button.disabled = true;
  button.textContent = 'Unlocking…';
  try {
    const jwe = load(KEYS.vault);
    const key = await unlockKey(jwe, password.value);
    const vault = fromCxf(JSON.parse(await open(jwe, key)));
    const typed = password.value;
    password.value = '';
    await startSession(key, vault);
    await refreshPasskey(typed);
    await offerPasskey(typed);
  } catch (problem) {
    error.textContent = problem.message;
    password.select();
  } finally {
    button.disabled = false;
    button.textContent = unlockLabel();
  }
});

// Fingerprint unlock.

function unlockLabel() {
  return passkeyCurrent() ? 'Unlock with password' : 'Unlock';
}

/** With fingerprint unlock on, it leads, and the password is the fallback. */
function renderUnlockView() {
  const record = load(KEYS.passkey);
  const fingerprintFirst = passkeyCurrent(record);
  const passkeyButton = $('#passkey-unlock');
  passkeyButton.hidden = !record;
  passkeyButton.classList.toggle('primary', fingerprintFirst);
  const submit = $('#unlock-form [type=submit]');
  submit.classList.toggle('primary', !fingerprintFirst);
  submit.textContent = unlockLabel();
}

/** Whether the passkey record unwraps the key the stored vault uses. */
function passkeyCurrent(record = load(KEYS.passkey)) {
  return (
    Boolean(record) && record.encryptedKey === load(KEYS.vault)?.encrypted_key
  );
}

// The fingerprint prompt in progress, so only one ever shows, and its abort
// controller, so unlocking with the password can close it.
let passkeyPrompt = null;
let passkeyAbort = null;
// When the last prompt ended, and whether the user left the app since.
// Closing a prompt hands the focus back to the window, which mustn't count
// as coming back, or canceling would only bring up the next prompt.
let promptEndedAt = 0;
let leftSincePrompt = true;

function unlockWithPasskey(options) {
  passkeyPrompt ??= promptForPasskey(options).finally(() => {
    passkeyPrompt = null;
    promptEndedAt = Date.now();
    leftSincePrompt = false;
  });
  return passkeyPrompt;
}

async function promptForPasskey({ quiet = false } = {}) {
  const record = load(KEYS.passkey);
  const error = $('#unlock-error');
  error.textContent = '';
  if (!passkeyCurrent(record)) {
    if (!quiet) {
      error.textContent =
        'The password changed since you turned on fingerprint unlock. Unlock with the password once to use your fingerprint again.';
    }
    return;
  }
  passkeyAbort = new AbortController();
  try {
    const jwe = load(KEYS.vault);
    const key = await unlockWithWrappedKey(
      jwe,
      record.wrappedKey,
      await passkeyWrappingKey(record, passkeyAbort.signal),
    );
    await startSession(key, fromCxf(JSON.parse(await open(jwe, key))));
  } catch (problem) {
    if (session) {
      return;
    }
    // Canceling the prompt needs no message, since the password still works.
    if (
      !quiet &&
      problem.name !== 'NotAllowedError' &&
      problem.name !== 'AbortError'
    ) {
      error.textContent = problem.message;
    }
    if (matchMedia('(pointer: fine)').matches) {
      $('#password').focus();
    }
  }
}

/** Asks for the fingerprint when a locked app comes to the foreground. */
function promptOnForeground() {
  if (
    !session &&
    !views.unlock.hidden &&
    leftSincePrompt &&
    !passkeyPrompt &&
    !document.hidden &&
    document.hasFocus() &&
    passkeyCurrent()
  ) {
    unlockWithPasskey({ quiet: true });
  }
}

addEventListener('blur', () => {
  // A blur right as a prompt ends belongs to the prompt.
  if (!passkeyPrompt && Date.now() - promptEndedAt > 1000) {
    leftSincePrompt = true;
  }
});
addEventListener('focus', promptOnForeground);

/** Turns on fingerprint unlock, which asks to create a passkey. */
async function turnOnPasskey(password) {
  try {
    const { record, wrappingKey } = await createPasskey();
    await enrollPasskey(record, wrappingKey, password);
    showToast('Fingerprint unlock is on.');
  } catch (problem) {
    if (problem.name !== 'NotAllowedError') {
      showToast(problem.message);
    }
  }
}

/**
 * Makes fingerprint unlock the default: the first time a password is set or
 * typed for a vault, asks to create the passkey. Declining leaves the switch
 * in Settings.
 */
async function offerPasskey(password) {
  if (
    load(KEYS.passkey) ||
    load(PASSKEY_OFFERED_KEY) ||
    !(await passkeysSupported())
  ) {
    return;
  }
  save(PASSKEY_OFFERED_KEY, true);
  await turnOnPasskey(password);
}

/** Stores the vault key wrapped for the passkey of `record`. */
async function enrollPasskey(record, wrappingKey, password) {
  const jwe = load(KEYS.vault);
  save(KEYS.passkey, {
    ...record,
    wrappedKey: await wrapKeyWith(jwe, password, wrappingKey),
    encryptedKey: jwe.encrypted_key,
  });
}

/**
 * After the password changed, wraps the new vault key for the passkey, which
 * asks for the fingerprint. Does nothing when fingerprint unlock is off or
 * current.
 */
async function refreshPasskey(password) {
  const record = load(KEYS.passkey);
  if (!record || passkeyCurrent(record)) {
    return;
  }
  try {
    await enrollPasskey(record, await passkeyWrappingKey(record), password);
    showToast('Fingerprint unlock now works with the new password.');
  } catch {
    showToast(
      'Fingerprint unlock stays paused until you next unlock with the password.',
    );
  }
}

$('#passkey-unlock').addEventListener('click', () => unlockWithPasskey());

// Cmd+F (Ctrl+F elsewhere) searches the vault while it's unlocked. Locked, or
// with a dialog open, the browser's own search keeps the shortcut.
// Chrome reports "macOS" and older APIs "MacIntel", so match any case.
const isApple = /mac|iphone|ipad/i.test(
  navigator.userAgentData?.platform ?? navigator.platform,
);

addEventListener('keydown', (event) => {
  if (
    session &&
    event.key.toLowerCase() === 'f' &&
    (isApple ? event.metaKey : event.ctrlKey) &&
    !event.altKey &&
    !event.shiftKey &&
    !dialogs.some((dialog) => dialog.open)
  ) {
    event.preventDefault();
    searchInput.focus();
    searchInput.select();
  }
});

$('#forget-locked').addEventListener('click', forgetDevice);
$('#forget-unlocked').addEventListener('click', forgetDevice);
$('#lock-button').addEventListener('click', lock);

for (const type of ['pointerdown', 'keydown']) {
  addEventListener(type, () => (lastActivity = Date.now()), { passive: true });
}

document.addEventListener('visibilitychange', async () => {
  if (document.hidden) {
    hiddenAt = Date.now();
    leftSincePrompt = true;
    return;
  }
  if (session && Date.now() - hiddenAt > HIDDEN_LOCK_MS) {
    await lock();
  }
  promptOnForeground();
});

// Token list.

searchInput.addEventListener('input', renderList);

tokenList.addEventListener('click', async (event) => {
  const item = event.target.closest('.token');
  if (!item) {
    return;
  }
  if (event.target.closest('.edit')) {
    openEdit(item.dataset.id);
    return;
  }
  const entry = rendered.get(item.dataset.id);
  if (!entry?.value) {
    return;
  }
  try {
    await navigator.clipboard.writeText(entry.value);
    showToast(`Copied the ${displayName(entry.token)} code.`);
  } catch {
    showToast('Couldn’t copy. Select the code to copy it by hand.');
    return;
  }
  save(
    KEYS.usage,
    recordUse(
      load(KEYS.usage),
      entry.token.id,
      Date.now(),
      new Set(session.vault.tokens.map((token) => token.id)),
    ),
  );
  // A search has done its job once a code is copied. Clearing it also
  // re-sorts the list. Without a search, the order stays put until the next
  // redraw, so tokens don't move under the pointer.
  if (searchInput.value) {
    searchInput.value = '';
    renderList();
    focusSearch();
  }
});

// Icons.

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetches icons for `tokens` one at a time, pausing between requests and
 * backing off when icon.horse rate limits. Stops when the vault locks.
 * Returns how many icons it got.
 */
async function fetchIcons(tokens, onProgress) {
  const current = session;
  let fetched = 0;
  for (const [index, token] of tokens.entries()) {
    const domain = guessDomain(token);
    for (let attempt = 0; domain; attempt++) {
      try {
        token.icon = await fetchIcon(domain);
        token.url ||= domain;
        token.modifiedAt = now();
        fetched++;
        break;
      } catch (error) {
        if (!error.retry || attempt >= ICON_RETRIES) {
          break;
        }
        await sleep(ICON_BACKOFF_MS * 2 ** attempt);
      }
      if (session !== current) {
        return fetched;
      }
    }
    onProgress(index + 1);
    await sleep(ICON_INTERVAL_MS);
    if (session !== current) {
      break;
    }
  }
  return fetched;
}

$('#fetch-icons').addEventListener('click', async (event) => {
  const button = event.target;
  const current = session;
  const tokens = session.vault.tokens.filter((token) => !token.icon);
  button.disabled = true;
  const fetched = await fetchIcons(tokens, (done) => {
    button.textContent = `Getting icons… ${done} of ${tokens.length}`;
  });
  button.disabled = false;
  button.textContent = 'Get icons';
  if (session !== current) {
    return;
  }
  if (fetched) {
    await persist();
  }
  const missed = tokens.length - fetched;
  // The banner stays while icons are missing, so another run can fill them in.
  if (!missed) {
    save(ICONS_DISMISSED_KEY, true);
  }
  renderList();
  showToast(
    `Got ${plural(fetched, 'icon')}.` +
      (missed
        ? ` ${missed} still ${missed === 1 ? 'has' : 'have'} none: try again later, or set the website or an image under ⋯.`
        : ''),
  );
});

$('#dismiss-icons').addEventListener('click', () => {
  save(ICONS_DISMISSED_KEY, true);
  renderList();
});

// Adding and editing.

for (const button of document.querySelectorAll('[data-close]')) {
  button.addEventListener('click', () => button.closest('dialog').close());
}

function readTokenFields(form) {
  return {
    issuer: form.issuer.value.trim(),
    account: form.account.value.trim(),
    url: hostOf(form.url.value),
    digits: Number(form.digits.value),
    period: Number(form.period.value) || 30,
    algorithm: normalizeAlgorithm(form.algorithm.value),
  };
}

function fillTokenFields(form, token) {
  form.issuer.value = token.issuer ?? '';
  form.account.value = token.account ?? '';
  form.url.value = token.url ?? '';
  form.digits.value = String(token.digits ?? 6);
  form.period.value = String(token.period ?? 30);
  form.algorithm.value = token.algorithm ?? 'SHA1';
  // Unusual parameters stay in view, since they're worth knowing about.
  form.querySelector('.advanced').open =
    form.digits.value !== '6' ||
    form.period.value !== '30' ||
    form.algorithm.value !== 'SHA1';
}

$('#add-button').addEventListener('click', () => {
  addForm.reset();
  addForm.querySelector('.advanced').open = false;
  addForm.querySelector('.error').textContent = '';
  addDialog.showModal();
});

// Filling the issuer suggests a website, which the icon comes from.
addForm.issuer.addEventListener('change', () => {
  if (!addForm.url.value.trim()) {
    addForm.url.value = guessDomain({ issuer: addForm.issuer.value });
  }
});

// A pasted link fills in the fields below it, which stay editable.
addForm.uri.addEventListener('change', () => {
  const error = addForm.querySelector('.error');
  try {
    const details = parseOtpauth(addForm.uri.value);
    fillTokenFields(addForm, { ...details, url: guessDomain(details) });
    error.textContent = '';
  } catch (problem) {
    error.textContent = addForm.uri.value.trim() ? problem.message : '';
  }
});

addForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const error = addForm.querySelector('.error');
  let token;
  try {
    // The secret comes from the link when there is one, and the labels from
    // the fields, which the link filled in.
    const secret = addForm.uri.value.trim()
      ? parseOtpauth(addForm.uri.value).secret
      : normalizeSecret(addForm.secret.value);
    if (!isBase32(secret)) {
      throw new Error(
        'Scan a QR code, or enter an otpauth link or a secret key.',
      );
    }
    token = createToken({ ...readTokenFields(addForm), secret });
    if (!token.issuer && !token.account) {
      throw new Error('Enter an issuer or an account name.');
    }
  } catch (problem) {
    error.textContent = problem.message;
    return;
  }
  const button = event.submitter ?? addForm.querySelector('[type=submit]');
  button.disabled = true;
  if (token.url) {
    const icon = await fetchIcon(token.url).catch(() => '');
    if (icon) {
      token.icon = icon;
    }
  }
  if (!addTokens(session.vault, [token])) {
    button.disabled = false;
    error.textContent = 'This token is already in the vault.';
    return;
  }
  await persist();
  button.disabled = false;
  addDialog.close();
  renderList();
  showToast(`Added ${displayName(token)}.`);
});

function openEdit(id) {
  const token = findToken(id);
  editForm.dataset.id = id;
  fillTokenFields(editForm, token);
  pendingIcon = undefined;
  renderIcon($('#edit-icon'), token);
  $('#remove-icon').disabled = !token.icon;
  editDialog.showModal();
}

function previewIcon(icon) {
  pendingIcon = icon;
  renderIcon($('#edit-icon'), {
    issuer: editForm.issuer.value,
    account: editForm.account.value,
    icon,
  });
  $('#remove-icon').disabled = !icon;
}

$('#fetch-icon').addEventListener('click', async (event) => {
  const button = event.target;
  const domain = guessDomain({
    url: editForm.url.value,
    issuer: editForm.issuer.value,
  });
  if (!domain) {
    showToast('Enter the website first.');
    return;
  }
  editForm.url.value = domain;
  button.disabled = true;
  try {
    previewIcon(await fetchIcon(domain));
  } catch {
    showToast(`Couldn’t get an icon for ${domain}.`);
  } finally {
    button.disabled = false;
  }
});

$('#upload-icon').addEventListener('click', () => {
  imagePurpose = 'icon';
  imageInput.click();
});

$('#remove-icon').addEventListener('click', () => previewIcon(''));

editForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const token = findToken(editForm.dataset.id);
  Object.assign(token, readTokenFields(editForm), { modifiedAt: now() });
  if (pendingIcon === '') {
    delete token.icon;
  } else if (pendingIcon) {
    token.icon = pendingIcon;
  }
  editDialog.close();
  await persist();
  renderList();
});

$('#copy-link').addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(
      buildOtpauth(findToken(editForm.dataset.id)),
    );
    showToast(
      'Copied the otpauth link. It contains the secret, so paste it only where you trust.',
    );
  } catch {
    showToast('Couldn’t copy the link.');
  }
});

$('#delete-token').addEventListener('click', async () => {
  const token = findToken(editForm.dataset.id);
  if (
    !confirm(
      `Delete ${displayName(token)}? You can only get it back from an export or the backup’s history.`,
    )
  ) {
    return;
  }
  session.vault.tokens = session.vault.tokens.filter(
    (other) => other !== token,
  );
  session.vault.deleted.push({ id: token.id, deletedAt: now() });
  editDialog.close();
  await persist();
  renderList();
});

// QR scanning.

/** Handles scanned text. Returns whether it was a usable token. */
function acceptScan(text) {
  let details;
  try {
    if (text.startsWith('otpauth-migration:')) {
      throw new Error(
        'This is a Google Authenticator export code, which isn’t supported yet.',
      );
    }
    details = parseOtpauth(text);
  } catch (problem) {
    scanStatus.textContent = text.startsWith('otpauth')
      ? problem.message
      : 'This QR code doesn’t hold a 2FA token. Keep looking.';
    return false;
  }
  addForm.uri.value = text;
  fillTokenFields(addForm, { ...details, url: guessDomain(details) });
  addForm.secret.value = '';
  addForm.querySelector('.error').textContent = '';
  scanDialog.close();
  showToast(
    `Scanned ${details.issuer || details.account}. Check the details and add it.`,
  );
  return true;
}

const scanner = new Scanner($('#scan-video'), acceptScan);

async function startCamera(deviceId) {
  scanStatus.textContent = 'Starting the camera…';
  try {
    const { cameras, current } = await scanner.start(deviceId);
    cameraSelect.replaceChildren(
      ...cameras.map(
        (camera, index) =>
          new Option(camera.label || `Camera ${index + 1}`, camera.deviceId),
      ),
    );
    cameraSelect.value = current;
    $('#camera-label').hidden = cameras.length < 2;
    scanStatus.textContent = 'Point the camera at the QR code.';
  } catch (error) {
    $('#scan-video').hidden = true;
    scanStatus.textContent =
      error.name === 'NotAllowedError'
        ? 'Camera access is blocked. Allow it in the site settings, or scan an image.'
        : 'No camera available. Scan an image or paste one instead.';
  }
}

$('#scan-button').addEventListener('click', () => {
  $('#scan-video').hidden = false;
  scanDialog.showModal();
  startCamera();
});

cameraSelect.addEventListener('change', () => {
  saveCamera(cameraSelect.value);
  startCamera(cameraSelect.value);
});

scanDialog.addEventListener('close', () => scanner.stop());

async function scanFile(file) {
  scanStatus.textContent = 'Reading the image…';
  try {
    const text = await scanImage(file);
    if (!text) {
      scanStatus.textContent = 'No QR code found in that image.';
    } else {
      acceptScan(text);
    }
  } catch {
    scanStatus.textContent = 'Couldn’t read that image.';
  }
}

$('#scan-image').addEventListener('click', () => {
  imagePurpose = 'scan';
  imageInput.click();
});

imageInput.addEventListener('change', async () => {
  const [file] = imageInput.files;
  imageInput.value = '';
  if (!file) {
    return;
  }
  if (imagePurpose === 'icon') {
    try {
      previewIcon(await imageToDataUrl(file));
    } catch {
      showToast('Couldn’t read that image.');
    }
    return;
  }
  scanFile(file);
});

// A screenshot of a QR code can be pasted while the scanner is open.
document.addEventListener('paste', (event) => {
  if (!scanDialog.open) {
    return;
  }
  const image = [...event.clipboardData.files].find((file) =>
    file.type.startsWith('image/'),
  );
  if (image) {
    event.preventDefault();
    scanFile(image);
  }
});

// Settings.

function renderSettings() {
  if (!session) {
    return;
  }
  $('#settings-github').textContent = session.github
    ? 'Change'
    : 'Set up backup';
  $('#settings-sync').hidden = !session.github;
  $('#settings-disconnect').hidden = !session.github;
  renderSyncStatus();
  renderPasskeySettings();
}

async function renderPasskeySettings() {
  const record = load(KEYS.passkey);
  const supported = Boolean(record) || (await passkeysSupported());
  const toggle = $('#passkey-toggle');
  toggle.textContent = record ? 'Turn off' : 'Turn on';
  toggle.disabled = !supported;
  $('#passkey-summary').textContent = !record
    ? supported
      ? 'Unlock with your fingerprint through a passkey on this device. The password keeps working, and new devices need it.'
      : 'This browser can’t unlock with a fingerprint here. It needs passkeys with the PRF extension.'
    : passkeyCurrent(record)
      ? 'On. A passkey on this device unlocks the vault after your fingerprint, face, or device PIN.'
      : 'Paused, because the password changed. Unlock with the password once to resume it.';
}

$('#passkey-toggle').addEventListener('click', async () => {
  if (load(KEYS.passkey)) {
    remove(KEYS.passkey);
    showToast(
      'Fingerprint unlock is off. You can delete the TOTP Vault passkey in your password manager.',
    );
    renderPasskeySettings();
    return;
  }
  const password = await askPassword({
    title: 'Turn on fingerprint unlock',
    message: 'Enter the vault password once to confirm.',
    submitLabel: 'Continue',
    verify: async (candidate) => {
      await unlockKey(load(KEYS.vault), candidate);
      return candidate;
    },
  });
  if (!password) {
    return;
  }
  await turnOnPasskey(password);
  renderPasskeySettings();
});

$('#settings-button').addEventListener('click', () => {
  renderSettings();
  settingsDialog.showModal();
});

$('#settings-github').addEventListener('click', async () => {
  const settings = await askGitHub({
    title: 'Back up to GitHub',
    submitLabel: 'Save and back up',
    verify: async (candidate) => {
      // Reading proves the token and repository work before saving them.
      await readFile(candidate);
      return candidate;
    },
  });
  if (!settings) {
    return;
  }
  const moved =
    !session.github ||
    ['owner', 'repo', 'path', 'branch'].some(
      (name) => settings[name] !== session.github[name],
    );
  session.github = settings;
  await saveGitHubSettings();
  if (moved) {
    // A new location starts unknown: merge with what's there, then upload.
    save(KEYS.sync, { sha: null, dirty: true });
  }
  renderSettings();
  await sync();
  renderSettings();
});

$('#settings-sync').addEventListener('click', async () => {
  save(KEYS.sync, { ...syncState(), dirty: true });
  await sync();
  renderSettings();
});

$('#settings-disconnect').addEventListener('click', () => {
  session.github = null;
  remove(KEYS.github);
  remove(KEYS.sync);
  setSyncStatus('idle');
  renderSettings();
  render();
});

$('#change-password').addEventListener('click', async () => {
  const answer = await askPassword({
    title: 'Choose a vault password',
    message:
      'The vault on this device and the GitHub backup switch to this password. Other devices ask for it on their next sync.',
    submitLabel: 'Save',
    confirm: true,
    verify: async (password) => ({ key: await createKey(password), password }),
  });
  if (!answer) {
    return;
  }
  session.oldKeys.push(session.key);
  session.key = answer.key;
  await saveGitHubSettings();
  await persist();
  showToast('Password changed.');
  await refreshPasskey(answer.password);
  renderPasskeySettings();
});

// Export.

function dateStamp() {
  return new Date().toISOString().slice(0, 10);
}

function download(filename, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const link = Object.assign(document.createElement('a'), {
    href: url,
    download: filename,
  });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function confirmPlaintext() {
  return confirm(
    'This file contains your 2FA secrets unencrypted. Anyone who gets it can generate your codes. ' +
      'Import it right away and delete it afterward.\n\nContinue?',
  );
}

$('#export-button').addEventListener('click', () => exportDialog.showModal());

$('#export-vault').addEventListener('click', () => {
  download(
    `totp-vault-${dateStamp()}.jwe.json`,
    JSON.stringify(load(KEYS.vault), null, 2) + '\n',
    'application/json',
  );
  exportDialog.close();
});

const plaintextExports = {
  'export-cxf': () => [
    `totp-vault-${dateStamp()}.cxf.json`,
    JSON.stringify(toPlainCxf(session.vault), null, 2),
    'application/json',
  ],
  'export-bitwarden': () => [
    `bitwarden-totp-${dateStamp()}.json`,
    JSON.stringify(toBitwarden(session.vault), null, 2),
    'application/json',
  ],
  'export-otpauth': () => [
    `totp-otpauth-${dateStamp()}.txt`,
    toOtpauthList(session.vault),
    'text/plain',
  ],
};

// Launches.

// The manifest's `launch_handler` focuses the open window for every launch
// of the installed app, so there's only ever one, and an unlocked vault
// stays unlocked. Each launch arrives here; the app has a single page, so
// readying the right field is all a launch needs.
window.launchQueue?.setConsumer(() => {
  if (session) {
    focusSearch();
  } else if (!views.unlock.hidden) {
    offerUnlock();
  }
});

// Title bar.

// With the Window Controls Overlay, the toolbar moves into the title bar.
// The user can fold the overlay away, which brings the regular header back.
const overlay = navigator.windowControlsOverlay;

function updateTitleBar() {
  document.documentElement.classList.toggle(
    'titlebar',
    Boolean(overlay?.visible),
  );
}

overlay?.addEventListener('geometrychange', updateTitleBar);
updateTitleBar();

for (const [id, build] of Object.entries(plaintextExports)) {
  $(`#${id}`).addEventListener('click', () => {
    if (confirmPlaintext()) {
      download(...build());
      exportDialog.close();
    }
  });
}

if ('serviceWorker' in navigator) {
  // A new version takes over right away. Reloading shows it, unless that
  // would lock an unlocked vault.
  const updating = Boolean(navigator.serviceWorker.controller);
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (!updating) {
      return;
    }
    if (session) {
      showToast('An update is ready. It applies when you next open the app.');
    } else {
      location.reload();
    }
  });
  navigator.serviceWorker.register('sw.js').catch(() => {});
}

/**
 * Readies the unlock view: with fingerprint unlock on, the fingerprint prompt
 * appears right away, and otherwise the password field gets the focus.
 */
function offerUnlock() {
  // The unlock view is hidden while the page parses, so `autofocus` misses it.
  if (!passkeyCurrent() || matchMedia('(pointer: fine)').matches) {
    $('#password').focus();
  }
  if (passkeyCurrent()) {
    unlockWithPasskey({ quiet: true });
  }
}

render();
if (!views.unlock.hidden) {
  offerUnlock();
}
