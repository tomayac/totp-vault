/**
 * Copyright 2026 Thomas Steiner
 * SPDX-License-Identifier: Apache-2.0
 */

import { fromBase64, toBase64 } from './jwe.js';

// Reads and writes one file in a GitHub repository through the REST API,
// which allows cross-origin requests. Settings are
// `{ owner, repo, path, branch, token }`, with a fine-grained personal access
// token that can read and write the repository's contents.

const API = 'https://api.github.com';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

export class GitHubError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'GitHubError';
    this.status = status;
  }
}

function explain(status, message) {
  switch (status) {
    case 401:
      return 'GitHub rejected the token. It may have expired.';
    case 403:
      return 'The token can’t write to this repository. Give it Contents read and write access.';
    case 404:
      return 'GitHub can’t find the repository, or the token has no access to it.';
    default:
      return `GitHub answered ${status}: ${message}`;
  }
}

async function request(settings, url, init = {}) {
  let response;
  try {
    response = await fetch(url, {
      ...init,
      cache: 'no-store',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${settings.token}`,
        'X-GitHub-Api-Version': '2022-11-28',
        ...init.headers,
      },
    });
  } catch {
    throw new GitHubError(0, 'Can’t reach GitHub. Check the connection.');
  }
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new GitHubError(
      response.status,
      explain(response.status, body.message ?? response.statusText),
    );
  }
  return response.json();
}

function repoUrl({ owner, repo }) {
  return `${API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
}

function contentsUrl(settings) {
  const path = settings.path.split('/').map(encodeURIComponent).join('/');
  return `${repoUrl(settings)}/contents/${path}`;
}

/** Returns `{ sha, text }`, or `null` when the file doesn't exist yet. */
export async function readFile(settings) {
  const query = settings.branch
    ? `?ref=${encodeURIComponent(settings.branch)}`
    : '';
  let file;
  try {
    file = await request(settings, contentsUrl(settings) + query);
  } catch (error) {
    if (error.status === 404) {
      // Distinguish a missing file from a missing or inaccessible repository.
      await request(settings, repoUrl(settings));
      return null;
    }
    throw error;
  }
  let { content } = file;
  // The contents API leaves out files over 1 MB, and the blobs API has them.
  if (!content) {
    content = (
      await request(settings, `${repoUrl(settings)}/git/blobs/${file.sha}`)
    ).content;
  }
  return { sha: file.sha, text: decoder.decode(fromBase64(content)) };
}

/** Writes `text` over the version `sha`, or creates the file. Returns the new sha. */
export async function writeFile(settings, text, sha) {
  const body = {
    message: 'Back up the vault',
    content: toBase64(encoder.encode(text)),
    ...(sha ? { sha } : {}),
    ...(settings.branch ? { branch: settings.branch } : {}),
  };
  const result = await request(settings, contentsUrl(settings), {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return result.content.sha;
}
