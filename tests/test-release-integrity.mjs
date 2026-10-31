/**
 * Regression tests for the release-artifact integrity findings (audit 2026-10-26).
 *
 * These tests guard the thing that actually reaches the user's disk:
 * the PUBLISHED tree (the `Github/` git repository) and the bridge folder
 * that is deployed to Cloudflare Pages.
 *
 *   R1  the shipped `main.js` must be the one built from the current sources
 *   R2  `auth-bridge/_headers` must be tracked by git (Cloudflare Pages
 *       applies it automatically; without it there is NO anti-clickjacking)
 *   R3  the bridge CSP must not rely on `frame-ancestors` inside <meta>
 *       (the directive is ignored there: it only works as an HTTP header)
 *
 * Every test here FAILS against the published tree as it was and passes once
 * the published tree is synchronized with the audited sources.
 */

import assert from 'node:assert';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';

const ROOT = path.resolve(import.meta.dirname, '..');

/**
 * Returns the directory that holds the PUBLISHED tree.
 *
 * Locally the published repository is the `Github/` subdirectory; in CI the
 * checkout itself IS the published repository.
 */
function resolvePublishedDir() {
  if (fs.existsSync(path.join(ROOT, 'Github', '.git'))) {
    return path.join(ROOT, 'Github');
  }
  if (fs.existsSync(path.join(ROOT, '.git'))) {
    return ROOT;
  }
  return path.join(ROOT, 'Github');
}

const PUBLISHED_DIR = resolvePublishedDir();
const GIT_DIR = path.join(PUBLISHED_DIR, '.git');

/** Returns true when the published tree is a git repository we can inspect. */
function publishedGitAvailable() {
  return fs.existsSync(path.join(GIT_DIR, 'HEAD'));
}

/**
 * Reads a file as COMMITTED at HEAD of the published tree (not the working
 * copy), using the git binary. `git show HEAD:<path>` handles every repository
 * layout the CI can produce: loose objects, packfiles with deltas, shallow
 * clones and the detached HEAD that actions/checkout leaves on a tag push.
 *
 * @param relPath path inside the published tree, relative to its root
 * @returns the file content, or null when it is not committed at HEAD
 */
function publishedCommittedContent(relPath) {
  if (!publishedGitAvailable()) return null;
  try {
    return execFileSync('git', ['-C', PUBLISHED_DIR, 'show', `HEAD:${relPath}`], {
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      stdio: ['ignore', 'pipe', 'ignore']
    });
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// R1 — the PUBLISHED (committed) bundle must carry the audited controls
// ---------------------------------------------------------------------------

/**
 * The security controls that the second audit round introduced. Each one is
 * a MARKER that only exists in the corrected sources; its absence in the
 * published bundle means the release ships the vulnerable version.
 */
const PUBLISHED_SECURITY_MARKERS = [
  ['VUL-22: password change verifies the current password', 'current password is incorrect'],
  ['VUL-25: envelope shape validation', 'isValidEnvelopeShape'],
  ['VUL-29: deferred AAD re-binds', 'pendingRebinds'],
  ['VUL-30: per-path serialization of compound writes', 'pathQueues'],
  ['VUL-31: the Publish guard follows the plugin instance', 'refresh()'],
  ['VUL-33: the bridge callback survives a "%" in the error message', 'currentSession.reject(new Error(message))']
];

test('R1: the PUBLISHED bundle contains the audited security controls', () => {
  if (!publishedGitAvailable()) return;

  const bundle = publishedCommittedContent('main.js');
  assert.ok(bundle !== null, 'the published tree must ship a committed main.js');

  const missing = [];
  for (const [label, marker] of PUBLISHED_SECURITY_MARKERS) {
    if (!bundle.includes(marker)) missing.push(`${label} (marker: ${marker})`);
  }

  assert.deepStrictEqual(
    missing,
    [],
    'the PUBLISHED main.js is missing security controls that exist in the audited ' +
    'sources. A release would ship code that was never audited:\n  - ' +
    missing.join('\n  - ')
  );
});

test('R1: the published main.js is the bundle built from the current sources', () => {
  // Only meaningful when BOTH trees sit side by side (the local development
  // layout). In CI the repository IS the published tree and there is no
  // sibling copy to compare against.
  if (!fs.existsSync(PUBLISHED_DIR)) return;

  const shipped = path.join(PUBLISHED_DIR, 'main.js');
  const local = path.join(ROOT, 'main.js');

  assert.ok(fs.existsSync(shipped), 'the published tree must ship main.js');
  assert.ok(fs.existsSync(local), 'the root tree must ship main.js');

  const shippedBytes = fs.readFileSync(shipped);
  const localBytes = fs.readFileSync(local);

  assert.strictEqual(
    shippedBytes.length,
    localBytes.length,
    'the published main.js has a different size than the audited bundle'
  );
  assert.ok(
    shippedBytes.equals(localBytes),
    'the published main.js differs from the audited bundle: the release would ship code that was never audited'
  );
});

// ---------------------------------------------------------------------------
// R2 — the Cloudflare Pages headers file must be versioned
// ---------------------------------------------------------------------------

test('R2: auth-bridge/_headers is COMMITTED in the published tree', () => {
  if (!publishedGitAvailable()) {
    // Nothing to assert against: the published tree is not a git checkout.
    return;
  }

  const committed = publishedCommittedContent('auth-bridge/_headers');

  assert.notStrictEqual(
    committed,
    null,
    'auth-bridge/_headers is NOT committed in the published tree: Cloudflare Pages will ' +
    'not apply the anti-clickjacking (X-Frame-Options / frame-ancestors) or the WebAuthn ' +
    'Permissions-Policy when the bridge is deployed from the repository'
  );
});

test('R2: the committed _headers file declares the anti-clickjacking headers', () => {
  if (!publishedGitAvailable()) return;

  const content = publishedCommittedContent('auth-bridge/_headers');
  if (content === null) return; // the previous test already reports it

  assert.ok(
    /X-Frame-Options:\s*DENY/i.test(content),
    '_headers must set X-Frame-Options: DENY to stop clickjacking'
  );
  assert.ok(
    /frame-ancestors\s+'none'/i.test(content),
    "_headers must set frame-ancestors 'none' (it is ignored in a <meta> tag)"
  );
  assert.ok(
    /Permissions-Policy:/i.test(content),
    '_headers must restrict the WebAuthn API with a Permissions-Policy'
  );
});

// ---------------------------------------------------------------------------
// R3 — the CSP must not rely on frame-ancestors inside a <meta> tag
// ---------------------------------------------------------------------------

test('R3: the bridge CSP does not rely on frame-ancestors inside a <meta> tag', () => {
  const metaTags = [];

  // The working tree of both copies.
  for (const dir of [path.join(ROOT, 'auth-bridge'), path.join(PUBLISHED_DIR, 'auth-bridge')]) {
    const indexPath = path.join(dir, 'index.html');
    if (!fs.existsSync(indexPath)) continue;
    metaTags.push(...findFrameAncestorsInMeta(indexPath, fs.readFileSync(indexPath, 'utf8')));
  }

  // The COMMITTED bridge page (what a deployment actually serves).
  if (publishedGitAvailable()) {
    const committed = publishedCommittedContent('auth-bridge/index.html');
    if (committed !== null) {
      metaTags.push(
        ...findFrameAncestorsInMeta('HEAD:auth-bridge/index.html', committed)
      );
    }
  }

  assert.deepStrictEqual(
    metaTags,
    [],
    'frame-ancestors is IGNORED when the CSP is delivered through a <meta> tag ' +
    '(it only works as an HTTP header). Remove it from the <meta> and rely on _headers.'
  );
});

/**
 * Finds a `frame-ancestors` directive inside a <meta> CSP tag.
 *
 * @returns a list of human readable locations (empty when there is none)
 */
function findFrameAncestorsInMeta(label, html) {
  const found = [];
  for (const match of html.matchAll(/<meta\b[^>]*http-equiv=["']Content-Security-Policy["'][^>]*>/gi)) {
    const tag = match[0];
    if (/frame-ancestors/i.test(tag)) {
      found.push(`${label}: ${tag.slice(0, 120)}`);
    }
  }
  return found;
}
