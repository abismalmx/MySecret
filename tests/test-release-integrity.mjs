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
import zlib from 'node:zlib';
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
 * Reads a file out of the published tree's git OBJECT DATABASE.
 *
 * The published tree is a real git repository, but the CI image may not ship
 * the `git` binary, so the objects are decoded directly:
 *
 *   - a loose object is zlib-compressed and prefixed with "<type> <size>\0"
 *   - a packed object is looked up in `objects/pack/*.idx`
 *
 * @param relPath path inside the published tree, relative to its root
 * @returns the file content, or null when it is not committed at HEAD
 */
function publishedCommittedContent(relPath) {
  if (!publishedGitAvailable()) return null;

  // Prefer the git CLI if available (handles detached HEAD, packed-refs, shallow clones)
  try {
    return execFileSync('git', ['show', `HEAD:${relPath}`], {
      cwd: PUBLISHED_DIR,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch {
    // Fall back to reading the object database directly
  }

  const head = fs.readFileSync(path.join(GIT_DIR, 'HEAD'), 'utf8').trim();
  let commitSha = null;

  if (/^[0-9a-f]{40}$/i.test(head)) {
    commitSha = head;
  } else {
    const refMatch = head.match(/^ref:\s*(.+)$/);
    if (!refMatch) return null;

    const refPath = path.join(GIT_DIR, refMatch[1]);
    if (fs.existsSync(refPath)) {
      commitSha = fs.readFileSync(refPath, 'utf8').trim();
    } else {
      const packedRefsPath = path.join(GIT_DIR, 'packed-refs');
      if (fs.existsSync(packedRefsPath)) {
        const packedContent = fs.readFileSync(packedRefsPath, 'utf8');
        for (const line of packedContent.split('\n')) {
          const parts = line.trim().split(/\s+/);
          if (parts.length === 2 && parts[1] === refMatch[1]) {
            commitSha = parts[0];
            break;
          }
        }
      }
    }
  }

  if (!commitSha) return null;

  const commit = readGitObject(commitSha);
  if (!commit) return null;

  // The commit object lists the tree sha on its "tree <sha>" line.
  const treeMatch = commit.toString('utf8').match(/^tree ([0-9a-f]{40})$/m);
  if (!treeMatch) return null;

  const tree = readGitObject(treeMatch[1]);
  if (!tree) return null;

  const entry = findTreeEntry(tree, relPath);
  if (!entry) return null;

  const blob = readGitObject(entry.sha);
  return blob ? blob.toString('utf8') : null;
}

/** Reads and inflates a loose git object, or one from a pack file. */
function readGitObject(sha) {
  const loose = path.join(GIT_DIR, 'objects', sha.slice(0, 2), sha.slice(2));
  if (fs.existsSync(loose)) {
    return inflate(fs.readFileSync(loose));
  }
  return readPackedObject(sha);
}

/** Inflates a zlib-compressed git object and strips the "<type> <size>\0" header. */
function inflate(buffer) {
  const inflated = zlib.inflateSync(buffer);
  const nul = inflated.indexOf(0);
  return inflated.slice(nul + 1);
}

/** Looks a sha up in the pack files and returns its inflated content. */
function readPackedObject(sha) {
  const packDir = path.join(GIT_DIR, 'objects', 'pack');
  if (!fs.existsSync(packDir)) return null;

  for (const idxName of fs.readdirSync(packDir).filter(f => f.endsWith('.idx'))) {
    const idx = fs.readFileSync(path.join(packDir, idxName));
    const packPath = path.join(packDir, idxName.replace(/\.idx$/, '.pack'));
    if (!fs.existsSync(packPath)) continue;

    // v2 index: 8-byte header, then 256 fan-out entries of 4 bytes each.
    const fanoutStart = 8;
    const count = idx.readUInt32BE(fanoutStart + 255 * 4);
    const shaStart = fanoutStart + 256 * 4;

    const target = Buffer.from(sha, 'hex');
    for (let i = 0; i < count; i++) {
      const offset = shaStart + i * 20;
      if (idx.compare(target, 0, 20, offset, offset + 20) !== 0) continue;

      const pack = fs.readFileSync(packPath);
      let p = Number(idx.readBigUInt64BE(shaStart + count * 20 + i * 4 +
        (idx.readUInt8(shaStart + count * 20 + i * 4) & 0x7f) * 4));

      // Skip the object header (type nibble + size varint).
      p += 1;
      let shift = 0;
      let size = 0;
      let byte;
      do {
        byte = pack[p++];
        size |= (byte & 0x7f) << shift;
        shift += 7;
      } while (byte & 0x80);

      return zlib.inflateRawSync(pack.slice(p, p + size));
    }
  }
  return null;
}

/**
 * Walks a git tree object looking for `relPath`.
 *
 * @returns { sha: string, mode: string } of the blob, or null
 */
function findTreeEntry(treeBuffer, relPath) {
  const parts = relPath.split('/');
  let current = treeBuffer;
  let found = null;

  for (let depth = 0; depth < parts.length; depth++) {
    const name = parts[depth];
    let offset = 0;
    let descended = false;

    while (offset < current.length) {
      const space = current.indexOf(0x20, offset);
      if (space === -1) break;
      const nul = current.indexOf(0x00, space);
      if (nul === -1) break;

      const mode = current.slice(offset, space).toString('utf8');
      const entryName = current.slice(space + 1, nul).toString('utf8');
      const sha = current.slice(nul + 1, nul + 21).toString('hex');
      offset = nul + 21;

      if (entryName !== name) continue;

      if (depth === parts.length - 1) {
        found = { sha, mode };
      } else {
        const subtree = readGitObject(sha);
        if (!subtree) return null;
        current = subtree;
        descended = true;
      }
      break;
    }

    if (!found && !descended) return null;
  }

  return found;
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
  if (!fs.existsSync(PUBLISHED_DIR) || PUBLISHED_DIR === ROOT) return;

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
