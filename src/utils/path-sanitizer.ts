/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Path Sanitization Utilities (Anti Path-Traversal / Zip Slip Protection)
 *
 * These helpers are the single source of truth for deciding whether an
 * untrusted path (coming from a ZIP archive, an external manifest, etc.) may be
 * written inside the vault. They are deliberately *rejecting* rather than
 * *normalizing*: a path that contains a traversal segment is never repaired,
 * it is refused. Silently rewriting `../../etc/passwd` into `etc/passwd` hides
 * an attack instead of stopping it.
 */

/**
 * Maximum number of path segments accepted in a vault-relative path.
 */
const MAX_PATH_SEGMENTS = 64;

/**
 * Maximum length (in characters) accepted for a vault-relative path.
 */
const MAX_PATH_LENGTH = 1024;

/**
 * Segment names that could poison `Object.prototype` when a path is used as
 * a key of a plain object (prototype pollution).
 */
const FORBIDDEN_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);

/**
 * Matches an absolute Windows drive prefix such as `C:` or `c:/`.
 */
const WINDOWS_DRIVE_RE = /^[a-zA-Z]:/;

/**
 * Characters that are illegal (or dangerous) inside a path segment.
 * `<`, `>`, `"`, `|`, `?`, `*` are rejected because they are special on
 * Windows and are a common vector for shell/glob injection.
 */
const ILLEGAL_SEGMENT_RE = /[\x00-\x1f<>:"|?*]/;

export interface PathSanitizeResult {
  /** True when the path is safe to write inside the vault */
  safe: boolean;
  /** The normalized vault-relative path (only meaningful when `safe` is true) */
  path: string;
  /** Human readable reason explaining the rejection (null when safe) */
  reason: string | null;
}

/**
 * Validates and normalizes an untrusted path so it can be safely used as a
 * vault-relative path.
 *
 * Rejected: absolute paths (POSIX and Windows), UNC paths, traversal segments
 * (`..`), hidden/system segments (`.obsidian`, `.git`, ...), prototype
 * pollution names and segments with illegal characters.
 *
 * @param rawPath Untrusted path (e.g. a ZIP entry name)
 */
export function sanitizeVaultRelativePath(rawPath: string): PathSanitizeResult {
  const reject = (reason: string): PathSanitizeResult => ({ safe: false, path: '', reason });

  if (typeof rawPath !== 'string') {
    return reject('Path is not a string.');
  }
  if (rawPath.length === 0) {
    return reject('Path is empty.');
  }
  if (rawPath.length > MAX_PATH_LENGTH) {
    return reject('Path exceeds the maximum allowed length.');
  }

  // Normalize Windows separators to POSIX ones before any analysis.
  const unified = rawPath.replace(/\\/g, '/');

  if (unified.includes('\0')) {
    return reject('Path contains null bytes.');
  }
  if (unified.startsWith('/')) {
    return reject('Absolute paths are not allowed.');
  }
  if (WINDOWS_DRIVE_RE.test(unified)) {
    return reject('Absolute Windows paths are not allowed.');
  }

  const segments: string[] = [];
  for (const rawSegment of unified.split('/')) {
    const segment = rawSegment.trim();

    // Collapse empty segments ("a//b" -> "a/b") and current-dir markers.
    if (segment.length === 0 || segment === '.') continue;

    // Traversal is never repaired: it is always an error.
    if (segment === '..') {
      return reject('Path traversal ("..") is not allowed.');
    }
    // Hidden / system directories (.obsidian, .git, .trash, ...) are never
    // restored: writing there would allow arbitrary code execution.
    if (segment.startsWith('.')) {
      return reject('Hidden or system directories are not allowed.');
    }
    if (FORBIDDEN_SEGMENTS.has(segment.toLowerCase())) {
      return reject('Reserved segment name is not allowed.');
    }
    if (ILLEGAL_SEGMENT_RE.test(segment)) {
      return reject('Path contains illegal characters.');
    }

    segments.push(segment);
  }

  if (segments.length === 0) {
    return reject('Path does not contain any usable segment.');
  }
  if (segments.length > MAX_PATH_SEGMENTS) {
    return reject('Path has too many segments.');
  }

  return { safe: true, path: segments.join('/'), reason: null };
}

/**
 * Convenience wrapper around {@link sanitizeVaultRelativePath}.
 */
export function isSafeVaultRelativePath(rawPath: string): boolean {
  return sanitizeVaultRelativePath(rawPath).safe;
}

/**
 * Checks whether a path contains a segment name that is unsafe to use as a
 * key of a plain JavaScript object (`__proto__`, `constructor`, `prototype`).
 *
 * SECURITY: assigning `obj['__proto__'] = value` on a normal object does NOT
 * create a property, it mutates the object's prototype. The ZIP writer used by
 * the backup engine iterates the object with `for...in`, so a poisoned
 * prototype would make it emit bogus entries (or crash). Files whose path
 * contains such a segment are therefore skipped when building a backup, and
 * rejected when restoring one.
 */
export function hasForbiddenSegment(rawPath: string): boolean {
  const unified = rawPath.replace(/\\/g, '/');
  for (const segment of unified.split('/')) {
    if (FORBIDDEN_SEGMENTS.has(segment.trim().toLowerCase())) {
      return true;
    }
  }
  return false;
}
