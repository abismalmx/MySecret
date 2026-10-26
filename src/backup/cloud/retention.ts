/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Backup Retention: which old cloud backups to remove
 *
 * Deleting remote files is the most dangerous thing a backup feature does, so
 * the decision is isolated here as a pure function and is deliberately narrow:
 *
 *  - only files named exactly like the ones this plugin uploads
 *    (`MySecret_<vault>_Cifrado_<YYYY-MM-DDTHH-mm-ss>.zip`) are candidates;
 *  - only those of the SAME vault (same prefix), so another vault sharing the
 *    folder is never touched;
 *  - the age comes from the timestamp in the NAME, not from remote metadata
 *    (which a provider may rewrite), and the newest `keep` files are kept.
 */

import { CloudProvider, CloudPruneResult } from './provider-interface';

const TIMESTAMP_SUFFIX = /(\d{4})-(\d{2})-(\d{2})T(\d{2})-(\d{2})-(\d{2})\.zip$/;

/** Default number of backups kept when the setting is missing or invalid. */
export const DEFAULT_RETENTION_COUNT = 5;

/**
 * Returns the per-vault prefix of a backup file name
 * (`MySecret_<vault>_Cifrado_`), or null when the name is not one of ours.
 */
export function backupFilenamePrefix(filename: string): string | null {
  const match = TIMESTAMP_SUFFIX.exec(filename);
  if (!match) return null;
  const prefix = filename.slice(0, match.index);
  return /^MySecret_.*_Cifrado_$/.test(prefix) ? prefix : null;
}

/** Milliseconds since epoch encoded in the name, or null if it is not one of ours. */
function backupTime(name: string, prefix: string): number | null {
  if (!name.startsWith(prefix)) return null;
  const rest = name.slice(prefix.length);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2})-(\d{2})-(\d{2})\.zip$/.exec(rest);
  if (!match) return null;
  const [, y, mo, d, h, mi, s] = match;
  const time = Date.UTC(+y, +mo - 1, +d, +h, +mi, +s);
  return Number.isNaN(time) ? null : time;
}

/** Normalizes the configured retention: an integer >= 1 (never "delete everything"). */
export function normalizeRetention(keep: unknown): number {
  const n = Math.floor(Number(keep));
  return Number.isFinite(n) && n >= 1 ? n : DEFAULT_RETENTION_COUNT;
}

/**
 * Picks the entries to delete: ours, same vault, older than the newest `keep`.
 */
export function selectBackupsToDelete<T extends { name: string }>(
  entries: T[],
  prefix: string,
  keep: number
): T[] {
  const limit = normalizeRetention(keep);
  const ours = entries
    .map(entry => ({ entry, time: backupTime(entry.name, prefix) }))
    .filter((item): item is { entry: T; time: number } => item.time !== null)
    .sort((a, b) => b.time - a.time);
  return ours.slice(limit).map(item => item.entry);
}

/**
 * Applies the retention policy after a successful upload.
 *
 * Never throws: a failed cleanup must not turn a successful backup into a
 * failed one.
 *
 * @returns the provider's result, or null when nothing could be pruned.
 */
export async function pruneAfterUpload(
  provider: CloudProvider,
  uploadedFilename: string,
  keep: unknown
): Promise<CloudPruneResult | null> {
  const prefix = backupFilenamePrefix(uploadedFilename);
  if (!prefix || typeof provider.pruneBackups !== 'function') return null;
  try {
    return await provider.pruneBackups(prefix, normalizeRetention(keep));
  } catch (err) {
    console.warn('[MySecret] Backup retention failed:', err);
    return null;
  }
}
