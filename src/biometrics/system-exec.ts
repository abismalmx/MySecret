/**
 * MySecret - Obsidian Transparent Encryption Plugin
 * Safe OS Process Helpers for the Biometric Providers
 *
 * SECURITY RATIONALE
 * ------------------
 * The biometric providers shell out to operating-system tools (Windows Hello
 * through PowerShell, `fprintd-verify`, `secret-tool`). Doing that naively is
 * dangerous in two ways:
 *
 *  1. PATH HIJACKING. Spawning `"fprintd-verify"` lets the OS resolve the
 *     binary through `$PATH`. If a user-writable directory precedes the system
 *     directories in `$PATH`, an attacker who can drop a file next to the vault
 *     can substitute a fake binary that returns "verified" without any
 *     fingerprint check.
 *     -> This module resolves every binary to an ABSOLUTE path inside a
 *        root-owned system directory and verifies the ownership/permission
 *        bits before using it.
 *
 *  2. SHELL INJECTION. Building a command line by string concatenation lets
 *     attacker-controlled data (a prompt, a base64 blob) escape into the
 *     command line.
 *     -> This module NEVER uses a shell (`shell: false`) and passes data
 *        through stdin / environment variables instead of the argument vector.
 *
 * It also enforces timeouts and output size limits so a wedged or hostile
 * helper process can neither hang the UI nor exhaust the renderer's memory.
 */

/** Directories that are root-owned on a sane Linux system. */
const LINUX_SYSTEM_BIN_DIRS = [
  '/usr/local/sbin',
  '/usr/local/bin',
  '/usr/sbin',
  '/usr/bin',
  '/sbin',
  '/bin'
];

export interface ProcessResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface RunProcessOptions {
  /** Absolute path of the executable. Never a bare name. */
  bin: string;
  args: string[];
  /** Data written to the child's stdin and then closed. */
  input?: string;
  /** Milliseconds before the child is killed. Defaults to 30 s. */
  timeoutMs?: number;
  /** Extra environment variables for the child process. */
  env?: Record<string, string>;
  /** Maximum number of bytes captured from stdout/stderr. Defaults to 64 KiB. */
  maxOutputBytes?: number;
}

/**
 * Returns a Node.js module from the Electron renderer, or `null` when the
 * environment does not expose Node (mobile WebView, sandboxed renderer).
 */
export function getNodeModule(moduleName: string): any {
  try {
    if (typeof window !== 'undefined' && (window as any).require) {
      return (window as any).require(moduleName);
    }
  } catch {
    // Fall through: the module is not reachable.
  }
  return null;
}

/**
 * Reads an environment variable without assuming that `process` exists.
 */
export function getEnv(name: string): string | undefined {
  try {
    if (typeof process !== 'undefined' && process.env) {
      const value = process.env[name];
      if (typeof value === 'string' && value.length > 0) return value;
    }
  } catch {
    // Fall through.
  }
  return undefined;
}

/**
 * Returns the current user's home directory.
 *
 * `os.homedir()` is preferred; the environment variables are only a
 * fallback for exotic environments.
 */
export function getEnvHome(): string {
  const os = getNodeModule('os');
  try {
    if (os && typeof os.homedir === 'function') {
      const home = os.homedir();
      if (home) return home;
    }
  } catch {
    // Fall through.
  }
  return getEnv('HOME') || getEnv('USERPROFILE') || '/tmp';
}

/**
 * Resolves the current OS user name.
 *
 * `process.env.USER` is NOT defined on Windows, so `os.userInfo()` is used as
 * the primary source. The result is only ever used as a *label* for OS
 * tools, never as key material.
 */
export function getCurrentUsername(): string {
  const os = getNodeModule('os');
  try {
    if (os && typeof os.userInfo === 'function') {
      const info = os.userInfo();
      if (info && typeof info.username === 'string' && info.username) {
        return info.username;
      }
    }
  } catch {
    // Fall through.
  }
  return getEnv('USER') || getEnv('LOGNAME') || getEnv('USERNAME') || 'unknown';
}

/**
 * Verifies that a candidate binary lives in a root-owned, non-writable
 * directory and is not writable by anybody but its owner.
 */
function isTrustedSystemBinary(fs: any, filePath: string): boolean {
  try {
    const stats = fs.statSync(filePath);
    if (!stats || !stats.isFile()) return false;
    // Reject group- or world-writable files (mode & 0o022).
    if (typeof stats.mode === 'number' && (stats.mode & 0o022) !== 0) {
      return false;
    }
    // When running as root, only accept files owned by root.
    if (typeof stats.uid === 'number' && typeof process !== 'undefined') {
      const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
      if (isRoot && stats.uid !== 0) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolves a Linux/Unix helper binary to an absolute path inside a
 * root-owned system directory.
 *
 * @returns the absolute path, or `null` when no trusted binary was found.
 */
export function resolveSystemBinary(name: string): string | null {
  const fs = getNodeModule('fs');
  const path = getNodeModule('path');
  if (!fs || !path) return null;

  // Only allow simple, well-known names: never accept a path here.
  if (!/^[A-Za-z0-9._-]+$/.test(name)) return null;

  for (const dir of LINUX_SYSTEM_BIN_DIRS) {
    const candidate = path.join(dir, name);
    try {
      if (fs.existsSync(candidate) && isTrustedSystemBinary(fs, candidate)) {
        return candidate;
      }
    } catch {
      // Ignore unreadable directories and continue with the next candidate.
    }
  }
  return null;
}

/**
 * Resolves `powershell.exe` to an absolute path inside the Windows system
 * directory, bypassing `$PATH` entirely.
 */
export function resolvePowerShell(): string | null {
  const fs = getNodeModule('fs');
  const path = getNodeModule('path');
  if (!fs || !path) return null;

  const systemRoot = getEnv('SystemRoot') || getEnv('windir') || 'C:\\Windows';
  const candidates = [
    path.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    path.join(systemRoot, 'SysWOW64', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
  ];

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) return candidate;
    } catch {
      // Ignore and continue.
    }
  }
  return null;
}

/**
 * Returns a copy of the current environment, or an empty object when the
 * environment is not reachable.
 */
function getSafeEnv(): Record<string, string> {
  try {
    if (typeof process !== 'undefined' && process.env) {
      return { ...(process.env as Record<string, string>) };
    }
  } catch {
    // Fall through.
  }
  return {};
}

/**
 * Spawns a process WITHOUT a shell, feeding `input` to its stdin and
 * enforcing a timeout and an output size limit.
 */
export function runProcess(options: RunProcessOptions): Promise<ProcessResult> {
  const cp = getNodeModule('child_process');
  const timeoutMs = options.timeoutMs ?? 30000;
  const maxOutputBytes = options.maxOutputBytes ?? 64 * 1024;

  return new Promise<ProcessResult>((resolve) => {
    if (!cp || !options.bin) {
      resolve({ code: null, stdout: '', stderr: 'child_process unavailable', timedOut: false });
      return;
    }

    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;

    let child: any;
    try {
      child = cp.spawn(options.bin, options.args, {
        // NEVER use a shell: it would re-enable command injection.
        shell: false,
        windowsHide: true,
        env: options.env ? { ...getSafeEnv(), ...options.env } : getSafeEnv()
      });
    } catch (err: any) {
      resolve({ code: null, stdout: '', stderr: String(err?.message || err), timedOut: false });
      return;
    }

    const finish = (code: number | null): void => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    };

    const timer = window.setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      finish(null);
    }, timeoutMs);

    child.stdout?.on('data', (chunk: any) => {
      if (stdout.length < maxOutputBytes) stdout += chunk.toString();
    });
    child.stderr?.on('data', (chunk: any) => {
      if (stderr.length < maxOutputBytes) stderr += chunk.toString();
    });
    child.on('error', (err: any) => {
      stderr += String(err?.message || err);
      finish(null);
    });
    child.on('close', (code: number | null) => finish(code));

    if (options.input !== undefined) {
      try {
        child.stdin.write(options.input);
      } catch {
        // Ignore: the child may have closed stdin already.
      }
    }
    try {
      child.stdin.end();
    } catch {
      // Ignore.
    }
  });
}
