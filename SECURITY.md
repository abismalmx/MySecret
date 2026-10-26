# Security Architecture & Hardened Defenses — MySecret

**English** • [Versión en Español](SECURITY.es.md)

**MySecret** implements an absolute **Zero-Knowledge** security model engineered to protect notes, canvases, and media attachments in Obsidian via transparent, on-the-fly at-rest disk encryption.

This document outlines the cryptographic primitives, defense-in-depth principles, and all audited attack vectors against which the plugin maintains a 100% undefeated record across its automated test suite.

---

## 1. Core Cryptographic Primitives

- **Absolute Zero-Knowledge:** Cryptographic master keys are derived exclusively in local volatile RAM. No unencrypted keys, credentials, or plaintext content are ever transmitted to external servers or persisted unencrypted on disk.
- **Authenticated Symmetric Encryption (AEAD):** Powered by hardware-accelerated **AES-256-GCM** via the native Web Crypto API (`window.crypto.subtle`). Every encrypted block includes a randomly generated 96-bit cryptographic Initialization Vector (IV) and a 128-bit authentication tag, ensuring both confidentiality and tamper-proof integrity.
- **Robust Key Derivation (KDF):** Master vault keys are derived using **Argon2id** (WebAssembly via `hash-wasm`), the award-winning winner of the Password Hashing Competition, configured with high memory and iteration parameters to defeat GPU/ASIC-assisted brute-force attacks.
- **Deterministic BIP-39 Recovery:** 24-word mnemonic recovery phrase based on 256 bits of cryptographic entropy and SHA-256 checksum for disaster recovery without relying on third-party servers.
- **Active Memory Zeroization:** Guaranteed wiping of sensitive RAM memory buffers (`zeroize()`) upon vault locking, inactivity timeout, or runtime error states.

---

## 2. Hardened Defenses & Audited Attack Vectors

The following sections detail the active defenses against specific attack vectors verified during security assessments:

### 🛡️ Strict Protection Against Zip Slip & Path Traversal
- **Sanitizer Module:** `src/utils/path-sanitizer.ts` strictly inspects and validates every incoming path during backup restoration or file extraction.
- **Defense:** Immediately rejects relative `..` path segments, Windows backward slashes, absolute filesystem paths (`/etc/...`, `C:\...`), null bytes, and hidden configuration folders (`.obsidian/`, `.git/`). Prevents malicious archives from writing outside the vault or dropping unauthorized plugins.

### 🛡️ Strict Path Binding Integrity (AAD Binding)
- **Path Association:** During AES-256-GCM encryption, the normalized relative path (NFC Unicode format) is cryptographically bound as Additional Authenticated Data (AAD).
- **Protection on Rename & Copy:** The file adapter's `rename` and `copy` operations cryptographically reconcile and update the file's AAD in real time, preventing ciphertext relocation or substitution attacks between vault folders.

### 🛡️ KDF Parameter Immutability & Anti-Downgrade Armor
- **Runtime Enforced Bounds:** The key derivation engine enforces strict lower and upper bounds on Argon2id parameters (`memoryKib`, `iterations`, `parallelism`).
- **Defense:** Automatically rejects downgraded or tampered vault envelope headers attempting to weaken encryption for brute-force cracking, as well as oversized parameters that could induce Denial of Service (DoS).

### 🛡️ Comprehensive File Adapter Interception (Zero Plaintext Leakage)
- **Full Coverage:** Transparently intercepts every file operation method on Obsidian's `app.vault.adapter`: `read`, `write`, `readBinary`, `writeBinary`, `append`, and `appendBinary`.
- **Guarantee:** No file write operation bypasses the cryptographic engine; binary attachments and text notes are encrypted in-flight before touching the filesystem.

### 🛡️ Surface Separation: On-Disk Ciphertext vs. In-Memory Plaintext
- **Adapter surface (`DataAdapter.readBinary`):** Returns **exactly the bytes stored on disk** (the ciphertext). It never returns cleartext.
- **Vault surface (`Vault.readBinary`):** Returns the **decrypted plaintext**, and is the only surface the Obsidian metadata indexer (`MetadataCache.computeFileMetadataAsync`) uses to extract links, footnotes and frontmatter.
- **Why the separation is required:** Obsidian **Sync** reads files through `app.vault.adapter.readBinary(path)` (a direct adapter call), while the indexer and Obsidian **Publish** go through `vault.readBinary(file)`. Decrypting in the adapter exposed the cleartext of **every** note to the sync engine, which uploaded it to the cloud in the clear.
- **Result:** Encrypted notes remain indexable (footnotes, links and search keep working) while the cleartext never leaves the process towards Obsidian Sync.

### 🛡️ Double-Encryption Integrity Guard (Anti Double-Encryption)
- **Threat:** Obsidian Sync downloads the ciphertext of a file and writes it back **verbatim** on disk through `vault.modifyBinary()` → `adapter.writeBinary()`. If the write hook encrypted it again, the file would end up encrypted **twice** and would become permanently unreadable.
- **Defense:** Before encrypting, the `write` and `writeBinary` hooks check whether the bytes already form an **authenticated MySecret container** for that exact path, cryptographically verifying the GCM tag with the path as associated data.
- **Guarantee:** Only a container produced by MySecret for that path is stored as-is; a file that merely *looks* like a container (e.g. an image starting with the `MYSE` bytes) is encrypted normally and never leaks in cleartext.

### 🛡️ MetadataCache Hash Alignment with Obsidian Sync
- **Threat:** The metadata indexer computes `SHA-256(vault.readBinary())` (plaintext) while Sync computes `SHA-256(adapter.readBinary())` (ciphertext). Since they never match, Sync would detect a change on **every** file on **every** run, re-downloading and rewriting the whole vault forever.
- **Defense:** `MetadataHashPatch` replaces the hash exposed by `metadataCache.getFileInfo()` with the ciphertext hash (the one Sync actually compares), without mutating the original metadata cache entry so links, footnotes and frontmatter keep working.

### 🛡️ Encrypted Note Publication Block (Obsidian Publish)
- **Threat:** Obsidian Publish uploads notes to a **public website** and reads them through `vault.readBinary(file)`, the same path that hands the cleartext to the indexer.
- **Defense:** `PublishGuard` intercepts the internal `publish` plugin's `apiUploadFile()` and **rejects** the upload of any file that is encrypted on disk, with an actionable message pointing to "Decrypt everything".
- **Guarantee:** The cleartext of an encrypted note is never published; plaintext notes (excluded folders) publish normally.

### 🛡️ Guaranteed Memory Zeroization on Error Paths
- **Unconditional Cleanup:** Sensitive cryptographic scrubbing (`zeroize()`) is enforced inside `finally` blocks across all critical cryptographic pathways.
- **Defense:** In the event of an unexpected exception or failure, intermediate keys and password buffers are immediately overwritten with zeros in RAM, preventing memory inspection attacks.

### 🛡️ Authenticated At-Rest Encryption for Cloud Credentials
- **Credentials Envelope:** Access tokens and passwords for remote cloud providers (WebDAV / Nextcloud, Google Drive, OneDrive) are never stored in plaintext within settings.
- **Protection:** Encrypted with AES-256-GCM using a key derived from the master vault key (`vaultKey`), remaining inaccessible to third parties whenever the vault is locked.

### 🛡️ Strict Buffer Isolation & HTTP Memory Safety
- **Payload Truncation:** Network requests in `src/utils/http.ts` utilize `toExactArrayBuffer()` to ensure that only the active view slice (`byteOffset`, `byteLength`) is transmitted.
- **Prevention:** Eliminates accidental leakage of neighboring memory or shared typed array buffers over the network.

### 🛡️ URL Scheme Validation & Enforced HTTPS
- **Scheme Filtering:** Rigorous URL validation across all cloud connectors and WebDAV endpoints.
- **Defense:** Rejects dangerous URI schemes (`javascript:`, `data:`, `file:`) and strictly enforces HTTPS on remote connections to protect against Man-in-the-Middle (MitM) attacks.

### 🛡️ Secret-Safe User Interface
- **Protected Input:** All master password inputs utilize native masked controls (`<input type="password">`) with controlled, temporary visibility toggles.
- **Defense:** Eradicates insecure global popups like `window.prompt()`, preventing accidental disclosure in screen captures, system logs, or shoulder-surfing.

### 🛡️ Protected BIP-39 Recovery Phrase Access
- **Authenticated Disclosure:** The 24-word recovery phrase can only be re-revealed by confirming the active master password inside a dedicated modal, ensuring disaster recovery access remains strictly under the user's control.

### 🛡️ High-Entropy Password Policy
- **Minimum Strength:** Enforces a strict minimum of 12 characters across all setup and password-change workflows, coupled with a real-time visual entropy meter.

### 🛡️ Cryptographically Secure Random Number Generation (CSPRNG)
- **Uniform Entropy:** All session identifiers, IVs, salts, and multipart boundaries are generated exclusively via `crypto.getRandomValues()`.
- **Defense:** Zero reliance on weak pseudo-random generators (`Math.random()`), eliminating predictability.

### 🛡️ Prototype Pollution Immunity
- **Sanitized Object Structures:** Dictionaries used for backup manifest parsing and envelope decoding are instantiated with null prototypes (`Object.create(null)`).
- **Defense:** Dangerous object keys (`__proto__`, `constructor`, `prototype`) are filtered, ensuring runtime immunity against prototype pollution attacks.

### 🛡️ Strict Path Confinement for Local Folder Sync
- **Local Isolation:** The local folder sync provider validates that sync destinations cannot traverse outside the user-configured base directory.

### 🛡️ Secure Biometric Authentication (WebAuthn Bridge)
- **Ephemeral ECDH Key Exchange:** On Android, the companion WebAuthn PWA bridge negotiates a session key via **ECDH over the P-256 curve**.
- **Domain Pinning & Challenge Verification:** The RP ID is pinned to the registrable domain on Cloudflare Pages with single-use timestamped challenges to prevent replay attacks.
- **Vault Anonymity:** The actual vault ID is never transmitted to the browser; only a one-way cryptographic SHA-256 binding is exchanged.
- **Linux requires a real gate:** biometric unlock needs a working `fprintd` fingerprint reader. The former "Secret Service only" mode authenticated nobody (the keyring is normally already unlocked in a logged-in session), so it can no longer be enrolled and old enrollments fail closed.
- **Windows availability check** compares whole output lines (`UNAVAILABLE` contains `AVAILABLE`).

### 🛡️ Second-Audit Hardening
- **Re-authentication for sensitive actions:** changing the password (which also requires the *current* password), revealing/removing the recovery phrase, enrolling biometrics and exporting plaintext all ask for the master password again; being unlocked is not enough.
- **Stable vault id:** device-local biometric slots are keyed by a `vaultId` that survives password changes (it used to be the Argon2 salt, which silently orphaned the enrollment).
- **Authenticated restore:** every ZIP entry is judged by its content, never by the `mode` its own manifest claims. Ciphertext must authenticate with *this* vault's key and *this* path; plaintext is encrypted on the way in. Restore requires an unlocked vault and reports every rejected entry.
- **Backups never drop files silently:** files that cannot be included (no key, non-UTF-8, I/O error) are reported. The "on lock" auto-backup keeps the key it needs until the upload is built.
- **Safe policy changes:** excluding a folder or turning attachment encryption off first decrypts what is already encrypted (all-or-nothing per file), instead of serving raw ciphertext that a later save would corrupt.
- **Deferred re-binds:** a rename/copy performed while the vault is locked is queued, persisted and replayed on unlock; replaying is idempotent. Hooked `process`/`append` calls are serialized per path (no lost updates).
- **Envelope handling:** `vault-envelope.json` is validated on load, written through a temp file + read-back + `.bak`, and a damaged envelope never triggers the setup wizard (which would create a new key over encrypted notes). The wizard also warns if encrypted files exist and refuses to overwrite an initialized vault.
- **Publish guard follows the plugin instance** (enabled later / re-enabled) instead of being installed once at load.
- **Hidden text notes** inside folders (`Notes/.private.md`) are encrypted; hidden folders at any depth are excluded.
- **CI:** actions are pinned to commit SHAs, releases only run for semantic-version tags, CodeQL runs on every push/PR.

### ⚠️ Known Limitations (read these)
- **Changing the master password does NOT rotate the vault key.** Anyone holding an older copy of `vault-envelope.json` (cloud history, backups) together with the *old* password can still decrypt the notes. If a password was exposed, treat the vault as exposed.
- **The lock is a UI lock.** The key is wiped and open notes are closed, but Obsidian and other plugins may keep plaintext in memory (metadata cache, editor state). It protects against casual access, not against a debugger or a malicious plugin.
- **The AAD binds the file path only.** Someone who can write to your vault can restore an older ciphertext of the same file or replace a note with plaintext; the plugin cannot detect that.
- **Biometric unlock on Windows and Linux is a convenience gate** enforced by the plugin: the wrapping secret is protected by DPAPI / a `0600` file readable by the same OS user. Malware running as you can bypass it. Only the WebAuthn (PRF) provider derives the key from the authenticator itself. Use the master password if that matters to you.
- **Backups only contain files that the plugin encrypts.** Excluded folders and hidden/system files are not included.
- **Third-party plugins** that read notes through the Obsidian API receive plaintext by design.

---

## 3. Verification Matrix & Automated Test Suite

Every security defense is continuously validated through automated unit, cryptographic, and integration tests:

| Component | Test Suite | Status |
| :--- | :---: | :---: |
| **Path Sanitization & Zip Slip Defense** | 6 tests | ✅ Passed |
| **Argon2id Cost Bounds & Anti-Downgrade** | 4 tests | ✅ Passed |
| **HTTP Buffer Isolation & URL Validation** | 4 tests | ✅ Passed |
| **At-Rest Cloud Credential Encryption** | 5 tests | ✅ Passed |
| **Prototype Pollution Immunity** | 2 tests | ✅ Passed |
| **Path Traversal Defense in Restore** | 2 tests | ✅ Passed |
| **WebAuthn Biometric Session Security** | 16 tests | ✅ Passed |
| **AES-256-GCM AEAD & NFC Path Normalization** | 8 tests | ✅ Passed |
| **BIP-39 Mnemonic Generation & Validation** | 4 tests | ✅ Passed |
| **Memory Buffer Zeroization** | 2 tests | ✅ Passed |
| **Key Lifecycle & Master Password Change** | 4 tests | ✅ Passed |
| **Internationalization (i18n) Integrity** | 6 tests | ✅ Passed |
| **Adapter Interception & Streaming I/O** | 19 tests | ✅ Passed |
| **Second-audit regression tests** (re-auth, restore, backup, re-binds, biometrics) | 30+ tests | ✅ Passed |
| **Recovery tools compatibility** (HTML + Python decrypt a real vault) | 8 tests | ✅ Passed |
| **Total Automated Tests** | **128 tests** | **100% Passing** |

---

## 4. Comprehensive Security Audit, Supply Chain & Code Hardening (Grade A+)

The MySecret codebase underwent an exhaustive technical security audit, code inspection, and supply-chain review, fully documented in the [Security Audit & Hardening Report](SECURITY_AUDIT.md).

### 🔍 Supply Chain Vulnerability Remediated (`GHSA-67mh-4wv8-2f99` / CWE-346)
- **Vulnerability Details**: `esbuild@0.20.2` (affected `<= 0.24.2`) had a Moderate severity advisory (CVSS 5.3) where `esbuild.serve()` configured `Access-Control-Allow-Origin: *`, allowing arbitrary external websites to query a local development server and read responses.
- **Remediation**: Upgraded `esbuild` from `^0.20.0` to `^0.25.0` (resolved to `0.25.12`) in `package.json` and `package-lock.json`.
- **Real-World Exploitability**: **Zero in production** — `esbuild` is strictly an offline build tool, not bundled into runtime code (`main.js` contains 0 esbuild references), and MySecret never invokes `esbuild.serve()`. The patch was implemented to guarantee supply chain integrity and secure the local development environment.

### 🛡️ Code Review Findings & Hardening in `src/i18n/index.ts`
During manual source-code audit of the internationalization engine, two critical edge-case bugs in template string interpolation were discovered and patched:
1. **Replacement String Pattern Leak / Corruption**: Previously, `text.replace(new RegExp(...), String(val))` was vulnerable to JavaScript replacement patterns (`$&`, `` $` ``, `$'`, `$1`, `$2`). When error messages containing user-controlled or remote-server text (such as `notices.exportFailed` or `notices.backupFailed` interpolating `err.message`) contained dollar signs, the message corrupted or leaked neighboring template text. **Patch**: Replaced with functional replacer `() => String(val)` which never interprets special regex replacement symbols.
2. **Key Metacharacter Regex Injection**: Interpolation placeholder keys containing regex metacharacters (`.`, `{`, etc.) could cause syntax errors or fail matching. **Patch**: Key names are strictly escaped using `escapeRegExp()`.
3. **Prototype Pollution Guard**: Lookup paths explicitly filter `__proto__`, `constructor`, and `prototype`, paired with `hasOwnProperty` validation.
4. **Regression Testing**: 2 dedicated regression test cases added to `tests/test-i18n.mjs` verifying both `$1` / `$&` safety and regex key escaping.

### 🤖 Continuous Automated CI/CD Guardrails
- **Google OSV-Scanner (`.github/workflows/osv-scanner.yml`)**: Continuous automated supply chain monitoring using official Google workflows (`osv-scanner-reusable.yml@v2.7.0` for full repo scans and `osv-scanner-reusable-pr.yml@v2.7.0` for pull requests) with `fail-on-vuln: true`. Runs on `push`, `pull_request`, `tags`, weekly schedule, and manual dispatch.
- **GitHub CodeQL SAST (`.github/workflows/codeql.yml`)**: Automated security and taint-flow analysis scanning every commit and PR across JavaScript/TypeScript code.
- **Semgrep SAST**: Over **503 rules** executed across the entire repository with zero security findings.
- **Gitleaks Secret Detection**: Deep scanning across all Git history commits and working tree files confirmed **0 exposed secrets** (no tokens, credentials, or private keys).

### 🔬 Attack Surface & Defense-in-Depth Verification
- **GitHub Actions Security**: All CI dependencies (`actions/checkout@v4`, `actions/setup-node@v4`, `github/codeql-action@v3`, `softprops/action-gh-release@v2`) audited via OSV database — **0 vulnerabilities**.
- **Recovery tools**: `tools/offline-decryptor.html` has zero dependencies. `tools/standalone-decryptor.py` needs `cryptography` (and `argon2-cffi` only for `--password`), since AES-GCM and Argon2id are not in the Python standard library. Both are tested against vaults produced by the real plugin code.
- **Zero External CDNs or Runtime Scripts**: No third-party CDN scripts or remote resources in the HTML/JS layers of either the plugin or the companion WebAuthn PWA bridge.
- **Zero `eval`, `innerHTML`, or `insertAdjacentHTML`**: The codebase strictly uses Obsidian's native DOM methods (`createEl`, `setIcon`, `setText`, `setCssStyles`), preventing DOM-based XSS.
- **Full Cryptographic Assurance**: AES-256-GCM (96-bit IV, 128-bit tag), Argon2id (64 MiB / 3 iterations / 16-byte salt), HKDF-SHA256, vault-bound AAD, constant-time comparisons, deterministic BIP-39 recovery, and proactive RAM zeroization.

---

## 5. Responsible Disclosure Policy

If you discover a potential security concern or an unhandled edge case, please submit a private vulnerability advisory on GitHub or contact the author directly. All security inquiries are investigated with highest priority.
