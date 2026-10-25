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
| **Total Automated Tests** | **82 tests** | **100% Passing** |

---

## 4. Comprehensive Security Audit, SAST & Secret Leak Verification (Grade A+)

The codebase underwent an end-to-end technical security audit, fully detailed in the [Security Audit & Hardening Report](SECURITY_AUDIT_AND_PATCHES.md):

- **Static Application Security Testing (Semgrep SAST):** Over **503 security rules** were executed across the entire repository. The i18n lookup engine (`src/i18n/index.ts`) was hardened against *Prototype Pollution* attacks using explicit `hasOwnProperty` validation and active blocking of prototype properties (`__proto__`, `constructor`, `prototype`). Result: **0 vulnerabilities**.
- **Secret Leak Detection (Gitleaks):** Deep scan across all Git commits in repository history and all local working tree files. Result: **0 exposed secrets** (no tokens, credentials, or private keys leaked).
- **Strict Static Typing (TypeScript `tsc`):** Zero compilation errors or unhandled type mismatches (`0 errors`).
- **Code Quality & Obsidian Guidelines (ESLint):** Full compliance with official Obsidian developer policies, destructive action conventions, and API requirements (`0 errors`).
- **Supply Chain Security:** Audited and upgraded build tooling (`esbuild` to `^0.25.0`), eliminating known local development vulnerabilities (CWE-346 / GHSA-67mh-4wv8-2f99).

---

## 5. Responsible Disclosure Policy

If you discover a potential security concern or an unhandled edge case, please submit a private vulnerability advisory on GitHub or contact the author directly. All security inquiries are investigated with highest priority.
