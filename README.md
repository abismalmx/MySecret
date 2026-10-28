<div align="center">

<img src="logo.webp" alt="MySecret Logo" width="160" height="160" style="border-radius: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.15);" />

# MySecret — Transparent Vault Encryption for Obsidian

[![Obsidian](https://img.shields.io/badge/Obsidian-v1.0.0+-7C3AED?logo=obsidian&logoColor=white)](https://obsidian.md)
[![Tests](https://img.shields.io/badge/Tests-157%20passing-success?logo=githubactions&logoColor=white)](tests/)
[![Security](https://img.shields.io/badge/Security-Hardened%20%26%20Zero--Trust-brightgreen?logo=shield&logoColor=white)](SECURITY.md)
[![Obsidian Sync](https://img.shields.io/badge/Obsidian%20Sync-100%25%20Compatible-blue?logo=icloud&logoColor=white)](#-the-10-breakthrough-advantages-of-mysecret)
[![License](https://img.shields.io/badge/License-PolyForm%20Noncommercial-orange?style=flat-square)](LICENSE)

**Your vault knows your secrets. Make sure only you do.**  
*Transparent, at-rest zero-knowledge encryption for Obsidian vaults without breaking search, graph or sync.*

**[📖 User Manual](USER_GUIDE.md)** • **[💻 Developer Guide](DEVELOPER_GUIDE.md)** • **[🛡️ Security Architecture](SECURITY.md)** • **[⚖️ Comparison](COMPARISON.md)**  
*(🇬🇧 English • [Versión en Español](README.es.md))*

</div>

---

### 📽️ Slide Presentation / Presentación

> 📊 **Explore the Architecture & Feature Slides:**
> - 🇬🇧 **[English Presentation (Default)](media/MySecret_Presentation_en.pdf)**
> - 🇪🇸 **[Presentación en Español](media/MySecret_Presentation_es.pdf)**

---

## 🌟 Overview

**MySecret** is a security and privacy plugin for [Obsidian](https://obsidian.md) that automatically encrypts every file in your vault — notes, canvases, and attachments (images, PDFs, audio, video) — the instant they are written to disk.

It works like a **one-way mirror** between Obsidian and your hard drive: from inside Obsidian you see everything clearly — full-text search, graph view, links, Canvas. From outside — from the disk, from your cloud service, from whoever stole your laptop — there is only mathematical noise. Nothing readable.

Cryptographic keys exist only in your device's RAM while the vault is unlocked. Not even the plugin developer can read your notes.

---

## 🎬 Video Overview & Interactive Guide

Explore the architectural walkthrough and interactive guides powered by Google NotebookLM:

| 🇬🇧 English Resources | 🇪🇸 Recursos en Español |
| :---: | :---: |
| 🧠 [**Watch Video on NotebookLM**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/ef0d6ffc-dc85-48e2-b52d-11fdbaf5e533) | 🧠 [**Ver Video en NotebookLM**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/e06b57d7-18c5-4e3a-8e99-a25dc10c2804) |
| 📘 [**Interactive Guide & Q&A**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/30901254-af54-4f59-96ac-2c865a5d6e7b) | 📘 [**Guía Interactiva y Consultas**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/be9105e9-f902-4a92-89ac-e67e6ef72d2c) |

---

## 📊 Why MySecret: Comparison & Key Advantages

Your Obsidian notes are plain text files sitting on your hard drive. Anyone who opens your vault folder can read them. Your cloud service has access. If someone steals your laptop, they have everything. This is not alarmism — it is simply how a normal file system works.

Before MySecret, you had two bad options: **encrypt note by note** with plugins like Meld Encrypt (which turns your notes into unreadable blocks, breaks global search, destroys the graph view, and makes tags disappear) or **use external tools** like Cryptomator or VeraCrypt (workable on desktop, but mounting encrypted volumes on Android is frustrating even for experienced users).

**MySecret eliminates this trade-off.** It encrypts your entire vault automatically and transparently, without breaking any Obsidian functionality.

### 📊 Feature Comparison Matrix

| Capability | **MySecret** | **Note-Locking Plugins**<br>*(e.g., Meld Encrypt, Cryptr)* | **External Drive Containers**<br>*(e.g., Cryptomator, VeraCrypt)* |
| :--- | :---: | :---: | :---: |
| **Transparent Vault Encryption** | ✅ **Automatic on disk** | ❌ Manual (note by note) | ✅ Automatic inside container |
| **Full Obsidian Features Intact**<br>*(Full-text search, Graph View, Backlinks, Canvas)* | ✅ **100% Functional**<br>*(while unlocked)* | ❌ **Broken**<br>*(notes are unsearchable cipher blocks)* | ⚠️ Can cause sync collisions or locked-file errors |
| **Obsidian Sync Official Compatibility** | ⚡ **100% Native & Loop-Free**<br>*(Aligned ciphertext hashing)* | ❌ Unusable / causes file conflicts | ❌ Broken / frequent collision loops |
| **Binary Attachments Encrypted**<br>*(Images, PDFs, Audio, Video)* | ✅ **Yes**<br>*(Hardware-accelerated AES-GCM)* | ❌ **No**<br>*(Only raw text is encrypted)* | ✅ Yes |
| **Key Derivation Algorithm** | 🛡️ **Argon2id (WASM, 64 MB)**<br>*(GPU/ASIC Brute-Force Proof)* | ⚠️ **PBKDF2 / SHA-256**<br>*(Easily cracked by modern GPUs)* | 🛡️ Scrypt or Argon2 |
| **Disaster Recovery** | 🔑 **24-word BIP-39 phrase**<br>*(Hardware crypto wallet style)* | ❌ **None**<br>*(Forgot password = 100% data loss)* | ⚠️ Long alpha-numeric recovery key |
| **Automated Test Coverage** | 🧪 **60,000+ lines of test code**<br>*(Source + production bundle audit)* | ❌ Almost zero / minimal unit tests | ⚠️ General library tests |
| **Biometric Unlock (Fingerprint / Face ID)** | ✅ **Windows Hello, Touch ID, Linux & Android** | ❌ None | ⚠️ App-dependent |
| **Android & Mobile Experience** | 📱 **Seamless**<br>*(via secure WebAuthn PWA bridge)* | ⚠️ Clunky manual prompts | ❌ **Frustrating**<br>*(requires mounting virtual drives)* |
| **Cloud Backups (WebDAV, Google Drive, OneDrive)** | ✅ **Built-in**<br>*(Credentials encrypted at rest)* | ❌ None | ❌ Requires separate backup tools |
| **Memory Security (Scrubbing / Zeroize)** | 🧹 **Guaranteed in RAM** | ❌ Plaintext strings kept in memory | ⚠️ Variable |
| **Open & Future-Proof Standards** | ✅ **Standard files on disk** | ⚠️ Custom tags embedded in text | ❌ Proprietary virtual drive formats |

---

### 🌟 The 10 Breakthrough Advantages of MySecret

#### 1. 🪄 Completely Invisible Encryption (Obsidian Keeps Working)
- **The Problem with Traditional Plugins:** Plugins like *Meld Encrypt* turn your notes into unsightly blocks of encrypted Base64 code on screen. Because Obsidian cannot read the encrypted text, **global search stops working, tags disappear, and the Graph View breaks completely**.
- **The MySecret Solution:** MySecret works quietly at the file system level (`app.vault.adapter`). When your vault is unlocked, Obsidian functions normally: your graph view connects your thoughts, quick-switcher finds any phrase in milliseconds, and canvases render smoothly. The moment files touch your hard drive, they are securely sealed in AES-256-GCM.

#### 2. 🔄 100% Compatible with Obsidian Sync (No Re-download Loops)
- **The Graveyard of Encryption Plugins:** Almost all encryption plugins break Obsidian Sync. Because in-memory notes are plaintext while cloud notes are encrypted, Obsidian Sync calculates mismatched checksums, assumes files are out of sync, and enters an endless loop of overwriting and re-downloading entire vaults.
- **The MySecret Solution:** MySecret performs surgical runtime alignment on Obsidian's hashing engine. Obsidian Sync compares the hash of the **ciphertext in rest** (matching the cloud byte-for-byte), while the user interface reads plaintext in memory. Zero sync loops, zero double encryption, zero bandwidth waste.

#### 3. 🧪 Industrial-Grade Automated Test Suite (60,000+ Lines)
- **The Problem with Community Plugins:** 99% of community plugins ship with zero automated tests or minimal toy assertions. When working with your personal vault, an unhandled race condition can destroy years of notes in milliseconds.
- **The MySecret Solution:** Built with defense-in-depth engineering. The codebase includes **over 60,000 lines of automated tests** (`tests/`), running both against source files and against the minified production bundle (`main.js`). It tests memory corruption recovery, power-failure simulations, AAD tamper detection, and adversarial attack vectors under an integrated Obsidian runtime emulator (`obsidian-stub.mjs`).

#### 4. 📸 Photos, Documents & Audio Are Also Encrypted
- **The Problem with Traditional Plugins:** Traditional encryption plugins only encrypt markdown text. If you attach an image of a medical document, a private contract PDF, or an audio recording, those files are stored in plaintext in your attachments folder.
- **The MySecret Solution:** MySecret encrypts **every file type**. Text notes use an armored container, while binary media (PNG, JPG, PDF, MP3, MP4) use a compact 32-byte binary header (`MYSE`). Your confidential attachments are just as protected as your written thoughts.

#### 5. 🛡️ GPU-farm-resistant cryptography (Argon2id vs. PBKDF2)
- **The Problem with Traditional Plugins:** Almost all Obsidian security plugins use **PBKDF2**, an algorithm from two decades ago designed for speed. A modern gaming GPU (like an NVIDIA RTX 4090) can test *tens of millions of passwords per second* against a PBKDF2 hash. Given time and money, it is crackable.
- **The MySecret Solution:** MySecret uses **Argon2id**, the winner of the Password Hashing Competition — a global contest where thousands of cryptographers competed for years to build the algorithm most resistant to modern attacks. Argon2id forces any attacker to allocate **64 MB of RAM per password guess**. Multiplied across millions of parallel attempts, this makes a GPU farm or cloud cluster economically unviable. Think of it as the difference between a regular lock and one that makes the thief carry a truck of sand before trying each combination.

#### 6. 🔑 24-word emergency recovery — like a crypto hardware wallet, for your notes
- **The Problem with Traditional Plugins:** If you forget your master password in other plugins, your data is gone permanently. There is no recovery mechanism, no plan B.
- **The MySecret Solution:** When you first set up your vault, MySecret generates a standard **24-word BIP-39 mnemonic phrase** — the same standard used by the best hardware cryptocurrency wallets to protect fortunes. If you ever forget your password, enter your 24 words and your vault is instantly restored, completely offline, with no servers or support needed. Write them on paper and store them somewhere physically safe.

#### 7. 👆 Fingerprint & Face Unlock Everywhere (Even on Android!)
- **The Problem with Mobile Security:** Obsidian Mobile on Android runs inside a restricted WebView where Google blocks native fingerprint APIs. Because of this hurdle, **no other plugin has been able to offer biometric unlock on Android**.
- **The MySecret Solution:**
  - **On Windows:** Seamless native **Windows Hello** (fingerprint, facial recognition, or PIN) via DPAPI. Zero setup required.
  - **On macOS & Linux:** Native Touch ID and `fprintd` support.
  - **On Android:** An innovative, lightweight companion PWA bridge hosted for free on Cloudflare Pages. It uses **ECDH P-256 ephemeral cryptography** to verify your fingerprint in your mobile browser and securely unlock Obsidian in milliseconds—without your vault key ever leaving your device.

#### 8. ☁️ Encrypted Cloud & WebDAV Backups Built Right In
- **The Problem with Traditional Tools:** Syncing encrypted containers through third-party services often leads to corrupted files, synchronization locks, or conflicted copies.
- **The MySecret Solution:** MySecret includes a built-in snapshot and backup engine. With a single click or command, you can export full vault snapshots or automatically upload them to **Nextcloud / WebDAV, Google Drive, or Microsoft OneDrive**. All cloud credentials are themselves encrypted at rest with your vault key.

#### 9. 🧹 Active RAM Scrubbing (Zero-Knowledge & Zeroize)
- **The Problem with Everyday Software:** When you close an app, your passwords and decryption keys often linger in your computer's RAM memory for hours, where malware or memory dump tools can extract them.
- **The MySecret Solution:** MySecret systematically scrubs sensitive memory buffers (`zeroize()`) with zeros inside strict `finally` blocks whenever the vault is locked, when the auto-lock timer expires, or if an unexpected error occurs.

#### 10. 🔓 Your notes are yours — even without Obsidian, even without MySecret
- **The legitimate fear of trusting any plugin:** *”What if this project is abandoned and I can't open my notes?”*
- **The MySecret Guarantee:** Your files are encrypted with **open, internationally standardized, universally implemented** cryptographic specifications: AES-256-GCM (NIST SP 800-38D), Argon2id (RFC 9106, IETF Standard), and BIP-39 (the same standard used by the best hardware crypto wallets). These are not formats invented for this plugin — they are specifications published in thousands of books, implemented in thousands of independent software libraries. If MySecret disappeared tomorrow, you could decrypt your entire vault with:
  1. **Python:** A 15-line script using universal libraries (`cryptography` or `pycryptodome` + `argon2-cffi`). No Obsidian needed.
  2. **Any modern web browser (fully offline):** The native `crypto.subtle` API (Chrome, Firefox, Safari, Edge) can decrypt any note from a local HTML file.
  3. **CyberChef (GCHQ's cryptographic Swiss Army knife):** Paste the base64 IV, Tag, and ciphertext directly using the standard AES-GCM recipe.
  4. **OpenSSL, Node.js, Go, Rust:** Any language with standard AES-GCM support can read and process your files. Your data is mathematically yours forever.

---

## 🔒 Security & Cryptographic Architecture

- **Zero-Knowledge Architecture:** Decryption keys are derived exclusively in memory using your master password. Neither unencrypted keys nor plaintext files ever leave your device.
- **AES-256-GCM:** Authenticated Encryption with Associated Data (AEAD) using hardware-accelerated Web Crypto API (`window.crypto.subtle`).
- **AAD Path Binding:** The relative file path is strictly bound as Additional Authenticated Data (AAD) preventing ciphertext relocation or swap attacks.
- **Argon2id (WASM):** State-of-the-art key derivation function resistant to GPU/ASIC attacks, powered by WebAssembly via `hash-wasm`.
- **BIP-39 Emergency Recovery:** Deterministic 24-word recovery phrase allows emergency vault recovery if you ever forget your password.
- **Memory Zeroization:** Sensitive cryptographic buffers (keys, master password bytes, mnemonic secrets) in RAM are actively scrubbed (`zeroize()`) upon lock, idle timeout, or app exit.
- **Biometric WebAuthn Bridge:** Native biometric support (Touch ID, Face ID, Windows Hello) and cross-platform Android biometric unlock via our standalone WebAuthn PWA bridge on Cloudflare Pages.

---

## ✨ Features

- 🛡️ **Transparent On-the-Fly Encryption:** Automatically secures markdown notes and binary media files without altering your daily Obsidian workflow.
- 🔐 **Dual-Container Envelope:**
  - **Text notes:** ASCII-armored format (`-----BEGIN MYSECRET ENCRYPTED FILE-----`).
  - **Binary attachments:** Compact 32-byte header with magic bytes `MYSE`.
- ⏱️ **Auto-Lock Timer:** Locks automatically after a configurable period of inactivity.
- 📦 **Automated Encrypted Backups:** Full vault snapshot export and restore with built-in Zip-Slip path sanitization protection.
- ☁️ **Remote Cloud Backups:** Directly upload encrypted vault snapshots to:
  - WebDAV / Nextcloud / ownCloud
  - Google Drive
  - Microsoft OneDrive
- 👆 **Biometric Authentication:**
  - Desktop: Native WebAuthn (Touch ID, Windows Hello, Security Keys).
  - Android & Mobile: Secure bridge via Cloudflare Pages PWA using ECDH key exchange and HMAC-SHA256 assertion validation.
- 🌍 **Internationalization (i18n):** Native support for:
  - English (en)
  - Español (es)
  - Русский (ru)
  - 中文 (zh)

---

## 🚀 Installation

### Option 1: Via Obsidian Community Plugins *(Pending review)*
1. Open Obsidian **Settings** → **Community Plugins**.
2. Turn off **Restricted mode**.
3. Search for **MySecret** and click **Install**, then **Enable**.

### Option 2: Via BRAT (Beta Reviewer's Auto-update Tester)
1. Install the [BRAT](https://github.com/TfTHacker/obsidian42-brat) plugin in Obsidian.
2. Go to **Options** → **BRAT** → **Add Beta plugin**.
3. Enter: `https://github.com/abismalmx/MySecret`
4. Enable the plugin under **Community plugins**.

### Option 3: Manual Installation
1. Download the latest release (`main.js`, `manifest.json`, `styles.css`) from the [Releases](https://github.com/abismalmx/MySecret/releases) page.
2. Navigate to your Obsidian vault directory: `<vault>/.obsidian/plugins/`
3. Create a folder named `mysecret` and place the three downloaded files inside:
   ```
   <vault>/.obsidian/plugins/mysecret/
   ├── main.js
   ├── manifest.json
   └── styles.css
   ```
4. Reload Obsidian, go to **Settings** → **Community plugins**, and toggle on **MySecret**.

---

## 🛠️ Building & Development

### Prerequisites
- Node.js 18+ (Node 20 LTS recommended)
- npm or pnpm

### Clone & Install
```bash
git clone https://github.com/abismalmx/MySecret.git
cd obsidian-mysecret
npm install
```

### Development Build (Watch Mode)
```bash
npm run dev
```

### Production Build
```bash
npm run build
```

### Run Automated Security & Unit Tests
```bash
npm test
```
> All 157 unit, integration, and cryptographic regression tests pass with 100% success rate.

---

## 📱 Mobile Biometric Bridge (iOS / Android) (`auth-bridge/`)

Obsidian Mobile on Android and iOS runs inside a restricted WebView where `navigator.credentials.get()` / WebAuthn is unavailable for custom app schemes.

MySecret solves this via a companion **WebAuthn PWA Bridge**:
1. You deploy the static files inside the `auth-bridge/` folder to a free **Cloudflare Pages** site (zero setup, 1 click).
2. The plugin uses deep-linking (`obsidian://`) with ECDH (P-256) ephemeral key exchange and HMAC verification.
3. Safari on iOS activates **Face ID / Touch ID** via Apple's Secure Enclave; Chrome on Android activates the **Fingerprint / Biometric sensor**.
4. The vault key never leaves the device.

See [auth-bridge/README.md](auth-bridge/README.md) for step-by-step setup instructions.

---

## 📚 Documentation

- 📖 **[User Manual](USER_GUIDE.md)** ([Versión en Español](USER_GUIDE.es.md)) — Complete step-by-step user guide.
- 💻 **[Developer Manual](DEVELOPER_GUIDE.md)** ([Versión en Español](DEVELOPER_GUIDE.es.md)) — Deep-dive architecture and API reference.
- 🛡️ **[Security Architecture](SECURITY.md)** ([Versión en Español](SECURITY.es.md)) — Cryptographic primitives and audited defenses.
- 📊 **[Why MySecret / Comparison](COMPARISON.md)** ([Versión en Español](COMPARISON.es.md)) — Key advantages vs. traditional encryption tools.
- 📱 **[Mobile Biometric Bridge (iOS / Android)](auth-bridge/README.md)** — Cloudflare Pages deployment guide.

---

## 🇪🇸 Documentación en Español

Puedes consultar la versión completa en español de este documento en [README.es.md](README.es.md).

---

## 📄 License

Distributed under the **[PolyForm Noncommercial License 1.0.0](LICENSE)**.

- **Free and open** for personal use, learning, non-profit organizations, and academic security research.
- **Auditable source code:** The entire codebase is public on GitHub — mathematically verifiable with zero backdoors.
- Commercial use requires prior written authorization. Contact the author at `abismalmx.splurge748@8shield.net`. See [LICENSE](LICENSE) for full legal terms.
