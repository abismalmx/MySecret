<div align="center">

<img src="logo.webp" alt="MySecret Logo" width="160" height="160" style="border-radius: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.15);" />

# MySecret — Transparent Vault Encryption for Obsidian

[![Obsidian](https://img.shields.io/badge/Obsidian-v1.0.0+-7C3AED?logo=obsidian&logoColor=white)](https://obsidian.md)
[![License](https://img.shields.io/badge/License-Non--Commercial-blue.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-96%20passing-success)](tests/)
[![Security](https://img.shields.io/badge/Security-Hardened%20%26%20Verified-brightgreen)](SECURITY.md)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?logo=typescript&logoColor=white)](tsconfig.json)

**Zero-Knowledge, on-the-fly encryption for your Obsidian notes and media files.**  
*AES-256-GCM • Argon2id (WASM) • BIP-39 Mnemonic Recovery • WebAuthn & Biometrics • Multi-Cloud Backups*

[English](README.md) • [Español](README.es.md)

</div>

---

### 📽️ Slide Presentation / Presentación

> 📊 **Explore the Architecture & Feature Slides:**
> - 🇬🇧 **[English Presentation (Default)](media/MySecret_for_Obsidian.pptx)**
> - 🇪🇸 **[Presentación en Español](media/MySecret_presentación.pptx)**

---

## 🌟 Overview

**MySecret** is an advanced security and privacy plugin for [Obsidian](https://obsidian.md). It transparently intercepts Obsidian's file adapter (`app.vault.adapter`) to encrypt and decrypt notes (`.md`), canvases (`.canvas`), and binary attachments (images, PDFs, audio, video) in real-time.

On disk, your files remain fully encrypted at rest. When unlocked, you interact with Obsidian normally—with full search, graph view, links, and editing capabilities.

---

## 🎬 Video Overview & Architecture Walkthrough

Watch the complete video overview of MySecret explaining how transparent at-rest encryption protects your Obsidian vault:

| 🇬🇧 English Walkthrough | 🇪🇸 Explicación en Español |
| :---: | :---: |
| 🌐 [**Watch Online Streaming (No Download)**](https://abismalmx.github.io/MySecret/docs/interactive-infographic.html) | 🌐 [**Ver Online sin Descargar (Streaming)**](https://abismalmx.github.io/MySecret/docs/interactive-infographic.html) |
| 🧠 [**Watch on Google NotebookLM**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/ef0d6ffc-dc85-48e2-b52d-11fdbaf5e533) | 🧠 [**Ver en Google NotebookLM**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/e06b57d7-18c5-4e3a-8e99-a25dc10c2804) |
| 💾 [Download MP4 File](media/MySecret_en.mp4) | 💾 [Descargar Archivo MP4](media/MySecret_es.mp4) |

> [!TIP]
> 🌐 **Interactive Security Infographic (Web)**: Explore the interactive architecture, stream videos, and test the crypto simulator at **[abismalmx.github.io/MySecret](https://abismalmx.github.io/MySecret/docs/interactive-infographic.html)**.  
> 🧠 **Interactive NotebookLM Guide**:
> - 🇬🇧 [Explore on NotebookLM (English)](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/30901254-af54-4f59-96ac-2c865a5d6e7b)
> - 🇪🇸 [Explorar en NotebookLM (Español)](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/be9105e9-f902-4a92-89ac-e67e6ef72d2c)

---

## 📊 Why MySecret: Comparison & Key Advantages

When choosing an encryption solution for your personal knowledge base in [Obsidian](https://obsidian.md), you typically have to choose between **security** and **convenience**. Most solutions either force you to manually encrypt notes one by one (breaking search, graph view, and backlinks) or require cumbersome external virtual drives (like Cryptomator or VeraCrypt) that are frustrating to manage on mobile devices.

**MySecret eliminates this trade-off.** It brings true **military-grade, zero-knowledge, at-rest transparent encryption** directly into Obsidian without breaking your everyday workflow.

### 📊 Feature Comparison Matrix

| Capability | **MySecret** | **Note-Locking Plugins**<br>*(e.g., Meld Encrypt, Cryptr)* | **External Drive Containers**<br>*(e.g., Cryptomator, VeraCrypt)* |
| :--- | :---: | :---: | :---: |
| **Transparent Vault Encryption** | ✅ **Automatic on disk** | ❌ Manual (note by note) | ✅ Automatic inside container |
| **Full Obsidian Features Intact**<br>*(Full-text search, Graph View, Backlinks, Canvas)* | ✅ **100% Functional**<br>*(while unlocked)* | ❌ **Broken**<br>*(notes are unsearchable cipher blocks)* | ⚠️ Can cause sync collisions or locked-file errors |
| **Binary Attachments Encrypted**<br>*(Images, PDFs, Audio, Video)* | ✅ **Yes**<br>*(Hardware-accelerated AES-GCM)* | ❌ **No**<br>*(Only raw text is encrypted)* | ✅ Yes |
| **Key Derivation Algorithm** | 🛡️ **Argon2id (WASM, 64 MB)**<br>*(GPU/ASIC Brute-Force Proof)* | ⚠️ **PBKDF2 / SHA-256**<br>*(Easily cracked by modern GPUs)* | 🛡️ Scrypt or Argon2 |
| **Disaster Recovery** | 🔑 **24-word BIP-39 phrase**<br>*(Hardware crypto wallet style)* | ❌ **None**<br>*(Forgot password = 100% data loss)* | ⚠️ Long alpha-numeric recovery key |
| **Biometric Unlock (Fingerprint / Face ID)** | ✅ **Windows Hello, Touch ID, Linux & Android** | ❌ None | ⚠️ App-dependent |
| **Android & Mobile Experience** | 📱 **Seamless**<br>*(via secure WebAuthn PWA bridge)* | ⚠️ Clunky manual prompts | ❌ **Frustrating**<br>*(requires mounting virtual drives)* |
| **Cloud Backups (WebDAV, Google Drive, OneDrive)** | ✅ **Built-in**<br>*(Credentials encrypted at rest)* | ❌ None | ❌ Requires separate backup tools |
| **Memory Security (Scrubbing / Zeroize)** | 🧹 **Guaranteed in RAM** | ❌ Plaintext strings kept in memory | ⚠️ Variable |
| **Open & Future-Proof Standards** | ✅ **Standard files on disk** | ⚠️ Custom tags embedded in text | ❌ Proprietary virtual drive formats |

---

### 🌟 The 8 Breakthrough Advantages of MySecret

#### 1. 🪄 Completely Invisible Encryption (Obsidian Keeps Working)
- **The Problem with Traditional Plugins:** Plugins like *Meld Encrypt* turn your notes into unsightly blocks of encrypted Base64 code on screen. Because Obsidian cannot read the encrypted text, **global search stops working, tags disappear, and the Graph View breaks completely**.
- **The MySecret Solution:** MySecret works quietly at the file system level (`app.vault.adapter`). When your vault is unlocked, Obsidian functions normally: your graph view connects your thoughts, quick-switcher finds any phrase in milliseconds, and canvases render smoothly. The moment files touch your hard drive, they are securely sealed in AES-256-GCM.

#### 2. 📸 Photos, Documents & Audio Are Also Encrypted
- **The Problem with Traditional Plugins:** Traditional encryption plugins only encrypt markdown text. If you attach an image of a medical document, a private contract PDF, or an audio recording, those files are stored in plaintext in your attachments folder.
- **The MySecret Solution:** MySecret encrypts **every file type**. Text notes use an armored container, while binary media (PNG, JPG, PDF, MP3, MP4) use a compact 32-byte binary header (`MYSE`). Your confidential attachments are just as protected as your written thoughts.

#### 3. 🛡️ Supercomputer-Resistant Cryptography (Argon2id vs. PBKDF2)
- **The Problem with Traditional Plugins:** Almost all Obsidian security plugins use **PBKDF2** with low iteration counts. A modern graphics card (like an NVIDIA RTX 4090) can test tens of millions of passwords per second against PBKDF2.
- **The MySecret Solution:** MySecret uses **Argon2id** (the official winner of the global Password Hashing Competition) compiled directly into WebAssembly. It forces any attacker to allocate **64 Megabytes of RAM per password guess**, mathematically neutralizing GPU, ASIC, and cloud brute-force cracking attempts.

#### 4. 🔑 24-Word Emergency Recovery Phrase (Like a Crypto Cold Wallet)
- **The Problem with Traditional Plugins:** If you forget your master password in other plugins, your notes are permanently lost forever. There is no recovery mechanism.
- **The MySecret Solution:** When you first set up your vault, MySecret provides a standard **24-word BIP-39 mnemonic phrase** derived from 256 bits of mathematical entropy. If you ever forget your password, simply enter your 24 words, and your vault is instantly restored offline.

#### 5. 👆 Fingerprint & Face Unlock Everywhere (Even on Android!)
- **The Problem with Mobile Security:** Obsidian Mobile on Android runs inside a restricted WebView where Google blocks native fingerprint APIs. Because of this hurdle, **no other plugin has been able to offer biometric unlock on Android**.
- **The MySecret Solution:**
  - **On Windows:** Seamless native **Windows Hello** (fingerprint, facial recognition, or PIN) via DPAPI. Zero setup required.
  - **On macOS & Linux:** Native Touch ID and `fprintd` support.
  - **On Android:** An innovative, lightweight companion PWA bridge hosted for free on Cloudflare Pages. It uses **ECDH P-256 ephemeral cryptography** to verify your fingerprint in your mobile browser and securely unlock Obsidian in milliseconds—without your vault key ever leaving your device.

#### 6. ☁️ Encrypted Cloud & WebDAV Backups Built Right In
- **The Problem with Traditional Tools:** Syncing encrypted containers through third-party services often leads to corrupted files, synchronization locks, or conflicted copies.
- **The MySecret Solution:** MySecret includes a built-in snapshot and backup engine. With a single click or command, you can export full vault snapshots or automatically upload them to **Nextcloud / WebDAV, Google Drive, or Microsoft OneDrive**. All cloud credentials are themselves encrypted at rest with your vault key.

#### 7. 🧹 Active RAM Scrubbing (Zero-Knowledge & Zeroize)
- **The Problem with Everyday Software:** When you close an app, your passwords and decryption keys often linger in your computer's RAM memory for hours, where malware or memory dump tools can extract them.
- **The MySecret Solution:** MySecret systematically scrubs sensitive memory buffers (`zeroize()`) with zeros inside strict `finally` blocks whenever the vault is locked, when the auto-lock timer expires, or if an unexpected error occurs.

#### 8. 🔓 Zero Vendor Lock-in: Recover Your Files Without Obsidian
- **The Common Fear:** *“What if the plugin is discontinued, Obsidian disappears 20 years from now, or my application fails to launch?”*
- **The MySecret Guarantee:** **You are NEVER trapped by the plugin or Obsidian.** MySecret is built entirely on open, internationally standardized cryptographic specifications:
  - **AES-256-GCM** (NIST SP 800-38D).
  - **Argon2id** (RFC 9106, IETF Standard).
  - **BIP-39** (International cryptocurrency hardware wallet standard).
- **What Other Software Can Decrypt Your Notes?**
  1. **Python:** A simple 15-line script using universal, battle-tested libraries (`cryptography` or `pycryptodome` + `argon2-cffi`) can batch-decrypt your entire vault in seconds without Obsidian even installed.
  2. **Any Modern Web Browser (100% Offline):** The native `crypto.subtle` API in Chrome, Firefox, Safari, or Edge can decrypt any note using a lightweight local HTML file.
  3. **CyberChef (The Cyber Swiss Army Knife by GCHQ):** Paste your base64 IV, Tag, and Ciphertext directly into CyberChef using the standard AES-GCM recipe.
  4. **OpenSSL / Node.js / Go / Rust:** Any programming language with standard AES-GCM support can easily parse and decrypt your notes. Your data is mathematically yours forever.

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
> All 81 unit, integration, and cryptographic regression tests pass with 100% success rate.

---

## 📱 Android Biometric Bridge (`auth-bridge/`)

Obsidian Mobile on Android runs inside a restricted WebView where `navigator.credentials.get()` / WebAuthn is unavailable.

MySecret solves this via a companion **WebAuthn PWA Bridge**:
1. You deploy the static files inside the `auth-bridge/` folder to a free **Cloudflare Pages** site (zero setup, 1 click).
2. The plugin uses deep-linking / intent with ECDH (P-256) ephemeral key exchange and HMAC verification.
3. The vault key never leaves the device.

See [auth-bridge/README.md](auth-bridge/README.md) for step-by-step setup instructions.

---

## 📚 Documentation

- 📖 **[User Manual](USER_GUIDE.md)** ([Versión en Español](USER_GUIDE.es.md)) — Complete step-by-step user guide.
- 💻 **[Developer Manual](DEVELOPER_GUIDE.md)** ([Versión en Español](DEVELOPER_GUIDE.es.md)) — Deep-dive architecture and API reference.
- 🛡️ **[Security Architecture](SECURITY.md)** ([Versión en Español](SECURITY.es.md)) — Cryptographic primitives and audited defenses.
- 📊 **[Why MySecret / Comparison](COMPARISON.md)** ([Versión en Español](COMPARISON.es.md)) — Key advantages vs. traditional encryption tools.
- 📱 **[Android Biometric Bridge](auth-bridge/README.md)** — Cloudflare Pages deployment guide.

---

## 🇪🇸 Documentación en Español

Puedes consultar la versión completa en español de este documento en [README.es.md](README.es.md).

---

## 📄 License

Copyright (c) 2026 Anthony Rios Licea (@abismalmx).  
Licensed under the **MySecret Non-Commercial Software License**. Free for personal, academic, and non-commercial use. Commercial use or redistribution is strictly prohibited without prior written authorization from the author. See [LICENSE](LICENSE) for full legal terms.
