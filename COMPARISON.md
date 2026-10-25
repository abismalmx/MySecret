# Why MySecret: Comparison & Key Advantages

**English** • [Versión en Español](COMPARISON.es.md)

When choosing an encryption solution for your personal knowledge base in [Obsidian](https://obsidian.md), you typically have to choose between **security** and **convenience**. Most solutions either force you to manually encrypt notes one by one (breaking search, graph view, and backlinks) or require cumbersome external virtual drives (like Cryptomator or VeraCrypt) that are frustrating to manage on mobile devices.

**MySecret eliminates this trade-off.** It brings true **military-grade, zero-knowledge, at-rest transparent encryption** directly into Obsidian without breaking your everyday workflow.

---

## 📊 Feature Comparison Matrix

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

## 🌟 The 7 Breakthrough Advantages of MySecret

### 1. 🪄 Completely Invisible Encryption (Obsidian Keeps Working)
- **The Problem with Traditional Plugins:** Plugins like *Meld Encrypt* turn your notes into unsightly blocks of encrypted Base64 code on screen. Because Obsidian cannot read the encrypted text, **global search stops working, tags disappear, and the Graph View breaks completely**.
- **The MySecret Solution:** MySecret works quietly at the file system level (`app.vault.adapter`). When your vault is unlocked, Obsidian functions normally: your graph view connects your thoughts, quick-switcher finds any phrase in milliseconds, and canvases render smoothly. The moment files touch your hard drive, they are securely sealed in AES-256-GCM.

---

### 2. 📸 Photos, Documents & Audio Are Also Encrypted
- **The Problem with Traditional Plugins:** Traditional encryption plugins only encrypt markdown text. If you attach an image of a medical document, a private contract PDF, or an audio recording, those files are stored in plaintext in your attachments folder.
- **The MySecret Solution:** MySecret encrypts **every file type**. Text notes use an armored container, while binary media (PNG, JPG, PDF, MP3, MP4) use a compact 32-byte binary header (`MYSE`). Your confidential attachments are just as protected as your written thoughts.

---

### 3. 🛡️ Supercomputer-Resistant Cryptography (Argon2id vs. PBKDF2)
- **The Problem with Traditional Plugins:** Almost all Obsidian security plugins use **PBKDF2** with low iteration counts. A modern graphics card (like an NVIDIA RTX 4090) can test tens of millions of passwords per second against PBKDF2.
- **The MySecret Solution:** MySecret uses **Argon2id** (the official winner of the global Password Hashing Competition) compiled directly into WebAssembly. It forces any attacker to allocate **64 Megabytes of RAM per password guess**, mathematically neutralizing GPU, ASIC, and cloud brute-force cracking attempts.

---

### 4. 🔑 24-Word Emergency Recovery Phrase (Like a Crypto Cold Wallet)
- **The Problem with Traditional Plugins:** If you forget your master password in other plugins, your notes are permanently lost forever. There is no recovery mechanism.
- **The MySecret Solution:** When you first set up your vault, MySecret provides a standard **24-word BIP-39 mnemonic phrase** derived from 256 bits of mathematical entropy. If you ever forget your password, simply enter your 24 words, and your vault is instantly restored offline.

---

### 5. 👆 Fingerprint & Face Unlock Everywhere (Even on Android!)
- **The Problem with Mobile Security:** Obsidian Mobile on Android runs inside a restricted WebView where Google blocks native fingerprint APIs. Because of this hurdle, **no other plugin has been able to offer biometric unlock on Android**.
- **The MySecret Solution:**
  - **On Windows:** Seamless native **Windows Hello** (fingerprint, facial recognition, or PIN) via DPAPI. Zero setup required.
  - **On macOS & Linux:** Native Touch ID and `fprintd` support.
  - **On Android:** An innovative, lightweight companion PWA bridge hosted for free on Cloudflare Pages. It uses **ECDH P-256 ephemeral cryptography** to verify your fingerprint in your mobile browser and securely unlock Obsidian in milliseconds—without your vault key ever leaving your device.

---

### 6. ☁️ Encrypted Cloud & WebDAV Backups Built Right In
- **The Problem with Traditional Tools:** Syncing encrypted containers through third-party services often leads to corrupted files, synchronization locks, or conflicted copies.
- **The MySecret Solution:** MySecret includes a built-in snapshot and backup engine. With a single click or command, you can export full vault snapshots or automatically upload them to **Nextcloud / WebDAV, Google Drive, or Microsoft OneDrive**. All cloud credentials are themselves encrypted at rest with your vault key.

---

### 7. 🧹 Active RAM Scrubbing (Zero-Knowledge & Zeroize)
- **The Problem with Everyday Software:** When you close an app, your passwords and decryption keys often linger in your computer's RAM memory for hours, where malware or memory dump tools can extract them.
- **The MySecret Solution:** MySecret systematically scrubs sensitive memory buffers (`zeroize()`) with zeros inside strict `finally` blocks whenever the vault is locked, when the auto-lock timer expires, or if an unexpected error occurs.

---

### 8. 🔓 Zero Vendor Lock-in: Recover Your Files Without Obsidian
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

## 🎯 Summary: Who Is MySecret Built For?

- **Journalers & Writers:** Keep personal thoughts, mental health logs, and diaries safe from family members, colleagues, or device theft.
- **Professionals & Researchers:** Store proprietary code, confidential client notes, patent drafts, and medical or legal records in compliance with strict privacy standards.
- **Crypto & Privacy Enthusiasts:** Experience the same zero-knowledge, deterministic security principles used by hardware crypto wallets directly inside your second brain.
