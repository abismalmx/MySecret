# MySecret — Comprehensive User Manual

**English** • [Versión en Español](USER_GUIDE.es.md)

Welcome to the **MySecret User Manual**. This guide provides an exhaustive, step-by-step walkthrough of installing, configuring, using, backing up, and recovering an encrypted Obsidian vault with MySecret.

> [!IMPORTANT]
> ### ⚠️ Mandatory Pre-Installation Step: Backup Your Vault First
> **Before installing, enabling, or migrating an existing vault with MySecret, it is strongly recommended that you make a complete backup copy of your Obsidian vault folder.**
> Simply copy your entire vault folder to an external drive, USB stick, or another folder on your computer. Because MySecret performs real, hardware-accelerated at-rest disk encryption, keeping an unencrypted backup ensures total peace of mind and guarantees you can always restore your original files if you ever forget your master password or misplace your 24-word recovery phrase.

---

## Table of Contents

1. [Introduction & Core Concepts](#1-introduction--core-concepts)
2. [Installation](#2-installation)
3. [Initial Setup Wizard](#3-initial-setup-wizard)
4. [Daily Usage & Workflow](#4-daily-usage--workflow)
5. [Biometric Authentication Guide](#5-biometric-authentication-guide)
   - [Windows (Windows Hello)](#windows-windows-hello)
   - [macOS (Touch ID)](#macos-touch-id)
   - [Linux (fprintd)](#linux-fprintd)
   - [Android (Cloudflare Pages Bridge)](#android-cloudflare-pages-bridge)
6. [Vault Migration & Bulk Processing](#6-vault-migration--bulk-processing)
7. [Backups & Cloud Storage](#7-backups--cloud-storage)
   - [Local Vault Snapshots](#local-vault-snapshots)
   - [Restoring from Backups](#restoring-from-backups)
   - [Remote Cloud Backups (WebDAV, Google Drive, OneDrive)](#remote-cloud-backups)
8. [Disaster Recovery & Key Management](#8-disaster-recovery--key-management)
9. [How to Decrypt Notes Independently Without the Plugin or Obsidian](#9-how-to-decrypt-notes-independently-without-the-plugin-or-obsidian)
10. [Frequently Asked Questions (FAQ)](#10-frequently-asked-questions-faq)

---

## 1. Introduction & Core Concepts

### What is Transparent Encryption?
Traditional file encryption usually requires manually locking or unlocking individual files, or keeping notes inside closed, proprietary encrypted databases that break Obsidian's file-based ecosystem.

**MySecret** takes a radically different approach:
- **At Rest (On Disk):** Every markdown note (`.md`), canvas file (`.canvas`), and media attachment (PNG, JPG, PDF, MP3, MP4) is stored completely encrypted using **AES-256-GCM**. If someone steals your laptop, opens your vault folder in VS Code, or accesses your cloud backup, all they will see are encrypted containers.
- **In Memory (Inside Obsidian):** When your vault is unlocked, MySecret transparently intercepts Obsidian's internal filesystem calls. You can edit notes, click links, view embedded images, search your vault, and explore the Graph View with zero friction.
- **Zero-Knowledge Architecture:** Decryption keys are held strictly in temporary RAM. No keys, passwords, or recovery phrases are ever transmitted over the network or saved unencrypted on your disk.

---

## 2. Installation

### Method A: Via BRAT (Recommended for Beta & Direct Updates)
1. Install and enable the **BRAT** plugin from Obsidian's Community Plugins directory.
2. In Obsidian, go to **Settings** → **BRAT**.
3. Click **Add Beta plugin**.
4. Enter the GitHub repository URL:
   ```
   https://github.com/abismalmx/MySecret
   ```
5. Click **Add Plugin**, wait for the download to complete, and enable **MySecret** under **Settings** → **Community plugins**.

### Method B: Manual Installation
1. Navigate to the [Releases](https://github.com/abismalmx/MySecret/releases) page on GitHub.
2. Download the three release files:
   - `main.js`
   - `manifest.json`
   - `styles.css`
3. Open your Obsidian vault folder and navigate into the hidden plugin directory:
   ```
   <your-vault>/.obsidian/plugins/
   ```
4. Create a new folder named `mysecret` and place the three downloaded files inside:
   ```
   .obsidian/plugins/mysecret/
   ├── main.js
   ├── manifest.json
   └── styles.css
   ```
5. In Obsidian, open **Settings** → **Community plugins**, click **Reload plugins**, and toggle on **MySecret**.

---

## 3. Initial Setup Wizard

When you first enable MySecret in a vault, an interactive **Setup Wizard** will appear to configure your vault's cryptographic envelope.

```
┌────────────────────────────────────────────────────────┐
│                   MySecret Vault Setup                 │
├────────────────────────────────────────────────────────┤
│ Step 1: Create Master Password (Entropy meter)         │
│ Step 2: 24-Word BIP-39 Recovery Phrase Cards           │
│ Step 3: Interactive Word Verification Challenge        │
└────────────────────────────────────────────────────────┘
```

### Step 1: Create Your Master Password
- **Minimum Length:** Must be at least **12 characters**.
- **Strength Evaluation:** The built-in entropy meter evaluates character diversity (uppercase, lowercase, numbers, and symbols).
- **Tip:** Use a passphrase composed of 4 or 5 random words that you can easily remember (e.g., `coral-galaxy-timber-panther-beacon`).

### Step 2: Secure Your 24-Word BIP-39 Recovery Phrase
- MySecret generates 256 bits of cryptographically secure entropy formatted into a standard **24-word BIP-39 mnemonic phrase**.
- **Crucial Rule:** Write down these 24 words in physical order on paper and store them in a secure location (such as a fireproof safe).
- **Warning:** If you ever lose your master password, this phrase is the **only** mathematical way to restore access to your encrypted notes.

### Step 3: Verification Challenge
- To ensure you have safely recorded your recovery phrase, the wizard will prompt you to verify two random word positions (e.g., Word #7 and Word #19).
- Once verified, your vault envelope is initialized, and your vault is ready to use!

---

## 4. Daily Usage & Workflow

### Unlocking Your Vault
When you launch Obsidian:
1. The **MySecret Lock Screen** will overlay Obsidian's interface.
2. Enter your master password or click the **Biometric Unlock** button (Touch ID, Windows Hello, or Fingerprint).
3. Upon successful decryption, the interface immediately unlocks, restoring full access to your notes, graph view, and search.

### Status Bar Indicator
In the bottom-right corner of Obsidian's status bar, MySecret displays the current vault security status:
- 🟢 **Vault Unlocked:** Your session is active; edits are being transparently encrypted in real-time.
- 🔒 **Lock Now:** Clicking the status bar icon immediately locks the vault and scrubs RAM.

### Auto-Lock Timer
To protect your privacy when stepping away from your computer:
1. Open **Settings** → **MySecret**.
2. Locate **Auto-Lock Timeout**.
3. Set your desired inactivity interval (e.g., 5, 10, or 30 minutes, or Disabled).
4. When the timer expires, MySecret immediately scrubs the master key from RAM (`zeroize()`) and re-engages the lock screen.

### How Encrypted Files Look on Disk
If you inspect your vault using an external file explorer:
- **Markdown Notes (`.md`):** Look like standardized ASCII-armored envelopes:
  ```markdown
  -----BEGIN MYSECRET ENCRYPTED FILE-----
  Version: 1
  IV: d8f3a9e1b2c4d5e6f7a8b9c0
  Tag: 4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d

  q8XyZ1v...[Base64 Encrypted Ciphertext]...==
  -----END MYSECRET ENCRYPTED FILE-----
  ```
- **Binary Attachments (Images, PDFs, Audio):** Saved as compact binary files with the `MYSE` magic header followed by the 12-byte IV, 16-byte GCM authentication tag, and ciphertext.

---

## 5. Biometric Authentication Guide

MySecret provides cross-platform biometric unlocking tailored to each operating system.

### Windows (Windows Hello)
- **Supported:** Fingerprint readers, IR facial recognition cameras, or Windows Hello PIN.
- **Setup:**
  1. Ensure Windows Hello is enabled in Windows Settings → Accounts → Sign-in options.
  2. In Obsidian, go to **Settings** → **MySecret** → **Biometrics**.
  3. Toggle **Enable Biometrics** to ON and confirm your master password.
- **Is a Cloudflare URL needed?** **NO.** Windows uses 100% native operating system APIs via DPAPI and `UserConsentVerifier`. No internet connection is needed.

### macOS (Touch ID)
- **Supported:** Built-in Touch ID sensors on MacBooks, Magic Keyboards with Touch ID, and Apple Watch unlocking.
- **Setup:** Enable biometrics in plugin settings; macOS handles verification locally via WebAuthn platform authenticators.
- **Is a Cloudflare URL needed?** **NO.** Works 100% locally.

### Linux (fprintd)
- **Supported:** PAM-compatible fingerprint scanners integrated with `fprintd` and `SecretService`.
- **Setup:** Configure `fprintd-enroll` in your Linux distribution, then enable biometrics in MySecret settings.
- **Is a Cloudflare URL needed?** **NO.** Fully local.

### Android (Cloudflare Pages Bridge)
On Android, the Obsidian app runs within an Android WebView where native WebAuthn access is restricted by Android security policies. MySecret bridges this gap via a lightweight companion Web app hosted on Cloudflare Pages:

1. **One-Time Deployment (100% Free):**
   - Log in to [dash.cloudflare.com](https://dash.cloudflare.com/).
   - Go to **Workers & Pages** → **Create application** → **Pages** tab → **Upload assets**.
   - Name your project (e.g., `my-vault-auth`).
   - Drag and drop the `auth-bridge/` folder from the plugin repository and click **Deploy site**.
   - Cloudflare will assign you a private HTTPS URL (e.g., `https://my-vault-auth.pages.dev`).
2. **Configure in Obsidian Mobile:**
   - In Obsidian for Android, go to **Settings** → **MySecret** → **Android Biometric Unlock**.
   - Paste your Cloudflare Pages URL into the text box.
   - Click **Test Bridge URL** to verify the connection.
   - Toggle **Enable Biometrics** and perform your first biometric enrollment.
3. **Daily Unlock:**
   - On the lock screen, tap **Biometric Unlock**.
   - Your mobile browser securely opens the bridge, reads your fingerprint, and immediately returns to Obsidian with the session key negotiated via ECDH P-256.

---

## 6. Vault Migration & Bulk Processing

If you are installing MySecret into an existing vault with pre-existing plaintext notes, or if you ever decide to export your vault back to plaintext:

1. Open **Settings** → **MySecret**.
2. Click **Vault Migration**.
3. Choose the desired action:
   - **Encrypt Entire Vault:** Scans all plaintext markdown files, canvases, and attachments, converting them into encrypted containers in-place.
   - **Decrypt Entire Vault:** Reverts all encrypted files back into clean plaintext notes and original binary assets.
4. An interactive modal displays a live progress bar, file counters, and an emergency stop button.

---

## 7. Backups & Cloud Storage

### Local Vault Snapshots
MySecret includes a snapshot generator that packages your entire vault into an encrypted ZIP archive:
1. Open the Command Palette (`Ctrl+P` or `Cmd+P`).
2. Run **MySecret: Create Encrypted Vault Backup**.
3. Select your destination directory to save the `.zip` archive.

### Restoring from Backups
1. Run **MySecret: Restore Vault from Backup**.
2. Select your `.zip` backup file.
3. **Safety Protection:** The built-in Path Sanitizer inspects all archive entries, automatically blocking Zip Slip exploits, directory traversal attacks, or attempts to overwrite sensitive system files.

### Remote Cloud Backups
You can automatically upload encrypted vault snapshots to remote cloud storage:
- **WebDAV / Nextcloud / ownCloud:** Enter your server URL, username, and password. Connections enforce HTTPS.
- **Google Drive:** Seamless backup integration with isolated app-data folder scope.
- **Microsoft OneDrive:** Automated upload to your personal Microsoft cloud drive.
- **Security Note:** All cloud credentials are encrypted at rest with your master vault key before being stored in plugin settings.

---

## 8. Disaster Recovery & Key Management

### What to do if you forget your Master Password
1. On the lock screen, click **Forgot Password? / Recovery Phrase**.
2. Enter your 24-word BIP-39 recovery phrase with words separated by single spaces.
3. The cryptographic engine regenerates your 256-bit Vault Key.
4. You will be prompted to set a new master password. All existing encrypted notes remain intact.

### Changing Your Master Password
1. Unlock your vault normally.
2. In the Command Palette or Settings, select **Change Master Password**.
3. Enter your current password, followed by your new password (minimum 12 characters).
4. MySecret re-encrypts the vault envelope with a fresh Argon2id salt and key. None of your underlying note ciphertexts need to be re-encrypted, ensuring the change is instant and safe.

---

## 9. How to Decrypt Notes Independently Without the Plugin or Obsidian

A core architectural strength of MySecret is that **you are never locked into Obsidian or this plugin**. Because all files use open industry standards (**AES-256-GCM**, **Argon2id**, and **BIP-39**), you can decrypt your vault independently with standalone tools.

The repository includes ready-to-run recovery tools inside the `tools/` directory:

### Method 1: Using Any Web Browser (100% Offline)
Zero installation required. Works for **one note or attachment at a time**, with your recovery phrase:
1. Double-click to open [`tools/offline-decryptor.html`](tools/offline-decryptor.html) in your browser (Chrome, Firefox, Safari, or Edge).
2. Open `.obsidian/plugins/mysecret/vault-envelope.json` with a text editor and paste its whole content.
3. Enter your 24-word BIP-39 recovery phrase.
4. Type the **exact** vault path the file had (e.g., `Notes/Journal.md`). The path is part of the authenticated data: a wrong path fails on purpose.
5. Paste the armored note (starting with `-----BEGIN MYSECRET ENCRYPTED FILE-----`) or pick an encrypted attachment, then click **Decrypt**.

> Vaults created without a recovery phrase ("password only" mode) cannot use this page: use Method 2 with `--password`.

### Method 2: Batch Decryption with Python (`tools/standalone-decryptor.py`)
To decrypt an entire vault containing hundreds of notes and image attachments in one pass:
1. Ensure Python 3 is installed and install the required dependencies (`argon2-cffi` is only needed for `--password`):
   ```bash
   pip install cryptography argon2-cffi
   ```
2. Batch-decrypt the entire vault using your 24-word recovery phrase:
   ```bash
   python tools/standalone-decryptor.py --vault "/path/to/vault" --mnemonic "word1 word2 ... word24" --output "/path/to/decrypted_vault"
   ```
3. Or decrypt using your Master Password. The tool reads `.obsidian/plugins/mysecret/vault-envelope.json` (use `--envelope` if it is elsewhere). Leave `--password` without a value to be prompted, so the password stays out of your shell history:
   ```bash
   python tools/standalone-decryptor.py --vault "/path/to/vault" --password --output "/path/to/decrypted_vault"
   ```
4. The script reconstructs your vault hierarchy with all markdown files and attachments in plaintext. The output folder must be **outside** the vault. A single file: add `--file note.md --relative-path "Notes/note.md"`.

### Method 3: Using CyberChef (GCHQ Web Utility)
1. Navigate to [CyberChef](https://gchq.github.io/CyberChef/).
2. Select the **AES Decrypt** recipe with mode set to **GCM**.
3. Provide the 32-byte derived key, the 12-byte IV, and set the Additional Authenticated Data (AAD) to the relative file path (e.g., `Notes/Ideas.md`).

---

## 10. Frequently Asked Questions (FAQ)

#### Q: Are note titles and file names encrypted?
**A:** File names on disk remain visible so that Obsidian's internal linking engine, folder structure, and caching can function normally. However, the entire text content, frontmatter, canvases, and all binary attachments are fully encrypted.

#### Q: Does MySecret work with Obsidian Sync or Git?
**A:** Yes! Because files on disk are standard encrypted text files, Obsidian Sync, Git, or cloud sync providers (Dropbox, iCloud, Syncthing) simply sync the encrypted containers. Cloud providers cannot read your notes.

#### Q: What happens if I uninstall the plugin?
**A:** If you uninstall the plugin while your files are encrypted, your notes on disk will remain encrypted. To return your notes to plaintext, run **Decrypt Entire Vault** in Settings *before* removing the plugin. If you already removed it, simply re-install MySecret and enter your master password to decrypt.
