# MySecret — User Manual

**English** • [Versión en Español](USER_GUIDE.es.md)

> [!IMPORTANT]
> ### ⚠️ Read this before installing anything
> MySecret **really encrypts** the files in your vault. If you lose the master password **and** the 24 recovery words, your notes are gone **forever**: there is no recovery email, no "unlock" button, and no support team that can help you. That is why the very first thing we ask of you is a **backup copy** of your vault. Two minutes of work, and it saves everything.

---

## 📖 How to read this manual

This manual is written so that **anyone** can understand it, not just technical readers. Therefore:

- Every section opens with **"In one sentence"**: what you will achieve.
- Technical words always come with a **plain-language translation**. If you need the rigorous version, they are in the [Glossary](#3-glossary-the-words-you-will-see-in-the-settings).
- If something can go wrong, there is a warning. If it can go wrong **irrecoverably**, it is flagged as such.

**Choose your path:**

| Are you…? | Start at… | ⏱️ |
| :--- | :--- | :---: |
| 👤 A regular user who just wants to encrypt their notes | [4. Before you start](#4-before-you-start-the-installation-checklist) | 15 min |
| 🔄 Migrating an existing vault full of notes | [11. Migration and maintenance](#11-migration-and-maintenance-of-your-vault) | 20 min |
| 😰 Locked out and need to recover | [12. Disaster recovery](#12-disaster-recovery) | 5 min |
| 📱 On mobile and want fingerprint unlock | [9. Biometric unlock](#9-unlock-with-fingerprint-face-id-and-touch-id) | 20 min |
| 🧠 Curious about the "why" under the hood | [2. How it works](#2-how-it-works-under-the-hood-explained-without-jargon) | 15 min |

---

## 📑 Table of Contents

**PART I — Understand**
1. [What MySecret really is (no jargon)](#1-what-mysecret-really-is-no-jargon)
2. [How it works under the hood (explained without jargon)](#2-how-it-works-under-the-hood-explained-without-jargon)
3. [Glossary: the words you will see in the settings](#3-glossary-the-words-you-will-see-in-the-settings)

**PART II — Install and start**
4. [Before you start: the installation checklist](#4-before-you-start-the-installation-checklist)
5. [Installing the plugin (step by step)](#5-installing-the-plugin-step-by-step)
6. [The initial setup wizard](#6-the-initial-setup-wizard-step-by-step)
7. [Your first day: using the vault day to day](#7-your-first-day-using-the-vault-day-to-day)

**PART III — Configure**
8. [Every setting, explained section by section](#8-every-setting-explained-section-by-section)
9. [Unlock with fingerprint, Face ID and Touch ID](#9-unlock-with-fingerprint-face-id-and-touch-id)

**PART IV — Protect and recover**
10. [Backups and cloud storage](#10-backups-and-cloud-storage)
11. [Migration and maintenance of your vault](#11-migration-and-maintenance-of-your-vault)
12. [Disaster recovery](#12-disaster-recovery)
13. [Decrypting your notes without the plugin or Obsidian](#13-decrypting-your-notes-without-the-plugin-or-obsidian)

**PART V — Reference**
14. [Frequently asked questions](#14-frequently-asked-questions-faq)
15. [Troubleshooting](#15-troubleshooting)
16. [Final security checklist](#16-final-security-checklist)

---

## 1. What MySecret really is (no jargon)

**In one sentence:** MySecret turns your notes folder into a safe: inside Obsidian you keep seeing and using your notes exactly as before, but on disk there is only unreadable code.

### The one-way mirror analogy

Imagine a window you can see through from inside, but from the outside it looks like a mirror. MySecret sits between Obsidian and your hard drive:

| From inside Obsidian | From the outside (disk, cloud, a thief with your laptop) |
| :--- | :--- |
| You write, edit, search | Only mathematical noise |
| Global search finds any phrase | No cloud provider can read anything |
| The knowledge graph works | A stolen note is unreadable |
| Images display normally | Attachments are encrypted too |

### What IS encrypted

- ✅ The text of all your notes (`.md`).
- ✅ The **frontmatter** (the YAML metadata at the top of a note: tags, aliases, properties).
- ✅ Obsidian **canvas** files (`.canvas`).
- ✅ **Every attachment**: images, PDFs, audio, video, any binary file.
- ✅ The ZIP backups the plugin generates.

### What is NOT encrypted (and why that is fine)

- ⚠️ **File and folder names.** This is not an oversight: Obsidian needs to read those names to keep its index, search, backlinks and file tree working. If they were encrypted, Obsidian would break. Your *content* is 100% encrypted.
- ⚠️ **The system folders** `.obsidian/`, `.git/` and `.trash/`. These are application settings, not your notes. (This is also why `vault-envelope.json` lives there: it is the "safe" holding your wrapped key.)
- ⚠️ **A hidden file at the vault root** such as `.DS_Store` or `.gitignore`. However, **a hidden note inside a folder IS encrypted** (e.g. `Notes/.private.md`).

### What MySecret is NOT

To avoid misunderstandings:

- ❌ **Not an antivirus.** It does not block malware.
- ❌ **Not a password manager.** It protects notes, not accounts.
- ❌ **It does not encrypt your whole disk.** Only your Obsidian vault.
- ❌ **It does not upload anything on its own.** The only optional network connection is the mobile biometric bridge, and it is one-way (you reach out to the bridge; the bridge never sees your notes).
---

## 2. How it works under the hood (explained without jargon)

> If you just want to use the plugin, you can skip this section. But reading it will save you surprises and let you make better decisions (when to enable auto-lock, whether a recovery phrase is worth it, and so on).

### 2.1 The key to the safe

There is exactly one key that opens and closes everything: the **vault key** (called *VaultKey*), a random 256-bit number generated on your own device.

That key is stored "wrapped" (encrypted) inside a file called **`vault-envelope.json`** (the "envelope"), which lives at:

```
<your-vault>/.obsidian/plugins/mysecret/vault-envelope.json
```

And the envelope is itself encrypted with a key derived from **one of two things**:

- Your **master password**, processed with **Argon2id** (64 MB of memory, 3 iterations).
- Your **24 recovery words**, processed with PBKDF2-HMAC-SHA512 (2048 iterations).

> **Practical consequence:** if you have neither the password nor the words, the envelope cannot be opened. There is no shortcut, no backdoor, no "magic" recovery. That is why the wizard asks you to generate a recovery phrase: it is your second way in.

MySecret also keeps a `.bak` copy of the envelope (`vault-envelope.json.bak`) and writes it atomically: first to a temporary file, reads it back to verify it is correct, saves the previous version, and only then replaces the original. So a failure halfway through a write **cannot** leave you without a key.

### 2.2 What happens when you save a note

1. You write your note in Obsidian.
2. Obsidian asks to save the file to disk.
3. **MySecret intercepts the request before it reaches the disk** and encrypts the content with **AES-256-GCM**.
4. On your disk, what remains is a container like this:

   ```markdown
   -----BEGIN MYSECRET ENCRYPTED FILE-----
   Version: 1
   IV: d8f3a9e1b2c4d5e6f7a8b9c0
   Tag: 4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d

   q8XyZ1v...[Encrypted content in Base64]...==
   -----END MYSECRET ENCRYPTED FILE-----
   ```

5. When you open the note, the reverse happens: MySecret decrypts **in memory** and Obsidian never sees the ciphertext.

**Attachments** (images, PDFs, audio) are stored in a compact binary format: 4 magic bytes `MYSE`, one version byte, the 12-byte initialization vector (IV) and the 16-byte authentication tag (Tag), followed by the encrypted content.

### 2.3 The four words that matter

| Word | What it means in your day-to-day life |
| :--- | :--- |
| **AES-256-GCM** | The lock itself. The same standard banking apps use. |
| **IV** | A random number that differs on every save. It stops two identical notes from producing identical files. |
| **Tag** | The "signature" that proves nobody tampered with the content. If someone edits a single byte, the file stops opening. |
| **AAD (authenticated data)** | The file's **path inside the vault** is signed together with the content. If someone manually renames "Note.md" to "Secret.md", the file stops decrypting. It stops anyone swapping, tampering with or stealing individual files. |

> ℹ️ The AAD also means something good in daily use: **you can rename and move notes normally inside Obsidian**. MySecret detects the rename and re-signs the file for its new path. It would only fail if someone renamed the file **outside Obsidian**, directly in the file explorer.

### 2.4 Why search and the graph still work

MySecret does not "open" your notes: it **decrypts in memory** while the vault is unlocked. To Obsidian, your notes are ordinary notes, so global search, the quick switcher, backlinks, the graph view and canvases all work normally.

The moment you lock the vault:
- The key is wiped from RAM (overwritten with zeros, not merely "the pointer is dropped").
- Open notes are closed and the plaintext Obsidian had cached is discarded.
- The screen is covered by a blurred veil so nothing behind it is visible.

> 🔐 This protects against casual access (someone opens your laptop, or a search in Obsidian's history). It is not protection against a debugger with administrator rights, and the plugin's own security documentation says so with complete honesty.
---

### 2.5 What happens when you sync

The files on disk are standard encrypted text, so **Obsidian Sync, Git, Dropbox, iCloud, Syncthing, OneDrive…** simply copy them without being able to read them.

One technical detail that affects you daily: MySecret aligns the "hash" Obsidian Sync uses to detect changes so that the hash being compared is the one of the **ciphertext** (the same as the cloud's). Without this alignment, Obsidian Sync would think every file changed on every launch, re-downloading and re-writing your entire vault over and over.

### 2.6 Guards you will never see (but that protect you)

| Guard | What it prevents |
| :--- | :--- |
| **Anti-double-encryption** | An already-encrypted file being encrypted a second time and becoming unrecoverable. |
| **Argon2id anti-downgrade** | Someone editing the envelope to lower the cost parameters and turn a slow derivation into an instant one. If the parameters are too low, the plugin **rejects** the envelope instead of accepting it. |
| **Envelope limits** | A tampered envelope asking for 4 GB of memory and freezing the app. |
| **Publish blocking** | If **Obsidian Publish** is enabled, MySecret blocks uploading encrypted notes in cleartext to a public website. You get a 15-second notice explaining why. |
| **Authenticated restore** | When restoring a ZIP, every entry is judged by its **actual content**, not by what its own manifest claims. Ciphertext must authenticate with *this* vault's key and *this* path. |
| **Anti-ZIP Slip / anti-ZIP bomb** | A malicious ZIP writing files outside your vault or exhausting memory. |
| **Re-authentication for sensitive actions** | Viewing, changing or deleting the recovery phrase, enrolling biometrics, or exporting in plaintext **ask for the master password again**, even if the vault is already unlocked. An open vault is not enough. |

- ❌ **It does not protect against someone watching your screen.** It is at-rest encryption, not protection from eyes.

## 3. Glossary: the words you will see in the settings

If the interface ever throws a strange word at you, look it up here.

| Technical word | What it means, in plain language |
| :--- | :--- |
| **Encryption** | Turning your text into a code that only the right key can read. |
| **Transparent encryption** | Encrypting without you noticing: you use Obsidian as usual, the encryption happens in the background. |
| **At-rest encryption** | Encryption that happens when the file sits on disk (not while you are reading it). |
| **Key** | The "secret" that opens and closes the lock. |
| **Master password** | Your master password. The main key to your vault. |
| **Vault key (VaultKey)** | The actual key that encrypts your notes. Generated randomly on your device and never written in cleartext. |
| **Envelope** | The `vault-envelope.json` file holding your wrapped vault key. Think of it as the safe that contains the key. |
| **Argon2id** | The algorithm that turns your password into a key. It is designed to make trying millions of passwords extremely expensive. |
| **Salt** | A random number added to your password before deriving the key, so two users with the same password get different keys. |
| **AES-256-GCM** | The algorithm that encrypts your file contents. A worldwide standard, hardware accelerated. |
| **IV (initialization vector)** | A different random value on every encryption, so two identical files do not look alike. |
| **Tag** | The signature that detects whether an encrypted file was modified. |
| **AAD** | The file path, signed together with the content. Stops someone stealing a file and moving it elsewhere. |
| **BIP-39** | The standard behind the 24 recovery words. The same one cryptocurrency wallets use, which is why so much software understands it. |
| **Recovery phrase / mnemonic** | Your 24 words. The second key to your vault. |
| **RAM** | Your computer's working memory. The keys live there while the vault is open. |
| **Zeroization** | Overwriting the key with zeros so no trace is left in memory. |
| **WebAuthn** | The browser (and mobile) standard for authenticating with a fingerprint, face or physical security key. |
| **Bridge** | The small web app that bridges Obsidian on mobile and the phone's biometric sensor. |
| **ECDH** | The key exchange that lets the bridge and Obsidian talk without either handing over its secret. |
| **PWA** | "Progressive Web App": a website that behaves like an app and can be installed on your phone. The bridge is a PWA. |
| **Frontmatter** | The YAML block at the top of a note (tags, aliases). MySecret encrypts it too. |
| **Obsidian Publish** | Obsidian's paid plugin that publishes notes to a public website. MySecret blocks publishing encrypted notes. |
| **BRAT** | An Obsidian plugin that installs other plugins straight from their GitHub repository. |
| **HMAC / SHA-256 / SHA-512** | "Digital hashing" functions: they turn any data into a short, unique fingerprint. |

---

## 4. Before you start: the installation checklist

**In one sentence:** four steps, fifteen minutes, and your vault is protected.

> [!WARNING]
> ### ⚠️ Step 0 (mandatory): copy your vault BEFORE touching anything
> MySecret is going to encrypt the **real** files on your disk. Before installing:
>
> 1. Close Obsidian.
> 2. Copy the **entire** vault folder somewhere else: an external drive, a USB stick, or your cloud.
> 3. Check the copy actually worked (open a couple of notes from the copy).
>
> **Why is it mandatory?** Because if you later lose the password **and** the 24 words, there is no way to recover the files. It is the only insurance policy that exists. Making the copy takes 2 minutes; losing years of notes has no price.

### The 4-step checklist

- [ ] **1.** I closed Obsidian and copied my vault somewhere else.
- [ ] **2.** I installed the plugin (two ways, in [section 5](#5-installing-the-plugin-step-by-step)).
- [ ] **3.** I completed the setup wizard and **wrote the 24 words on paper**.
- [ ] **4.** I confirmed I can unlock the vault and that my notes look right.

> 💡 **Tip:** keep the backup in a **different** place than the disk your vault lives on. If your laptop dies, you would otherwise lose the vault and its backup together. An external drive, a USB stick in a drawer or your personal cloud all work.

### Requirements

| Requirement | Detail |
| :--- | :--- |
| **Obsidian** | Version 1.5.0 or later. |
| **Operating system** | Windows, macOS, Linux, Android or iOS/iPadOS. |
| **Disk space** | The same you use now, plus the size of your notes once encrypted (practically identical). |
| **Internet** | Only to download the plugin (BRAT) or the mobile biometric bridge. **Encryption itself works 100% offline.** |
| **Browser** | Only if you plan to use the browser-based emergency decryptor ([section 13](#13-decrypting-your-notes-without-the-plugin-or-obsidian)). |

---

## 5. Installing the plugin (step by step)

**In one sentence:** there are two routes; both are free.

### Method A: BRAT (recommended, self-updating)

BRAT installs other plugins straight from GitHub and notifies you about new versions. It is the most convenient way to keep MySecret up to date.

1. In Obsidian, go to **Settings → Community plugins** and turn off **Restricted mode**.
2. Search for **BRAT**, install it and enable it.
3. Go to **Settings → BRAT** and click **Add Beta plugin**.
4. Paste this address:
   ```
   https://github.com/abismalmx/MySecret
   ```
5. Click **Add Plugin** and wait for the download to finish.
6. Go to **Settings → Community plugins**, find **MySecret** and **enable it**.
7. Restart Obsidian (or use **Reload app without saving** from the command palette).

> ℹ️ With this method BRAT tells you automatically when a new version is out. Install it and restart Obsidian.

### Method B: manual installation (without BRAT)

1. Go to the [Releases](https://github.com/abismalmx/MySecret/releases) page on GitHub.
2. Download **these three files** from the latest release:
   - `main.js`
   - `manifest.json`

### How do I know it worked?

The first time you enable the plugin, MySecret does **not** encrypt anything yet. It simply opens the **setup wizard** ([section 6](#6-the-initial-setup-wizard-step-by-step)) so you can choose your master password. Until you finish that wizard, your vault is still plain text.

> 🔐 **What if I already have notes?** Existing notes are **not** encrypted automatically. At the end of the wizard you will find a **"🔒 Encrypt existing notes now"** button. You can also do it later from **Settings → MySecret → Bulk File Maintenance → Encrypt Entire Vault**. Details are in [section 11](#11-migration-and-maintenance-of-your-vault).

---

## 6. The initial setup wizard (step by step)

**In one sentence:** four screens, two minutes, and your vault is protected for good.

The wizard appears **automatically** the first time you enable MySecret in a vault. You cannot dismiss it with `Esc` on purpose: that is a safety net so it is never cut short halfway through initialization.

```
┌───────────────────────────────────────────────────────────────┐
│  1. Password & mode  →  2. Recovery phrase  →                │
│  3. Verification      →  4. Fingerprint                       │
└───────────────────────────────────────────────────────────────┘
```

### Step 1 — Master password and recovery mode

You type your master password twice. The second field is only to confirm you know it by heart.

**Password rules:**
- Minimum **12 characters**.
- The strength meter reports a score in **bits** (how much entropy your password has). Above **80 bits** is very strong.
- The wizard **rejects** weak passwords: it will not let you continue with something made of repeated lowercase letters or runs like `abcdef`.

**💡 How to invent a password you can actually remember:**
Use 4 or 5 unrelated words joined by a separator. For example:
```
coral-galaxy-timber-panther-beacon
```
Five words, 30 characters, easy for you to remember and **impossible** for an attacker to guess. This technique is called a "passphrase" and it is what security experts recommend today.

**You also choose one of two recovery modes:**

| Mode | What happens | Who is it for? |
| :--- | :--- | :--- |
| 🔑 **24-word recovery phrase** *(recommended)* | A second key is generated and stored encrypted. If you forget the password, the 24 words save you. | Most people. |
| 🛡️ **Master password only** *(maximum security)* | **No backup key is stored on disk at all.** If you forget the password, the loss is permanent. | Only if you are in a very controlled environment and have a verified copy elsewhere. |

> ⚠️ If you pick "password only", the only way to recover your vault would be an external decryptor that **already has** your recovery phrase… which in this mode does not exist. In other words: no password, no way back. Since you are reading this: choose the recovery phrase mode.

### Step 2 — Your 24 recovery words

MySecret generates 256 bits of cryptographic entropy and renders them as 24 words from a standard list (BIP-39). You will see them as numbered cards.

**What to do:**

1. **Copy** the phrase with the **"📋 Copy phrase"** button (the clipboard clears itself after 30 seconds so your secret does not linger there).
2. **Write it on paper.** Seriously: paper. It is the safest medium there is.
3. If you would rather nobody watch you while you copy, hit **"🙈 Hide words"**.
4. Click **"I saved my phrase →"** once you have written it down.

> [!IMPORTANT]
> **The phrase will NOT be shown again the same way.** The plugin keeps it in memory **only for the current session**, and only in case you close the wizard without writing it down. As soon as you lock the vault, it disappears from RAM.
>
> And if you lose it anyway? There is a way out: from **Settings → MySecret → Password & Recovery Management → View recovery phrase** you can display it again (it asks for your master password first). If you have already locked the vault, your phrase is no longer in memory and **cannot be regenerated**: you would have to create a brand-new vault.

**Where to keep it (best to worst):**
- 🥇 A safe, a padlocked notebook, or your password manager (which usually encrypts with a key derived from your password).
- 🥈 A sealed envelope at home, in a dry and safe place.
- 🥉 A card in your wallet.
- ❌ **Never**: on the same disk as the vault, in a note inside the vault itself, in a text file in the cloud, or in a chat.

> 💡 **Trick to never lose it:** if the vault is on your phone and the phrase is on your laptop, a failure in either one locks you out. The ideal is **two copies in different places**, and one of them **outside your home**.

### Step 3 — The verification challenge

To confirm you wrote it down correctly, MySecret asks for **two random words** from your phrase (for example #6 and #18).

- Get them right → a green ✓ **"Backup verified successfully"**.
- Get one wrong → the field turns red and you can retry.

> ℹ️ This does **not** protect your vault: it only checks that the phrase was written down properly. If you get it wrong you can still continue (the continue button appears either way); it is simply worth making sure before you move on, because this is your only safety net.
---
**Here the "🔒 Encrypt existing notes now" button appears** if your vault already had notes. Pressing it starts encrypting everything it finds (thousands of files, takes a while). If you skip it now, you can do it later from the settings.

### Step 4 — Quick unlock with fingerprint (optional)

MySecret checks whether your device has a biometric sensor available and offers to enrol it.

- **If you have a sensor** (Windows Hello, Touch ID, a Linux fingerprint reader, or a mobile device with the bridge configured): enrol it now. It is convenient and saves you typing your password every time.
- **If you have no sensor, or would rather not**: skip it. You can enrol later from the settings.
- When you finish, your vault is **unlocked** and ready to use.

### What if the wizard fails?

MySecret writes the key to disk **before** unlocking it in memory. If something goes wrong mid-process, your vault is **not** left half-initialized: either it initializes correctly, or it does not initialize at all.

If you see this notice when opening Obsidian:

> *vault-envelope.json exists but is corrupted or has been modified. A new vault will not be created.*

**Do not do anything drastic.** MySecret refuses to create a new vault precisely so it does not invalidate your already-encrypted notes. Restore the `vault-envelope.json` file (or its `.bak`) from your backup and open Obsidian again.

   - `styles.css`
3. Open your Obsidian vault folder and go into `.obsidian/plugins/`.
   - 💡 On Windows and macOS, dot-prefixed folders are hidden: press **⌘/Ctrl + Shift + .** (macOS) or **Ctrl + H** (Windows) to reveal them.
4. Create a folder named **`mysecret`** and put the three files inside:
5. In Obsidian, go to **Settings → Community plugins**, reload the list and enable **MySecret**.
6. Restart Obsidian.

   ```
   <your-vault>/.obsidian/plugins/mysecret/
   ├── main.js
   ├── manifest.json
   └── styles.css
   ```

## 7. Your first day: using the vault day to day

**In one sentence:** from here on, MySecret disappears. You write, search and work exactly as before.

### Unlocking your vault

Every time you open Obsidian with an encrypted vault:

1. MySecret's **lock screen** appears. You cannot close it with `Esc` or click around it: that is deliberate.
2. Type your **master password** and click **Unlock Vault**.
   - It takes a moment (around 240 ms) because it has to "stir" your password with Argon2id. You will see **"Deriving key…"** and then **"Decrypting…"**. This is normal, and it is the proof that the encryption is strong.
   - If you get it wrong, you will see **"Invalid master password"** and the card will shake. Try again.
3. If you have biometrics enabled, you can also click the **"Unlock with Fingerprint"** button.
4. The screen disappears and Obsidian works normally.

### The padlock icon (your status indicator)

In Obsidian's **left ribbon** there is a MySecret padlock icon. That is your indicator:

| Icon | Meaning | On click |
| :--- | :--- | :--- |
| 🔴 **Red padlock** | Vault **locked**. Nothing can be read. | Opens the unlock screen. |
| 🟢 **Green padlock** | Vault **unlocked**. Everything running. | **Locks** the vault instantly. |

> 💡 **Tip:** clicking the green padlock is the quickest way to "shut down" when you leave. The keyboard route is the **command palette** (`Ctrl+P` / `Cmd+P`) → **MySecret: Lock vault now**.

### The commands available to you

Open the command palette (`Ctrl+P` on Windows/Linux, `Cmd+P` on macOS) and type **MySecret** to see them all:

| Command | What it does |
| :--- | :--- |
| **MySecret: Lock vault now** | Locks instantly and wipes the keys from RAM. |
| **MySecret: Unlock vault** | Opens the unlock screen (if the vault is locked). |
| **MySecret: Change master password** | Changes your password. See [section 12](#12-disaster-recovery). |
| **MySecret: Export vault backup (ZIP)** | Creates a `.zip` with your notes. See [section 10](#10-backups-and-cloud-storage). |
| **MySecret: Configure cloud backup** | Sets up Google Drive, OneDrive, WebDAV or a local folder. |
| **MySecret: Restore vault backup (ZIP)** | Recovers your notes from a backup `.zip`. |
| **MySecret: Encrypt Entire Vault** | Bulk-encrypts any notes still in plain text. |

### Auto-lock: letting it lock itself

This is the feature that will give you the most peace of mind. If you walk away from your desk and leave the laptop open, MySecret locks the vault on its own.

1. Go to **Settings → MySecret → Protection & Auto-Lock**.
2. Under **Auto-lock on inactivity**, choose the time: **Disabled**, 1 minute, 5 minutes (recommended), 15 minutes or 30 minutes.
3. Turn on **"Lock when minimised or window loses focus"** if you want it to lock the moment you switch applications.
4. Click **Save**.

> ℹ️ MySecret counts anything as "activity": moving the mouse, typing, touching the screen, pressing a key. The timer resets itself with every movement.

> 💡 **Practical recommendation:** 5 minutes of inactivity plus lock-on-window-change. That is the usual balance between security and convenience.

### What the disk looks like (so you do not panic)

If you open your vault with the system file browser or a text editor, this is what you will see:

**Your notes (`.md`)** are text containers:

```markdown
-----BEGIN MYSECRET ENCRYPTED FILE-----
Version: 1
IV: d8f3a9e1b2c4d5e6f7a8b9c0
Tag: 4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d

q8XyZ1v...[Encrypted content in Base64]...==
-----END MYSECRET ENCRYPTED FILE-----
```

**Your attachments** (images, PDFs, audio) are binaries starting with the magic bytes `MYSE`, followed by the version, the IV and the Tag.

**Your filenames** stay readable (so Obsidian keeps working), but the **content** is noise.

> 💡 **A quick way to convince yourself:** open a note in Windows Notepad and then open the same file in a text editor. In Obsidian you read your note; in the editor you only see the encrypted container. That is the proof that it works.

## 8. Every setting, explained section by section

**In one sentence:** everything you can change in MySecret is here, and we explain what each one does.

Go to **Settings → MySecret**. There are eight blocks. Here they are in the order you will find them.

### 8.1 Protection & Auto-Lock

| Setting | What it does | Recommendation |
| :--- | :--- | :--- |
| **Auto-lock on inactivity** | Locks the vault after X minutes of inactivity and wipes the keys from RAM. | **5 minutes** |
| **Lock when minimised or window loses focus** | Locks as soon as you minimise Obsidian or switch applications. | **Turn it on** |
| **Encrypt attachments (images, audio and documents)** | When ON, images, PDFs, audio and video are encrypted too. When OFF, **only** text notes are encrypted. | **Leave it ON** |

> ⚠️ **About turning attachment encryption off:** it is the only "less secure" option in the plugin, and it has a catch. When you turn it off, MySecret **converts already-encrypted attachments back to plain text** (otherwise the next save would corrupt them). In other words: you turn off attachment encryption → your images and PDFs end up **in cleartext on disk**. Use it only if an external tool (a script, a viewer) must read your images without decrypting.

> 💡 **Why auto-lock matters:** without it, if you unlock the vault and walk away without closing Obsidian, the keys sit in RAM all day. With a 5-minute auto-lock, your vault closes itself. That is the difference between "encrypted when I close the program" and "always encrypted".

### 8.2 Biometric Unlock & Fingerprint

Here you configure fingerprint, Face ID or Touch ID unlock. It is covered in detail in [section 9](#9-unlock-with-fingerprint-face-id-and-touch-id).

Summary of the options:

- **Unlock with fingerprint / Face ID on this device**: the main switch. Turning it on makes MySecret **ask for your master password again** (it is a sensitive action) and enrols your biometric.
- **Auto-prompt fingerprint when locking**: when ON, the sensor is invoked as soon as the lock screen appears, without you pressing anything.
- **Test fingerprint now**: verifies the sensor and the key work, without locking anything.
- **Remove biometric enrolment**: deletes the biometric data **from this device**.

> ℹ️ **Important detail:** biometrics are enrolled **per device**. Your laptop, your phone and your tablet each have their own record. Deleting the record on one leaves the others working.

### 8.3 Folders Excluded from Encryption

This section lets you say: "do **not** encrypt these folders".

**What is it for?** For folders whose content other apps need to read:
- Public notes you want to publish on your website.
- Folders shared with a sync tool that does not understand encryption.
- Files you open with an external program (a Markdown editor, a PDF viewer).

**How to add a folder:**
1. Click **"Select folder…"** and browse for it, or
2. Type the path by hand (for example `Public` or `Notes/Shared`) and click **Add**.
3. You can also **right-click any folder in Obsidian's file explorer** and choose **"MySecret: Exclude folder from encryption"**. To encrypt it again, do the same and pick **"Remove from excluded folders (Encrypt)"**.

> ⚠️ **What this really means:** an excluded folder stays **in plain text on your disk**, with no encryption at all. If you put something very sensitive there, you are leaving a hole. Use it with care.

> ℹ️ MySecret already excludes **on its own**, without any action from you, the `.obsidian/`, `.git/` and `.trash/` folders, plus hidden files at the vault root (`.DS_Store`, `.gitignore`). You do not need to add them to the list.

### 8.4 Password & Recovery Management

| Button | What it does |
| :--- | :--- |
| **Change Password** | Opens the dialog to change your master password. It asks for the **current** one and the new one. |
| **Show Phrase** | Displays your 24 words again. It asks for your master password first. |
| **Delete Recovery Phrase** | Erases the backup key from disk. Asks for confirmation. |
| **Enable Recovery Phrase** | (If you had none) Generates a new 24-word phrase and stores it. |

> ⚠️ **Deleting the recovery phrase is irreversible**: from that moment on your master password is the **only** way to open the vault. MySecret warns you explicitly before doing it.

> ℹ️ **Enabling the phrase later is a good idea** if you started in "password only" mode. You can do it any time from these same settings.

**Your attachments** (images, PDFs, audio) are binaries starting with the magic bytes `MYSE`, followed by the version, the IV and the Tag.

**Your filenames** stay readable (so Obsidian keeps working), but the **content** is noise.

> 💡 **A quick way to convince yourself:** open a note in Windows Notepad and then open the same file in a text editor. In Obsidian you read your note; in the editor you only see the encrypted container. That is the proof that it works.

---

### 8.5 Cloud Backups

Configures where your automatic backups are uploaded. Covered in detail in [section 10](#10-backups-and-cloud-storage).

| Setting | Detail |
| :--- | :--- |
| **Storage Provider** | None, Google Drive, Microsoft OneDrive, WebDAV (Nextcloud/ownCloud/Synology) or a synced local folder. |
| **Token / credentials** | Stored **encrypted** on your disk with your vault key. They are masked on screen. |
| **Test Connection** | Verifies the credentials work before you rely on them. |
| **Automatic backup** | Turns automatic uploads on. |
| **When to generate the copy** | When locking the vault, on a regular interval, or both. |
| **Frequency** | Every 1, 6, 12, 24 (recommended) or 72 hours. |

### 8.6 Backup Export & Restore

| Button | What it does |
| :--- | :--- |
| **Export to ZIP** | Creates a local `.zip` with your notes. You can choose **encrypted** or **plain text**. |
| **Upload to Cloud Now** | Builds the backup and uploads it to your configured provider in one go. |
| **Restore Backup** | Recovers your notes from a `.zip`. |

> ⚠️ **About the "plain text" mode:** it is useful (for migrating to another app, for instance), but it means **the ZIP contains your notes unencrypted**. Treat it like a confidential document and delete it as soon as you no longer need it.

### 8.7 Bulk File Maintenance

| Button | What it does |
| :--- | :--- |
| **🔒 Encrypt Entire Vault** | Scans the vault and encrypts everything still in plain text. |
| **🔓 Decrypt Entire Vault** | **WARNING:** returns every file to plain text. Use it only if you are about to uninstall the plugin. |

> ⚠️ **"Decrypt Entire Vault" leaves your notes in cleartext on disk.** If you press it by mistake and then close Obsidian, your notes are unprotected. Details in [section 11](#11-migration-and-maintenance-of-your-vault).

### 8.8 Language (plugin interface language)

MySecret has its own language section, **at the end of the settings**, and it works **independently** of Obsidian's language.

- **Auto (Follow Obsidian)**: follows Obsidian's language. *Note: it only affects the settings tab; the lock screen and the wizard use their own texts.*
- **English / Español / Русский / 简体中文**: pins the plugin interface language.

> 💡 If your Obsidian is in English but the plugin shows Spanish (or the other way round), come to this section and pick the one you want. Changes apply instantly.

---

## 9. Unlock with fingerprint, Face ID and Touch ID

**In one sentence:** unlock your vault with your finger or your face, without typing your password.

### The idea in 30 seconds

Your master password remains the **real** key. Biometrics only serve to **prove who you are** quickly, and the plugin uses that proof to unlock the key it already keeps on your device.

> 🔐 **Reassuring fact:** your fingerprint **never leaves your device**. Your phone or laptop's sensor verifies it inside its own security chip (Apple Secure Enclave, Google Titan, TrustZone…). Neither the plugin, nor Obsidian, nor the Cloudflare bridge receive your fingerprint: they receive a cryptographic confirmation that it was validated.

### 9.1 Setup order by platform

| Platform | Needs internet? | Needs anything else installed? |
| :--- | :--- | :--- |
| **Windows** (Windows Hello) | ❌ No | No |
| **macOS** (Touch ID / Apple Watch) | ❌ No | No |
| **Linux** (fingerprint via `fprintd`) | ❌ No | You must have a fingerprint already enrolled in the OS |
| **Android / iOS / iPadOS** | ⚠️ Only the **first** time (when opening the bridge) | Yes: a web bridge on Cloudflare Pages |

### 9.2 Windows (Windows Hello)

**Supports:** fingerprint readers, infrared cameras with face recognition, or your Windows Hello PIN.

1. Make sure **Windows Hello is enabled** in Windows Settings (Settings → Accounts → Sign-in options).
2. In Obsidian: **Settings → MySecret → Biometric Unlock & Fingerprint**.
3. Turn on **"Unlock with fingerprint / Face ID on this device"**.
4. Confirm your **master password** (MySecret always asks for it on sensitive actions).
5. Touch your sensor when prompted.

**Do I need a Cloudflare URL?** **NO.** Everything is native and local.

### 9.3 macOS (Touch ID)

**Supports:** Touch ID on MacBooks, Magic Keyboard with Touch ID, and Apple Watch unlocking.

1. In Obsidian: **Settings → MySecret → Biometric Unlock & Fingerprint**.
2. Turn on the switch and confirm your master password.

### 9.4 Linux (fingerprint via `fprintd`)

**Supports:** fingerprint readers configured with `fprintd` (the standard Linux service) and `SecretService`.

1. In a terminal, enrol your fingerprint in the system (usually `fprintd-enroll`; the exact name varies by distribution).
2. In Obsidian: **Settings → MySecret → Biometric Unlock & Fingerprint**.
3. Turn on the switch and confirm your master password.

**Do I need a Cloudflare URL?** **NO.** Works 100% locally.

> ⚠️ **Real requirement:** there must be an **enrolled and working** fingerprint reader. MySecret checks this before offering the option: if there is only a system keyring but no sensor, it will not let you enrol a "biometric" that in reality verifies nothing.

### 9.5 Android, iPhone and iPad (the Cloudflare Pages bridge)

**In one sentence:** on mobile, Obsidian cannot talk to your fingerprint sensor directly, so we use a small website that acts as an intermediary.

**Why is it needed?** Obsidian on mobile runs inside an isolated container (a *WebView*). For security reasons, iOS and Android **block** apps from using the biometric sensor directly from there. The solution is to open the **phone's browser** (Chrome or Safari), which *can* use the native sensor, and have it hand the confirmation back to Obsidian.

**Step 1 — Deploy your bridge (free, one click, no card):**

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com/) (free, and it **does not ask for a credit card**).
2. In the sidebar: **Workers & Pages → Create application → Pages**.
3. The **Upload assets** tab (direct upload).
4. Give your project a name, for example `my-vault-auth`.
5. Drag the **`auth-bridge/`** folder from the MySecret repository straight into the browser and click **Deploy site**.
6. Cloudflare gives you an HTTPS address like `https://my-vault-auth.pages.dev`.

> 💡 **Deploy the `auth-bridge/` folder COMPLETE.** The `_headers` file inside it is what enables the anti-clickjacking security headers. If you upload only some files, that protection is not applied.

**Step 2 — Configure Obsidian on your phone:**

1. On your phone, open Obsidian and go to **Settings → MySecret → Mobile Biometric Unlock**.
2. Paste your Cloudflare URL into the text field.
3. Tap **Test URL** to verify the connection.
4. Turn on the biometric unlock switch.
5. Do your **first enrolment**: tap the fingerprint button, the browser opens, and *there* it asks for your fingerprint or Face ID.

**Step 3 — Daily use:**

When the vault is locked, tap **Unlock with Fingerprint**. The browser opens for a moment, validates your fingerprint and returns automatically to Obsidian with the session key already agreed.

> 🔒 **Does Cloudflare see my data?** **No.** The session data travels in the URL fragment (the part starting with `#`), which browsers **never send** to the server. Cloudflare receives zero data from your vault. On top of that, the response is encrypted with an ephemeral session key (ECDH P-256 + AES-256-GCM) known only to your phone and Obsidian. Your real vault identifier does not travel either: only a one-way SHA-256 hash.

> 📴 **Does it work without internet?** **Yes**, most of the time. The bridge is a PWA with a *Service Worker*: the first time you open the URL it is stored on your phone and works afterwards in airplane mode.

> ⚠️ **A note about bridge URLs:** only `https://` addresses or `http://localhost` are accepted; anything else is rejected. And because the bridge lives on `pages.dev` (which is on the public suffix list), every project gets its own isolation: a credential enrolled on your bridge **does not** work on someone else's.

---
3. macOS handles the authentication for you through its native API.

## 10. Backups and cloud storage

**In one sentence:** encryption protects your notes from other people's eyes; backups protect you from **you** losing the disk.

> 💡 **These are two different things and you need both.** Encryption says "nobody else reads this". A backup says "you do not lose this". MySecret gives you both, but you have to configure the backup yourself.

### 10.1 Creating a manual backup (local ZIP)

1. Open the command palette (`Ctrl+P` / `Cmd+P`).
2. Run **MySecret: Export vault backup (ZIP)**.
3. Choose **Encrypted mode** (identical to what is on your disk) or **Decrypted mode** (plain text, readable in any editor).
4. You can choose whether to include the attachments and whether to include the `vault-envelope.json` (tick it if you want the ZIP to be **self-sufficient**: with it, an external decryptor can open the file without needing your vault's envelope).
5. Choose the destination folder.

> ⚠️ **Decrypted mode** creates a ZIP with your notes **in plain text**. Use it only if you have a clear reason (migrating to another program, for example) and delete the file as soon as you no longer need it.

### 10.2 Restoring from a ZIP

1. Run **MySecret: Restore vault backup (ZIP)**.
2. Select the `.zip` file.
3. Type the **master password** (or the phrase, if the ZIP was exported decrypted... in that case no password is needed: the content is taken as-is and MySecret encrypts it on the way in).
4. MySecret **overwrites** files that have the same path. It warns you about this before starting.

> 🔐 **Restore safety:** every entry in the ZIP is judged by its **actual content**, not by what its own manifest claims. Ciphertext must authenticate with *this* vault's key and *this* path; plain text is encrypted on the way in. The engine also blocks **path traversal** attempts (writing outside the vault) and **ZIP bombs** (decompressing too much). Files that cannot be included **are not dropped silently**: you are told.

### 10.3 Automatic cloud backups

Go to **Settings → MySecret → Cloud Backups** and pick a provider:

| Provider | Who it is for | What you need |
| :--- | :--- | :--- |
| **Google Drive** | You already have a Google account | An access token and, optionally, the destination folder ID |
| **Microsoft OneDrive** | You use Microsoft 365 / OneDrive | An access token and the folder path |
| **WebDAV** (Nextcloud, ownCloud, Synology NAS, pCloud) | You run your own server | URL, username, password or app password, and remote path |
| **Synced local folder** | You already have Dropbox, MEGA or Google Drive *Desktop* installed | The absolute path of the folder on your disk |

**The recommended flow:**

1. Pick the provider and fill in its details.
2. Click **Test Connection** until you see ✅.
3. Turn on **Automatic backup**.
4. Choose **When to generate the copy**:
   - **When locking the vault** ← the most useful (a copy every time you leave).
   - **On a regular interval** (every 1, 6, 12, 24 or 72 hours).
   - **Both** ← recommended.
5. Choose the **frequency**.
6. Click **Save Backup Configuration**.

## 11. Migration and maintenance of your vault

**In one sentence:** if your vault already had notes, this is where you turn them into ciphertext (or back into plain text if you are leaving).

### 11.1 Encrypting a vault that already has notes

**When you need it:** you installed MySecret on a vault with years of notes, or the setup wizard offered the **"🔒 Encrypt existing notes now"** button and you skipped it.

**From the settings:**
1. Go to **Settings → MySecret → Bulk File Maintenance**.
2. Click **🔒 Encrypt Entire Vault**.
3. A window opens with:
   - A **pre-flight count** of how many files are about to be encrypted.
   - A **live progress bar** with a counter of processed files.
   - An **emergency stop button** in case you want to cancel.
4. When it finishes you will see **"Operation completed successfully"**.

> 💡 **Let it run.** Encrypting a large vault (thousands of notes with attachments) can take several minutes. MySecret goes file by file, so you can watch the progress and barely notice the difference in daily use.

> ℹ️ **Only the files that should be encrypted are.** Excluded folders and system files are skipped, and files that are **already encrypted** are not encrypted again (MySecret recognises the format and leaves them alone).

### 11.2 Decrypting the entire vault (clean uninstall)

> [!WARNING]
> ### ⚠️ This leaves your notes in plain text on disk
> Use it **only** if you are about to uninstall MySecret. When it finishes, your notes are ordinary Markdown files, readable by anyone who gets access to your disk or your cloud.

1. Go to **Settings → MySecret → Bulk File Maintenance**.
2. Click **🔓 Decrypt Entire Vault** (the button is marked in red).
3. Check the count, confirm and wait for it to finish.

**The correct order to uninstall is this:**
1. Unlock the vault.
2. Run **Decrypt Entire Vault** and wait for it to finish.
3. Now that your notes are plain text, **disable or uninstall** the plugin.
4. Optionally delete the `.obsidian/plugins/mysecret/` folder.

> ⚠️ **If you uninstall the plugin while the vault is encrypted, your notes stay encrypted.** They are not lost, but Obsidian (and any other program) will see them as gibberish. The fix: reinstall MySecret, unlock with your password, and run **Decrypt Entire Vault**.

### 11.3 Migration summary table

| From → to | How | With what |
| :--- | :--- | :--- |
| Plain text → Encrypted | Settings → Maintenance → Encrypt Entire Vault | Master password (vault unlocked) |
| Encrypted → Plain text | Settings → Maintenance → Decrypt Entire Vault | Master password (vault unlocked) |
| Encrypted → Another vault | Export encrypted ZIP → Restore into the new one | Master password + `vault-envelope.json` in the ZIP |
| Another app → MySecret | Install → Wizard → Encrypt Entire Vault | Master password |

---
> 🔐 **Your cloud credentials are never stored in cleartext.** They are encrypted with your vault key before being written to the settings file. They are masked in the interface.

> 💡 **About retention:** MySecret automatically removes old copies that exceed the configured limit (5 by default). It only removes files whose name matches **exactly** the pattern `MySecret_<vault>_Cifrado_<date>.zip` and **only** those belonging to your own vault. On Google Drive and OneDrive they are moved to the **Trash**, not permanently deleted.

> ⚠️ **Special case for the "on lock" backup:** MySecret keeps the key in memory until the ZIP has finished being built, and warns you if any file could not be packaged. It does not interrupt the lock because of one problematic file.

---
**Do I need a Cloudflare URL?** **NO.** Works 100% locally.

## 12. Disaster recovery

**In one sentence:** this is what you do on the day you have lost access.

### 12.1 I forgot my master password

**If you have your 24 words:**

1. On the lock screen, click **"Forgot your password? / Use recovery phrase"**.
2. Type the 24 words **separated by a single space**, in the **same order** you wrote them down.
3. The **"X / 24 words"** counter helps you avoid mistakes.
4. Click **Recover with Phrase**.
5. MySecret regenerates your vault key and asks you to **set a new master password**.
6. **All your notes remain intact.** Nothing is re-encrypted: what changes is how the key is unlocked.

> ℹ️ If the plugin notices you just recovered with the phrase, it shows a notice: *"🔓 Vault recovered. We recommend changing the master password in Settings."* Do exactly that.

**If you do NOT have a recovery phrase** (you chose "password only"): **there is no possible recovery.** Your files are mathematically out of reach. This is not a plugin bug: it is exactly what "no escape hatch" means.

### 12.2 I forgot my password and have the phrase, but it does not work

| Symptom | Likely cause | Solution |
| :--- | :--- | :--- |
| "The recovery phrase is not valid" | Spelling, order, or words that are not in the BIP-39 list | Go word by word. The 24 words must be **exactly** the standard ones (English, lowercase). |
| "Must have 24 words (you entered N)" | Words missing or extra | Count them. Remember: a single space separator. |
| It counts 24 but still fails | Accents or non-standard characters | The plugin lowercases for you, but it does **not** accept accents. Use the words exactly as they are, without accents. |

### 12.3 Changing your master password

1. Unlock the vault.
2. Command palette → **MySecret: Change master password** (or **Settings → MySecret → Change Password**).
3. MySecret asks for the **current password** (a 2-minute re-authentication window) and then the new one, twice.
4. The new one must be **at least 12 characters** and pass the strength meter.
5. In seconds, the envelope is re-encrypted with a new salt. **Your notes are not rewritten on disk.**

> [!WARNING]
> **Important: changing the password does NOT rotate the vault key.**
> Anyone who keeps an old copy of `vault-envelope.json` (your cloud history, an old backup) **together with the previous password** can still decrypt your notes. Changing the password protects against someone *guessing* it; it does not protect against someone who already has a copy of your encrypted data.
>
> If you believe your old password **leaked** (more serious than "it was guessed"), the only clean solution is: export your notes in plain text, create a brand-new vault with a new password, and migrate the content.

> ℹ️ **Your biometrics keep working.** MySecret keeps a stable vault identifier precisely so that changing the password does not invalidate your fingerprint.

### 12.4 I lost the device that held my vault

Nothing serious happens:

- Your notes are encrypted on disk and in the cloud. Whoever has the device **cannot read them** without your password or phrase.
- If you had biometrics enabled, the biometric record **does not work on another device**: it is bound to the hardware and to this specific vault.
- Reinstall MySecret on another machine, unlock with your password or phrase, and carry on.
- **Change the password** if the device was your main laptop and you worry someone might use it.

---
## 13. Decrypting your notes without the plugin or Obsidian

**In one sentence:** you are never trapped inside MySecret. Because it uses open standards (AES-256-GCM, Argon2id, BIP-39), anyone with your words can recover your notes.

This is probably the **most important** feature of the plugin from a freedom-of-data point of view: MySecret is not a closed, proprietary format. Your notes are files that any standard tool can read.

All three tools live in the **`tools/`** folder of the repository.

### Method 1 — From any browser (100% offline)

Nothing to install. Ideal for recovering **a single note or attachment**.

1. Double-click [`tools/offline-decryptor.html`](tools/offline-decryptor.html) to open it in your browser (Chrome, Firefox, Safari or Edge).
   - 💡 You can open it **offline**: the page loads nothing from the internet (a strict security policy forbids it).
2. Open `.obsidian/plugins/mysecret/vault-envelope.json` with a text editor and **paste its whole content** into the first field.
3. Type your **24-word recovery phrase** in the second field.
4. Type the **exact path** the file had inside the vault (for example `Notes/Journal.md`).
   - ⚠️ The path is part of the authenticated data: if it is wrong, it **fails on purpose**. That is a protection, not a bug.
5. Paste the encrypted note (it starts with `-----BEGIN MYSECRET ENCRYPTED FILE-----`) **or** pick the encrypted attachment with the file button.
6. Click **Decrypt Now**. The plain text appears below and you can save it.

> ⚠️ Vaults created **without** a recovery phrase ("password only" mode) **cannot** use this page: use Method 2 with `--password`.

### Method 2 — With the Python script (the whole vault at once)

To decrypt hundreds of notes and images in a single pass.

1. Install the dependencies:
   ```bash
   pip install cryptography argon2-cffi
   ```
   (`argon2-cffi` is only needed if you use `--password`.)

2. Decrypt the whole vault with your **recovery phrase**:
   ```bash
   python tools/standalone-decryptor.py --vault "/path/to/vault" --mnemonic "word1 word2 ... word24" --output "/path/to/decrypted_vault"
   ```

3. Or with your **master password** (leave it valueless so it prompts you and **does not stay in your shell history**):
   ```bash
   python tools/standalone-decryptor.py --vault "/path/to/vault" --password --output "/path/to/decrypted_vault"
   ```

4. The script rebuilds the complete folder tree with all notes and attachments in plain text.
   - ⚠️ The output folder must be **outside** the vault.
   - For a single file: `--file note.md --relative-path "Notes/note.md"`.

> ℹ️ The tool reads `.obsidian/plugins/mysecret/vault-envelope.json` automatically. If yours is elsewhere, use `--envelope`.

### Method 3 — With CyberChef (web, nothing to install)

For those who want to see the process step by step:

1. Open [CyberChef](https://gchq.github.io/CyberChef/) (the web tool from the *GCHQ*, the British intelligence agency).
2. Add the **AES Decrypt** operation and set the mode to **GCM**.
3. Provide the **derived key** (32 bytes), the **IV** (12 bytes) and, in the **Additional Authenticated Data (AAD)** field, the file path (for example `Notes/Ideas.md`).
4. Paste the encrypted content (the Base64 part between the `-----BEGIN...` and `-----END...` lines).

> ℹ️ It is the slowest and most manual method. It is useful for independently verifying that your data really is encrypted, or for understanding the process.

---

## 14. Frequently asked questions (FAQ)

#### Q: Are note titles and file names encrypted?

**R:** No, and that is on purpose. Obsidian needs to read those names to keep its index, search, backlinks and file tree working. If they were encrypted, Obsidian would break. **All content** (text, frontmatter, canvases, attachments) is 100% encrypted.

#### Q: Does MySecret work with Obsidian Sync, Git or cloud sync?

**R:** Yes! Because the files on disk are standard text files with encrypted content, services like Obsidian Sync, Git, Dropbox, iCloud or Syncthing simply sync the safe containers. No cloud provider can read your notes. On top of that, MySecret aligns the Obsidian Sync hash so it does not re-download your whole vault on every launch.

#### Q: What happens if I uninstall the plugin?

**R:** If you uninstall the plugin while your files are encrypted, they **stay encrypted on disk**. To return them to plain text, run **Decrypt Entire Vault** before removing the plugin. If you already removed it, reinstall MySecret, enter your master password, and run Decrypt Entire Vault.

#### Q: Does the plugin work without an internet connection?

**R:** Yes, 100%. All encryption happens on your device. You only need internet to download the plugin and, on mobile, for the first load of the biometric bridge.

#### Q: Can I have an encrypted vault on several devices?

**R:** Yes. Sync the `vault-envelope.json` envelope along with the rest (it lives inside `.obsidian/plugins/mysecret/`, which some sync setups exclude by default: make sure it is included). On each device you enter the password or the phrase. Biometrics, on the other hand, must be enrolled **on each device separately**.

#### Q: Can the plugin developer spy on me?

**R:** No. The architecture is **zero-knowledge**: your vault key is generated on your device with the system random number generator and never leaves it. The source code is public and audited: there is not a single network call in the encryption path.

#### Q: What if I lose both the password and the 24 words?

**R:** Your notes are lost **permanently and irrecoverably**. There is no server, no recovery email and no customer service that can save you. That is why the wizard insists so much on the recovery phrase and on the backup beforehand.

#### Q: Does changing the password re-encrypt my notes?

**R:** No. Changing the password re-encrypts **the key stored in the envelope**, but your notes stay encrypted with the same vault key. It is instant and touches none of your files. If you believe your password **leaked** (more serious than "it was guessed"), you need to export in plain text and create a new vault.

#### Q: Can I use Obsidian Publish?

**R:** Yes, but MySecret **blocks** publishing encrypted notes, because doing so would upload your cleartext to a public website. If you want to publish, decrypt the vault first or exclude that note from publication.

#### Q: What if I use Obsidian Sync and sometimes cannot unlock?

**R:** Keep in mind that the `vault-envelope.json` envelope **is not encrypted** (it is the "envelope" holding your encrypted key: its content is metadata, not your notes). If a sync service uploads it to the cloud, whoever downloads it sees only an encrypted blob. Even so, add `.obsidian/plugins/mysecret/` to your `.gitignore` if you use Git and would rather not commit that file.

## 15. Troubleshooting

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| **"vault-envelope.json exists but is corrupted or has been modified"** | The envelope got corrupted or edited | **Do not delete anything.** Restore `vault-envelope.json` (or `vault-envelope.json.bak`) from your backup. MySecret refuses to create a new vault on purpose, so it does not invalidate your notes. |
| **"Invalid master password"** | Typo | Check capitals, a different keyboard layout and the caps lock. |
| **"The recovery phrase is not valid"** | Mistake in the words | Check there are 24, in order, lowercase and **without accents**. |
| **"Too many failed attempts. Wait Ns"** | Brute-force rate limit | Wait. The plugin applies a cooldown to slow down guessing attacks. |
| **The padlock is red and nothing opens** | Vault is locked | Click the red padlock in the left ribbon, or run **MySecret: Unlock vault**. |
| **A note says it cannot be decrypted** | The path changed outside Obsidian | Rename the file **inside Obsidian** so MySecret re-signs the path, or undo the change in the file explorer. |
| **Images do not show in reading view** | Attachment setting, or the vault is locked | Unlock the vault. If it persists, check **Encrypt attachments** in the settings. |
| **"The envelope could not be saved" / "disk full"** | No space to write the envelope | Free up space. MySecret **does not** overwrite the previous version until the new one is verified, so a failed write cannot cost you the key. |
| **The biometric bridge does not return to Obsidian** | The browser blocked the automatic redirect | The bridge shows a green **"Return to the App"** button. Tap it. |
| **"Biometrics not available or not configured"** | No sensor enrolled in the OS | Enrol your fingerprint in the operating system settings (Windows Hello, Touch ID, `fprintd-enroll`) and enrol the biometric again in MySecret. |
| **Obsidian Sync downloads the whole vault every time** | Hash misalignment | MySecret fixes this automatically. If it persists, disable and re-enable MySecret once: the patch is reinstalled on load. |
| **The plugin does not appear in the community list** | Restricted mode is on | Go to **Settings → Community plugins** and turn off restricted mode. |

---

## 16. Final security checklist

**In one sentence:** tick these six boxes and your vault is in a solid state.

- [ ] **I made an unencrypted backup** of my vault, on a disk or cloud **different** from the vault's own.
- [ ] **I wrote the 24 recovery words on paper** and stored them outside the vault. (Ideally: **two** copies, one outside the home.)
- [ ] **My master password is 12+ characters** and strong (ideally a 4-5 word passphrase).
- [ ] **Auto-lock on inactivity is on** (5 minutes is a good value) and **lock on window change** too.
- [ ] **Attachment encryption is on**, so images and PDFs are not left in cleartext.
- [ ] **Automatic cloud backup is configured and tested** (I clicked "Test Connection" and got ✅).

### Bonus: improve your security posture

- [ ] I reviewed the **Excluded Folders** section and made sure nothing sensitive was accidentally left out of encryption.
- [ ] I tried **decrypting a note with the browser decryptor** ([method 1](#method-1--from-any-browser-100-offline)), so I know I can recover my data if the plugin ever stops existing.
- [ ] I configured **biometrics** on my everyday devices, so the master password is used as little as possible.
- [ ] If I use **Obsidian Publish**, I made sure my public notes live in an **excluded folder**.

---

## 📚 Related documents

| Document | Who it is for |
| :--- | :--- |
| [README.md](README.md) | Plugin overview, comparison with other tools and the demo video. |
| [SECURITY.md](SECURITY.md) | Security architecture and the attack vectors it mitigates. |
| [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) | Technical documentation for contributing to the code. |
| [COMPARISON.md](COMPARISON.md) | MySecret versus Cryptomator, VeraCrypt, Meld Encrypt and Obsidian Sync. |
| [auth-bridge/README.en.md](auth-bridge/README.en.md) | Technical details of the biometric bridge for Cloudflare Pages. |

---

> **MySecret** · Public, auditable source code · Non-commercial licence.
> The privacy it offers is mathematically verifiable: you do not have to take our word for it, you can read the code.

#### Q: Does MySecret slow Obsidian down?

**R:** Encrypting a note takes between 1 and 5 milliseconds. It is imperceptible. What takes a little longer is the **unlock** (around 240 ms), because Argon2id is deliberately slow: that slowness is exactly what makes trying passwords so expensive for an attacker.

#### Q: Does it work with databases or external wikis?

**R:** MySecret encrypts **files in your vault**. If you use an app that stores its data in a database inside the vault, check the attachment behaviour in [section 8.1](#81-protection--auto-lock) and exclude that folder if needed.

---
