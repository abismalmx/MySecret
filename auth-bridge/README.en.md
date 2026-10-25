# MySecret Biometric Bridge for Cloudflare Pages

**English** • [Versión en Español](README.md)

This folder contains the standalone static Web application (PWA) to enable **fingerprint and facial biometric unlocking** in Obsidian for Android.

---

## 🚀 How to deploy for free on Cloudflare Pages in 1 minute

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com/) (100% free, no credit card required).
2. In the sidebar menu, navigate to **Workers & Pages** > **Create application** > **Pages** tab.
3. Select **Upload assets** (Direct upload).
4. Enter a project name (for example: `my-vault-auth`).
5. Drag and drop this `auth-bridge/` folder directly onto the browser and click **Deploy site**.
6. Cloudflare will instantly provide a free HTTPS URL, such as:
   `https://my-vault-auth.pages.dev`
7. Open Obsidian on your Android mobile device, go to **Settings > MySecret > Android Biometric Unlock**, and paste your Cloudflare Pages URL.

That's it! You can now use your biometric sensor to unlock your encrypted vault on Android.  
Once opened for the first time, the Web app is locally cached via its Service Worker (offline PWA) and operates seamlessly even without an Internet connection.

---

## ⚠️ Protocol v2 Notice

The bridge uses **Protocol v2** with enhanced cryptographic guarantees. If you had a previous version deployed, **re-upload this folder** to Cloudflare Pages; the plugin requires matching protocol versions.

### Cryptographic Guarantees (Protocol v2)

| Security Feature | Cryptographic Mechanism |
|---|---|
| **Full WebAuthn Assertion Verification** | Obsidian verifies the signature against the credential's public key using hardware-backed authenticators. |
| **Obsidian-Generated Single-Use Challenge** | Mitigates replay attacks by validating timestamps and nonces generated inside Obsidian. |
| **Pinned RP ID & Registrable Domain** | A credential enrolled on `my-vault.pages.dev` cannot be reused from any other origin. |
| **HKDF-SHA256 Key Derivation** | ECDH P-256 raw shared secrets pass through HKDF before deriving AES-GCM session keys. |
| **Strict AAD Binding** | Authenticated data binds the protocol version, action, session ID, and vault token. |
| **One-Way Vault Binding** | The actual vault ID never leaves the plugin; only a one-way SHA-256 binding (`vb`) is passed in the URL fragment. |
| **Strict CSP & Referrer Policy** | `Content-Security-Policy: default-src 'self'` and `no-referrer` prevent injection or data exfiltration. |
| **Cache Versioning** | The Service Worker enforces versioned cache invalidation. |

---

### Note on `pages.dev`

`pages.dev` is listed on the **Public Suffix List**, meaning each `your-project.pages.dev` domain is its own independent registrable domain with an isolated WebAuthn RP ID credential boundary.
