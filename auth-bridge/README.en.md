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

## 🔒 Cryptographic Architecture & Security Guarantees

The biometric bridge implements a hardened authentication architecture engineered to defeat replay, tampering, and impersonation attacks:

| Security Feature | Cryptographic Mechanism & Guarantee |
| :--- | :--- |
| **Full WebAuthn Assertion Verification** | Obsidian cryptographically verifies the signature against the registered credential public key using hardware-backed authenticators. |
| **Obsidian-Generated Single-Use Challenge** | Mitigates replay attacks by validating nonces and timestamps generated inside Obsidian per ceremony. |
| **Pinned RP ID & Registrable Domain** | A credential enrolled on your `pages.dev` project domain cannot be reused from any other origin. |
| **HKDF-SHA256 Key Derivation** | Raw **ECDH P-256** shared secrets pass through HKDF (NIST SP 800-56A) before deriving symmetric session keys. |
| **Strict AAD Binding** | Authenticated data binds the protocol version, action, session ID, and vault token. |
| **One-Way Vault Binding** | The actual vault ID never leaves Obsidian; only a one-way SHA-256 binding (`vb`) is passed in the URL fragment. |
| **Strict CSP & Referrer Policy** | `Content-Security-Policy: default-src 'self'` and `Referrer-Policy: no-referrer` block script injections and data exfiltration. |
| **Subdomain Isolation (`pages.dev`)** | Because `pages.dev` is listed on the *Public Suffix List*, each project operates in an isolated WebAuthn RP ID credential boundary. |

> **Security headers:** the `_headers` file in this folder (applied automatically by Cloudflare Pages) adds `frame-ancestors`/`X-Frame-Options` against clickjacking; those do not work inside a `<meta>` tag. Deploy the whole folder.
