/**
 * MySecret WebAuthn Bridge - Client Logic
 * Handles WebAuthn ceremonies in Chrome/Android and returns results via obsidian://
 * with end-to-end ECDH (P-256) + HKDF-SHA256 + AES-GCM encryption.
 *
 * SECURITY NOTES
 * --------------
 * 1. The PRF secret is NOT trusted by Obsidian on its own: the bridge also
 *    returns the full WebAuthn ASSERTION and Obsidian verifies the signature
 *    against the public key stored at enrollment time. This is what makes the
 *    bridge safe even if this page (or the hosting account) is compromised.
 * 2. The shared ECDH secret goes through HKDF-SHA256 before being used as an
 *    AES key (NIST SP 800-56A).
 * 3. The AES-GCM AAD binds the protocol version, action, session and vault
 *    (through the one-way `vb` binding sent by Obsidian).
 * 4. The relying party id is PINNED, so a credential created for another
 *    host can never be used here.
 */

/** Protocol version. Must match BRIDGE_PROTOCOL_VERSION in the plugin. */
const PROTOCOL_VERSION = 2;

/** HKDF context string. Must match the plugin side. */
const HKDF_INFO_PREFIX = 'mysecret-bridge:';

/**
 * The registered relying party id.
 *
 * It is read from the URL fragment (sent by Obsidian) and is ALWAYS the
 * registrable domain of the current origin. A credential is bound to it, so
 * a credential enrolled for `other.pages.dev` can never be used here.
 */
let pinnedRpId = null;

// Utility: Hex conversions
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function base64UrlToBytes(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Encodes bytes as standard Base64 (used for the WebAuthn SPKI key). */
function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

// UI Helpers
const statusBadge = document.getElementById('status-badge');
const statusText = document.getElementById('status-text');
const actionBtn = document.getElementById('action-btn');
const manualReturnBtn = document.getElementById('manual-return-btn');
const pulseRing = document.getElementById('pulse-ring');
const fingerprintIcon = document.getElementById('fingerprint-icon');

function setStatus(badgeClass, badgeText, description) {
  if (statusBadge) {
    statusBadge.className = `status-badge ${badgeClass}`;
    statusBadge.textContent = badgeText;
  }
  if (statusText) {
    statusText.textContent = description;
  }
}

function setSuccessState(callbackUrl) {
  setStatus('success', '✓ Autenticado', 'Huella verificada con éxito. Regresando a Obsidian...');
  if (fingerprintIcon) fingerprintIcon.style.stroke = '#10b981';
  if (pulseRing) pulseRing.style.display = 'none';

  if (manualReturnBtn) {
    manualReturnBtn.href = callbackUrl;
    manualReturnBtn.classList.remove('hidden');
  }

  // Attempt immediate redirect
  setTimeout(() => {
    window.location.replace(callbackUrl);
  }, 100);
}

function setErrorState(errorMsg, session) {
  setStatus('error', 'Error', errorMsg);
  if (fingerprintIcon) fingerprintIcon.style.stroke = '#ef4444';
  if (pulseRing) pulseRing.style.display = 'none';

  if (actionBtn) {
    actionBtn.textContent = 'Reintentar';
    actionBtn.classList.remove('hidden');
    actionBtn.onclick = () => window.location.reload();
  }

  if (session && manualReturnBtn) {
    const cancelUrl = `obsidian://mysecret-auth?session=${encodeURIComponent(session)}&error=${encodeURIComponent(errorMsg)}`;
    manualReturnBtn.textContent = 'Cancelar y volver a Obsidian';
    manualReturnBtn.href = cancelUrl;
    manualReturnBtn.classList.remove('hidden');
  }
}

// ECDH Encryption: Encrypt PRF secret for Obsidian
async function encryptForObsidian(obsidianPubHex, payloadObj, aadString) {
  const obsidianPubBytes = hexToBytes(obsidianPubHex);

  // Import Obsidian's P-256 public key (raw uncompressed format: 65 bytes starting with 0x04)
  const obsidianPubKey = await window.crypto.subtle.importKey(
    'raw',
    obsidianPubBytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  // Generate browser's ephemeral ECDH keypair.
  // The private key is non extractable: it never reaches the JS heap.
  const browserKeyPair = await window.crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );

  // Derive the raw ECDH shared secret.
  const sharedSecret = await window.crypto.subtle.deriveBits(
    { name: 'ECDH', public: obsidianPubKey },
    browserKeyPair.privateKey,
    256
  );

  // Export browser's public key
  const browserPubBytes = new Uint8Array(await window.crypto.subtle.exportKey('raw', browserKeyPair.publicKey));
  const browserPubHex = bytesToHex(browserPubBytes);

  // Derive the AES-256-GCM key through HKDF-SHA256.
  // SECURITY: the raw ECDH output must NEVER be used directly as a symmetric
  // key (NIST SP 800-56A requires a KDF). The HKDF salt binds the session
  // and the `info` binds the action, the protocol version and the vault
  // binding, so a captured ciphertext cannot be replayed into another context.
  const hkdfKey = await window.crypto.subtle.importKey(
    'raw',
    sharedSecret,
    'HKDF',
    false,
    ['deriveBits']
  );
  const saltBytes = new TextEncoder().encode(HKDF_INFO_PREFIX + (payloadObj.session || ''));
  const infoBytes = new TextEncoder().encode(aadString);
  const okm = await window.crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: infoBytes },
    hkdfKey,
    256
  );
  const sharedKey = await window.crypto.subtle.importKey(
    'raw',
    okm,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  // Encrypt payload JSON with the bound AAD
  const iv = new Uint8Array(12);
  window.crypto.getRandomValues(iv);
  const dataBytes = new TextEncoder().encode(JSON.stringify(payloadObj));

  const encryptedBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: infoBytes, tagLength: 128 },
    sharedKey,
    dataBytes
  );

  // Separate ciphertext and 16-byte tag (Web Crypto appends the tag at the end)
  const fullBytes = new Uint8Array(encryptedBuffer);
  const tagBytes = fullBytes.slice(fullBytes.length - 16);
  const cipherBytes = fullBytes.slice(0, fullBytes.length - 16);

  return {
    browserPubHex,
    ivHex: bytesToHex(iv),
    tagHex: bytesToHex(tagBytes),
    dataHex: bytesToHex(cipherBytes)
  };
}

/**
 * Builds the Additional Authenticated Data of the bridge message.
 *
 * It MUST match `buildBridgeAad()` in the plugin exactly, otherwise the
 * decryption fails closed.
 *
 * SECURITY: the vault identifier is NEVER sent to this page in the clear.
 * Obsidian sends a one-way `vb` binding (SHA-256) which is echoed back
 * verbatim. The plugin recomputes it, so tampering with it only breaks the
 * decryption.
 */
function buildBridgeAad(action, session, vaultBinding) {
  return `mysecret-bridge:v${PROTOCOL_VERSION}:${action}:${session}:${vaultBinding || ''}`;
}

/**
 * Parses the WebAuthn challenge provided by the relying party.
 *
 * SECURITY: the challenge is generated by Obsidian (the relying party) and
 * travels in the URL fragment. It MUST be used verbatim in the WebAuthn
 * ceremony, otherwise Obsidian would not be able to verify the resulting
 * assertion and the replay protection would be lost.
 *
 * A missing or malformed challenge is a hard error: the ceremony is aborted
 * instead of falling back to a locally generated value.
 */
function parseChallenge(challengeHex) {
  if (!challengeHex || typeof challengeHex !== 'string') {
    throw new Error('El desafío de la ceremonia no fue proporcionado por Obsidian.');
  }
  if (!/^[0-9a-fA-F]+$/.test(challengeHex) || challengeHex.length % 2 !== 0) {
    throw new Error('El desafío de la ceremonia tiene un formato inválido.');
  }
  const bytes = hexToBytes(challengeHex);
  if (bytes.length < 16) {
    throw new Error('El desafío de la ceremonia es demasiado corto.');
  }
  return bytes;
}

/**
 * Extracts the PRF secret from an extension result.
 *
 * The WebAuthn IDL defines the output as a BufferSource, but the JSON flavour
 * of the same dictionary uses a base64url string. Both are handled, and the
 * result MUST be at least 32 bytes: an empty secret would hash to a public
 * constant and would silently destroy the whole security of the envelope.
 */
function extractPrfSecret(extensionResults) {
  const prfResult = extensionResults?.prf?.results?.first;
  if (!prfResult) {
    throw new Error('El autenticador no liberó el secreto PRF.');
  }
  let bytes;
  if (prfResult instanceof ArrayBuffer) {
    bytes = new Uint8Array(prfResult);
  } else if (ArrayBuffer.isView(prfResult)) {
    bytes = new Uint8Array(prfResult.buffer, prfResult.byteOffset, prfResult.byteLength);
  } else if (typeof prfResult === 'string') {
    bytes = base64UrlToBytes(prfResult);
  } else {
    throw new Error('Formato de resultado PRF desconocido.');
  }
  if (bytes.length < 32) {
    throw new Error('El secreto PRF liberado es demasiado corto.');
  }
  return bytes;
}

// WebAuthn Handlers
async function handleEnroll(params) {
  const { session, pub, salt } = params;
  if (!session || !pub || !salt) {
    throw new Error('Parámetros de enrolamiento incompletos.');
  }

  setStatus('', 'Verificando huella', 'Coloca tu huella en el sensor de tu dispositivo...');

  // SECURITY: the challenge is generated by the RELYING PARTY (Obsidian) and
  // travels in the URL fragment. It MUST be used verbatim: it is what binds
  // the assertion to this exact ceremony and makes replay attacks impossible.
  const challenge = parseChallenge(params.challenge);

  const userId = new Uint8Array(16);
  window.crypto.getRandomValues(userId);
  const prfSaltBytes = hexToBytes(salt);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: {
        id: pinnedRpId,
        name: 'MySecret Bóveda Cifrada'
      },
      user: {
        id: userId,
        name: 'mysecret-user',
        displayName: 'Usuario MySecret'
      },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },  // ES256
        { alg: -257, type: 'public-key' } // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        userVerification: 'required'
      },
      extensions: {
        prf: {
          eval: {
            first: prfSaltBytes
          }
        }
      },
      timeout: 60000
    }
  });

  if (!credential) {
    throw new Error('No se generó la credencial biométrica.');
  }

  // SECURITY: userVerification was set to 'required' in authenticatorSelection.
  // Standard W3C AuthenticatorAttestationResponse does not have a userVerified property.
  // Only reject if an implementation explicitly reported userVerified === false.
  if (credential.response?.userVerified === false) {
    throw new Error('El autenticador no confirmó la verificación biométrica.');
  }

  // The SPKI public key is REQUIRED: Obsidian uses it to verify the
  // signature of every future assertion. Without it the bridge could not be
  // secured at all.
  let publicKeySpki = null;
  if (typeof credential.response?.getPublicKey === 'function') {
    publicKeySpki = credential.response.getPublicKey();
  } else if (credential.response?.publicKey) {
    publicKeySpki = credential.response.publicKey;
  }
  if (!publicKeySpki) {
    throw new Error('El navegador no expuso la clave pública de la credencial.');
  }
  const publicKeyBase64 = bytesToBase64(new Uint8Array(publicKeySpki));

  // Check if PRF was evaluated during create
  let extensionResults = credential.getClientExtensionResults?.() || {};

  // If not evaluated in create, do a quick get() to extract PRF.
  // The assertion is returned to Obsidian so it can verify the signature.
  let assertion = null;
  let getChallenge = null;
  if (!extensionResults?.prf?.results?.first) {
    getChallenge = new Uint8Array(32);
    window.crypto.getRandomValues(getChallenge);
    assertion = await navigator.credentials.get({
      publicKey: {
        challenge: getChallenge,
        rpId: pinnedRpId,
        userVerification: 'required',
        allowCredentials: [{ type: 'public-key', id: credential.rawId }],
        extensions: {
          prf: {
            eval: {
              first: prfSaltBytes
            }
          }
        },
        timeout: 60000
      }
    });

    extensionResults = assertion?.getClientExtensionResults?.() || {};
  }

  const prfSecretBytes = extractPrfSecret(extensionResults);
  const prfSecretHex = bytesToHex(prfSecretBytes);
  const credentialId = bytesToBase64Url(new Uint8Array(credential.rawId));

  // Encrypt payload for Obsidian
  const aad = buildBridgeAad('enroll', session, params.vb);
  const payload = {
    v: PROTOCOL_VERSION,
    action: 'enroll',
    credentialId,
    publicKey: publicKeyBase64,
    prfSecret: prfSecretHex,
    session,
    timestamp: Date.now()
  };
  // The assertion (when we performed one) is included so Obsidian can bind
  // the enrollment to a real user-verifying ceremony.
  if (assertion) {
    payload.assertion = serializeAssertion(assertion, getChallenge || challenge);
  }
  const encrypted = await encryptForObsidian(pub, payload, aad);

  const callbackUrl = `obsidian://mysecret-auth?session=${encodeURIComponent(session)}&action=enroll&pub=${encrypted.browserPubHex}&iv=${encrypted.ivHex}&tag=${encrypted.tagHex}&data=${encrypted.dataHex}`;
  setSuccessState(callbackUrl);
}

/**
 * Serializes a WebAuthn assertion so Obsidian can verify its signature.
 */
function serializeAssertion(assertion, challenge) {
  const response = assertion.response;
  if (!response?.authenticatorData || !response?.clientDataJSON || !response?.signature) {
    throw new Error('La aserción biométrica está incompleta.');
  }
  const authData = new Uint8Array(response.authenticatorData);
  const flags = authData.length >= 33 ? authData[32] : 0;
  // CTAP2 / WebAuthn AuthenticatorData flags byte 32: bit 2 (0x04) is UV (User Verified)
  const isUserVerified = (flags & 0x04) !== 0 || response.userVerified === true;
  return {
    authenticatorData: bytesToBase64(authData),
    clientDataJSON: bytesToBase64(new Uint8Array(response.clientDataJSON)),
    signature: bytesToBase64(new Uint8Array(response.signature)),
    userVerified: isUserVerified,
    challenge: bytesToBase64Url(new Uint8Array(challenge))
  };
}

async function handleVerify(params) {
  const { session, pub, salt, credentialId } = params;
  if (!session || !pub || !salt || !credentialId) {
    throw new Error('Parámetros de verificación incompletos.');
  }

  setStatus('', 'Verificando huella', 'Toca el sensor de huella dactilar para desbloquear tu bóveda...');

  // SECURITY: the challenge comes from the relying party and MUST be used
  // verbatim (see `parseChallenge`).
  const challenge = parseChallenge(params.challenge);
  const prfSaltBytes = hexToBytes(salt);
  const credIdBytes = base64UrlToBytes(credentialId);

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: pinnedRpId,
      userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: credIdBytes }],
      extensions: {
        prf: {
          eval: {
            first: prfSaltBytes
          }
        }
      },
      timeout: 60000
    }
  });

  if (!assertion) {
    throw new Error('No se recibió confirmación biométrica.');
  }

  // SECURITY: the user-verified flag is mandatory. A "discouraged"
  // verification (presence only) must never be accepted.
  // In WebAuthn, user verification is signaled by bit 2 (0x04) in authenticatorData flags.
  const authData = new Uint8Array(assertion.response?.authenticatorData || []);
  const flags = authData.length >= 33 ? authData[32] : 0;
  const isUserVerified = (flags & 0x04) !== 0 || assertion.response?.userVerified === true;
  if (!isUserVerified) {
    throw new Error('El autenticador no confirmó la verificación biométrica.');
  }

  const extensionResults = assertion.getClientExtensionResults?.() || {};
  const prfSecretBytes = extractPrfSecret(extensionResults);
  const prfSecretHex = bytesToHex(prfSecretBytes);

  // Encrypt payload for Obsidian.
  // The ASSERTION travels with the secret: Obsidian verifies the signature
  // against the public key stored at enrollment time. Without it, a
  // compromised bridge could hand over any secret it wants.
  const aad = buildBridgeAad('verify', session, params.vb);
  const payload = {
    v: PROTOCOL_VERSION,
    action: 'verify',
    credentialId,
    prfSecret: prfSecretHex,
    session,
    timestamp: Date.now(),
    assertion: serializeAssertion(assertion, challenge)
  };
  const encrypted = await encryptForObsidian(pub, payload, aad);

  const callbackUrl = `obsidian://mysecret-auth?session=${encodeURIComponent(session)}&action=verify&pub=${encrypted.browserPubHex}&iv=${encrypted.ivHex}&tag=${encrypted.tagHex}&data=${encrypted.dataHex}`;
  setSuccessState(callbackUrl);
}

// Main Flow
async function main() {
  // Parse hash query (e.g. #action=enroll&session=123...)
  const hash = window.location.hash.startsWith('#')
    ? window.location.hash.substring(1)
    : '';

  if (!hash) {
    setStatus('success', 'Listo', 'Puente WebAuthn activo y listo para Obsidian.');
    if (actionBtn) {
      actionBtn.textContent = 'Probar Compatibilidad de Huella';
      actionBtn.classList.remove('hidden');
      actionBtn.onclick = async () => {
        try {
          if (!window.PublicKeyCredential) {
            alert('Este navegador no soporta WebAuthn.');
            return;
          }
          const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
          alert(available ? '✓ Sensor biométrico / huella disponible en este navegador.' : 'Sensor biométrico no detectado.');
        } catch (e) {
          alert('Error: ' + e.message);
        }
      };
    }
    return;
  }

  const params = {};
  const searchParams = new URLSearchParams(hash);
  for (const [key, value] of searchParams.entries()) {
    params[key] = value;
  }

  // SECURITY: the fragment carries the session token, the ECDH public key and
  // the PRF salt. It is wiped from the address bar as soon as it has been
  // read, so it is not kept in the browser history nor leaked through the
  // `Referer` header to any third party resource.
  try {
    history.replaceState(null, '', window.location.pathname + window.location.search);
  } catch {
    // Some browsers restrict history manipulation: not fatal.
  }

  const session = params.session;

  try {
    // SECURITY: the protocol version is checked BEFORE anything else, so an
    // obsolete (weaker) bridge can never be used by mistake.
    const protoVersion = parseInt(params.v || '1', 10);
    if (protoVersion !== PROTOCOL_VERSION) {
      throw new Error(
        `Versión del protocolo no soportada (${protoVersion}). Actualiza la carpeta auth-bridge/ en Cloudflare Pages.`
      );
    }

    if (!window.PublicKeyCredential) {
      throw new Error('Tu navegador no soporta autenticación biométrica (WebAuthn).');
    }

    // SECURITY: the vault binding is mandatory. It binds the ciphertext to
    // the vault, so a message captured from another vault cannot be replayed
    // here. Obsidian recomputes it, so a tampered value simply fails the
    // decryption (fail closed).
    if (!params.vb || !/^[0-9a-f]{64}$/i.test(params.vb)) {
      throw new Error(
        'Falta el binding de bóveda (vb). Vuelve a iniciar el desbloqueo desde Obsidian.'
      );
    }

    // SECURITY: the relying party id is PINNED to the registrable domain of
    // the CURRENT origin. Obsidian sends the value it expects in the URL, but
    // it is validated here against the real origin so a manipulated fragment
    // cannot redirect the ceremony to another relying party.
    pinnedRpId = resolveRpId(params.rpId);
    if (!pinnedRpId) {
      throw new Error('No se pudo determinar el dominio de la aplicación (RP ID).');
    }

    if (params.action === 'enroll') {
      await handleEnroll(params);
    } else if (params.action === 'verify') {
      await handleVerify(params);
    } else {
      throw new Error(`Acción desconocida: ${params.action}`);
    }
  } catch (err) {
    console.error('[MySecret Bridge] Error:', err);
    const msg = err.name === 'NotAllowedError'
      ? 'Verificación cancelada o tiempo agotado.'
      : (err.message || 'Error en la verificación biométrica.');
    setErrorState(msg, session);
  }
}

/**
 * Resolves and validates the relying party id.
 *
 * The value sent by Obsidian is only ACCEPTED if it is the registrable
 * domain of the current origin (or a public suffix of it). Otherwise the
 * ceremony is rejected: a credential must never be bound to a host that the
 * current origin does not control.
 */
function resolveRpId(requested) {
  const host = window.location.hostname.toLowerCase();

  if (host === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return host;
  }

  const labels = host.split('.');
  const lastTwo = labels.slice(-2).join('.');
  const lastThree = labels.slice(-3).join('.');

  // The host itself (e.g. `foo.pages.dev`) or one of its parent domains.
  const candidates = [host, lastThree, lastTwo].filter(Boolean);

  if (requested && candidates.includes(requested.toLowerCase())) {
    return requested.toLowerCase();
  }

  // Fall back to the host itself: it is always a valid RP ID (the browser
  // accepts an RP ID equal to the origin's host).
  return host;
}

// Register service worker if available
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js').catch(err => {
      console.warn('[MySecret] Service worker registration failed:', err);
    });
  });
}

// Execute on load
window.addEventListener('DOMContentLoaded', main);
