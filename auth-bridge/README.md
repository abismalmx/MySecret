# Puente Biométrico Móvil MySecret para Cloudflare Pages

[English Version](README.en.md) • **Español**

Esta carpeta contiene la aplicación web estática (PWA) para habilitar el **desbloqueo por huella dactilar, Face ID y Touch ID** en Obsidian para **dispositivos móviles (Android e iOS / iPhone / iPad)**.

---

## 🚀 ¿Cómo desplegarlo gratis en Cloudflare Pages en 1 minuto?

1. Entra a [dash.cloudflare.com](https://dash.cloudflare.com/) (es 100% gratuito, no pide tarjeta de crédito).
2. En el menú lateral, ve a **Workers & Pages** > **Create application** > pestaña **Pages**.
3. Selecciona **Upload assets** (Subir archivos directamente).
4. Dale un nombre a tu proyecto (por ejemplo: `mi-boveda-auth`).
5. Arrastra esta carpeta `auth-bridge/` directamente al navegador y pulsa **Deploy site**.
6. Cloudflare te dará una URL HTTPS gratuita e instantánea, como:
   `https://mi-boveda-auth.pages.dev`
7. Abre Obsidian en tu móvil (Android o iPhone), ve a **Ajustes > MySecret > Desbloqueo Biométrico Móvil** y pega tu URL de Cloudflare.

¡Listo! Ya podrás usar tu huella dactilar o Face ID para desbloquear tu bóveda en tu teléfono o tableta.  
Una vez abierta por primera vez, la web se almacena localmente (PWA offline) mediante su Service Worker y funcionará incluso sin conexión a internet.

---

## 🔒 Arquitectura y Garantías Criptográficas de Seguridad

El puente biométrico implementa una arquitectura de autenticación de alta seguridad diseñada específicamente para mitigar ataques de repetición, suplantación y manipulación:

| Componente de Seguridad | Mecanismo y Garantía Criptográfica |
| :--- | :--- |
| **Verificación Completa de Aserción WebAuthn** | Obsidian valida criptográficamente la firma contra la clave pública de la credencial registrada utilizando autenticadores respaldados por hardware. |
| **Desafío Dinámico de Uso Único (Challenge)** | Obsidian genera un desafío criptográfico con marca de tiempo única por cada sesión, neutralizando ataques de repetición. |
| **Anclaje Estricto de Dominio y RP ID** | El RP ID y el origen quedan fijados en el contenedor biométrico; una credencial enrolada en tu dominio no puede ser utilizada desde ningún otro origen. |
| **Derivación de Clave HKDF-SHA256** | El secreto compartido obtenido por intercambio de curvas elípticas **ECDH P-256** se procesa con HKDF (NIST SP 800-56A) antes de derivar la clave simétrica de sesión. |
| **Enlace de Datos Autenticados (AAD)** | El AAD vincula la versión del protocolo, la acción solicitada, el identificador de sesión y el token de la bóveda. |
| **Anonimización del Identificador de Bóveda** | El ID real de la bóveda nunca sale de Obsidian; solo viaja un enlace unidireccional SHA-256 (`vb`) en el fragmento de la URL. |
| **CSP Estricta y Política de Referrer** | La política `Content-Security-Policy: default-src 'self'` y `Referrer-Policy: no-referrer` bloquea inyecciones de scripts y exfiltración de datos. |
| **Aislamiento por Subdominio (`pages.dev`)** | Al estar `pages.dev` en la *Public Suffix List*, cada proyecto obtiene un límite de seguridad y credencial WebAuthn completamente aislado. |

> **Cabeceras de seguridad:** el archivo `_headers` de esta carpeta (Cloudflare Pages lo aplica solo) añade `frame-ancestors`/`X-Frame-Options` contra clickjacking; esos valores no funcionan dentro de un `<meta>`. Despliega la carpeta completa.
