# Puente Biométrico MySecret para Cloudflare Pages

[English Version](README.en.md) • **Español**

Esta carpeta contiene la aplicación web estática para habilitar el **desbloqueo por huella dactilar** en Obsidian para Android.

## ¿Cómo desplegarlo gratis en Cloudflare Pages en 1 minuto?

1. Entra a [dash.cloudflare.com](https://dash.cloudflare.com/) (es 100% gratuito, no pide tarjeta de crédito).
2. En el menú lateral, ve a **Workers & Pages** > **Create application** > pestaña **Pages**.
3. Selecciona **Upload assets** (Subir archivos directamente).
4. Dale un nombre a tu proyecto (por ejemplo: `mi-boveda-auth`).
5. Arrastra esta carpeta `auth-bridge/` directamente al navegador y pulsa **Deploy site**.
6. Cloudflare te dará una URL HTTPS gratuita e instantánea, como:
   `https://mi-boveda-auth.pages.dev`
7. Abre Obsidian en tu móvil Android, ve a **Ajustes > MySecret > Desbloqueo Biométrico en Android** y pega tu URL de Cloudflare.

¡Listo! Ya podrás usar tu huella dactilar para desbloquear tu bóveda en Android.
Una vez abierta por primera vez, la web se almacena localmente (PWA offline) y funcionará incluso sin conexión a internet.

---

## ⚠️ IMPORTANTE: Protocolo v2 (actualiza esta carpeta)

La versión **v2** del puente cambia el protocolo criptográfico. Si ya tenías una
versión anterior desplegada, **debes volver a subir esta carpeta** a Cloudflare
Pages: el plugin rechazará un puente con una versión de protocolo distinta.

### Qué cambió y por qué

| Cambio | Motivo |
|---|---|
| **La aserción WebAuthn completa se envía a Obsidian** y su **firma se verifica** contra la clave pública de la credencial | Antes, Obsidian confiaba en el secreto PRF que le entregaba la web. Una web comprometida (o simplemente maliciosa) podía entregar *cualquier* valor y la bóveda se desbloquearía **sin ninguna comprobación biométrica real**. |
| **El desafío (challenge) lo genera Obsidian** | Permite detectar repeticiones de una aserción capturada. |
| **El RP ID y el origen quedan fijados** en el sobre biométrico | Una credencial enrolada en `mi-boveda.pages.dev` no puede usarse desde otro origen. |
| **La clave compartida ECDH pasa por HKDF-SHA256** | NIST SP 800-56A exige un KDF; la coordenada X cruda nunca debe usarse como clave simétrica. |
| **El AAD cifra versión, acción, sesión y bóveda** | Un mensaje capturado no se puede repetir en otro contexto. |
| **El identificador de bóveda nunca sale del plugin** | Solo viaja un *binding* SHA-256 (`vb`) de un solo sentido en el fragmento de la URL; el plugin lo recalcula siempre. |
| **CSP estricta y `Referer: no-referrer`** | Reduce el impacto de una inyección en la página. |
| **El Service Worker versiona la caché** | Un dispositivo nunca sigue usando una versión antigua (más débil) del puente. |

### Nota sobre `pages.dev`

`pages.dev` está en la **Public Suffix List**, por lo que
`https://mi-boveda.pages.dev` es un dominio registrable por sí mismo y cada
proyecto de Cloudflare Pages obtiene su propio RP ID. Por eso una credencial
creada para un proyecto **no** puede ser usada en otro.
