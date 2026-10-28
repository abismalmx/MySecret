<div align="center">

<img src="logo.webp" alt="Logo de MySecret" width="160" height="160" style="border-radius: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.15);" />

# MySecret — Cifrado Transparente de Bóveda para Obsidian

[![Obsidian](https://img.shields.io/badge/Obsidian-v1.0.0+-7C3AED?logo=obsidian&logoColor=white)](https://obsidian.md)
[![Pruebas](https://img.shields.io/badge/Pruebas-60k%2B%20l%C3%ADneas%20%7C%20Pasando-success?logo=githubactions&logoColor=white)](tests/)
[![Seguridad](https://img.shields.io/badge/Seguridad-Blindada%20y%20Zero--Trust-brightgreen?logo=shield&logoColor=white)](SECURITY.es.md)
[![Obsidian Sync](https://img.shields.io/badge/Obsidian%20Sync-100%25%20Compatible-blue?logo=icloud&logoColor=white)](#-por-qu%C3%A9-mysecret-juega-en-otra-liga)
[![Licencia](https://img.shields.io/badge/Licencia-No--Comercial-lightgrey.svg)](LICENSE)

**Tu bóveda sabe tus secretos. Asegúrate de que solo tú los conozcas.**  
*Cifrado transparente de conocimiento cero en reposo para Obsidian, sin romper la búsqueda, el grafo ni la sincronización.*

**[📖 Manual de Usuario](USER_GUIDE.es.md)** • **[💻 Guía de Desarrollo](DEVELOPER_GUIDE.es.md)** • **[🛡️ Arquitectura de Seguridad](SECURITY.es.md)** • **[⚖️ Comparativa](COMPARISON.es.md)**  
*(**Español** • [English Version](README.md))*

</div>

---

### 📽️ Presentación Diapositivas / Slide Deck

> 📊 **Explora la Presentación de Arquitectura y Características:**
> - 🇬🇧 **[Presentación en Inglés (Por defecto)](media/MySecret_Presentation_en.pdf)**
> - 🇪🇸 **[Presentación en Español](media/MySecret_Presentation_es.pdf)**

---

## 🌟 Descripción General

**MySecret** es un plugin de seguridad y privacidad para [Obsidian](https://obsidian.md) que cifra automáticamente cada archivo de tu bóveda — notas, lienzos y archivos adjuntos (imágenes, PDFs, audios, vídeos) — en el instante en que los escribe al disco.

Actúa como un **cristal unidireccional** entre Obsidian y tu disco duro: desde dentro de Obsidian ves todo con claridad total — búsqueda global, grafo de conocimiento, enlaces, Canvas. Desde fuera — desde el disco, desde tu servicio de nube, desde el ladrón que abrió tu portátil — solo hay ruido matemático. Nada legible.

Las claves criptográficas existen únicamente en la memoria RAM de tu dispositivo mientras la bóveda está abierta. Ni el desarrollador del plugin puede leer tus notas.

---

## 🎬 Demostración en Video y Guía Interactiva

Explora la arquitectura técnica y las guías interactivas impulsadas por Google NotebookLM:

| 🇬🇧 Recursos en Inglés | 🇪🇸 Recursos en Español |
| :---: | :---: |
| 🧠 [**Ver Video en NotebookLM**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/ef0d6ffc-dc85-48e2-b52d-11fdbaf5e533) | 🧠 [**Ver Video en NotebookLM**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/e06b57d7-18c5-4e3a-8e99-a25dc10c2804) |
| 📘 [**Guía Interactiva y Consultas**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/30901254-af54-4f59-96ac-2c865a5d6e7b) | 📘 [**Guía Interactiva y Consultas**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/be9105e9-f902-4a92-89ac-e67e6ef72d2c) |

---

## 📊 Por qué MySecret: Comparativa y Ventajas Clave

Tus notas de Obsidian son archivos de texto plano en tu disco duro. Cualquiera que abra la carpeta puede leerlas. Tu servicio de nube tiene acceso. Si alguien roba tu portátil, las tiene todas. Esto no es alarmismo — es simplemente cómo funciona un sistema de archivos normal.

Antes de MySecret, tenías dos opciones malas: **cifrar nota por nota** con plugins como Meld Encrypt (lo que convierte tus notas en bloques ilegibles, rompe la búsqueda global, elimina el grafo de conocimiento y hace que las etiquetas desaparezcan) o **usar herramientas externas** como Cryptomator o VeraCrypt (tolerables en escritorio, pero montar volúmenes cifrados en Android es una experiencia frustrante incluso para los más técnicos).

**MySecret elimina este dilema.** Cifra tu bóveda entera de forma automática y transparente, sin romper ninguna funcionalidad de Obsidian.

### 📊 Tabla Comparativa de Características

| Capacidad / Característica | **MySecret** | **Plugins de Bloqueo de Notas**<br>*(ej: Meld Encrypt, Cryptr)* | **Unidades Virtuales Externas**<br>*(ej: Cryptomator, VeraCrypt)* |
| :--- | :---: | :---: | :---: |
| **Cifrado Transparente en Disco** | ✅ **Automático en disco** | ❌ Manual (nota por nota) | ✅ Automático en contenedor |
| **Funciones Nativas de Obsidian Intactas**<br>*(Búsqueda global, Graph View, Enlaces, Canvas)* | ✅ **100% Funcional**<br>*(mientras está desbloqueado)* | ❌ **Roto**<br>*(las notas son bloques ilegibles)* | ⚠️ Puede generar colisiones de sync o bloqueos |
| **Compatibilidad con Obsidian Sync Oficial** | ⚡ **100% Nativo y Sin Bucles**<br>*(Alineación del hash del ciphertext)* | ❌ Inutilizable / genera conflictos | ❌ Roto / bucles infinitos de sobreescritura |
| **Cifrado de Adjuntos Multimedia**<br>*(Imágenes, PDFs, Audios, Videos)* | ✅ **Sí**<br>*(AES-GCM acelerado por hardware)* | ❌ **No**<br>*(Solo cifra texto markdown)* | ✅ Sí |
| **Algoritmo de Derivación de Clave (KDF)** | 🛡️ **Argon2id (WASM, 64 MB)**<br>*(Inmune a fuerza bruta por GPUs)* | ⚠️ **PBKDF2 / SHA-256**<br>*(Descifrable con GPUs modernas)* | 🛡️ Scrypt o Argon2 |
| **Recuperación ante Desastres** | 🔑 **Frase BIP-39 de 24 palabras**<br>*(Como billetera cripto fría)* | ❌ **Ninguna**<br>*(Olvidas contraseña = 100% pérdida)* | ⚠️ Clave de rescate alfanumérica larga |
| **Cobertura de Pruebas Automatizadas** | 🧪 **Más de 60.000 líneas de tests**<br>*(Auditado en código y bundle de producción)* | ❌ Casi nulo / pruebas mínimas | ⚠️ Pruebas generales de librería |
| **Desbloqueo Biométrico (Huella / Rostro)** | ✅ **Windows Hello, Touch ID, Linux y Android** | ❌ No disponible | ⚠️ Depende de la aplicación |
| **Experiencia en Android y Móviles** | 📱 **Fluida y Rápida**<br>*(mediante puente WebAuthn PWA)* | ⚠️ Incómoda y manual | ❌ **Muy frustrante**<br>*(montar volúmenes en Android)* |
| **Respaldos en la Nube (WebDAV, Drive, OneDrive)** | ✅ **Integrado nativamente**<br>*(Credenciales cifradas en reposo)* | ❌ No disponible | ❌ Requiere herramientas adicionales |
| **Seguridad en Memoria RAM (Zeroización)** | 🧹 **Garantizada (`zeroize`)** | ❌ Textos planos residuales en RAM | ⚠️ Variable |
| **Formato Abierto y a Prueba de Futuro** | ✅ **Archivos estándar en disco** | ⚠️ Etiquetas propietarias en texto | ❌ Contenedores binarios propietarios |

---

### 🌟 Las 10 Grandes Ventajas de MySecret Explicadas de Forma Simple

#### 1. 🪄 Cifrado Totalmente Invisible (Obsidian Sigue Funcionando)
- **El problema de los plugins tradicionales:** Plugins como *Meld Encrypt* convierten tus notas en bloques feos de caracteres incomprensibles (Base64) en la pantalla. Como Obsidian no puede leer lo que hay dentro, **la búsqueda global no encuentra nada, las etiquetas desaparecen y la vista de gráfico (Graph View) queda totalmente rota**.
- **La solución de MySecret:** MySecret trabaja silenciosamente por debajo, en el adaptador de archivos (`app.vault.adapter`). Mientras tu bóveda esté desbloqueada, Obsidian se comporta como siempre: buscas cualquier frase en milisegundos, tus enlaces conectan tus ideas y los lienzos Canvas se abren fluidos. Al momento en que el archivo se guarda en el disco duro, se sella herméticamente con AES-256-GCM.

#### 2. 🔄 100% Compatible con Obsidian Sync (Sin Bucles de Re-descarga)
- **El cementerio de plugins de cifrado:** Prácticamente todos los plugins de cifrado rompen Obsidian Sync. Como las notas en memoria están en texto plano y en la nube están cifradas, Obsidian Sync calcula huellas (hashes) diferentes, cree erróneamente que todos los archivos cambiaron y entra en un bucle destructivo de re-descargar y sobreescribir la bóveda entera.
- **La solución de MySecret:** MySecret realiza una alineación quirúrgica en tiempo de ejecución sobre el motor de cálculo de hashes de Obsidian. Obsidian Sync compara el hash del **texto cifrado en reposo** (idéntico al de la nube), mientras que la interfaz gráfica lee texto claro. Cero bucles de sincronización, cero doble cifrado y cero desperdicio de datos o batería.

#### 3. 🧪 Batería de Pruebas de Nivel Industrial (Más de 60.000 Líneas)
- **El problema de los plugins de la comunidad:** El 99% de los plugins de Obsidian se publican con cero pruebas automatizadas o con tests triviales. En una aplicación donde guardas tu vida digital, un error de concurrencia o un apagón accidental puede destruir años de notas.
- **La solución de MySecret:** Diseñado con ingeniería de defensa en profundidad. El proyecto cuenta con **más de 60.000 líneas de código dedicadas exclusivamente a tests automatizados** (`tests/`), ejecutados tanto sobre el código fuente como sobre el bundle empaquetado final (`main.js`). Prueban recuperación ante cortes de energía, ataques de manipulación en disco, inmunidad de AAD y concurrencia bajo un emulador completo del entorno interno de Obsidian (`obsidian-stub.mjs`).

#### 4. 📸 Fotos, Documentos y Audios También Están Protegidos
- **El problema de los plugins tradicionales:** La mayoría de plugins solo cifran texto `.md`. Si adjuntas una foto de una identificación personal, un contrato en PDF confidencial o una grabación de voz sensible, esos archivos se quedan en texto claro en tu disco duro, totalmente expuestos a cualquiera.
- **La solución de MySecret:** MySecret cifra **todos los tipos de archivo**. Las notas de texto usan un contenedor protegido y los archivos multimedia (PNG, JPG, PDF, MP3, MP4) utilizan una cabecera binaria compacta (`MYSE`). Tus documentos adjuntos están tan protegidos como tus notas escritas.

#### 5. 🛡️ Criptografía resistente a granjas de GPUs (Argon2id vs. PBKDF2)
- **El problema de los plugins tradicionales:** Casi todos los plugins usan **PBKDF2**, un algoritmo de hace dos décadas diseñado para la velocidad. Una tarjeta gráfica moderna para videojuegos (como una NVIDIA RTX 4090) puede probar *decenas de millones de contraseñas por segundo* contra un hash PBKDF2. Con tiempo y dinero, es vulnerable.
- **La solución de MySecret:** MySecret usa **Argon2id**, el ganador de la Password Hashing Competition — un certamen mundial donde miles de criptógrafos compitieron durante años para crear el algoritmo más resistente a los ataques modernos. Argon2id obliga a cualquier atacante a ocupar **64 megabytes de RAM por cada intento**. Multiplicado por millones de intentos en paralelo, hace que una granja de GPUs o un clúster en la nube sea económicamente inviable. Es la diferencia entre una cerradura convencional y una que obliga al ladrón a cargar un camión de arena antes de probar cada combinación.

#### 6. 🔑 Recuperación de emergencia con 24 palabras — como un monedero de criptomonedas, para tus notas
- **El problema de los plugins tradicionales:** En otros plugins, olvidar la contraseña maestra es un desastre total: toda la información cifrada queda irrecuperable de forma permanente. No existe ningún plan B.
- **La solución de MySecret:** Al configurar tu bóveda por primera vez, MySecret genera una **frase mnemónica BIP-39 de 24 palabras** — el mismo estándar que usan los mejores monederos físicos de criptomonedas para proteger fortunas millonarias. Si olvidas tu contraseña, introduces las 24 palabras y tu bóveda se recupera al instante, sin servidores, sin soporte técnico, completamente offline. Escríbelas en papel y guárdalas en un lugar físico seguro.

#### 7. 👆 Desbloqueo por Huella y Rostro en Todos tus Equipos (¡Incluyendo Android!)
- **El problema en dispositivos móviles:** En Android, Obsidian funciona dentro de un contenedor (WebView) donde Google bloquea el acceso a la huella dactilar. Por esta razón, **ningún otro plugin de Obsidian había logrado ofrecer desbloqueo biométrico en Android**.
- **La solución de MySecret:**
  - **En Windows:** Desbloqueo nativo e instantáneo con **Windows Hello** (huella, rostro o PIN) vía DPAPI. Cero configuración.
  - **En macOS y Linux:** Soporte local con Touch ID y `fprintd`.
  - **En Android:** Un puente PWA complementario y gratuito desplegable en 1 clic en Cloudflare Pages. Utiliza **criptografía efímera ECDH P-256** para validar tu huella en el navegador de tu móvil y desbloquear Obsidian en segundos, sin que tu clave salga jamás del dispositivo.

#### 8. ☁️ Copias de Seguridad Cifradas en la Nube con 1 Clic
- **El problema con herramientas externas:** Intentar sincronizar carpetas cifradas complejas mediante servicios externos suele provocar archivos corruptos, conflictos de sincronización o bloqueos de ficheros.
- **La solución de MySecret:** MySecret incluye su propio motor de respaldos. Con un clic o un comando puedes exportar copias completas o enviarlas cifradas automáticamente a **Nextcloud / WebDAV, Google Drive o Microsoft OneDrive**. Las credenciales de acceso a tu nube se guardan a su vez fuertemente cifradas con la clave de tu bóveda.

#### 9. 🧹 Limpieza Activa de Memoria RAM (Zeroize)
- **El problema con las aplicaciones comunes:** Cuando cierras una app o dejas tu equipo encendido, las contraseñas y claves de descifrado a menudo permanecen en la memoria RAM durante horas, donde programas maliciosos pueden extraerlas.
- **La solución de MySecret:** MySecret sobrescribe activamente con ceros (`zeroize()`) todos los buffers de claves en la memoria RAM en bloques estrictos `finally`, tanto al bloquearse la bóveda, al agotarse el tiempo de inactividad o ante cualquier error imprevisto.

#### 10. 🔓 Tus notas son tuyas — también sin Obsidian, también sin MySecret
- **El miedo legítimo de confiar en cualquier plugin:** *«¿Qué pasa si este proyecto se abandona y no puedo abrir mis notas?»*
- **La garantía de MySecret:** Tus archivos están cifrados con estándares criptográficos **abiertos, internacionales e implementados en cualquier lenguaje de programación**: AES-256-GCM (NIST SP 800-38D), Argon2id (RFC 9106, estándar IETF) y BIP-39 (el mismo estándar de los mejores monederos físicos de criptomonedas). No son formatos inventados para este plugin — son especificaciones publicadas en miles de libros, implementadas en miles de bibliotecas de software independientes. Si MySecret desaparece mañana, puedes descifrar toda tu bóveda con:
  1. **Python:** Un script de 15 líneas usando librerías universales (`cryptography` o `pycryptodome` + `argon2-cffi`). Sin Obsidian instalado.
  2. **Cualquier navegador web moderno (sin conexión):** La API nativa `crypto.subtle` (Chrome, Firefox, Safari, Edge) puede descifrar cualquier nota abriendo un archivo HTML local.
  3. **CyberChef (la navaja suiza criptográfica del GCHQ):** Pega el IV, el Tag y el texto en base64 directamente con la receta estándar AES-GCM.
  4. **OpenSSL, Node.js, Go, Rust:** Cualquier lenguaje con soporte AES-GCM estándar puede leer y procesar tus archivos. Tus datos son matemáticamente tuyos para siempre.

---

## 🔒 Arquitectura de Seguridad y Criptografía

- **Arquitectura de Cero Conocimiento (Zero-Knowledge):** Las claves criptográficas se derivan exclusivamente en la memoria RAM de tu dispositivo. Ninguna clave ni texto plano abandona jamás tu equipo.
- **AES-256-GCM:** Cifrado autenticado (AEAD) acelerado por hardware mediante la Web Crypto API nativa (`window.crypto.subtle`).
- **Enlace Criptográfico de Ruta (AAD Binding):** La ruta relativa del archivo se vincula estrictamente a los Datos Asociados Autenticados (AAD), imposibilitando ataques de sustitución o movimiento de archivos cifrados.
- **Argon2id (WASM):** Derivación de claves de última generación inmune a ataques de fuerza bruta mediante GPUs o ASICs, ejecutado en WebAssembly vía `hash-wasm`.
- **Rescate de Emergencia BIP-39:** Frase mnemónica determinista de 24 palabras para recuperar tu bóveda si olvidas tu contraseña maestra.
- **Zeroización de Memoria:** Limpieza activa con ceros (`zeroize()`) de todos los buffers criptográficos en RAM al bloquearse la bóveda, cerrarse la app o por inactividad.
- **Desbloqueo Biométrico:** Soporte nativo para Windows Hello (huella/rostro), Linux (`fprintd`), macOS (Touch ID) y puente PWA WebAuthn para Android en Cloudflare Pages con intercambio efímero ECDH P-256.

Para más detalles técnicos, consulta el documento de [Arquitectura de Seguridad (SECURITY.es.md)](SECURITY.es.md).

---

## ✨ Características Principales

- 🛡️ **Cifrado Transparente en Tiempo Real:** Protege notas y archivos adjuntos sin alterar tu flujo de trabajo en Obsidian.
- 🔐 **Formato Contenedor Dual:**
  - **Notas de texto:** Formato blindado ASCII (`-----BEGIN MYSECRET ENCRYPTED FILE-----`).
  - **Archivos adjuntos:** Cabecera binaria compacta de 32 bytes con identificador mágico `MYSE`.
- ⏱️ **Temporizador de Auto-Bloqueo:** Bloqueo configurable automático por inactividad.
- 📦 **Respaldos Cifrados Automatizados:** Exportación y restauración de instantáneas completas de la bóveda con protección contra Zip Slip.
- ☁️ **Respaldos Remotos en la Nube:** Sube copias de seguridad cifradas directamente a:
  - WebDAV / Nextcloud / ownCloud
  - Google Drive
  - Microsoft OneDrive
  - Carpeta sincronizada local
- 👆 **Autenticación Biométrica:**
  - **Escritorio (Windows, Mac, Linux):** 100% nativa y local sin requerir internet.
  - **Android:** Puente WebAuthn seguro vía Cloudflare Pages PWA con validación de aserción criptográfica.
- 🌍 **Soporte Multilingüe (i18n):** Interfaz completa en Español, English, Русский y 中文.

---

## 🚀 Instalación

### Opción 1: Mediante BRAT (Beta Reviewer's Auto-update Tester)
1. Instala el plugin [BRAT](https://github.com/TfTHacker/obsidian42-brat) en Obsidian.
2. Abre **Opciones** → **BRAT** → **Add Beta plugin**.
3. Pega el enlace: `https://github.com/abismalmx/MySecret`
4. Activa **MySecret** en la sección de **Plugins de la comunidad**.

### Opción 2: Instalación Manual
1. Descarga los archivos de la última versión (`main.js`, `manifest.json`, `styles.css`) desde la sección de [Releases](https://github.com/abismalmx/MySecret/releases).
2. Ve a la carpeta de tu bóveda de Obsidian: `<bóveda>/.obsidian/plugins/`
3. Crea una carpeta llamada `mysecret` y coloca los tres archivos dentro:
   ```
   <bóveda>/.obsidian/plugins/mysecret/
   ├── main.js
   ├── manifest.json
   └── styles.css
   ```
4. Reinicia Obsidian o recarga los plugins, ve a **Ajustes** → **Plugins de la comunidad** y activa **MySecret**.

---

## 🛠️ Compilación y Desarrollo

### Requisitos Previos
- Node.js 18+ (Node 20 LTS recomendado)
- npm o pnpm

### Clonar e Instalar
```bash
git clone https://github.com/abismalmx/MySecret.git
cd obsidian-mysecret
npm install
```

### Modo Desarrollo (Watch)
```bash
npm run dev
```

### Compilación para Producción
```bash
npm run build
```

### Ejecutar Suite de Pruebas Automatizadas
```bash
npm test
```
> Las 157 pruebas unitarias, de integración y regresión criptográfica se ejecutan con 100% de éxito.

---

## 📱 Puente Biométrico Móvil (iOS / Android) (`auth-bridge/`)

Obsidian Mobile en Android e iOS corre dentro de un WebView con restricciones donde `navigator.credentials.get()` / WebAuthn no está disponible para esquemas de aplicación locales.

MySecret soluciona esto mediante un **Puente PWA WebAuthn**:
1. Despliegas los archivos de la carpeta `auth-bridge/` en un sitio gratuito de **Cloudflare Pages** (sin configuración previa, 1 clic).
2. El plugin utiliza deep-linking (`obsidian://`) con intercambio de claves efímeras ECDH (P-256) y verificación de aserción.
3. Safari en iOS invoca **Face ID / Touch ID** mediante el Secure Enclave de Apple; Chrome en Android activa el **Sensor de Huella Dactilar**.
4. La clave de la bóveda jamás abandona tu dispositivo.

Consulta [auth-bridge/README.md](auth-bridge/README.md) para la guía paso a paso.

---

## 📚 Documentación Adicional

- 📖 **[Manual de Usuario](USER_GUIDE.es.md)** — Guía completa paso a paso para usuarios finales.
- 💻 **[Manual de Programador](DEVELOPER_GUIDE.es.md)** — Documentación de arquitectura interna, APIs y contribución.
- 🛡️ **[Arquitectura de Seguridad](SECURITY.es.md)** — Especificación técnica y mitigación de vectores de ataque.
- 📊 **[Por qué MySecret / Comparativa](COMPARISON.es.md)** — Ventajas frente a herramientas tradicionales.
- 📱 **[Puente Biométrico Móvil (iOS / Android)](auth-bridge/README.md)** — Instrucciones de despliegue en Cloudflare Pages.

---

## 📄 Licencia

Copyright (c) 2026 Anthony Rios Licea (@abismalmx).

**Código fuente público y auditable.** El código de MySecret está publicado íntegramente en GitHub — cualquier persona puede leerlo, auditarlo de forma independiente y verificar que no existe ninguna puerta trasera. La privacidad que ofrece es matemáticamente verificable: no tienes que confiar en nuestra palabra.

Licencia: gratuito para uso personal, educativo y no comercial. El uso comercial requiere autorización previa del autor. Consulta [LICENSE](LICENSE) para los términos completos.
