<div align="center">

<img src="logo.webp" alt="Logo de MySecret" width="160" height="160" style="border-radius: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.15);" />

# MySecret — Cifrado Transparente de Bóveda para Obsidian

[![Obsidian](https://img.shields.io/badge/Obsidian-v1.0.0+-7C3AED?logo=obsidian&logoColor=white)](https://obsidian.md)
[![Licencia](https://img.shields.io/badge/Licencia-No--Comercial-blue.svg)](LICENSE)
[![Pruebas](https://img.shields.io/badge/Pruebas-83%20pasando-success)](tests/)
[![Seguridad](https://img.shields.io/badge/Seguridad-Blindada%20y%20Auditada-brightgreen)](SECURITY.es.md)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?logo=typescript&logoColor=white)](tsconfig.json)

**Cifrado en tiempo real con arquitectura de Cero Conocimiento para tus notas y archivos de Obsidian.**  
*AES-256-GCM • Argon2id (WASM) • Rescate Mnemónico BIP-39 • WebAuthn y Biometría • Respaldos Multi-Nube*

[English Version](README.md) • **Español**

</div>

---

## 🌟 Descripción General

**MySecret** es un plugin de seguridad y privacidad avanzada para [Obsidian](https://obsidian.md). Intercepta de forma transparente el adaptador del sistema de archivos de Obsidian (`app.vault.adapter`) para cifrar y descifrar notas (`.md`), lienzos (`.canvas`) y archivos adjuntos binarios (imágenes, audios, PDFs, videos) en tiempo real.

En disco, todos tus archivos permanecen fuertemente cifrados en reposo. Al desbloquear la bóveda con tu contraseña maestra o huella digital, utilizas Obsidian con total normalidad: búsqueda completa, vista gráfica, enlaces internos y edición fluida.

---

## 🎬 Demostración en Video y Explicación del Sistema

Mira la demostración completa en video de MySecret explicando cómo el cifrado transparente en reposo protege tu bóveda de Obsidian:

| 🇬🇧 Demostración en Inglés | 🇪🇸 Explicación en Español |
| :---: | :---: |
| 🌐 [**Ver Online sin Descargar (Streaming Web)**](https://abismalmx.github.io/MySecret/docs/interactive-infographic.html) | 🌐 [**Ver Online sin Descargar (Streaming Web)**](https://abismalmx.github.io/MySecret/docs/interactive-infographic.html) |
| 🧠 [**Ver en Google NotebookLM**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/ef0d6ffc-dc85-48e2-b52d-11fdbaf5e533) | 🧠 [**Ver en Google NotebookLM**](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/e06b57d7-18c5-4e3a-8e99-a25dc10c2804) |
| 💾 [Descargar Archivo MP4](media/MySecret_en.mp4) | 💾 [Descargar Archivo MP4](media/MySecret_es.mp4) |

> [!TIP]
> 🌐 **Infografía de Seguridad Interactiva (Web)**: Explora la arquitectura interactiva, reproduce videos y prueba el simulador en **[abismalmx.github.io/MySecret](https://abismalmx.github.io/MySecret/docs/interactive-infographic.html)**.  
> 🧠 **Guía Interactiva en NotebookLM**:
> - 🇪🇸 [Explorar en NotebookLM (Español)](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/be9105e9-f902-4a92-89ac-e67e6ef72d2c)
> - 🇬🇧 [Explore on NotebookLM (English)](https://notebook.google.com/notebook/d5794d82-48a8-4e4b-b4b8-69b288423f72/artifact/30901254-af54-4f59-96ac-2c865a5d6e7b)

---

## 📊 Por qué MySecret: Comparativa y Ventajas Clave

Al buscar una solución de seguridad y cifrado para tus notas en [Obsidian](https://obsidian.md), tradicionalmente tenías que elegir entre **seguridad** o **comodidad**. La mayoría de las opciones existentes te obligan a bloquear notas una por una (rompiendo las búsquedas, la vista gráfica y los enlaces) o requieren programas externos complejos (como Cryptomator o VeraCrypt) que son muy difíciles e incómodos de sincronizar en teléfonos móviles.

**MySecret elimina este dilema.** Integra **cifrado transparente en disco, de grado militar y con arquitectura de Cero Conocimiento** directamente dentro de Obsidian, sin alterar tu ritmo de trabajo diario.

### 📊 Tabla Comparativa de Características

| Capacidad / Característica | **MySecret** | **Plugins de Bloqueo de Notas**<br>*(ej: Meld Encrypt, Cryptr)* | **Unidades Virtuales Externas**<br>*(ej: Cryptomator, VeraCrypt)* |
| :--- | :---: | :---: | :---: |
| **Cifrado Transparente en Disco** | ✅ **Automático en disco** | ❌ Manual (nota por nota) | ✅ Automático en contenedor |
| **Funciones Nativas de Obsidian Intactas**<br>*(Búsqueda global, Graph View, Enlaces, Canvas)* | ✅ **100% Funcional**<br>*(mientras está desbloqueado)* | ❌ **Roto**<br>*(las notas son bloques ilegibles)* | ⚠️ Puede generar colisiones de sync o bloqueos |
| **Cifrado de Adjuntos Multimedia**<br>*(Imágenes, PDFs, Audios, Videos)* | ✅ **Sí**<br>*(AES-GCM acelerado por hardware)* | ❌ **No**<br>*(Solo cifra texto markdown)* | ✅ Sí |
| **Algoritmo de Derivación de Clave (KDF)** | 🛡️ **Argon2id (WASM, 64 MB)**<br>*(Inmune a fuerza bruta por GPUs)* | ⚠️ **PBKDF2 / SHA-256**<br>*(Descifrable con GPUs modernas)* | 🛡️ Scrypt o Argon2 |
| **Recuperación ante Desastres** | 🔑 **Frase BIP-39 de 24 palabras**<br>*(Como billetera cripto fría)* | ❌ **Ninguna**<br>*(Olvidas contraseña = 100% pérdida)* | ⚠️ Clave de rescate alfanumérica larga |
| **Desbloqueo Biométrico (Huella / Rostro)** | ✅ **Windows Hello, Touch ID, Linux y Android** | ❌ No disponible | ⚠️ Depende de la aplicación |
| **Experiencia en Android y Móviles** | 📱 **Fluida y Rápida**<br>*(mediante puente WebAuthn PWA)* | ⚠️ Incómoda y manual | ❌ **Muy frustrante**<br>*(montar volúmenes en Android)* |
| **Respaldos en la Nube (WebDAV, Drive, OneDrive)** | ✅ **Integrado nativamente**<br>*(Credenciales cifradas en reposo)* | ❌ No disponible | ❌ Requiere herramientas adicionales |
| **Seguridad en Memoria RAM (Zeroización)** | 🧹 **Garantizada (`zeroize`)** | ❌ Textos planos residuales en RAM | ⚠️ Variable |
| **Formato Abierto y a Prueba de Futuro** | ✅ **Archivos estándar en disco** | ⚠️ Etiquetas propietarias en texto | ❌ Contenedores binarios propietarios |

---

### 🌟 Las 8 Grandes Ventajas de MySecret Explicadas de Forma Simple

#### 1. 🪄 Cifrado Totalmente Invisible (Obsidian Sigue Funcionando)
- **El problema de los plugins tradicionales:** Plugins como *Meld Encrypt* convierten tus notas en bloques feos de caracteres incomprensibles (Base64) en la pantalla. Como Obsidian no puede leer lo que hay dentro, **la búsqueda global no encuentra nada, las etiquetas desaparecen y la vista de gráfico (Graph View) queda totalmente rota**.
- **La solución de MySecret:** MySecret trabaja silenciosamente por debajo, en el adaptador de archivos (`app.vault.adapter`). Mientras tu bóveda esté desbloqueada, Obsidian se comporta como siempre: buscas cualquier frase en milisegundos, tus enlaces conectan tus ideas y los lienzos Canvas se abren fluidos. Al momento en que el archivo se guarda en el disco duro, se sella herméticamente con AES-256-GCM.

#### 2. 📸 Fotos, Documentos y Audios También Están Protegidos
- **El problema de los plugins tradicionales:** La mayoría de plugins solo cifran texto `.md`. Si adjuntas una foto de una identificación personal, un contrato en PDF confidencial o una grabación de voz sensible, esos archivos se quedan en texto claro en tu disco duro, totalmente expuestos a cualquiera.
- **La solución de MySecret:** MySecret cifra **todos los tipos de archivo**. Las notas de texto usan un contenedor protegido y los archivos multimedia (PNG, JPG, PDF, MP3, MP4) utilizan una cabecera binaria compacta (`MYSE`). Tus documentos adjuntos están tan protegidos como tus notas escritas.

#### 3. 🛡️ Criptografía Resistente a Supercomputadoras (Argon2id vs. PBKDF2)
- **El problema de los plugins tradicionales:** Casi todos los plugins usan **PBKDF2** con pocas iteraciones. Una tarjeta gráfica moderna para videojuegos (como una NVIDIA RTX 4090) puede probar decenas de millones de contraseñas por segundo contra este algoritmo.
- **La solución de MySecret:** MySecret implementa **Argon2id** (el algoritmo estándar ganador del Password Hashing Competition) compilado en WebAssembly. Este algoritmo obliga a cualquier atacante a gastar **64 Megabytes de memoria RAM por cada intento**, anulando matemáticamente los ataques de fuerza bruta con tarjetas gráficas o granjas de minería.

#### 4. 🔑 Frase de Rescate de 24 Palabras (Como una Billetera Cripto)
- **El problema de los plugins tradicionales:** En otros plugins, si olvidas tu contraseña maestra, has perdido toda tu información para siempre sin ninguna alternativa.
- **La solución de MySecret:** Al configurar tu bóveda por primera vez, MySecret te entrega una frase estandarizada de **24 palabras mnemónicas BIP-39** basada en 256 bits de entropía. Si un día olvidas tu clave, introduces tus 24 palabras y tu bóveda se recupera en tu dispositivo sin depender de ningún servidor ni soporte técnico.

#### 5. 👆 Desbloqueo por Huella y Rostro en Todos tus Equipos (¡Incluyendo Android!)
- **El problema en dispositivos móviles:** En Android, Obsidian funciona dentro de un contenedor (WebView) donde Google bloquea el acceso a la huella dactilar. Por esta razón, **ningún otro plugin de Obsidian había logrado ofrecer desbloqueo biométrico en Android**.
- **La solución de MySecret:**
  - **En Windows:** Desbloqueo nativo e instantáneo con **Windows Hello** (huella, rostro o PIN) vía DPAPI. Cero configuración.
  - **En macOS y Linux:** Soporte local con Touch ID y `fprintd`.
  - **En Android:** Un puente PWA complementario y gratuito desplegable en 1 clic en Cloudflare Pages. Utiliza **criptografía efímera ECDH P-256** para validar tu huella en el navegador de tu móvil y desbloquear Obsidian en segundos, sin que tu clave salga jamás del dispositivo.

#### 6. ☁️ Copias de Seguridad Cifradas en la Nube con 1 Clic
- **El problema con herramientas externas:** Intentar sincronizar carpetas cifradas complejas mediante servicios externos suele provocar archivos corruptos, conflictos de sincronización o bloqueos de ficheros.
- **La solución de MySecret:** MySecret incluye su propio motor de respaldos. Con un clic o un comando puedes exportar copias completas o enviarlas cifradas automáticamente a **Nextcloud / WebDAV, Google Drive o Microsoft OneDrive**. Las credenciales de acceso a tu nube se guardan a su vez fuertemente cifradas con la clave de tu bóveda.

#### 7. 🧹 Limpieza Activa de Memoria RAM (Zeroize)
- **El problema con las aplicaciones comunes:** Cuando cierras una app o dejas tu equipo encendido, las contraseñas y claves de descifrado a menudo permanecen en la memoria RAM durante horas, donde programas maliciosos pueden extraerlas.
- **La solución de MySecret:** MySecret sobrescribe activamente con ceros (`zeroize()`) todos los buffers de claves en la memoria RAM en bloques estrictos `finally`, tanto al bloquearse la bóveda, al agotarse el tiempo de inactividad o ante cualquier error imprevisto.

#### 8. 🔓 Cero Cautiverio de Proveedor (Sin Vendor Lock-in): Recupera tus Notas sin Obsidian
- **El miedo común:** *«¿Qué pasa si el plugin deja de actualizarse, si Obsidian desaparece dentro de 20 años o si mi aplicación no abre?»*
- **La garantía de MySecret:** **NO estás atado al plugin ni a Obsidian.** MySecret está construido exclusivamente sobre **estándares abiertos mundiales de la industria criptográfica**:
  - **AES-256-GCM** (NIST SP 800-38D).
  - **Argon2id** (RFC 9106, estándar IETF).
  - **BIP-39** (estándar mnemónico internacional de hardware wallets).
- **¿Con qué otros programas puedes descifrar tus notas?**
  1. **Python:** Un script estándar de 15 líneas usando librerías universales (`cryptography` o `pycryptodome` + `argon2-cffi`) puede descifrar todas tus notas y adjuntos en segundos sin tener Obsidian instalado.
  2. **Cualquier Navegador Web (Offline):** La API nativa `crypto.subtle` (presente en Chrome, Firefox, Safari, Edge) puede descifrar cualquier nota abriendo un archivo HTML local.
  3. **CyberChef (La navaja suiza de GCHQ):** Puedes pegar el IV, el Tag y el texto en base64 en CyberChef y descifrarlo directamente con la receta estándar de AES-GCM.
  4. **OpenSSL / Node.js / Go / Rust:** Cualquier lenguaje de programación con soporte AES-GCM estándar puede leer y procesar tus archivos. Tus datos son matemáticamente tuyos para siempre.

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
> Las 81 pruebas unitarias, de integración y regresión criptográfica se ejecutan con 100% de éxito.

---

## 📚 Documentación Adicional

- 📖 **[Manual de Usuario](USER_GUIDE.es.md)** — Guía completa paso a paso para usuarios finales.
- 💻 **[Manual de Programador](DEVELOPER_GUIDE.es.md)** — Documentación de arquitectura interna, APIs y contribución.
- 🛡️ **[Arquitectura de Seguridad](SECURITY.es.md)** — Especificación técnica y mitigación de vectores de ataque.
- 📊 **[Por qué MySecret / Comparativa](COMPARISON.es.md)** — Ventajas frente a herramientas tradicionales.
- 📱 **[Puente Biométrico para Android](auth-bridge/README.md)** — Instrucciones de despliegue en Cloudflare Pages.

---

## 📄 Licencia

Copyright (c) 2026 Anthony Rios Licea (@abismalmx).  
Publicado bajo la **Licencia de Software No Comercial MySecret**. Su uso es libre y gratuito para fines personales, educativos y no comerciales. Queda estrictamente prohibida su explotación comercial o redistribución con fines lucrativos sin la autorización previa y por escrito del autor. Consulta [LICENSE](LICENSE) para ver los términos legales completos.
