<div align="center">

<img src="logo.webp" alt="Logo de MySecret" width="160" height="160" style="border-radius: 24px; box-shadow: 0 8px 24px rgba(0,0,0,0.15);" />

# MySecret — Cifrado Transparente de Bóveda para Obsidian

[![Obsidian](https://img.shields.io/badge/Obsidian-v1.0.0+-7C3AED?logo=obsidian&logoColor=white)](https://obsidian.md)
[![Licencia](https://img.shields.io/badge/Licencia-No--Comercial-blue.svg)](LICENSE)
[![Pruebas](https://img.shields.io/badge/Pruebas-81%20pasando-success)](tests/)
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
3. Pega el enlace: `https://github.com/Abismalmx/obsidian-mysecret`
4. Activa **MySecret** en la sección de **Plugins de la comunidad**.

### Opción 2: Instalación Manual
1. Descarga los archivos de la última versión (`main.js`, `manifest.json`, `styles.css`) desde la sección de [Releases](https://github.com/Abismalmx/obsidian-mysecret/releases).
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
git clone https://github.com/Abismalmx/obsidian-mysecret.git
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

Copyright (c) 2026 Anthony Rios Licea (@Abismalmx).  
Publicado bajo la **Licencia de Software No Comercial MySecret**. Su uso es libre y gratuito para fines personales, educativos y no comerciales. Queda estrictamente prohibida su explotación comercial o redistribución con fines lucrativos sin la autorización previa y por escrito del autor. Consulta [LICENSE](LICENSE) para ver los términos legales completos.
