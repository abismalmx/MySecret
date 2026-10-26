# MySecret — Manual de Usuario Exhaustivo

[English Version](USER_GUIDE.md) • **Español**

Bienvenido al **Manual de Usuario de MySecret**. Esta guía proporciona un recorrido completo y detallado paso a paso para instalar, configurar, usar, respaldar y recuperar una bóveda de Obsidian protegida con MySecret.

> [!IMPORTANT]
> ### ⚠️ Paso Obligatorio Previo: Realiza una Copia de Seguridad de tus Notas
> **Antes de siquiera instalar, habilitar o cifrar tu bóveda con MySecret, se recomienda encarecidamente hacer una copia de seguridad completa de la carpeta de tus notas.**
> Simplemente copia la carpeta de tu bóveda de Obsidian a una memoria USB, a otra carpeta de tu computadora o a tu nube preferida. Como MySecret realiza cifrado real en reposo a nivel de disco, tener una copia previa sin cifrar te garantiza tranquilidad absoluta y protección total en caso de que olvides tu contraseña maestra o extravíes tu frase mnemónica de rescate de 24 palabras.

---

## Tabla de Contenidos

1. [Introducción y Conceptos Clave](#1-introducción-y-conceptos-clave)
2. [Instalación](#2-instalación)
3. [Asistente de Configuración Inicial](#3-asistente-de-configuración-inicial)
4. [Uso Diario y Flujo de Trabajo](#4-uso-diario-y-flujo-de-trabajo)
5. [Guía de Autenticación Biométrica](#5-guía-de-autenticación-biométrica)
   - [Windows (Windows Hello)](#windows-windows-hello)
   - [macOS (Touch ID)](#macos-touch-id)
   - [Linux (fprintd)](#linux-fprintd)
   - [Android (Puente en Cloudflare Pages)](#android-puente-en-cloudflare-pages)
6. [Migración y Procesamiento de la Bóveda](#6-migración-y-procesamiento-de-la-bóveda)
7. [Copias de Seguridad y Respaldo en la Nube](#7-copias-de-seguridad-y-respaldo-en-la-nube)
   - [Instantáneas Locales](#instantáneas-locales)
   - [Restauración Segura](#restauración-segura)
   - [Respaldos en la Nube (WebDAV, Google Drive, OneDrive)](#respaldos-en-la-nube)
8. [Recuperación ante Desastres y Gestión de Claves](#8-recuperación-ante-desastres-y-gestión-de-claves)
9. [Cómo Descifrar tus Notas sin el Plugin ni Obsidian](#9-cómo-descifrar-tus-notas-sin-el-plugin-ni-obsidian)
10. [Preguntas Frecuentes (FAQ)](#10-preguntas-frecuentes-faq)

---

## 1. Introducción y Conceptos Clave

### ¿Qué es el Cifrado Transparente?
Los sistemas tradicionales de cifrado suelen obligar al usuario a bloquear o desbloquear notas una por una, o bien a almacenar el contenido dentro de bases de datos cerradas y propietarias que rompen el ecosistema de archivos abiertos de Obsidian.

**MySecret** adopta un modelo radicalmente distinto:
- **En Reposo (En Disco):** Cada nota Markdown (`.md`), archivo de lienzo (`.canvas`) y archivo adjunto binario (imágenes PNG, JPG, documentos PDF, audios MP3) se almacena cifrado en disco con **AES-256-GCM**. Si un atacante extrae tu disco, abre tu bóveda en VS Code o accede a tu respaldo en la nube, solo verá contenedores criptográficos impenetrables.
- **En Memoria (Dentro de Obsidian):** Mientras la bóveda esté desbloqueada, MySecret intercepta de forma transparente las llamadas internas de lectura y escritura de Obsidian. Puedes editar notas, pulsar enlaces internos, ver imágenes incrustadas, hacer búsquedas globales y ver la vista de gráfico con total normalidad.
- **Arquitectura de Cero Conocimiento:** Las claves se derivan exclusivamente en la memoria RAM volátil. Ninguna clave, contraseña o frase de rescate sale jamás de tu dispositivo ni se guarda sin cifrar en disco.

---

## 2. Instalación

### Método A: Mediante BRAT (Recomendado para Actualizaciones Directas)
1. Instala y activa el plugin **BRAT** desde la lista de plugins comunitarios de Obsidian.
2. Abre **Ajustes** → **BRAT**.
3. Pulsa **Add Beta plugin**.
4. Pega la URL del repositorio:
   ```
   https://github.com/abismalmx/MySecret
   ```
5. Pulsa **Add Plugin**, espera a que termine la descarga y activa **MySecret** en **Ajustes** → **Plugins de la comunidad**.

### Método B: Instalación Manual
1. Ve a la sección de [Releases](https://github.com/abismalmx/MySecret/releases) en GitHub.
2. Descarga los tres archivos principales:
   - `main.js`
   - `manifest.json`
   - `styles.css`
3. En tu ordenador, abre la carpeta de tu bóveda de Obsidian y entra al directorio de plugins:
   ```
   <tu-boveda>/.obsidian/plugins/
   ```
4. Crea una carpeta llamada `mysecret` y coloca los tres archivos dentro:
   ```
   .obsidian/plugins/mysecret/
   ├── main.js
   ├── manifest.json
   └── styles.css
   ```
5. En Obsidian, ve a **Ajustes** → **Plugins de la comunidad**, recarga la lista y activa **MySecret**.

---

## 3. Asistente de Configuración Inicial

La primera vez que actives MySecret en una bóveda, se iniciará automáticamente el **Asistente de Bienvenida**:

```
┌────────────────────────────────────────────────────────┐
│             Configuración de Bóveda MySecret           │
├────────────────────────────────────────────────────────┤
│ Paso 1: Crear Contraseña Maestra (Medidor de entropía) │
│ Paso 2: Frase de Rescate BIP-39 (24 palabras)          │
│ Paso 3: Desafío Interactivo de Validación              │
└────────────────────────────────────────────────────────┘
```

### Paso 1: Crear tu Contraseña Maestra
- **Longitud Mínima:** Requiere un mínimo de **12 caracteres**.
- **Medidor de Entropía:** Evalúa en tiempo real la diversidad de caracteres (mayúsculas, minúsculas, números y símbolos).
- **Consejo:** Utiliza una frase compuesta por 4 o 5 palabras aleatorias fáciles de recordar para ti pero difíciles de predecir (ejemplo: `coral-galaxia-roble-pantera-faro`).

### Paso 2: Guardar tu Frase de Rescate BIP-39 (24 Palabras)
- MySecret genera 256 bits de entropía criptográfica formateada en una lista estandarizada de **24 palabras mnemónicas BIP-39**.
- **Regla Fundamental:** Escribe estas 24 palabras en papel en el orden exacto y guárdalas en un lugar seguro (por ejemplo, una caja de seguridad o libreta privada).
- **Aviso Vital:** Si alguna vez olvidas tu contraseña maestra, esta frase mnemónica es la **única** forma matemática de recuperar el acceso a tus notas cifradas.

### Paso 3: Desafío de Validación
- Para confirmar que guardaste la frase correctamente, el asistente te pedirá verificar dos posiciones de palabras elegidas al azar (por ejemplo, la Palabra #6 y la Palabra #18).
- Al completar la verificación, el contenedor de tu bóveda queda listo y protegido.

---

## 4. Uso Diario y Flujo de Trabajo

### Desbloquear la Bóveda
Al abrir Obsidian:
1. Aparecerá la **Pantalla de Bloqueo Flotante** de MySecret impidiendo el acceso a la interfaz.
2. Introduce tu contraseña maestra o pulsa el botón de **Desbloqueo Biométrico** (huella dactilar o rostro).
3. Una vez verificada la clave, la pantalla de bloqueo desaparece y Obsidian funciona de forma habitual.

### Indicador en la Barra de Estado
En la esquina inferior derecha de la barra de estado de Obsidian:
- 🟢 **Bóveda Desbloqueada:** Sesión activa y cifrado transparente operando en tiempo real.
- 🔒 **Bloquear Ahora:** Al hacer clic en el icono, la bóveda se bloquea inmediatamente y se limpian las claves de la memoria RAM.

### Temporizador de Auto-Bloqueo
Para proteger tus datos si te alejas de tu dispositivo:
1. Ve a **Ajustes** → **MySecret**.
2. Localiza la opción **Tiempo de Inactividad (Auto-Bloqueo)**.
3. Elige el tiempo deseado (por ejemplo: 5, 10 o 30 minutos, o Desactivado).
4. Cuando transcurra el tiempo sin actividad, MySecret destruye la clave maestra de la RAM (`zeroize()`) y vuelve a bloquear la pantalla.

### Cómo se ven los archivos en el disco duro
Si abres tu bóveda con el explorador de archivos del sistema operativo o con otro editor:
- **Notas Markdown (`.md`):** Aparecen encapsuladas en un contenedor seguro de texto ASCII:
  ```markdown
  -----BEGIN MYSECRET ENCRYPTED FILE-----
  Version: 1
  IV: d8f3a9e1b2c4d5e6f7a8b9c0
  Tag: 4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d

  q8XyZ1v...[Contenido Cifrado en Base64]...==
  -----END MYSECRET ENCRYPTED FILE-----
  ```
- **Archivos Adjuntos (Imágenes, PDFs, Audios):** Se guardan en formato binario compacto con la cabecera mágica `MYSE`, el vector IV de 12 bytes y el tag de autenticación de 16 bytes.

---

## 5. Guía de Autenticación Biométrica

### Windows (Windows Hello)
- **Compatible:** Lector de huellas dactilares, cámara infrarroja con reconocimiento facial o PIN de Windows Hello.
- **Configuración:**
  1. Asegúrate de tener Windows Hello activado en la configuración de Windows.
  2. En Obsidian, abre **Ajustes** → **MySecret** → **Autenticación Biométrica**.
  3. Activa la casilla y confirma tu contraseña maestra.
- **¿Se necesita URL de Cloudflare?** **NO.** En Windows la comunicación es 100% nativa y local a través de las APIs del sistema (`UserConsentVerifier` y DPAPI). No se requiere conexión a internet.

### macOS (Touch ID)
- **Compatible:** Sensores Touch ID integrados en MacBooks, Magic Keyboard con Touch ID o desbloqueo con Apple Watch.
- **Configuración:** Actívalo directamente en los ajustes del plugin; macOS gestiona la autenticación mediante la API nativa de WebAuthn.
- **¿Se necesita URL de Cloudflare?** **NO.** Funciona de forma 100% local.

### Linux (fprintd)
- **Compatible:** Lectores de huella configurados con `fprintd` y `SecretService`.
- **Configuración:** Enrola tu huella con `fprintd-enroll` en tu distribución y activa la opción en MySecret.
- **¿Se necesita URL de Cloudflare?** **NO.** Funciona de forma 100% local.

### Android (Puente en Cloudflare Pages)
En Android, Obsidian se ejecuta dentro de un WebView del sistema donde Google restringe el uso nativo de WebAuthn. MySecret resuelve esto de manera segura mediante una aplicación web complementaria en Cloudflare Pages:

1. **Despliegue Único (100% Gratuito):**
   - Inicia sesión en [dash.cloudflare.com](https://dash.cloudflare.com/).
   - Ve a **Workers & Pages** → **Create application** → pestaña **Pages** → **Upload assets**.
   - Asigna un nombre a tu proyecto (ejemplo: `mi-boveda-auth`).
   - Arrastra la carpeta `auth-bridge/` directamente al navegador y pulsa **Deploy site**.
   - Cloudflare te dará una URL HTTPS única (ejemplo: `https://mi-boveda-auth.pages.dev`).
2. **Configuración en Obsidian Móvil:**
   - En tu móvil Android, abre Obsidian y ve a **Ajustes** → **MySecret** → **Desbloqueo Biométrico en Android**.
   - Pega tu URL de Cloudflare en el campo de texto.
   - Pulsa **Probar URL del puente** para verificar la conexión.
   - Activa el interruptor y realiza tu primer enrolamiento con huella.
3. **Uso Diario:**
   - En la pantalla de bloqueo, pulsa **Desbloqueo Biométrico**. El navegador abrirá el puente, validará tu huella y regresará inmediatamente a Obsidian con la clave de sesión acordada mediante ECDH P-256.

---

## 6. Migración y Procesamiento de la Bóveda

Si instalas MySecret en una bóveda que ya contenía notas en texto plano, o si en el futuro decides descifrar todo para migrar:

1. Ve a **Ajustes** → **MySecret**.
2. Pulsa en **Migración de Bóveda**.
3. Selecciona la opción deseada:
   - **Cifrar Bóveda Completa:** Convierte todas las notas en texto claro, archivos canvas y adjuntos en contenedores cifrados.
   - **Descifrar Bóveda Completa:** Revierte todos los archivos cifrados a notas legibles en texto plano y restaura los archivos originales.
4. Un cuadro de diálogo mostrará una barra de progreso en vivo, contador de archivos y un botón de parada de emergencia.

---

## 7. Copias de Seguridad y Respaldo en la Nube

### Instantáneas Locales
MySecret genera respaldos completos empaquetados en archivos ZIP cifrados:
1. Abre la paleta de comandos (`Ctrl+P` o `Cmd+P`).
2. Ejecuta **MySecret: Crear respaldo cifrado de la bóveda**.
3. Selecciona la carpeta destino donde deseas guardar el archivo `.zip`.

### Restauración Segura
1. Ejecuta el comando **MySecret: Restaurar bóveda desde respaldo**.
2. Selecciona el archivo `.zip` a restaurar.
3. **Seguridad Integrada:** El motor de descompresión cuenta con un módulo de sanitización estricta que bloquea ataques de Path Traversal (Zip Slip) o intentos de sobreescritura de carpetas del sistema.

### Respaldos en la Nube
Puedes subir automáticamente copias de seguridad cifradas a tu proveedor de almacenamiento preferido:
- **WebDAV / Nextcloud / ownCloud:** Conexión directa mediante HTTPS con validación de credenciales.
- **Google Drive:** Almacenamiento seguro en tu unidad de Google.
- **Microsoft OneDrive:** Subida de instantáneas a tu almacenamiento de Microsoft.
- **Seguridad:** Todas las credenciales de nube se almacenan fuertemente cifradas con la clave maestra de la bóveda antes de guardarse en el archivo de configuración.
- **Retención Automática de Copias:** Puedes configurar cuántas copias de seguridad recientes deseas conservar (por ejemplo, las últimas 5 o 10). MySecret podará automáticamente los respaldos más antiguos de esta bóveda, enviándolos a la Papelera en Google Drive y OneDrive para evitar saturar tu almacenamiento sin riesgo de borrado accidental.
- **Respaldo Seguro al Bloquear:** Si tienes activado el respaldo automático al bloquear, MySecret conserva de forma segura la clave en memoria hasta que el archivo ZIP termina de construirse, notificándote si algún archivo no pudo empaquetarse.

---

## 8. Recuperación ante Desastres y Gestión de Claves

### ¿Qué hacer si olvidas tu Contraseña Maestra?
1. En la pantalla de bloqueo, pulsa en **¿Olvidaste tu contraseña? / Frase de rescate**.
2. Introduce las 24 palabras BIP-39 separadas por un espacio simple.
3. El motor criptográfico regenerará la clave maestra original de 256 bits.
4. El sistema te pedirá establecer una nueva contraseña maestra. Todos tus archivos existentes permanecerán intactos y accesibles.

### Cambiar tu Contraseña Maestra
1. Desbloquea la bóveda de forma habitual.
2. En la paleta de comandos o en Ajustes, selecciona **Cambiar contraseña maestra**.
3. Por seguridad, el plugin te solicitará **confirmar tu contraseña actual** (ventana de reautenticación de 2 minutos).
4. Introduce tu nueva contraseña (mínimo 12 caracteres).
5. El sobre maestro se re-encripta con una nueva sal Argon2id de forma instantánea, preservando tu identificador de bóveda para no romper la biometría.

> [!WARNING]
> **Aviso importante sobre el cambio de contraseña:**  
> Cambiar la contraseña maestra vuelve a proteger la clave de la bóveda, pero **no re-cifra las notas con una clave nueva**. Si sospechas que tu contraseña anterior fue comprometida o filtrada, exporta tus notas en texto plano y crea una bóveda nueva.

---

## 9. Cómo Descifrar tus Notas sin el Plugin ni Obsidian (Cero Dependencia)

Una de las grandes fortalezas de MySecret es que **nunca estás cautivo del plugin ni de Obsidian**. Debido a que utiliza los estándares mundiales **AES-256-GCM**, **Argon2id** y **BIP-39**, puedes descifrar tus notas de forma 100% independiente con herramientas externas.

El repositorio incluye herramientas listas para usar dentro de la carpeta `tools/`:

### Método 1: Desde Cualquier Navegador (100% Offline)
Sin instalar nada. Sirve para **una nota o un adjunto a la vez**, con tu frase de rescate:
1. Abre con doble clic [`tools/offline-decryptor.html`](tools/offline-decryptor.html) en tu navegador (Chrome, Firefox, Safari o Edge).
2. Abre `.obsidian/plugins/mysecret/vault-envelope.json` con un editor de texto y pega todo su contenido.
3. Escribe tu frase de rescate BIP-39 de 24 palabras.
4. Indica la ruta **exacta** que tenía el archivo en la bóveda (p. ej. `Notas/Diario.md`). La ruta forma parte de los datos autenticados: una ruta incorrecta falla a propósito.
5. Pega la nota cifrada (empieza con `-----BEGIN MYSECRET ENCRYPTED FILE-----`) o elige un adjunto cifrado y pulsa **Descifrar**.

> Las bóvedas creadas sin frase de recuperación (modo «solo contraseña») no pueden usar esta página: usa el Método 2 con `--password`.

### Método 2: Con el Script de Python (`tools/standalone-decryptor.py`)
Para descifrar una bóveda completa con cientos de notas e imágenes de una sola vez:
1. Instala las dependencias (`argon2-cffi` solo se necesita con `--password`):
   ```bash
   pip install cryptography argon2-cffi
   ```
2. Descifra toda la bóveda con tu frase de rescate de 24 palabras:
   ```bash
   python tools/standalone-decryptor.py --vault "/ruta/a/tu/boveda" --mnemonic "palabra1 palabra2 ... palabra24" --output "/ruta/a/boveda_descifrada"
   ```
3. O con tu Contraseña Maestra. La herramienta lee `.obsidian/plugins/mysecret/vault-envelope.json` (usa `--envelope` si está en otro sitio). Deja `--password` sin valor para que te la pida y no quede en el historial del shell:
   ```bash
   python tools/standalone-decryptor.py --vault "/ruta/a/tu/boveda" --password --output "/ruta/a/boveda_descifrada"
   ```
4. El script reconstruye la jerarquía con todas las notas y adjuntos en texto plano. La carpeta de salida debe estar **fuera** de la bóveda. Para un solo archivo: `--file nota.md --relative-path "Notas/nota.md"`.

### Método 3: Con CyberChef (Herramienta Web de GCHQ)
1. Abre [CyberChef](https://gchq.github.io/CyberChef/).
2. Añade la operación **AES Decrypt**.
3. Selecciona el modo **GCM**.
4. Pega la clave derivada (32 bytes), el IV (12 bytes) y en los datos autenticados adicionales (AAD) introduce la ruta del archivo (ejemplo: `Notas/Idea.md`).

---

## 10. Preguntas Frecuentes (FAQ)

#### P: ¿Se cifran los nombres de los archivos y carpetas?
**R:** Los nombres de los archivos en disco se mantienen visibles para que el motor de indexación, enlaces bidireccionales y vista de árbol de Obsidian funcionen con el máximo rendimiento. Sin embargo, todo el contenido de las notas, metadatos frontmatter, lienzos y archivos adjuntos quedan 100% cifrados.

#### P: ¿Puedo usar Obsidian Sync, Git o sincronizaciones en la nube?
**R:** ¡Sí! Dado que los archivos en disco son ficheros de texto estándar con contenido cifrado, servicios como Obsidian Sync, Git, Dropbox, iCloud o Syncthing simplemente sincronizarán los contenedores seguros. Ningún proveedor de la nube podrá leer el contenido de tus notas.

#### P: ¿Qué ocurre si desinstalo el plugin?
**R:** Si desinstalas el plugin mientras tus archivos están cifrados, permanecerán cifrados en el disco. Para dejarlos en texto plano, ejecuta la opción **Descifrar Bóveda Completa** antes de eliminar el plugin. Si ya lo eliminaste, basta con volver a instalar MySecret e introducir tu contraseña maestra para descifrarlos.
