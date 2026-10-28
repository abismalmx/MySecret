# MySecret — Manual de Usuario

[English Version](USER_GUIDE.md) • **Español**

> [!IMPORTANT]
> ### ⚠️ Lee esto antes de instalar nada
> MySecret **cifra de verdad** los archivos de tu bóveda. Si pierdes la contraseña maestra **y** las 24 palabras de rescate, tus notas se pierden **para siempre**: no hay correo de recuperación, ni botón de "desbloquear", ni soporte técnico que pueda ayudarte. Por eso, lo primero que te vamos a pedir es una **copia de seguridad** de tu bóveda. Son dos minutos de trabajo y te salvan la vida.

---

## 📖 Cómo leer este manual

Este manual está escrito para que lo entienda **cualquier persona**, no solo técnicos. Por eso:

- Cada sección empieza con **"En una frase"**: qué consigues con ella.
- Las palabras técnicas aparecen siempre **traducidas a lenguaje cotidiano**. Si necesitas el rigor, están en el [Glosario](#3-glosario-las-palabras-que-verás-en-los-ajustes).
- Si algo puede salir mal, hay un aviso. Si puede salir mal **de forma irrecuperable**, está marcado como tal.

**Elige tu camino:**

| ¿Eres…? | Empieza por… | ⏱️ |
| :--- | :--- | :---: |
| 👤 Usuario normal, quiero cifrar mis notas ya | [4. Antes de empezar](#4-antes-de-empezar-el-checklist-de-instalación) | 15 min |
| 🔄 Vengo de una bóveda con notas y quiero migrarla | [11. Migración y mantenimiento](#11-migración-y-mantenimiento-de-la-bóveda) | 20 min |
| 😰 He perdido la contraseña y necesito recuperar | [12. Recuperación ante desastres](#12-recuperación-ante-desastres) | 5 min |
| 📱 Uso el móvil y quiero la huella dactilar | [9. Desbloqueo biométrico](#9-desbloqueo-con-huella-dactilar-face-id-y-touch-id) | 20 min |
| 🧠 Me interesa entender el "por qué" por dentro | [2. Cómo funciona por dentro](#2-cómo-funciona-por-dentro-explicado-sin-jerga) | 15 min |

---

## 📑 Índice

**PARTE I — Entender**
1. [Qué es MySecret de verdad (sin jerga)](#1-qué-es-mysecret-de-verdad-sin-jerga)
2. [Cómo funciona por dentro (explicado sin jerga)](#2-cómo-funciona-por-dentro-explicado-sin-jerga)
3. [Glosario: las palabras que verás en los ajustes](#3-glosario-las-palabras-que-verás-en-los-ajustes)

**PARTE II — Instalar y empezar**
4. [Antes de empezar: el checklist de instalación](#4-antes-de-empezar-el-checklist-de-instalación)
5. [Instalar el plugin (paso a paso)](#5-instalar-el-plugin-paso-a-paso)
6. [El asistente de configuración inicial](#6-el-asistente-de-configuración-inicial-paso-a-paso)
7. [Tu primer día: usar la bóveda a diario](#7-tu-primer-día-usar-la-bóveda-a-diario)

**PARTE III — Configurar**
8. [Los ajustes explicados sección por sección](#8-los-ajustes-explicados-sección-por-sección)
9. [Desbloqueo con huella, Face ID y Touch ID](#9-desbloqueo-con-huella-dactilar-face-id-y-touch-id)

**PARTE IV — Proteger y recuperar**
10. [Copias de seguridad y respaldo en la nube](#10-copias-de-seguridad-y-respaldo-en-la-nube)
11. [Migración y mantenimiento de la bóveda](#11-migración-y-mantenimiento-de-la-bóveda)
12. [Recuperación ante desastres](#12-recuperación-ante-desastres)
13. [Descifrar tus notas sin el plugin ni Obsidian](#13-descifrar-tus-notas-sin-el-plugin-ni-obsidian)

**PARTE V — Referencia**
14. [Preguntas frecuentes (FAQ)](#14-preguntas-frecuentes-faq)
15. [Solución de problemas](#15-solución-de-problemas)
16. [Checklist final de seguridad](#16-checklist-final-de-seguridad)

---

## 1. Qué es MySecret de verdad (sin jerga)

**En una frase:** MySecret convierte tu carpeta de notas en una caja fuerte: dentro de Obsidian sigues viendo y usando tus notas exactamente igual, pero en tu disco solo hay código indescifrable.

### La analogía del cristal unidireccional

Piensa en una ventana desde la que se ve una habitación pero desde fuera solo se ve un espejo. MySecret se coloca entre Obsidian y tu disco duro:

| Desde dentro de Obsidian | Desde fuera (disco, nube, un ladrón con tu portátil) |
| :--- | :--- |
| Escribes, editas, buscas | Solo hay ruido matemático |
| La búsqueda global encuentra cualquier frase | Ningún proveedor de nube puede leer nada |
| El grafo de conocimiento funciona | Una nota robada es indescifrable |
| Las imágenes se ven normalmente | Los adjuntos también están cifrados |

### Lo que SÍ se cifra

- ✅ El texto de todas tus notas (`.md`).
- ✅ El **frontmatter** (los metadatos YAML del principio de la nota: etiquetas, aliases, propiedades).
- ✅ Los **lienzos** de Obsidian (`.canvas`).
- ✅ **Todos los adjuntos**: imágenes, PDFs, audio, vídeo, cualquier archivo binario.
- ✅ Las copias de seguridad en ZIP que genera el plugin.

### Lo que NO se cifra (y por qué no es un problema)

- ⚠️ **Los nombres de los archivos y de las carpetas.** No es un descuido: Obsidian necesita leer esos nombres para mantener su índice, la búsqueda, los enlaces bidireccionales y la vista de árbol. Si los cifrara, Obsidian se rompería. Tu contenido sí está 100% cifrado.
- ⚠️ **Las carpetas del sistema** `.obsidian/`, `.git/` y `.trash/`. Son ajustes del programa, no tus notas. (Por eso `vault-envelope.json` vive ahí: es la "caja" donde se guarda tu llave cifrada.)
- ⚠️ **Un archivo oculto en la raíz** como `.DS_Store` o `.gitignore`. En cambio, **una nota oculta dentro de una carpeta sí se cifra** (p. ej. `Notas/.privada.md`).

### Lo que MySecret NO es

Para evitar malentendidos:

- ❌ **No es un antivirus** ni bloquea la entrada de malware.
- ❌ **No es un gestor de contraseñas**: guarda tus notas, no tus cuentas.
- ❌ **No cifra tu disco entero**: solo tu bóveda de Obsidian.
- ❌ **No sube nada a internet por su cuenta.** La única conexión opcional es el puente biométrico en móvil, y es unidireccional (tú sales hacia el puente; el puente nunca ve tus notas).
- ❌ **No te protege de alguien que mire tu pantalla mientras escribes.** Cifra en reposo (en disco), no frente a la mirada.

---

## 2. Cómo funciona por dentro (explicado sin jerga)

> Si solo quieres usar el plugin, puedes saltarte esta sección. Pero leerla te evitará sorpresas y te permitirá tomar mejores decisiones (por ejemplo, cuándo activar el auto-bloqueo o si conviene una frase de rescate).

### 2.1 La llave de la caja fuerte

Hay una sola llave que abre y cierra todo: la **clave de bóveda** (llamada *VaultKey*), un número aleatorio de 256 bits generado en tu propio dispositivo.

Esa llave se guarda "envuelta" (cifrada) dentro de un archivo llamado **`vault-envelope.json`** (el "sobre"), que vive en:

```
<tu-bóveda>/.obsidian/plugins/mysecret/vault-envelope.json
```

Y el sobre está cifrado, a su vez, con una llave derivada de **una de estas dos cosas**:

- Tu **contraseña maestra**, procesada con **Argon2id** (64 MB de memoria, 3 iteraciones).
- Tus **24 palabras de rescate**, procesadas con PBKDF2-HMAC-SHA512 (2048 iteraciones).

> **Consecuencia práctica:** si no tienes la contraseña **ni** las palabras, el sobre no se puede abrir. No hay atajo, ni puerta trasera, ni recuperación "mágica". Por eso el asistente te pide generar la frase de rescate: es tu segundo camino de entrada.

MySecret además guarda una copia `.bak` del sobre (`vault-envelope.json.bak`) y lo escribe de forma atómica: primero en un temporal, lo relee para comprobar que está bien, guarda la copia anterior y solo entonces sustituye el original. Así, un fallo a mitad de escritura **no puede** dejarte sin llave.

### 2.2 Qué pasa cuando guardas una nota

1. Escribes tu nota en Obsidian.
2. Obsidian pide guardar el archivo en el disco.
3. **MySecret intercepta la petición antes de que toque el disco** y cifra el contenido con **AES-256-GCM**.
4. En tu disco queda un contenedor con esta forma:

   ```markdown
   -----BEGIN MYSECRET ENCRYPTED FILE-----
   Version: 1
   IV: d8f3a9e1b2c4d5e6f7a8b9c0
   Tag: 4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d

   q8XyZ1v...[Contenido Cifrado en Base64]...==
   -----END MYSECRET ENCRYPTED FILE-----
   ```

5. Cuando abres la nota, ocurre al revés: MySecret descifra **en memoria** y Obsidian nunca ve el texto cifrado.

**Los adjuntos** (imágenes, PDFs, audio) se guardan en formato binario compacto: 4 bytes mágicos `MYSE`, un byte de versión, el vector de inicialización (IV) de 12 bytes y la etiqueta de autenticación (Tag) de 16 bytes, seguidos del contenido cifrado.

### 2.3 Las cuatro palabras que importan

| Palabra | Qué significa en tu día a día |
| :--- | :--- |
| **AES-256-GCM** | El candado. El mismo estándar que usan las apps bancarias. |
| **IV** | Un número aleatorio distinto en cada guardado. Evita que dos notas idénticas produzcan archivos idénticos. |
| **Tag** | La "firma" que comprueba que nadie ha modificado el contenido. Si alguien edita un byte del archivo cifrado, deja de abrirse. |
| **AAD (datos autenticados)** | La **ruta del archivo** dentro de la bóveda se firma junto al contenido. Si alguien renombra "Nota.md" a "Secreto.md" a mano, el archivo deja de descifrarse. Impide que alguien mezcle, cambie o robe archivos sueltos. |

> ℹ️ El AAD también significa algo bueno en el uso diario: **puedes renombrar y mover notas con normalidad** dentro de Obsidian. MySecret detecta el renombrado y vuelve a "firmar" el archivo en su nueva ruta. Solo fallaría si alguien renombra el archivo **por fuera de Obsidian**, directamente en el explorador de archivos.

### 2.4 Por qué la búsqueda y el grafo siguen funcionando

MySecret no "abre" tus notas: **descifra en memoria** mientras la bóveda está desbloqueada. Para Obsidian, tus notas son notas normales, así que la búsqueda global, el conmutador rápido, los enlaces, el grafo y los lienzos funcionan con normalidad total.

En cuanto bloqueas la bóveda:
- La llave se borra de la memoria RAM (se sobrescribe con ceros, no simplemente se "borra el puntero").
- Las notas abiertas se cierran y el contenido en claro que Obsidian tenía en caché se descarta.
- La pantalla se cubre con un velo borroso para que no se vea nada detrás.

> 🔐 Esto protege frente a un acceso casual (alguien abre tu portátil, o una búsqueda en el historial de Obsidian). No es una protección frente a un debugger con permisos de administrador, y el manual de seguridad del propio plugin lo dice con total honestidad.

### 2.5 Qué pasa cuando sincronizas

Los archivos de tu disco son texto cifrado estándar, así que **Obsidian Sync, Git, Dropbox, iCloud, Syncthing, OneDrive…** simplemente los copian sin poder leerlos.

Detalle técnico que te afecta en el día a día: MySecret ajusta el "hash" que usa Obsidian Sync para detectar cambios, de modo que el hash que compara es el del **texto cifrado** (igual que el de la nube). Sin esta alineación, Obsidian Sync creería que todos tus archivos han cambiado en cada arranque y re-descargaría y re-escribiría la bóveda entera, una y otra vez.

### 2.6 Guardas que no verás nunca (pero que te protegen)

| Guarda | Qué evita |
| :--- | :--- |
| **Anti-doble-cifrado** | Que un archivo ya cifrado se cifre otra vez y quede irrecuperable. |
| **Anti-degradación de Argon2id** | Que alguien edite el sobre para bajar los parámetros y convertir un descifrado lento en uno instantáneo. Si los parámetros son demasiado bajos, el plugin **rechaza** el sobre en vez de aceptarlo. |
| **Límites del sobre** | Que un sobre manipulado pida 4 GB de memoria y bloquee la aplicación. |
| **Bloqueo de publicación** | Si tienes **Obsidian Publish** activo, MySecret impide subir notas cifradas en claro a un sitio web público. Te avisa con un aviso de 15 segundos. |
| **Restauración autenticada** | Al restaurar un ZIP, cada archivo se juzga por su **contenido real**, no por lo que su manifiesto diga. El texto cifrado debe autenticarse con la llave de *esta* bóveda y *esta* ruta. |
| **Anti-ZIP Slip / anti-ZIP bomb** | Que un ZIP malicioso escriba archivos fuera de la bóveda o desborde la memoria. |
| **Re-autenticación en acciones sensibles** | Ver la frase, cambiarla, borrarla, registrar la huella o exportar en texto plano **piden la contraseña maestra otra vez**, aunque la bóveda esté desbloqueada. Tener la bóveda abierta no basta. |

## 3. Glosario: las palabras que verás en los ajustes

Si en algún punto de la interfaz te sale una palabra rara, búscala aquí.

| Palabra técnica | Qué es, en lenguaje normal |
| :--- | :--- |
| **Cifrado** | Convertir tu texto en un código que solo se puede leer con la llave correcta. |
| **Cifrado transparente** | Cifrar sin que te enteres: tú usas Obsidian igual, el cifrado pasa por detrás. |
| **Cifrado en reposo** | El cifrado que ocurre cuando el archivo está guardado en el disco (no mientras lo miras). |
| **Clave / llave** | El "secreto" que abre y cierra el candado. |
| **Clave maestra** | Tu contraseña maestra. Es la llave principal de tu bóveda. |
| **Clave de bóveda (VaultKey)** | La llave real que cifra tus notas. Se genera al azar en tu dispositivo y nunca se escribe en claro. |
| **Sobre (envelope)** | El archivo `vault-envelope.json` donde se guarda tu llave de bóveda ya cifrada. Piensa en él como la "caja fuerte" que contiene la llave. |
| **Argon2id** | El algoritmo que convierte tu contraseña en una llave. Está diseñado para que probar millones de contraseñas sea carísimo. |
| **Sal (salt)** | Un número aleatorio que se añade a tu contraseña antes de derivarla, para que dos usuarios con la misma contraseña tengan llaves distintas. |
| **AES-256-GCM** | El algoritmo que cifra el contenido de tus archivos. Estándar mundial, acelerado por hardware. |
| **IV (vector de inicialización)** | Un valor aleatorio distinto en cada cifrado, para que dos archivos iguales no se parezcan. |
| **Tag** | La firma que detecta si alguien ha modificado un archivo cifrado. |
| **AAD** | La ruta del archivo, firmada junto al contenido. Impide que alguien robe un archivo y lo ponga en otro sitio. |
| **BIP-39** | El estándar de las 24 palabras de rescate. Es el mismo que usan las billeteras de criptomonedas, y por eso hay tanto software que lo entiende. |
| **Frase de rescate / mnemónico** | Tus 24 palabras. La segunda llave de tu bóveda. |
| **RAM / memoria RAM** | La memoria de trabajo de tu equipo. Las llaves viven ahí mientras la bóveda está abierta. |
| **Zeroización** | Sobrescribir la llave con ceros para que no quede rastro en la memoria. |
| **WebAuthn** | El estándar del navegador (y de los móviles) para autenticarse con huella, rostro o llave física. |
| **Puente (bridge)** | La pequeña web que sirve de puente entre Obsidian en el móvil y el sensor biométrico del teléfono. |
| **ECDH** | El intercambio de claves que permite que el puente y Obsidian se entiendan sin que ninguno entregue su secreto. |
| **PWA** | "Progressive Web App": una web que se puede usar como app y guardar en el móvil. El puente es una PWA. |
| **Frontmatter** | El bloque YAML del principio de una nota (etiquetas, aliases). MySecret también lo cifra. |
| **Obsidian Publish** | El plugin de pago de Obsidian que publica notas en una web pública. MySecret bloquea la publicación de notas cifradas. |
| **BRAT** | Un plugin de Obsidian que instala otros plugins desde su repositorio de GitHub. |
| **HMAC / SHA-256 / SHA-512** | Funciones de "picado digital": convierten cualquier dato en una huella corta e irrepetible. |

---

## 4. Antes de empezar: el checklist de instalación

**En una frase:** cuatro pasos, quince minutos, y tu bóveda queda protegida.

> [!WARNING]
> ### ⚠️ Paso 0 (obligatorio): copia tu bóveda ANTES de tocar nada
> MySecret va a cifrar los archivos **reales** de tu disco. Antes de instalar:
>
> 1. Cierra Obsidian.
> 2. Copia **toda** la carpeta de tu bóveda a otro sitio: un disco externo, una memoria USB, o tu nube.
> 3. Comprueba que la copia se ha hecho bien (abre un par de notas desde la copia).
>
> **¿Por qué es obligatorio?** Porque si luego pierdes la contraseña **y** las 24 palabras, no hay forma de recuperar los archivos. Es el único seguro que existe. Hacer la copia tarda 2 minutos; perder años de notas, no tiene precio.

### Checklist de 4 pasos

- [ ] **1.** He cerrado Obsidian y he copiado mi bóveda a otro sitio.
- [ ] **2.** He instalado el plugin (hay dos formas, en la [sección 5](#5-instalar-el-plugin-paso-a-paso)).
- [ ] **3.** He completado el asistente de configuración y **he anotado las 24 palabras en papel**.
- [ ] **4.** He comprobado que puedo desbloquear la bóveda y que mis notas se ven bien.

> 💡 **Consejo:** guarda la copia de seguridad en un sitio **diferente** del disco donde vive tu bóveda. Si tu portátil se rompe, te llevas por delante la bóveda y su copia. Un disco externo, una USB en tu cajón o tu nube personal sirven perfectamente.

### Requisitos

| Requisito | Detalle |
| :--- | :--- |
| **Obsidian** | Versión 1.5.0 o superior. |
| **Sistema operativo** | Windows, macOS, Linux, Android o iOS/iPadOS. |
| **Espacio en disco** | El mismo que usas normalmente, más el tamaño de tus notas cifradas (prácticamente idéntico). |
| **Internet** | Solo para descargar el plugin (BRAT) o el puente biométrico en móvil. **El cifrado en sí funciona 100% sin internet.** |
| **Navegador** | Solo si vas a usar el descifrador de emergencia del navegador ([sección 13](#13-descifrar-tus-notas-sin-el-plugin-ni-obsidian)). |

---

## 5. Instalar el plugin (paso a paso)

**En una frase:** hay dos caminos; los dos son gratis.

### Método A: BRAT (recomendado, se actualiza solo)

BRAT es un plugin que instala otros plugins directamente desde GitHub y te avisa cuando hay versiones nuevas. Es la forma más cómoda de seguir MySecret al día.

1. En Obsidian, ve a **Ajustes → Plugins de la comunidad** y desactiva el modo seguro (*Restricted mode*).
2. Busca **BRAT** e instálalo y actívalo.
3. Ve a **Ajustes → BRAT** y pulsa **Add Beta plugin**.
4. Pega esta dirección:
   ```
   https://github.com/abismalmx/MySecret
   ```
5. Pulsa **Add Plugin** y espera a que termine la descarga.
6. Ve a **Ajustes → Plugins de la comunidad**, busca **MySecret** y **actívalo**.
7. Reinicia Obsidian (o usa **Recargar plugins sin guardar** en la paleta de comandos).

> ℹ️ Con este método, BRAT te avisará automáticamente cuando haya una versión nueva. Cuando la instales, reinicia Obsidian.

### Método B: instalación manual (sin BRAT)

1. Ve a la sección [Releases](https://github.com/abismalmx/MySecret/releases) de GitHub.
2. Descarga **estos tres archivos** de la última versión:
   - `main.js`
   - `manifest.json`
   - `styles.css`
3. Abre la carpeta de tu bóveda de Obsidian y entra en `.obsidian/plugins/`.
   - 💡 En Windows y macOS las carpetas que empiezan por punto están ocultas: pulsa **⌘/Ctrl + Shift + .** (macOS) o **Ctrl + H** (Windows) para verlas.
4. Crea una carpeta llamada **`mysecret`** y mete dentro los tres archivos:
   ```
   <tu-bóveda>/.obsidian/plugins/mysecret/
   ├── main.js
   ├── manifest.json
   └── styles.css
   ```

5. En Obsidian, ve a **Ajustes → Plugins de la comunidad**, recarga la lista y activa **MySecret**.
6. Reinicia Obsidian.

### ¿Cómo sé que funcionó?

Al activar el plugin por primera vez, MySecret **no** cifra nada todavía. Simplemente te abrirá el **asistente de configuración** ([sección 6](#6-el-asistente-de-configuración-inicial-paso-a-paso)) para que elijas tu contraseña maestra. Hasta que completes ese asistente, tu bóveda sigue en texto plano.

> 🔐 **¿Y si ya tengo una bóveda con notas?** Las notas que ya tienes **no se cifran solas**. Al final del asistente te saldrá un botón **"🔒 Cifrar notas existentes ahora"**. También puedes hacerlo después desde **Ajustes → MySecret → Mantenimiento Masivo de Archivos en Disco → Cifrar Toda la Bóveda**. Los detalles están en la [sección 11](#11-migración-y-mantenimiento-de-la-bóveda).

---

## 6. El asistente de configuración inicial (paso a paso)

**En una frase:** cuatro pantallas, dos minutos, y tu bóveda queda protegida para siempre.

El asistente aparece **automáticamente** la primera vez que activas MySecret en una bóveda. No se puede cerrar con la tecla `Esc` a propósito: es una protección para que no se te corte a mitad de la inicialización.

```
┌───────────────────────────────────────────────────────────────┐
│  1. Contraseña y modo  →  2. Frase de auxilio  →            │
│  3. Verificación       →  4. Huella digital                   │
└───────────────────────────────────────────────────────────────┘
```

### Paso 1 — Contraseña maestra y modo de recuperación

Escribes tu contraseña maestra dos veces. La segunda es solo para confirmar que te la sabes de memoria.

**Reglas de la contraseña:**
- Mínimo **12 caracteres**.
- El medidor de fuerza te da una nota en **bits** (cuántos bits de entropía tiene). Por encima de **80 bits** ya es muy robusta.
- El asistente **rechaza** contraseñas débiles: no te deja continuar con una que solo tenga letras minúsculas repetidas o secuencias tipo `abcdef`.

**💡 Cómo inventar una contraseña que puedas recordar:**
Usa 4 o 5 palabras que no tengan relación entre sí, unidas por un separador. Por ejemplo:
```
coral-galaxia-roble-pantera-faro
```
Son 5 palabras, 30 caracteres, fácil de recordar para ti e **imposible** de adivinar para un atacante. Esta técnica se llama "passphrase" y hoy es la recomendación de los expertos en seguridad.

**Además, eliges uno de dos modos de recuperación:**

| Modo | Qué pasa | ¿Para quién? |
| :--- | :--- | :--- |
| 🔑 **Frase de recuperación de 24 palabras** *(recomendado)* | Se genera y se guarda cifrada una segunda llave. Si olvidas la contraseña, las 24 palabras te salvan. | La mayoría de la gente. |
| 🛡️ **Solo contraseña maestra** *(máxima seguridad)* | **No se guarda ninguna llave de auxilio en el disco.** Si olvidas la contraseña, la pérdida es permanente. | Solo si estás en un entorno muy controlado y tienes otra copia verificada por fuera. |

> ⚠️ Si eliges el modo "solo contraseña", la única forma de recuperar tu bóveda será un descifrador externo **que ya tenga tu frase de rescate**… que en este modo no existe. Es decir: sin contraseña, sin vuelta atrás. Ya que estás leyendo esto: elige el modo con frase de rescate.

### Paso 2 — Tus 24 palabras de rescate

MySecret genera 256 bits de entropía criptográfica y los convierte en 24 palabras de una lista estándar (BIP-39). Verás las palabras en tarjetas numeradas.

**Lo que debes hacer:**

1. **Copia** la frase con el botón **"📋 Copiar frase"** (el portapapeles se borra solo a los 30 segundos, para que no quede ahí tu secreto).
2. **Anótala en papel.** En serio: papel. Es lo más seguro que existe.
3. Si no quieres que nadie te espere mientras la copias, pulsa **"🙈 Ocultar palabras"**.
4. Pulsa **"He guardado mi auxilio →"** cuando la tengas anotada.

> [!IMPORTANT]
> **La frase NO volverás a mostrarse por el mismo camino.** El plugin la guarda en memoria **solo durante esta sesión**, y solo para el caso de que cierres el asistente sin haberla anotado. En cuanto bloquees la bóveda, desaparece de la RAM.
>
> ¿Y si la perdí igualmente? Hay una salida: desde **Ajustes → MySecret → Gestión de Contraseña y Recuperación → Ver frase de recuperación** puedes volver a verla (te pedirá la contraseña maestra). Si ya habías bloqueado la bóveda, tu frase ya no está en memoria y **no se puede regenerar**: habría que crear una bóveda nueva.

**Dónde guardarla (de mejor a peor):**
- 🥇 Una caja fuerte, una libreta con candado, o tu gestor de contraseñas (que suele cifrar con una llave derivada de tu contraseña).
- 🥈 Un sobre sellado en tu casa, guardado en un lugar seco y seguro.
- 🥉 Una tarjeta en tu cartera.
- ❌ **Nunca**: en el mismo disco que la bóveda, en una nota de la propia bóveda, en un archivo de texto en la nube, ni en un chat.

> 💡 **Truco para no perderla:** si la bóveda está en el móvil y la frase en el portátil, un fallo en cualquiera de los dos te deja sin acceso. Lo ideal es tener **dos copias en sitios distintos**, y una de ellas **fuera de tu casa**.

### Paso 3 — El desafío de verificación

Para confirmar que la anotaste bien, MySecret te pide **dos palabras** al azar de tu frase (por ejemplo, la número 6 y la número 18).

- Si las escribes bien → un ✓ verde de **"Respaldo verificado correctamente"**.
- Si te equivocas → el campo se marca en rojo y puedes reintentar.

> ℹ️ Esto **no** protege tu bóveda: es solo una comprobación de que la frase está bien anotada. Si te equivocas, puedes seguir adelante (el botón de continuar aparece igualmente); simplemente conviene asegurarte antes de seguir, porque es tu única red de seguridad.

**Aquí te aparece el botón "🔒 Cifrar notas existentes ahora"** si tu bóveda ya tenía notas. Si lo pulsas, MySecret empieza a cifrar todo lo que encuentra (miles de archivos, un rato). Si no lo pulsas ahora, puedes hacerlo después desde los ajustes.

### Paso 4 — Desbloqueo rápido con huella (opcional)

MySecret comprueba si tu equipo tiene sensor biométrico disponible y te ofrece registrarlo.

- **Si tienes un sensor** (Windows Hello, Touch ID, huella en Linux, o móvil con puente configurado): regístralo ahora. Es cómodo y te ahorra teclear la contraseña cada vez.
- **Si no tienes sensor, o prefieres no usarlo**: sáltalo. Puedes registrarlo más tarde desde los ajustes.
- Al terminar, tu bóveda queda **desbloqueada** y lista para usar.

### ¿Y si el asistente falla?

MySecret escribe la llave en el disco **antes** de desbloquearla en memoria. Si algo sale mal a mitad del proceso, tu bóveda **no** queda a medias: o se inicializa bien, o no se inicializa.

Si al abrir Obsidian ves este aviso:

> *vault-envelope.json existe pero está dañado o ha sido modificado. No se creará una bóveda nueva.*

**No hagas nada raro.** MySecret se niega a crear una bóveda nueva precisamente para no invalidar tus notas ya cifradas. Restaura el archivo `vault-envelope.json` (o su `.bak`) desde tu copia de seguridad y vuelve a abrir Obsidian.

---

## 7. Tu primer día: usar la bóveda a diario

**En una frase:** a partir de aquí, MySecret desaparece. Escribes, buscas y trabajas como siempre.

### Desbloquear la bóveda

Cada vez que abras Obsidian con una bóveda cifrada:

1. Aparece la **pantalla de bloqueo** de MySecret. No puedes cerrarla con `Esc` ni hacer clic alrededor: es deliberado.
2. Escribe tu **contraseña maestra** y pulsa **Desbloquear Bóveda**.
   - El proceso tarda un momento (unos 240 ms) porque tiene que "cocer" tu contraseña con Argon2id. Verás **"Derivando clave…"** y luego **"Descifrando…"**. Es normal y es la prueba de que el cifrado es fuerte.
   - Si te equivocas, verás **"Contraseña maestra incorrecta"** y la tarjeta dará un tirón. Vuelve a intentarlo.
3. Si tienes la biometría activada, también puedes pulsar el botón **"Desbloquear con Huella Digital"**.
4. La pantalla desaparece y Obsidian funciona con normalidad.

### El icono del candado (tu indicador de estado)

En la **barra lateral izquierda** de Obsidian hay un icono de candado de MySecret. Es tu indicador:

| Icono | Significado | Al hacer clic |
| :--- | :--- | :--- |
| 🔴 **Candado rojo** | Bóveda **bloqueada**. Nada se puede leer. | Abre la pantalla de desbloqueo. |
| 🟢 **Candado verde** | Bóveda **desbloqueada**. Todo funcionando. | **Bloquea** la bóveda al instante. |

> 💡 **Consejo:** si haces clic en el candado verde para bloquear, es la forma más rápida de "cerrar" cuando te vas. El atajo de teclado es la **paleta de comandos** (`Ctrl+P` / `Cmd+P`) → **MySecret: Bloquear bóveda ahora**.

   ```
   <tu-bóveda>/.obsidian/plugins/mysecret/
   ├── main.js
   ├── manifest.json
   └── styles.css
   ```

### Los comandos que tienes disponibles

Abre la paleta de comandos (`Ctrl+P` en Windows/Linux, `Cmd+P` en macOS) y escribe **MySecret** para verlos todos:

| Comando | Qué hace |
| :--- | :--- |
| **MySecret: Bloquear bóveda ahora** | Bloquea al instante y borra las llaves de la memoria RAM. |
| **MySecret: Desbloquear bóveda** | Abre la pantalla de desbloqueo (si la bóveda está bloqueada). |
| **MySecret: Cambiar contraseña maestra** | Cambia tu contraseña. Ver [sección 12](#12-recuperación-ante-desastres). |
| **MySecret: Exportar respaldo de la bóveda (ZIP)** | Crea un `.zip` con tus notas. Ver [sección 10](#10-copias-de-seguridad-y-respaldo-en-la-nube). |
| **MySecret: Configurar copia de seguridad en la nube** | Configura Google Drive, OneDrive, WebDAV o una carpeta local. |
| **MySecret: Restaurar respaldo de la bóveda (ZIP)** | Recupera tus notas desde un `.zip` de respaldo. |
| **MySecret: Cifrar Toda la Bóveda** | Cifra en lote las notas que aún estén en texto plano. |

### Auto-bloqueo: que se bloquee solo

Esta es la función que más te va a dar tranquilidad. Si te levantas del escritorio y dejas el portátil abierto, MySecret bloquea la bóveda solo.

1. Ve a **Ajustes → MySecret → Protección y Bloqueo Automático**.
2. En **Auto-bloqueo por inactividad**, elige el tiempo: **Desactivado**, 1 minuto, 5 minutos (recomendado), 15 minutos o 30 minutos.
3. Activa **"Bloquear al minimizar o cambiar de ventana"** si quieres que se bloquee en cuanto cambies de aplicación.
4. Pulsa **Guardar**.

> ℹ️ MySecret considera "actividad" cualquier cosa que hagas: mover el ratón, escribir, tocar la pantalla, pulsar una tecla. El temporizador se reinicia solo con cada movimiento.

> 💡 **Recomendación práctica:** 5 minutos de inactividad + bloquear al cambiar de ventana. Es el equilibrio habitual entre seguridad y comodidad.

### Qué se ve en el disco (para que no te asustes)

Si abres tu bóveda con el explorador de archivos o con un editor de texto, esto es lo que verás:

**Tus notas (`.md`)** son contenedores de texto:
```markdown
-----BEGIN MYSECRET ENCRYPTED FILE-----
Version: 1
IV: d8f3a9e1b2c4d5e6f7a8b9c0
Tag: 4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d

q8XyZ1v...[Contenido Cifrado en Base64]...==
-----END MYSECRET ENCRYPTED FILE-----
```
**Tus nombres de archivo** siguen siendo legibles (para que Obsidian funcione), pero el **contenido** es ruido.

> 💡 **Prueba rápida para convencerte:** abre una nota en el bloc de notas de Windows y luego ábrela en un editor de texto. En Obsidian leerás tu nota; en el editor de texto, solo verás el contenedor cifrado. Esa es la prueba de que funciona.

**Tus adjuntos** (imágenes, PDFs, audios) son binarios que empiezan con los bytes mágicos `MYSE`, seguidos de la versión, el IV y el Tag.

## 8. Los ajustes explicados sección por sección

**En una frase:** todo lo que puedes cambiar de MySecret está aquí, y te explicamos qué hace cada cosa.

Ve a **Ajustes → MySecret**. Son ocho bloques. Te los explicamos en el orden en que aparecen.

### 8.1 Protección y Bloqueo Automático

| Ajuste | Qué hace | Recomendación |
| :--- | :--- | :--- |
| **Auto-bloqueo por inactividad** | Bloquea la bóveda tras X minutos sin actividad y borra las llaves de la RAM. | **5 minutos** |
| **Bloquear al minimizar o cambiar de ventana** | Bloquea en cuanto minimizas Obsidian o cambias de aplicación. | **Actívalo** |
| **Cifrar archivos adjuntos (imágenes, audios y documentos)** | Si está ON, también se cifran imágenes, PDFs, audio y vídeo. Si lo apagas, **solo** se cifran las notas de texto. | **Déjalo ON** |

> ⚠️ **Sobre apagar el cifrado de adjuntos:** es la única opción "menos segura" del plugin, y tiene una trampa. Al apagarla, MySecret **convierte los adjuntos ya cifrados de vuelta a texto plano** (si no lo hiciera, el siguiente guardado los corrompería). Es decir: apagas el cifrado de adjuntos → tus imágenes y PDFs pasan a estar **en claro en el disco**. Úsalo solo si necesitas que una app externa (un script, un visor) lea tus imágenes sin descifrar.

> 💡 **¿Por qué el auto-bloqueo importa?** Sin él, si desbloqueas la bóveda y te vas sin cerrar Obsidian, las llaves siguen en la RAM todo el día. Con auto-bloqueo de 5 minutos, tu bóveda se cierra sola. Es la diferencia entre "cifrada cuando cierro el programa" y "cifrada siempre".

### 8.2 Desbloqueo Biométrico y Huella Digital

Aquí configuras el desbloqueo con huella, Face ID o Touch ID. Está detallado en la [sección 9](#9-desbloqueo-con-huella-dactilar-face-id-y-touch-id).

Resumen de las opciones:

- **Activar el desbloqueo biométrico en este dispositivo**: el interruptor principal. Al activarlo, MySecret **te pide la contraseña maestra otra vez** (es una acción sensible) y registra tu biometría.
- **Solicitar huella automáticamente al bloquear**: si está ON, al aparecer la pantalla de bloqueo se invoca el sensor directamente sin que pulses nada.
- **Probar huella ahora**: verifica que el sensor y la clave funcionan, sin bloquear nada.
- **Eliminar registro biométrico**: borra la biometría de **este** dispositivo.

> ℹ️ **Dato importante:** la biometría se registra **por dispositivo**. Tu portátil, tu móvil y tu tablet tienen registros distintos. Si borras el registro de uno, los otros siguen funcionando.

### 8.3 Carpetas Excluidas del Cifrado

Esta sección te deja decir: "estas carpetas **no** las cifres".

**¿Para qué sirve?** Para carpetas cuyo contenido necesitas que otras apps puedan leer:
- Notas públicas que quieres publicar en tu web.
- Carpetas compartidas con un sincronizador que no entiende cifrado.
- Archivos que abres con un programa externo (un editor de Markdown, un visor de PDF).

**Cómo añadir una carpeta:**
1. Pulsa **"Seleccionar carpeta…"** y búscala en el explorador, o
2. Escribe la ruta a mano (por ejemplo `Public` o `Notas/Compartido`) y pulsa **Añadir**.
3. También puedes **hacer clic derecho sobre cualquier carpeta en el explorador de archivos de Obsidian** y elegir **"MySecret: Excluir carpeta del cifrado"**. Para volver a cifrarla, misma acción pero eligiendo **"Quitar de carpetas excluidas (Cifrar)"**.
> ⚠️ **Lo que esto significa de verdad:** una carpeta excluida queda **en texto plano en tu disco**, sin cifrar de ninguna manera. Si metes ahí algo muy sensible, estás dejando un agujero. Úsala con criterio.

> ℹ️ MySecret ya excluye **solo**, sin que hagas nada, las carpetas `.obsidian/`, `.git/` y `.trash/`, y los archivos ocultos de la raíz (`.DS_Store`, `.gitignore`). No hace falta que los añadas a la lista.

### 8.4 Gestión de Contraseña y Recuperación

| Botón | Qué hace |
| :--- | :--- |
| **Cambiar Contraseña** | Abre el diálogo para cambiar tu contraseña maestra. Te pide la **actual** y la nueva. |
| **Mostrar Frase** | Vuelve a mostrar tus 24 palabras. Te pide la contraseña maestra antes. |
| **Eliminar Frase de Rescate** | Borra la llave de auxilio del disco. Pide confirmación. |
| **Activar Frase de Rescate** | (Si no la tenías) Genera una frase de 24 palabras nueva y la guarda. |

> ⚠️ **Eliminar la frase de rescate** es irreversible: a partir de ese momento tu contraseña maestra es la **única** forma de abrir la bóveda. MySecret te avisa con un aviso explícito antes de hacerlo.

> ℹ️ **Activar la frase más tarde es una buena idea** si empezaste en modo "solo contraseña". Puedes hacerlo cuando quieras desde estos mismos ajustes.

### 8.5 Copias de Seguridad en la Nube

Configura dónde se suben tus respaldos automáticos. Está detallado en la [sección 10](#10-copias-de-seguridad-y-respaldo-en-la-nube).

| Ajuste | Detalle |
| :--- | :--- |
| **Proveedor de Almacenamiento** | Ninguno, Google Drive, Microsoft OneDrive, WebDAV (Nextcloud/ownCloud/Synology) o carpeta local sincronizada. |
| **Token / credenciales** | Se guardan **cifrados** en tu disco con la llave de tu bóveda. En pantalla se muestran enmascarados. |
| **Probar Conexión** | Verifica que las credenciales funcionan antes de confiar en ellas. |
| **Copia de seguridad automática** | Activa la subida automática. |
| **Cuándo generar la copia** | Al bloquear la bóveda, por intervalo regular, o ambos. |
| **Frecuencia** | Cada 1, 6, 12, 24 (recomendado) o 72 horas. |

### 8.6 Exportación y Restauración de Respaldos

| Botón | Qué hace |
| :--- | :--- |
| **Exportar a ZIP** | Crea un `.zip` local con tus notas. Puedes elegir **cifrado** o **en texto plano**. |
| **Subir a la Nube Ahora** | Genera el respaldo y lo sube al proveedor configurado, en una sola operación. |
| **Restaurar Respaldo** | Recupera tus notas desde un `.zip`. |

> ⚠️ **Sobre el modo "texto plano":** es útil (por ejemplo, para migrar a otro gestor o para archivar), pero significa que **el ZIP contiene tus notas sin cifrar**. Trátalo como si fuera un documento confidencial: bórralo en cuanto no lo necesites.

### 8.7 Mantenimiento Masivo de Archivos en Disco

| Botón | Qué hace |
| :--- | :--- |
| **🔒 Cifrar Toda la Bóveda** | Escanea la bóveda y cifra todo lo que esté en texto plano. |
| **🔓 Descifrar Toda la Bóveda** | **ADVERTENCIA:** devuelve todos los archivos a texto plano. Úsalo solo si vas a desinstalar el plugin. |

> ⚠️ **"Descifrar Toda la Bóveda" deja tus notas en claro en el disco.** Si pulsas esto por error y luego cierras Obsidian, tus notas están desprotegidas. Detalles en la [sección 11](#11-migración-y-mantenimiento-de-la-bóveda).

### 8.8 Language (idioma de la interfaz)

MySecret tiene su propia sección de idioma, **al final de los ajustes**, y funciona **independientemente** del idioma de Obsidian.

- **Auto (Follow Obsidian)**: sigue el idioma de Obsidian. *Atención: solo se aplica a los ajustes; la pantalla de bloqueo y el asistente usan sus propios textos.*
- **English / Español / Русский / 简体中文**: fija el idioma de la interfaz del plugin.

> 💡 Si tu Obsidian está en español y el plugin te sale en inglés, ve a esta sección y elige **Español**. Los cambios se aplican al instante.

## 9. Desbloqueo con huella dactilar, Face ID y Touch ID

**En una frase:** desbloquea tu bóveda con tu dedo o tu cara, sin teclear la contraseña.

### La idea en 30 segundos

Tu contraseña maestra sigue siendo la llave **real**. La biometría solo sirve para **demostrar que eres tú** de forma rápida, y el plugin usa esa demostración para abrir la llave que ya tiene guardada en tu dispositivo.

> 🔐 **Dato tranquilizador:** tu huella dactilar **nunca sale de tu dispositivo**. El sensor de tu móvil o de tu portátil es el que la verifica, dentro de su propio chip de seguridad (Apple Secure Enclave, Google Titan, TrustZone…). Ni el plugin, ni Obsidian, ni el puente de Cloudflare reciben tu huella: reciben una confirmación criptográfica de que ha sido validada.

### 9.1 Orden de instalación por plataforma

| Plataforma | ¿Necesita internet? | ¿Necesita instalar algo más? |
| :--- | :--- | :--- |
| **Windows** (Windows Hello) | ❌ No | No |
| **macOS** (Touch ID / Apple Watch) | ❌ No | No |
| **Linux** (huella con `fprintd`) | ❌ No | Hay que tener la huella ya enrolled en el sistema |
| **Android / iOS / iPadOS** | ⚠️ Solo la **primera** vez (al abrir el puente) | Sí: un puente web en Cloudflare Pages |

### 9.2 Windows (Windows Hello)

**Compatible con:** lector de huellas, cámara infrarroja con reconocimiento facial, o el PIN de Windows Hello.

1. Asegúrate de tener **Windows Hello activado** en la configuración de Windows (Ajustes → Cuentas → Opciones de inicio de sesión).
2. En Obsidian: **Ajustes → MySecret → Desbloqueo Biométrico y Huella Digital**.
3. Activa **"Desbloqueo con huella / Face ID en este dispositivo"**.
4. Confirma tu **contraseña maestra** (MySecret la pide siempre en acciones sensibles).
5. Toca tu sensor cuando se te pida.

**¿Necesita URL de Cloudflare?** **NO.** Todo es nativo y local.

### 9.3 macOS (Touch ID)

**Compatible con:** Touch ID en MacBooks, Magic Keyboard con Touch ID, y desbloqueo con Apple Watch.

1. En Obsidian: **Ajustes → MySecret → Desbloqueo Biométrico y Huella Digital**.
2. Activa el interruptor y confirma tu contraseña maestra.
3. macOS gestionará la autenticación por ti mediante su API nativa.

**¿Necesita URL de Cloudflare?** **NO.** Funciona 100% local.

### 9.4 Linux (huella con `fprintd`)

**Compatible con:** lectores de huella configurados con `fprintd` (el servicio estándar de Linux) y `SecretService`.

1. En una terminal, enrola tu huella en el sistema (normalmente con `fprintd-enroll`; el nombre exacto varía según tu distribución).
2. En Obsidian: **Ajustes → MySecret → Desbloqueo Biométrico y Huella Digital**.
3. Activa el interruptor y confirma tu contraseña maestra.

**¿Necesita URL de Cloudflare?** **NO.** Funciona 100% local.

> ⚠️ **Requisito real:** debe existir un lector de huella **enrollado y funcionando**. MySecret lo comprueba antes de ofrecerte la opción: si solo hay un llavero del sistema pero ningún sensor, no te deja registrar una "biometría" que en realidad no comprobaría nada.

---

### 9.5 Android, iPhone y iPad (el puente en Cloudflare Pages)

**En una frase:** en el móvil, Obsidian no puede hablar directamente con tu sensor de huella, así que usamos una pequeña web que hace de intermediario.

**¿Por qué hace falta?** Obsidian en móvil corre dentro de un contenedor aislado (un *WebView*). Por seguridad, iOS y Android **impiden** que las apps usen directamente el sensor biométrico desde ahí. La solución es abrir el **navegador del móvil** (Chrome o Safari), que sí puede usar el sensor nativo, y que devuelva la confirmación a Obsidian.

**Paso 1 — Despliega tu puente (gratis, 1 clic, sin tarjeta):**

1. Entra en [dash.cloudflare.com](https://dash.cloudflare.com/) (es gratis y **no pide tarjeta de crédito**).
2. En el menú lateral: **Workers & Pages → Crear aplicación → Pages**.
3. Pestaña **Upload assets** (subir archivos directamente).
4. Dale un nombre a tu proyecto, por ejemplo `mi-boveda-auth`.
5. Arrastra la carpeta **`auth-bridge/`** del repositorio de MySecret directamente al navegador y pulsa **Deploy site**.
6. Cloudflare te dará una dirección HTTPS como `https://mi-boveda-auth.pages.dev`.

> 💡 **Despliega la carpeta `auth-bridge/` COMPLETA.** El archivo `_headers` que lleva dentro es el que activa las cabeceras de seguridad anti-clickjacking. Si subes solo algunos archivos, esa protección no se aplica.

**Paso 2 — Configura Obsidian en el móvil:**

1. En tu móvil, abre Obsidian y ve a **Ajustes → MySecret → Desbloqueo Biométrico Móvil**.
2. Pega tu URL de Cloudflare en el campo de texto.
3. Pulsa **Probar URL** para verificar la conexión.
4. Activa el interruptor de desbloqueo biométrico.
5. Haz tu **primer registro**: pulsa el botón de huella, el navegador se abrirá, y ahí sí te pedirá la huella o el Face ID.

**Paso 3 — Uso diario:**

Cuando la bóveda esté bloqueada, pulsa **Desbloqueo con Huella Digital**. El navegador se abrirá un instante, validará tu huella y volverá automáticamente a Obsidian con la llave de sesión ya acordada.

> 🔒 **¿Cloudflare ve mis datos?** **No.** Los datos de la sesión viajan en el fragmento de la URL (la parte que empieza por `#`), que los navegadores **nunca envían** al servidor. Cloudflare recibe cero datos de tu bóveda. Además, la respuesta va cifrada con una clave de sesión efímera (ECDH P-256 + AES-256-GCM) que solo tu teléfono y Obsidian conocen. El identificador real de tu bóveda tampoco viaja: solo un hash SHA-256 de un solo sentido.

> 📴 **¿Funciona sin internet?** **Sí**, la mayoría de las veces. El puente es una PWA con un *Service Worker*: la primera vez que abres la URL, se guarda en tu móvil y funciona después en modo avión.

> ⚠️ **Un aviso sobre las URLs del puente:** solo se aceptan direcciones `https://` o `http://localhost`. Cualquier otra cosa se rechaza. Y como el puente vive en `pages.dev` (que está en la lista de sufijos públicos), cada proyecto tiene su propio aislamiento: una credencial registrada en tu puente **no** sirve en el de otra persona.

---

## 10. Copias de seguridad y respaldo en la nube

**En una frase:** el cifrado protege tus notas de ojos ajenos; los respaldos te protegen de que **tú** pierdas el disco.

> 💡 **Son dos cosas distintas y necesitas las dos.** El cifrado dice "que nadie más lea esto". El respaldo dice "que no pierdas esto". MySecret te da las dos, pero el respaldo lo tienes que configurar tú.

### 10.1 Crear un respaldo manual (ZIP local)

1. Abre la paleta de comandos (`Ctrl+P` / `Cmd+P`).
2. Ejecuta **MySecret: Exportar respaldo de la bóveda (ZIP)**.
3. Elige **modo Cifrado** (idéntico a lo que hay en tu disco) o **modo Descifrado** (texto plano, legible en cualquier editor).
4. Puedes elegir si incluir los adjuntos y si incluir el `vault-envelope.json` (márcalo si quieres que el ZIP sea **autosuficiente**: con él, un descifrador externo puede abrir el archivo sin necesitar el sobre de tu bóveda).
5. Elige la carpeta de destino.

> ⚠️ El modo **Descifrado** crea un ZIP con tus notas **en texto plano**. Úsalo solo si tienes una razón clara (migrar a otro programa, por ejemplo) y borra el archivo en cuanto ya no lo necesites.

### 10.2 Restaurar desde un ZIP

1. Ejecuta **MySecret: Restaurar respaldo de la bóveda (ZIP)**.
2. Selecciona el archivo `.zip`.
3. Escribe la **contraseña maestra** (o la frase, si el ZIP se exportó descifrado... en ese caso no hace falta contraseña: el contenido va tal cual y MySecret lo cifra al entrar).
4. MySecret **sobrescribe** los archivos que tengan la misma ruta. Te avisa de esto antes de empezar.

> 🔐 **Seguridad de la restauración:** cada entrada del ZIP se juzga por su **contenido real**, no por lo que su propio manifiesto diga. El texto cifrado debe autenticarse con la llave de *esta* bóveda y *esta* ruta; el texto plano se cifra al entrar. El motor también bloquea los intentos de **Path Traversal** (escribir fuera de la bóveda) y de **ZIP bomb** (descomprimir de más). Los archivos que no se pueden incluir **no se descartan en silencio**: se te informa.

### 10.3 Respaldos automáticos en la nube

Ve a **Ajustes → MySecret → Copias de Seguridad en la Nube** y elige proveedor:

| Proveedor | Para quién | Qué necesitas |
| :--- | :--- | :--- |
| **Google Drive** | Ya tienes una cuenta de Google | Un token de acceso y, opcionalmente, el ID de la carpeta destino |
| **Microsoft OneDrive** | Usas Microsoft 365 / OneDrive | Un token de acceso y la ruta de la carpeta |
| **WebDAV** (Nextcloud, ownCloud, Synology NAS, pCloud) | Tienes tu propio servidor | URL, usuario, contraseña o clave de aplicación, y ruta remota |
| **Carpeta local sincronizada** | Tienes Dropbox, MEGA o Google Drive *Desktop* ya instalados | La ruta absoluta de la carpeta en tu disco |

**El flujo recomendado:**

1. Elige el proveedor y rellena sus datos.
2. Pulsa **Probar Conexión** hasta que salga ✅.
3. Activa **Copia de seguridad automática**.
4. Elige **Cuándo generar la copia**:
   - **Al bloquear la bóveda** ← el más útil (cada vez que te vas, se guarda una copia).
   - **Por intervalo de tiempo regular** (cada 1, 6, 12, 24 o 72 horas).
   - **Ambos** ← recomendado.
5. Elige la **frecuencia**.
6. Pulsa **Guardar Configuración de Respaldo**.

> 🔐 **Tus credenciales de nube no se guardan en claro.** Se cifran con la llave de tu bóveda antes de escribirse en el archivo de configuración. En la interfaz se muestran enmascaradas.

> 💡 **Sobre la retención:** MySecret borra automáticamente las copias antiguas que superan el límite configurado (5 por defecto). Solo borra archivos cuyo nombre sea **exactamente** del patrón `MySecret_<boveda>_Cifrado_<fecha>.zip` y **solo** los de tu misma bóveda. En Google Drive y OneDrive los manda a la **Papelera**, no los borra de forma definitiva.

> ⚠️ **Caso especial del respaldo "al bloquear":** MySecret conserva la clave en memoria hasta que el ZIP termina de construirse, y te avisa si algún archivo no pudo empaquetarse. No interrumpe el bloqueo por culpa de un archivo problemático.

---

## 11. Migración y mantenimiento de la bóveda

**En una frase:** si tu bóveda ya tenía notas, aquí las conviertes a texto cifrado (o de vuelta a texto plano si quieres irte).

### 11.1 Cifrar una bóveda que ya tiene notas

**Cuándo lo necesitas:** instalaste MySecret en una bóveda con años de notas, o el asistente inicial te ofreció el botón **"🔒 Cifrar notas existentes ahora"** y no lo pulsaste.

**Desde los ajustes:**
1. Ve a **Ajustes → MySecret → Mantenimiento Masivo de Archivos en Disco**.
2. Pulsa **🔒 Cifrar Toda la Bóveda**.
3. Se abre una ventana con:
   - Un **recuento previo** de cuántos archivos se van a cifrar.
   - Una **barra de progreso** en vivo con el contador de archivos procesados.
   - Un **botón de parada de emergencia** por si quieres cancelar.
4. Al terminar verás **"Operación completada con éxito"**.

> 💡 **Déjalo correr.** Cifrar una bóveda grande (miles de notas con adjuntos) puede tardar varios minutos. MySecret va archivo por archivo, así que puedes ver el progreso y casi no notas la diferencia en el uso diario.

> ℹ️ **Solo se cifran los archivos que deben cifrarse.** Las carpetas excluidas y los archivos del sistema se saltan, y los archivos **ya cifrados** no se vuelven a cifrar (MySecret detecta el formato y no los toca).

### 11.2 Descifrar toda la bóveda (desinstalación limpia)

> [!WARNING]
> ### ⚠️ Esto deja tus notas en texto plano en el disco
> Úsalo **solo** si vas a desinstalar MySecret. Cuando termine, tus notas serán archivos Markdown normales, legible por cualquiera que acceda a tu disco o a tu nube.

1. Ve a **Ajustes → MySecret → Mantenimiento Masivo de Archivos en Disco**.
2. Pulsa **🔓 Descifrar Toda la Bóveda** (el botón está marcado en rojo).
3. Revisa el recuento, confirma y espera a que termine.

**El orden correcto para desinstalar es este:**
1. Desbloquea la bóveda.
2. Ejecuta **Descifrar Toda la Bóveda** y espera a que termine.
3. Ya con tus notas en texto plano, **desactiva o desinstala** el plugin.
4. Borra (opcionalmente) la carpeta `.obsidian/plugins/mysecret/`.

> ⚠️ **Si desinstalas el plugin con la bóveda cifrada, tus notas siguen cifradas.** No se pierden, pero Obsidian (y cualquier otro programa) las verá como texto basura. La solución: volver a instalar MySecret, desbloquear con tu contraseña y ejecutar **Descifrar Toda la Bóveda**.

### 11.3 Tabla resumen de migraciones

| De → a | Cómo | Con qué |
| :--- | :--- | :--- |
| Texto plano → Cifrado | Ajustes → Mantenimiento → Cifrar Toda la Bóveda | Contraseña maestra (bóveda desbloqueada) |
| Cifrado → Texto plano | Ajustes → Mantenimiento → Descifrar Toda la Bóveda | Contraseña maestra (bóveda desbloqueada) |
| Cifrado → Otra bóveda | Exportar ZIP cifrado → Restaurar en la nueva | Contraseña maestra + `vault-envelope.json` en el ZIP |
| Otro programa → MySecret | Instalar → Asistente → Cifrar Toda la Bóveda | Contraseña maestra |

---

## 12. Recuperación ante desastres

**En una frase:** esto es lo que haces el día que te has quedado sin acceso.

### 12.1 He olvidado la contraseña maestra

**Si tienes tu frase de 24 palabras:**

1. En la pantalla de bloqueo, pulsa **"¿Olvidaste tu contraseña? / Usar frase de rescate"**.
2. Escribe las 24 palabras **separadas por un espacio simple**, en el **mismo orden** en que las anotaste.
3. El contador **"X / 24 palabras"** te ayuda a no equivocarte.
4. Pulsa **Recuperar con Frase**.
5. MySecret regenera la clave de tu bóveda y te pide **establecer una contraseña maestra nueva**.
6. **Todas tus notas siguen intactas.** No se re-cifra nada: lo que cambia es la forma de abrir la llave.

> ℹ️ Si el plugin detecta que acabas de recuperar con la frase, te muestra un aviso: *"🔓 Bóveda recuperada. Te recomendamos cambiar la contraseña maestra en Ajustes."* Hazle caso.

**Si NO tienes frase de rescate** (elegiste el modo "solo contraseña"): **no hay recuperación posible.** Tus archivos están matemáticamente fuera de alcance. Esto no es un fallo del plugin: es exactamente lo que significa "sin puerta de auxilio".

### 12.2 He olvidado la contraseña y tengo la frase, pero no funciona

| Síntoma | Causa probable | Solución |
| :--- | :--- | :--- |
| "La frase de recuperación no es válida" | Ortografía, orden o palabras que no son de la lista BIP-39 | Revisa palabra por palabra. Las 24 palabras deben ser **exactamente** las del estándar (inglés, minúsculas). |
| "Debe tener 24 palabras (has introducido N)" | Faltan o sobran palabras | Cuenta las palabras. Recuerda: separador simple (un espacio). |
| Cuenta 24 pero no valida | Acentos o caracteres no estándar | El plugin normaliza a minúsculas, pero **no** acepta tildes ni ñ. Usa las palabras tal cual, sin acentos. |

### 12.3 Cambiar tu contraseña maestra

1. Desbloquea la bóveda.
2. Paleta de comandos → **MySecret: Cambiar contraseña maestra** (o **Ajustes → MySecret → Cambiar Contraseña**).
3. MySecret te pide la **contraseña actual** (ventana de reautenticación de 2 minutos) y luego la nueva, dos veces.
4. La nueva debe tener **mínimo 12 caracteres** y superar el medidor de fuerza.
5. En segundos, el sobre se re-cifra con una sal nueva. **Tus notas no se reescriben en disco.**

> [!WARNING]
> **Importante: cambiar la contraseña NO rota la clave de la bóveda.**
> Quién conserve una copia antigua de `vault-envelope.json` (el historial de tu nube, un backup antiguo) **junto con la contraseña anterior** todavía podrá descifrar tus notas. Cambiar la contraseña protege contra que alguien la adivine; no protege contra que alguien ya tenga una copia de tus datos cifrados.
>
> Si crees que tu contraseña anterior se ha **filtrado** (no que la hayan adivinado), la única solución limpia es: exportar tus notas en texto plano, crear una bóveda nueva con una contraseña nueva y migrar el contenido.

> ℹ️ **Tu biometría sigue funcionando.** MySecret mantiene un identificador de bóveda estable precisamente para que cambiar la contraseña no invalide tu huella dactilar.

### 12.4 He perdido el dispositivo con la bóveda

No pasa nada grave:

- Tus notas están cifradas en el disco y en la nube. Quien tenga el dispositivo **no puede leerlas** sin tu contraseña o tu frase.
- Si tenías la biometría activada, el registro biométrico **no sirve** en otro dispositivo: está atado al hardware y a esta bóveda concreta.
- Vuelve a instalar MySecret en otro equipo, desbloquea con tu contraseña o tu frase, y sigue como antes.
- **Cambia la contraseña** si el dispositivo era tu portátil principal y temes que alguien la use.

---

## 13. Descifrar tus notas sin el plugin ni Obsidian

**En una frase:** nunca estás atrapado en MySecret. Como usa estándares abiertos (AES-256-GCM, Argon2id, BIP-39), cualquier persona con tus palabras puede recuperar tus notas.

Esta es, probablemente, la **característica más importante** del plugin desde el punto de vista de la libertad: MySecret no es un formato propietario cerrado. Tus notas son archivos que cualquier herramienta estándar puede leer.

Las tres herramientas están en la carpeta **`tools/`** del repositorio.

### Método 1 — Desde cualquier navegador (100% offline)

Sin instalar nada. Ideal para recuperar **una nota o un adjunto** suelto.

1. Abre con doble clic el archivo [`tools/offline-decryptor.html`](tools/offline-decryptor.html) en tu navegador (Chrome, Firefox, Safari o Edge).
   - 💡 Puedes abrirlo **sin conexión**: la página no carga nada de internet (tiene una política de seguridad estricta que lo prohíbe).
2. Abre `.obsidian/plugins/mysecret/vault-envelope.json` con un editor de texto y **pega todo su contenido** en el primer campo.
3. Escribe tu **frase de rescate de 24 palabras** en el segundo campo.
4. Escribe la **ruta exacta** que tenía el archivo dentro de la bóveda (por ejemplo `Notas/Diario.md`).
   - ⚠️ La ruta forma parte de los datos autenticados: si es incorrecta, **falla a propósito**. Es una protección, no un error.
5. Pega la nota cifrada (empieza por `-----BEGIN MYSECRET ENCRYPTED FILE-----`) **o** selecciona el adjunto cifrado con el botón de archivo.
6. Pulsa **Descifrar Ahora**. El texto plano aparece abajo y puedes guardarlo.

> ⚠️ Las bóvedas creadas **sin** frase de rescate (modo "solo contraseña") **no** pueden usar esta página: usa el Método 2 con `--password`.

### Método 2 — Con el script de Python (toda la bóveda de golpe)

Para descifrar cientos de notas e imágenes de una sola vez.

1. Instala las dependencias:
   ```bash
   pip install cryptography argon2-cffi
   ```
   (`argon2-cffi` solo hace falta si usas `--password`.)

2. Descifra toda la bóveda con tu **frase de rescate**:
   ```bash
   python tools/standalone-decryptor.py --vault "/ruta/a/tu/boveda" --mnemonic "palabra1 palabra2 ... palabra24" --output "/ruta/a/boveda_descifrada"
   ```

3. O con tu **contraseña maestra** (déjala sin valor para que te la pida y **no quede en el historial** del shell):
   ```bash
   python tools/standalone-decryptor.py --vault "/ruta/a/tu/boveda" --password --output "/ruta/a/boveda_descifrada"
   ```

4. El script reconstruye la jerarquía completa con todas las notas y adjuntos en texto plano.
   - ⚠️ La carpeta de salida debe estar **fuera** de la bóveda.
   - Para un solo archivo: `--file nota.md --relative-path "Notas/nota.md"`.

> ℹ️ La herramienta lee `.obsidian/plugins/mysecret/vault-envelope.json` automáticamente. Si lo tienes en otro sitio, usa `--envelope`.

### Método 3 — Con CyberChef (web, sin instalar nada)

Para los que quieren ver el proceso paso a paso:

1. Abre [CyberChef](https://gchq.github.io/CyberChef/) (la herramienta web del*GCHQ*, la agencia de inteligencia británica).
2. Añade la operación **AES Decrypt** y pon el modo en **GCM**.
3. Proporciona la **clave derivada** (32 bytes), el **IV** (12 bytes) y en los **datos autenticados (AAD)** la ruta del archivo (por ejemplo `Notas/Idea.md`).
4. Pega el contenido cifrado (la parte Base64 entre las líneas `-----BEGIN...` y `-----END...`).

> ℹ️ Es el método más lento y manual. Sirve para verificar de forma independiente que tus datos están bien cifrados, o para entender el proceso.

---

## 14. Preguntas frecuentes (FAQ)

#### P: ¿Se cifran los nombres de los archivos y carpetas?

**R:** No, y es a propósito. Obsidian necesita leer esos nombres para mantener su índice, la búsqueda, los enlaces bidireccionales y la vista de árbol. Si se cifraran, Obsidian dejaría de funcionar. **Todo el contenido** (texto, frontmatter, lienzos, adjuntos) sí está 100% cifrado.

#### P: ¿Puedo usar Obsidian Sync, Git o sincronizaciones en la nube?

**R:** ¡Sí! Como los archivos en disco son ficheros de texto estándar con contenido cifrado, servicios como Obsidian Sync, Git, Dropbox, iCloud o Syncthing simplemente sincronizan los contenedores seguros. Ningún proveedor de la nube puede leer tus notas. Además, MySecret ajusta el hash de Obsidian Sync para que no re-descargue la bóveda entera en cada arranque.

#### P: ¿Qué ocurre si desinstalo el plugin?

**R:** Si desinstalas el plugin mientras tus archivos están cifrados, **permanecen cifrados en el disco**. Para dejarlos en texto plano, ejecuta **Descifrar Toda la Bóveda** antes de eliminar el plugin. Si ya lo eliminaste, vuelve a instalar MySecret, introduce tu contraseña maestra y ejecuta Descifrar Toda la Bóveda.

#### P: ¿El plugin funciona sin conexión a internet?

**R:** Sí, al 100%. Todo el cifrado ocurre en tu dispositivo. Solo necesitas internet para descargar el plugin y, en móvil, para la primera carga del puente biométrico.

#### P: ¿Puedo tener la bóveda cifrada en varios dispositivos?

**R:** Sí. Sincroniza el sobre `vault-envelope.json` junto con el resto (está dentro de `.obsidian/plugins/mysecret/`, que algunos servicios de sincronización excluyen por defecto: asegúrate de incluirlo). En cada dispositivo introduces la contraseña o la frase. La biometría, en cambio, hay que registrarla **en cada dispositivo por separado**.

#### P: ¿Me puede espiar el desarrollador del plugin?

**R:** No. La arquitectura es de **cero conocimiento**: la clave de tu bóveda se genera en tu dispositivo con el generador de números aleatorios del sistema, y nunca sale de tu equipo. El código fuente es público y auditado: no hay ni una llamada de red en el camino del cifrado.

#### P: ¿Y si pierdo la contraseña y las 24 palabras?

**R:** Tus notas se pierden de forma **permanente e irrecuperable**. No hay servidor, ni correo de recuperación, ni servicio de atención al cliente que pueda salvarte. Por eso el asistente insiste tanto en la frase de rescate y en la copia de seguridad previa.

#### P: ¿Cambiar la contraseña re-cifra mis notas?

**R:** No. Cambiar la contraseña re-cifra **la llave guardada en el sobre**, pero tus notas siguen cifradas con la misma clave de bóveda. Es instantáneo y no toca tus archivos. Si crees que tu contraseña **se ha filtrado** (más grave que "la hayan adivinado"), necesitas exportar en texto plano y crear una bóveda nueva.

#### P: ¿Puedo usar Obsidian Publish?

**R:** Sí, pero MySecret **bloquea** la publicación de notas cifradas, porque hacerlo subiría tu texto claro a una web pública. Si quieres publicar, descifra la bóveda primero o excluye esa nota de la publicación.

#### P: ¿Y si tengo Obsidian Sync y a veces no puedo desbloquear?

**R:** Ten en cuenta que el sobre `vault-envelope.json` **no está cifrado** (es el "sobre" que contiene tu llave cifrada: su contenido es metadata, no tus notas). Si el sincronizador lo sube a la nube, quien lo descarga ve solo un blob cifrado. Aun así, añade `.obsidian/plugins/mysecret/` a tu `.gitignore` si usas Git y no quieres subir ese archivo.

#### P: ¿MySecret ralentiza Obsidian?

**R:** El cifrado de una nota tarda entre 1 y 5 milisegundos. Es imperceptible. Lo que sí tarda un poco es el **desbloqueo** (unos 240 ms), porque Argon2id está diseñado deliberadamente para ser lento: esa lentitud es lo que hace que probar contraseñas sea carísimo para un atacante.

#### P: ¿Funciona con bases de datos o wikis externos?

**R:** MySecret cifra **archivos de tu bóveda**. Si usas una app que guarda sus datos en una base de datos dentro de la bóveda, échale un vistazo al comportamiento de los adjuntos en la [sección 8.1](#81-protección-y-bloqueo-automático) y, si hace falta, excluye esa carpeta.

---

## 15. Solución de problemas

| Síntoma | Causa | Solución |
| :--- | :--- | :--- |
| **"vault-envelope.json existe pero está dañado o ha sido modificado"** | El sobre se corrompió o alguien lo editó | **No borres nada.** Restaura `vault-envelope.json` (o `vault-envelope.json.bak`) desde tu copia de seguridad. MySecret se niega a crear una bóveda nueva a propósito, para no invalidar tus notas. |
| **"Contraseña maestra incorrecta"** | Error al teclear | Comprueba mayúsculas, teclado en otro idioma y bloque de mayúsculas. |
| **"La frase de recuperación no es válida"** | Error en las palabras | Cuenta que sean 24, en orden, minúsculas y **sin tildes**. |
| **"Demasiados intentos fallidos. Espera Ns"** | Rate limit de fuerza bruta | Espera. El plugin aplica un enfriamiento para frenar los ataques de adivinación. |
| **El candado está rojo y no puedo abrir nada** | Bóveda bloqueada | Pulsa el candado rojo en la barra lateral izquierda o usa el comando **MySecret: Desbloquear bóveda**. |
| **Una nota dice que no se puede descifrar** | La ruta cambió por fuera de Obsidian | Renombra el archivo **dentro de Obsidian** para que MySecret re-firme la ruta, o revierte el cambio en el explorador de archivos. |
| **Las imágenes no se ven en la vista de lectura** | Ajuste de adjuntos o bóveda bloqueada | Desbloquea la bóveda. Si sigue igual, revisa **Cifrar archivos adjuntos** en los ajustes. |
| **"El sobre no se puede guardar" / "disco lleno"** | No hay espacio para escribir el sobre | Libera espacio. MySecret **no** sobrescribe la versión anterior hasta que la nueva está verificada, así que no perderás la llave por un fallo de escritura. |
| **El puente biométrico no vuelve a Obsidian** | El navegador bloqueó la redirección automática | En el puente verás un botón verde **"Regresar a la Aplicación"**. Pulsa y listo. |
| **"Biometría no disponible o no configurada"** | No hay sensor enrollado en el sistema | Enrolla tu huella en los ajustes del sistema operativo (Windows Hello, Touch ID, `fprintd-enroll`) y vuelve a registrar la biometría en MySecret. |
| **Obsidian Sync descarga la bóveda entera cada vez** | Desalineación de hashes | MySecret lo corrige automáticamente. Si persiste, desactiva y reactiva MySecret una vez: el parche se reinstala al cargar. |
| **El plugin no aparece en la lista de la comunidad** | Modo seguro activo | Ve a **Ajustes → Plugins de la comunidad** y desactiva el modo seguro. |

---

## 16. Checklist final de seguridad

**En una frase:** marca estas seis casillas y tu bóveda está en un estado sólido.

- [ ] **He hecho una copia de seguridad sin cifrar** de mi bóveda, en un disco o nube **distinta** del de la bóveda.
- [ ] **He anotado las 24 palabras de rescate en papel** y las he guardado fuera de la bóveda. (Ideal: **dos** copias, una fuera de casa.)
- [ ] **Mi contraseña maestra tiene 12+ caracteres** y es fuerte (ideal: frase de 4-5 palabras).
- [ ] **El auto-bloqueo por inactividad está activado** (5 minutos es un buen valor) y **bloquear al cambiar de ventana** también.
- [ ] **El cifrado de adjuntos está activado**, para que las imágenes y PDFs no queden en claro.
- [ ] **La copia de seguridad automática en la nube está configurada y probada** (he pulsado "Probar Conexión" y salió ✅).

### Bonus: mejora tu postura de seguridad

- [ ] He revisado la sección **Carpetas Excluidas** y me aseguro de que no hay nada sensible que haya dejado fuera del cifrado por accidente.
- [ ] He probado a **descifrar una nota con el descifrador del navegador** ([método 1](#método-1--desde-cualquier-navegador-100-offline)), para saber que sé recuperar mis datos si el plugin deja de existir.
- [ ] He configurado la **biometría** en mis dispositivos de uso diario, para que la contraseña maestra se use lo mínimo.
- [ ] Si uso **Obsidian Publish**, me he asegurado de que las notas públicas están en una **carpeta excluida**.

---

## 📚 Documentos relacionados

| Documento | Para quién |
| :--- | :--- |
| [README.es.md](README.es.md) | Vista general del plugin, comparativa con otras herramientas y vídeo de demostración. |
| [SECURITY.es.md](SECURITY.es.md) | Arquitectura de seguridad y los vectores de ataque que mitiga. |
| [DEVELOPER_GUIDE.es.md](DEVELOPER_GUIDE.es.md) | Documentación técnica para contribuir al código. |
| [COMPARISON.es.md](COMPARISON.es.md) | MySecret frente a Cryptomator, VeraCrypt, Meld Encrypt y Obsidian Sync. |
| [auth-bridge/README.md](auth-bridge/README.md) | Detalles técnicos del puente biométrico para Cloudflare Pages. |

---

> **MySecret** · Código fuente público y auditable · Licencia no comercial.
> La privacidad que ofrece es matemáticamente verificable: no tienes que confiar en nuestra palabra, puedes leer el código.

---
