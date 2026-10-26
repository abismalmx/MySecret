# Arquitectura de Seguridad y Fortalezas Auditadas — MySecret

[English Version](SECURITY.md) • **Español**

**MySecret** implementa un modelo de seguridad de **Cero Conocimiento (Zero-Knowledge)** diseñado para proteger notas, diagramas y archivos adjuntos en Obsidian mediante cifrado transparente en disco.

Este documento consolida las fortalezas criptográficas, los principios de diseño de defensa en profundidad y todos los vectores de ataque auditados y validados contra los cuales el plugin se mantiene invicto a través de su suite automatizada de pruebas.

---

## 1. Principios Criptográficos Fundamentales

- **Cero Conocimiento Absoluto:** Las claves criptográficas maestras se derivan en la memoria RAM volátil del dispositivo local. Ninguna clave, credencial o texto en claro se envía a servidores externos ni se persiste sin cifrar en disco.
- **Cifrado Simétrico Autenticado (AEAD):** Utiliza **AES-256-GCM** acelerado por hardware a través de la Web Crypto API nativa (`window.crypto.subtle`). Cada bloque cifrado incluye un vector de inicialización (IV) criptográfico de 96 bits generado aleatoriamente y un tag de autenticación de 128 bits que garantiza confidencialidad e integridad inviolable.
- **Derivación de Clave Robusta (KDF):** La clave maestra de la bóveda se deriva mediante **Argon2id** (WebAssembly via `hash-wasm`), el algoritmo estándar ganador del Password Hashing Competition, optimizado con alta memoria e iteraciones para neutralizar ataques de fuerza bruta asistidos por GPUs o ASICs.
- **Rescate Determinista BIP-39:** Algoritmo mnemónico de 24 palabras basado en 256 bits de entropía criptográfica y checksum SHA-256 para recuperación de desastres sin requerir servidores de terceros.
- **Zeroización Activa de Memoria:** Limpieza garantizada de buffers en memoria (`zeroize()`) tras el bloqueo de la bóveda, inactividad o fallos en tiempo de ejecución.

---

## 2. Fortalezas de Seguridad y Vectores Auditados

A continuación se detallan las medidas de endurecimiento activas contra vectores de ataque específicos evaluados durante las auditorías de seguridad:

### 🛡️ Protección Estricta contra Zip Slip y Path Traversal
- **Módulo de Sanitización:** `src/utils/path-sanitizer.ts` inspecciona y convalida cada entrada al restaurar respaldos o importar archivos.
- **Defensa:** Rechaza de inmediato cualquier segmento relativo `..`, barras invertidas de Windows, rutas absolutas (`/etc/...`, `C:\...`), bytes nulos y directorios de configuración oculta (`.obsidian/`, `.git/`). Impide que un archivo malicioso pueda escribir fuera de la bóveda o inyectar código en la carpeta de plugins.

### 🛡️ Integridad de Enlace de Ruta (Strict AAD Binding)
- **Asociación de Ruta:** En cada cifrado AES-256-GCM, la ruta relativa normalizada en formato NFC se vincula como Datos Asociados Autenticados (AAD).
- **Protección en Renombramiento y Copia:** Las operaciones de `rename` y `copy` en el adaptador de archivos reconcilian y actualizan criptográficamente el AAD del archivo en tiempo real, impidiendo ataques de manipulación o sustitución de archivos cifrados entre carpetas.

### 🛡️ Inmutabilidad de Parámetros KDF y Blindaje contra Degradación (Anti-Downgrade)
- **Validación en Tiempo de Ejecución:** El sistema cuenta con guardas que verifican los parámetros de coste de Argon2id (`memoryKib`, `iterations`, `parallelism`).
- **Defensa:** Rechaza automáticamente cualquier configuración degradada o manipulada en el sobre de la bóveda que intente acelerar ataques de fuerza bruta, así como valores inflados que busquen generar denegación de servicio (DoS).

### 🛡️ Cobertura Exhaustiva del Adaptador de Archivos (Zero Plaintext Leakage)
- **Intercepción Completa:** Intercepción transparente de todos los métodos del adaptador de almacenamiento de Obsidian: `read`, `write`, `readBinary`, `writeBinary`, `append` y `appendBinary`.
- **Garantía:** Ningún flujo de escritura en disco elude el motor de cifrado; los adjuntos binarios grandes y las notas se cifran en streaming antes de tocar el sistema de ficheros.

### 🛡️ Separación de Superficies: Cifrado en Disco vs. Texto Claro en Memoria
- **Superficie del Adaptador (`DataAdapter.readBinary`):** Devuelve **exactamente los bytes almacenados en disco** (el ciphertext). Nunca devuelve texto claro.
- **Superficie de la Bóveda (`Vault.readBinary`):** Devuelve el **texto claro** descifrado, y es la única superficie que usa el indexador de metadatos de Obsidian (`MetadataCache.computeFileMetadataAsync`) para extraer enlaces, notas al pie y frontmatter.
- **Por qué la separación es necesaria:** Obsidian **Sync** lee los archivos mediante `app.vault.adapter.readBinary(path)` (llamada directa al adaptador), mientras que el indexador y Obsidian **Publish** usan `vault.readBinary(file)`. Descifrar en el adaptador exponía el texto claro de **todas** las notas al motor de sincronización, que las subía a la nube en claro.
- **Resultado:** Las notas blindadas siguen siendo indexables (notas al pie, enlaces y búsqueda funcionan) sin que el texto claro salga nunca del proceso hacia Obsidian Sync.

### 🛡️ Integridad contra el Doble Cifrado (Anti Double-Encryption)
- **Amenaza:** Obsidian Sync descarga el ciphertext de un archivo y lo reescribe **literalmente** en disco mediante `vault.modifyBinary()` → `adapter.writeBinary()`. Si el hook de escritura lo cifrara de nuevo, el archivo quedaría cifrado **dos veces** y sería ilegible de forma permanente.
- **Defensa:** Antes de cifrar, los hooks `write` y `writeBinary` comprueban si los bytes ya constituyen un **contenedor MySecret autenticado** para esa ruta concreta, verificando criptográficamente la etiqueta GCM con el AAD (la ruta) como datos asociados.
- **Garantía:** Solo un contenedor producido por MySecret para esa ruta se almacena tal cual; un archivo que *parezca* un contenedor (p. ej. una imagen que empiece por los bytes `MYSE`) se cifra normalmente y nunca queda en claro.

### 🛡️ Alineación del Hash del MetadataCache con Obsidian Sync
- **Amenaza:** El indexador de metadatos calcula `SHA-256(vault.readBinary())` (texto claro) mientras que Sync calcula `SHA-256(adapter.readBinary())` (ciphertext). Como nunca coinciden, Sync detectaría un cambio en **todos** los archivos en **cada** ejecución, re-descargando y reescribiendo la bóveda entera indefinidamente.
- **Defensa:** `MetadataHashPatch` sustituye el hash expuesto por `metadataCache.getFileInfo()` por el hash del ciphertext (el que Sync realmente compara), sin mutar la entrada original del cache de metadatos para no perder enlaces, notas al pie ni frontmatter.

### 🛡️ Bloqueo de la Publicación de Notas Cifradas (Obsidian Publish)
- **Amenaza:** Obsidian Publish sube las notas a un **sitio web público** y las lee mediante `vault.readBinary(file)`, la misma ruta que entrega el texto claro al indexador.
- **Defensa:** `PublishGuard` intercepta `apiUploadFile()` del plugin interno `publish` y **rechaza** la subida de cualquier archivo que esté cifrado en disco, con un mensaje accionable que indica usar «Descifrar todo».
- **Garantía:** Nunca se publica texto claro de una nota blindada; las notas en texto plano (carpetas excluidas) se publican con normalidad.

### 🛡️ Zeroización de Memoria Garantizada en Rutas de Error
- **Limpieza Incondicional:** La rutina criptográfica de borrado de memoria (`zeroize()`) se ejecuta dentro de bloques `finally` en todas las operaciones críticas.
- **Defensa:** Ante cualquier error o excepción, las claves intermedias y los fragmentos de contraseñas son inmediatamente sobrescritos con ceros en RAM, evitando fugas por inspección de memoria residual.

### 🛡️ Cifrado Autenticado en Reposo para Credenciales de Nube
- **Envelope de Credenciales:** Los tokens de acceso y contraseñas de proveedores remotos (WebDAV / Nextcloud, Google Drive, OneDrive) no se almacenan en texto plano en la configuración.
- **Protección:** Se encriptan mediante AES-256-GCM utilizando una clave derivada directamente de la clave maestra de la bóveda (`vaultKey`), manteniéndose inaccesibles a terceros si la bóveda está bloqueada.

### 🛡️ Gestión Estricta de Buffers y Aislamiento HTTP
- **Normalización de Cargas:** El módulo `src/utils/http.ts` utiliza `toExactArrayBuffer()` para asegurar que únicamente los bytes correspondientes a la vista activa (`byteOffset`, `byteLength`) se transmitan en peticiones de red.
- **Prevención:** Evita la exposición involuntaria de memoria adyacente o buffers compartidos en transferencias remotas.

### 🛡️ Validación Estricta de URLs y Enlace Seguro HTTPS
- **Filtrado de Esquemas:** Validación rigurosa de URLs en todos los conectores de red y WebDAV.
- **Defensa:** Bloqueo terminante de esquemas inseguros (`javascript:`, `data:`, `file:`) y forzado estricto de HTTPS en servicios remotos para prevenir ataques Man-in-the-Middle (MitM) y fuga de credenciales.

### 🛡️ Interfaz de Usuario Protegida contra Exposición de Secretos
- **Entrada Segura:** Todos los campos de contraseña maestra emplean controles nativos protegidos (`<input type="password">`) con opción de visibilidad temporal controlada.
- **Defensa:** Se erradica el uso de diálogos globales inseguros como `window.prompt()`, previniendo la captura o exposición accidental en capturas de pantalla o logs.

### 🛡️ Visualización y Respaldo Controlado de Frase BIP-39
- **Acceso Protegido:** La frase de rescate de 24 palabras solo puede ser visualizada tras reingresar la contraseña maestra activa mediante un modal dedicado, asegurando que el usuario pueda recuperarla en cualquier momento posterior a la configuración inicial.

### 🛡️ Política Unificada de Contraseñas de Alta Entropía
- **Requisito Mínimo:** Se impone un mínimo uniforme y estricto de 12 caracteres en todos los flujos de creación y cambio de contraseña, complementado con indicadores visuales de entropía.

### 🛡️ Generación Criptográfica de Aleatoriedad (CSPRNG)
- **Entropía Segura:** Todos los identificadores, IVs, sales y boundaries multipart se generan exclusivamente a través de `crypto.getRandomValues()`.
- **Defensa:** Ausencia total de generadores pseudoaleatorios débiles (`Math.random()`), eliminando cualquier predictibilidad criptográfica.

### 🛡️ Inmunidad contra Prototype Pollution
- **Estructuras Sanitizadas:** Las estructuras de diccionario utilizadas en el desempaquetado de respaldos y serialización se instancian con prototipo nulo (`Object.create(null)`).
- **Defensa:** Se filtran nombres de propiedades peligrosas como `__proto__`, `constructor` y `prototype`, garantizando la inmunidad del runtime de JavaScript.

### 🛡️ Confinamiento de Rutas en Carpetas Locales de Sincronización
- **Aislamiento Local:** El proveedor de almacenamiento en carpeta local convalida que ninguna operación de sincronización pueda navegar fuera de la ruta base configurada mediante secuencias de escape de directorio.

### 🛡️ Desbloqueo Biométrico Seguro (WebAuthn Bridge)
- **Intercambio Criptográfico Efímero:** En Android y navegadores móviles, el puente WebAuthn PWA utiliza intercambio de claves **ECDH sobre curva P-256**.
- **Anclaje de Dominio y Desafíos:** Anclaje estricto de RP ID al dominio registrable de Cloudflare Pages y desafíos con marca de tiempo única contra ataques de repetición.
- **Anonimización:** El identificador de la bóveda nunca viaja al navegador externo; se emplea un enlace unívoco unidireccional derivado criptográficamente.
- **Linux exige una verificación real:** el desbloqueo biométrico requiere un lector de huellas `fprintd` operativo. El antiguo modo «solo Secret Service» no autenticaba a nadie (el llavero suele estar ya desbloqueado en una sesión abierta); ya no se puede inscribir y las inscripciones antiguas fallan cerradas.
- **Comprobación de disponibilidad en Windows** compara líneas completas (`UNAVAILABLE` contiene `AVAILABLE`).

### 🛡️ Endurecimiento de la Segunda Auditoría
- **Reautenticación en acciones sensibles:** cambiar la contraseña (que además exige la contraseña *actual*), ver/eliminar la frase de recuperación, inscribir biometría y exportar en texto plano piden de nuevo la contraseña maestra; estar desbloqueado no basta.
- **Identificador de bóveda estable:** el espacio biométrico local se indexa por un `vaultId` que sobrevive al cambio de contraseña (antes era la sal de Argon2 y la inscripción quedaba huérfana en silencio).
- **Restauración autenticada:** cada entrada del ZIP se juzga por su contenido, nunca por el `mode` que declara su propio manifiesto. El texto cifrado debe autenticarse con la clave de *esta* bóveda y *esta* ruta; el texto plano se cifra al entrar. Exige bóveda desbloqueada y informa de cada entrada rechazada.
- **Los respaldos no descartan archivos en silencio:** lo que no puede incluirse (sin clave, no UTF-8, error de E/S) se informa. El respaldo automático «al bloquear» conserva la clave necesaria hasta construir el archivo.
- **Cambios de política seguros:** excluir una carpeta o desactivar el cifrado de adjuntos descifra antes lo que ya está cifrado (todo o nada por archivo), en lugar de servir texto cifrado crudo que un guardado posterior corrompería.
- **Re-vinculaciones diferidas:** un renombrado/copia hecho con la bóveda bloqueada se encola, se persiste y se reaplica al desbloquear (de forma idempotente). Las llamadas `process`/`append` se serializan por ruta (sin actualizaciones perdidas).
- **Manejo del sobre:** `vault-envelope.json` se valida al cargar, se escribe con archivo temporal + relectura + `.bak`, y un sobre dañado nunca abre el asistente (que crearía una clave nueva sobre notas cifradas). El asistente además avisa si hay archivos cifrados y se niega a sobrescribir una bóveda inicializada.
- **El guardián de Publish sigue a la instancia del plugin** (activado después / reactivado), en vez de instalarse una sola vez al cargar.
- **Notas de texto ocultas** dentro de carpetas (`Notas/.privada.md`) se cifran; las carpetas ocultas a cualquier profundidad se excluyen.
- **CI:** acciones fijadas por SHA de commit, releases solo con tags de versión semántica, CodeQL en cada push/PR.

### ⚠️ Limitaciones Conocidas (léelas)
- **Cambiar la contraseña maestra NO rota la clave de la bóveda.** Quien conserve una copia antigua de `vault-envelope.json` (historial de la nube, backups) junto con la contraseña *anterior* aún puede descifrar las notas. Si una contraseña se expuso, considera la bóveda expuesta.
- **El bloqueo es un bloqueo de interfaz.** Se borra la clave y se cierran las notas abiertas, pero Obsidian y otros plugins pueden conservar texto plano en memoria (caché de metadatos, estado del editor). Protege contra acceso casual, no contra un depurador o un plugin malicioso.
- **El AAD vincula solo la ruta del archivo.** Quien pueda escribir en tu bóveda puede restaurar un cifrado antiguo del mismo archivo o sustituir una nota por texto plano; el plugin no puede detectarlo.
- **El desbloqueo biométrico en Windows y Linux es una comodidad** aplicada por el plugin: el secreto de envoltura lo protege DPAPI / un archivo `0600` legible por el mismo usuario del SO. Malware ejecutándose como tú puede saltárselo. Solo el proveedor WebAuthn (PRF) deriva la clave del propio autenticador. Si esto te importa, usa la contraseña maestra.
- **Los respaldos solo contienen los archivos que el plugin cifra.** Las carpetas excluidas y los archivos ocultos/de sistema no se incluyen.
- **Plugins de terceros** que leen notas por la API de Obsidian reciben texto plano por diseño.

---

## 3. Matriz de Verificación y Pruebas Automatizadas

La integridad de todas estas protecciones se valida continuamente mediante una suite automatizada de pruebas unitarias y de integración que se ejecuta en cada build:

| Componente | Pruebas | Estado |
| :--- | :---: | :---: |
| **Sanitización de Rutas y Prevención Zip Slip** | 6 tests | ✅ Invicto |
| **Control de Coste y Anti-Downgrade Argon2id** | 4 tests | ✅ Invicto |
| **Aislamiento de Cargas y Protección HTTP** | 4 tests | ✅ Invicto |
| **Cifrado en Reposo de Credenciales** | 5 tests | ✅ Invicto |
| **Inmunidad contra Prototype Pollution** | 2 tests | ✅ Invicto |
| **Prevención de Traversal en Restauración** | 2 tests | ✅ Invicto |
| **Intercambio y Seguridad WebAuthn / Biometría** | 16 tests | ✅ Invicto |
| **Cifrado AES-256-GCM y Normalización AAD** | 8 tests | ✅ Invicto |
| **Generación y Verificación Mnemónica BIP-39** | 4 tests | ✅ Invicto |
| **Zeroización de Buffers en Memoria** | 2 tests | ✅ Invicto |
| **Ciclo de Vida de Claves y Cambio de Contraseña** | 4 tests | ✅ Invicto |
| **Internacionalización y Formato Multilingüe** | 6 tests | ✅ Invicto |
| **Intercepción de Adaptador y Archivos** | 19 tests | ✅ Invicto |
| **Regresión de la segunda auditoría** (reautenticación, restauración, respaldos, re-vinculaciones, biometría) | 30+ tests | ✅ Invicto |
| **Compatibilidad de herramientas de recuperación** (HTML + Python descifran una bóveda real) | 8 tests | ✅ Invicto |
| **Total de pruebas verificadas** | **128 tests** | **100% Exitoso** |

---

## 4. Auditoría Integral de Seguridad, Cadena de Suministro y Endurecimiento de Código (Calificación A+)

El código fuente de MySecret fue sometido a una auditoría técnica profunda, inspección manual y revisión de cadena de suministro, detallada exhaustivamente en el [Informe de Auditoría y Parches de Seguridad](SECURITY_AUDIT_AND_PATCHES.md).

### 🔍 Vulnerabilidad en Cadena de Suministro Mitigada (`GHSA-67mh-4wv8-2f99` / CWE-346)
- **Detalle de la Vulnerabilidad**: `esbuild@0.20.2` (afectaba versiones `<= 0.24.2`) presentaba un advisory de severidad Moderada (CVSS 5.3) en el cual `esbuild.serve()` configuraba por defecto la cabecera `Access-Control-Allow-Origin: *`, permitiendo a sitios web externos no autorizados enviar peticiones y leer respuestas del servidor local de desarrollo.
- **Corrección**: Se actualizó `esbuild` de `^0.20.0` a `^0.25.0` (resuelto a `0.25.12`) en `package.json` y `package-lock.json`.
- **Explotabilidad Real**: **Nula en producción** — `esbuild` es exclusivamente un empaquetador de compilación offline, no forma parte del bundle en tiempo de ejecución (`main.js` contiene 0 referencias a esbuild) y el plugin jamás invoca `esbuild.serve()`. El parche se aplicó para garantizar la integridad de la cadena de suministro y proteger el entorno local de desarrollo.

### 🛡️ Hallazgos de Revisión Manual y Endurecimiento en `src/i18n/index.ts`
Durante la revisión manual del motor de internacionalización, se identificaron y subsanaron dos vulnerabilidades en la interpolación de cadenas:
1. **Fuga y Corrupción por Patrones de Reemplazo Regex**: Anteriormente, `text.replace(new RegExp(...), String(val))` evaluaba el valor con la semántica de reemplazo de JavaScript (`$&`, `` $` ``, `$'`, `$1`, `$2`). Cuando mensajes de error generados por servidores remotos o entradas no confiables (ej. `notices.exportFailed` o `notices.backupFailed` interpolando `err.message`) contenían signos de dólar, el mensaje se corrompía o filtraba fragmentos de la plantilla. **Parche**: Se sustituyó por una función de reemplazo `() => String(val)`, que neutraliza cualquier interpretación de secuencias especiales.
2. **Inyección de Metacaracteres Regex en Claves**: Si una clave de sustitución contenía metacaracteres (`.`, `{`, etc.), podía lanzar errores de sintaxis o fallar en el reemplazo. **Parche**: Sanitización estricta de nombres de claves mediante `escapeRegExp()`.
3. **Inmunidad contra Prototype Pollution**: La resolución de propiedades filtra explícitamente `__proto__`, `constructor` y `prototype`, junto con verificación `hasOwnProperty`.
4. **Pruebas de Regresión**: Se añadieron 2 tests específicos en `tests/test-i18n.mjs` que validan la seguridad ante patrones `$1` / `$&` y el escape de claves regex.

### 🤖 Guardias Automatizadas Continuas en CI/CD
- **Google OSV-Scanner (`.github/workflows/osv-scanner.yml`)**: Escaneo continuo de la cadena de suministro con los workflows oficiales de Google (`osv-scanner-reusable.yml@v2.7.0` para análisis completo y `osv-scanner-reusable-pr.yml@v2.7.0` para Pull Requests) con `fail-on-vuln: true`. Se ejecuta en `push`, `pull_request`, `tags`, ejecución programada semanal y despacho manual.
- **GitHub CodeQL SAST (`.github/workflows/codeql.yml`)**: Análisis SAST automatizado de flujo de datos y seguridad en cada push y PR sobre todo el código TypeScript/JavaScript.
- **Semgrep SAST**: Más de **503 reglas de seguridad** analizadas sobre la totalidad del código, con 0 vulnerabilidades.
- **Detección de Fugas Gitleaks**: Escaneo profundo de todo el historial de commits y del árbol de trabajo confirmando **0 secretos expuestos** (sin credenciales, tokens ni claves privadas).

### 🔬 Verificaciones de Superficie de Ataque y Defensa en Profundidad
- **Seguridad en Acciones de CI**: Todas las GitHub Actions utilizadas (`actions/checkout@v4`, `actions/setup-node@v4`, `github/codeql-action@v3`, `softprops/action-gh-release@v2`) auditadas en la base de datos OSV — **0 vulnerabilidades**.
- **Herramientas de recuperación**: `tools/offline-decryptor.html` no tiene dependencias. `tools/standalone-decryptor.py` necesita `cryptography` (y `argon2-cffi` solo para `--password`), porque AES-GCM y Argon2id no están en la biblioteca estándar de Python. Ambas se prueban contra bóvedas generadas por el código real del plugin.
- **Cero CDNs o Scripts Remotos de Terceros**: Sin scripts externos ni llamadas remotas en el HTML/JS del plugin ni en el puente PWA WebAuthn.
- **Cero uso de `eval`, `innerHTML` o `insertAdjacentHTML`**: El código utiliza rigurosamente las APIs seguras de Obsidian (`createEl`, `setIcon`, `setText`, `setCssStyles`), eliminando cualquier vector de Cross-Site Scripting (XSS).
- **Rigor Criptográfico**: AES-256-GCM (IV 96 bits, tag 128 bits), Argon2id (64 MiB / 3 iteraciones / sal 16 bytes), HKDF-SHA256, AAD vinculado a la ruta de la bóveda, comparaciones en tiempo constante, rescate determinista BIP-39 y zeroización inmediata de memoria en RAM.

---

## 5. Política de Divulgación Responsable

Si descubres una posible debilidad de seguridad o vector no cubierto, te invitamos a reportarlo de forma responsable abriendo un reporte de seguridad privado en GitHub o contactando directamente al autor. Todas las consultas son evaluadas con máxima prioridad técnica.
