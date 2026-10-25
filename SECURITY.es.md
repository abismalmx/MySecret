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
| **Total de pruebas verificadas** | **82 tests** | **100% Exitoso** |

---

## 4. Auditoría Integral de Seguridad, SAST y Fuga de Secretos (Calificación A+)

El proyecto fue sometido a una auditoría técnica profunda y rigurosa, documentada en el [Informe de Auditoría y Parches de Seguridad](SECURITY_AUDIT_AND_PATCHES.md):

- **Análisis Estático SAST (Semgrep):** Se ejecutaron **503 reglas de seguridad** sobre la totalidad del código fuente. Se blindó la resolución de traducciones (`src/i18n/index.ts`) contra ataques de *Prototype Pollution* mediante validación estricta con `hasOwnProperty` y filtrado explícito de segmentos peligrosos (`__proto__`, `constructor`, `prototype`). Resultado: **0 vulnerabilidades**.
- **Auditoría de Fuga de Secretos (Gitleaks):** Escaneo automatizado del historial completo de Git (todos los commits) y del árbol de archivos. Resultado: **0 secretos expuestos** (sin credenciales, tokens OAuth ni claves privadas filtradas).
- **Tipado Estático Estricto (TypeScript `tsc`):** El código compila al 100% sin advertencias ni errores (`0 errores`).
- **Linter de Calidad y Directrices Obsidian (ESLint):** Cumplimiento estricto con las políticas de interfaz, botones destructivos y APIs oficiales (`0 errores`).
- **Seguridad en Cadena de Suministro:** Se auditó y actualizó la dependencia `esbuild` a `^0.25.0` mitigando de raíz cualquier vector conocido (CWE-346 / GHSA-67mh-4wv8-2f99).

---

## 5. Política de Divulgación Responsable

Si descubres una posible debilidad de seguridad o vector no cubierto, te invitamos a reportarlo de forma responsable abriendo un reporte de seguridad privado en GitHub o contactando directamente al autor. Todas las consultas son evaluadas con máxima prioridad técnica.
