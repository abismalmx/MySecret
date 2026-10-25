# Auditoría de Seguridad — MySecret (Plugin de Obsidian)

**Fecha:** 23 de octubre de 2026
**Alcance:** código fuente completo del plugin (`src/`, ~9.000 LOC), configuración de build, `manifest.json` y dependencias.
**Auditor:** Cline (análisis estático + verificación empírica de cada hipótesis)
**Resultado:** 15 vulnerabilidades confirmadas y corregidas (más 2 defectos detectados en el propio parche de VUL-03 durante una segunda ronda de revisión). **39/39 tests pasan** (12 preexistentes + 27 nuevos de regresión de seguridad).

---

## 1. Resumen ejecutivo

MySecret implementa cifrado transparente en disco para Obsidian (AES-256-GCM + Argon2id + BIP-39). La auditoría encontró **defectos de seguridad reales y explotables** en la capa de interoperabilidad (restauración de respaldos, hooks del adaptador) y en el manejo de secretos (credenciales de nube, contraseña maestra, frase de recuperación).

Los tres hallazgos más graves eran:

| ID | Severidad | Resumen |
|----|-----------|---------|
| **VUL-01** | CRÍTICA | **Zip Slip → ejecución remota de código.** Un archivo ZIP malicioso escribía fuera de la bóveda y podía *colocar un plugin ejecutable* en `.obsidian/plugins/`. |
| **VUL-02** | CRÍTICA | La función de restauración `restoreVaultZip()` **no existía**: la restauración fallaba en tiempo de ejecución. |
| **VUL-03** | CRÍTICA | El AAD del AES-GCM está ligado a la ruta del archivo, pero `rename`/`copy` **no estaban hookeados**: renombrar una nota la dejaba **permanentemente descifrable** (pérdida silenciosa de datos). |

Un atacante con acceso de lectura al disco podía **degradar el KDF** de 238 ms a 2 ms (VUL-04), y las **credenciales de la nube se guardaban en texto plano** dentro de la bóveda (VUL-07).

> **Nota sobre VUL-01:** la vulnerabilidad no era hipotética. `fflate.unzipSync()` preserva literalmente los nombres de entrada, incluidos `../` y rutas absolutas (verificado empíricamente, §3 → VUL-01).

### Segunda ronda: auditoría de la integración con Obsidian Sync y Publish

Una segunda ronda de auditoría se centró en las **integraciones con servicios externos**, auditando el código real de Obsidian (`app.js` del paquete `app.asar`) para determinar qué rutas de lectura usan realmente el motor de sincronización y el de publicación. Esa investigación reveló **cinco defectos adicionales** que anulaban la protección del cifrado transparente en los escenarios más comunes:

| ID | Severidad | Resumen |
|----|-----------|---------|
| **VUL-16** | CRÍTICA | **Fuga total de texto claro a Obsidian Sync.** El descifrado estaba en el hook del `DataAdapter`, la capa que Sync consume **directamente** (`app.vault.adapter.readBinary(path)`): todas las notas se subían a la nube **en claro**. |
| **VUL-17** | CRÍTICA | **Doble cifrado → pérdida irreversible de datos.** Sync reescribe el ciphertext descargado mediante `vault.modifyBinary()` → `adapter.writeBinary()`, y el hook lo cifraba **otra vez**, dejando la nota permanentemente ilegible. |
| **VUL-18** | ALTA | **Caché del `TFile` contaminada.** El `Vault.readBinary()` original cachea los bytes crudos, por lo que `cachedRead()` devolvía el sobre blindado en lugar de la nota. |
| **VUL-19** | ALTA | **Bucle de re-sincronización.** MetadataCache hashea el texto claro y Sync hashea el ciphertext: los hashes nunca coincidían, por lo que Sync re-descargaba y reescribía la bóveda entera en cada ejecución. |
| **VUL-20** | ALTA | **Publicación en un sitio web público.** Obsidian Publish leía las notas por la misma ruta que el indexador y las subía **en claro** a Internet. |

> **Nota sobre VUL-16 y VUL-17:** la causa raíz común era hookear la capa equivocada. El descifrado pertenece a `Vault.readBinary()` (que usa el indexador de metadatos), **nunca** al `DataAdapter` (que consume Sync). La corrección no consiste en "cifrar menos", sino en **separar las dos superficies** para que cada consumidor reciba exactamente lo que necesita. Los cinco hallazgos están corregidos y cubiertos por tests de regresión (§3 → VUL-16..VUL-20).

---

## 2. Metodología

1. **Modelado de amenazas.** Superficie expuesta: (a) archivos de la bóveda controlables por el atacante, (b) archivos ZIP de respaldo controlables por el atacante, (c) `vault-envelope.json` y `data.json` editables por quien tenga la bóveda, (d) respuestas HTTP de proveedores de nube, (e) red local (WebDAV).
2. **Revisión manual línea a línea** de los 32 módulos, priorizando: criptografía, gestión de claves, hooks del adaptador, motor de respaldo, proveedores de nube y UI.
3. **Verificación empírica.** Cada hipótesis se comprobó con un script ejecutable antes de tocar el código. Los falsos positivos se descartaron explícitamente (§4).
4. **Búsqueda de patrones peligrosos** en todo el árbol: `innerHTML`, `eval`, `execScript`, `document.write`, `prompt()`, `Math.random()`, `.buffer`, `localStorage`.
5. **Revisión de dependencias** (`npm audit` → 0 vulnerabilidades) y del *surface* de la API de Obsidian (`node_modules/obsidian/obsidian.d.ts`).
6. **Corrección + tests de regresión** que fallan con el código vulnerable y pasan con el corregido.

### Convenciones de severidad

| Severidad | Criterio |
|-----------|----------|
| **CRÍTICA** | Escritura arbitraria de archivos / RCE / pérdida irreversible de datos, alcanzable sin autenticación previa. |
| **ALTA** | Degradación fuerte de la seguridad criptográfica, o exposición de secretos, o corrupción/fuga silenciosa de contenido cifrado. |
| **MEDIA** | Filtración de información, incoherencias de política o riesgos explotables bajo condiciones específicas. |
| **BAJA** | Endurecimiento y mejores prácticas; impacto marginal por sí solo. |

---


## 3. Hallazgos detallados

### VUL-01 — Zip Slip / escritura arbitraria de archivos en la restauración

| | |
|---|---|
| **Severidad** | CRÍTICA |
| **Tipo** | CWE-22 (Path Traversal) → CWE-434 (Unrestricted Upload) → RCE |
| **Ubicación** | `src/backup/backup-engine.ts` → `restoreFromZip()` |
| **Estado** | ✅ Corregido |

**Descripción.** El motor de restauración descomprimía el ZIP y escribía cada entrada usando el nombre tal cual, sin ningún tipo de validación:

```ts
// Código vulnerable
const unzipped = unzipSync(zipBytes);            // preserva "../" y rutas absolutas
for (const [entryPath, data] of Object.entries(unzipped)) {
  await rawAdapter.write(entryPath, textContent); // escribe donde le digan
}
```

`fflate.unzipSync()` **no** sanea los nombres de entrada. Comprobación empírica:

```
=== TEST 1: unzipSync preserves ../ traversal paths (ZIP SLIP) ===
  key: "../../../../tmp/pwned.txt"
  key: "/etc/pwned_abs.txt"
  key: "normal/file.md"
```

**Impacto.**
- Escritura arbitraria de archivos **fuera de la bóveda** (`../../../../home/usuario/.bashrc`, `/etc/cron.d/...`).
- **Ejecución remota de código** vía *drop* de plugin: una entrada `.obsidian/plugins/evil/main.js` + `manifest.json` se instalaba como plugin de Obsidian y se ejecutaba con los privilegios del usuario.
- Sobrescritura de notas legítimas (destrucción de datos).

**Parche aplicado.** Nuevo módulo `src/utils/path-sanitizer.ts` con política de **rechazo** (nunca *reparación*: normalizar `../../etc/passwd` a `etc/passwd` escondería el ataque en lugar de detenerlo):

- Rechaza segmentos `..` (traversal).
- Rechaza rutas absolutas POSIX (`/…`), unidades Windows (`C:/…`) y UNC.
- Rechaza cualquier segmento que empiece por `.` → bloquea `.obsidian/`, `.git/`, `.trash/` y el *drop* de plugins.
- Rechaza bytes nulos, caracteres ilegales de Windows (`<>:"|?*`) y nombres reservados (`__proto__`, `constructor`, `prototype`).
- Limita longitud (1024) y número de segmentos (64).

```ts
// src/utils/path-sanitizer.ts
if (segment === '..') {
  return reject('Path traversal ("..") is not allowed.');
}
if (segment.startsWith('.')) {
  return reject('Hidden or system directories are not allowed.');
}
```

Integrado en `restoreFromZip()` **antes** de tocar el sistema de ficheros, con registro explícito del intento:

```ts
const sanitized = sanitizeVaultRelativePath(entryPath);
if (!sanitized.safe) {
  console.warn(`[MySecret] Blocked unsafe restore path "${entryPath}": ${sanitized.reason}`);
  result.skippedFiles++;
  result.errors.push({ path: entryPath, error: `Ruta de archivo rechazada por seguridad: ${sanitized.reason}` });
  continue;
}
```

### VUL-02 — Función de restauración inexistente (`restoreVaultZip`)

| | |
|---|---|
| **Severidad** | CRÍTICA |
| **Tipo** | CWE-477 (Uso de API no válida) → denegación de servicio funcional |
| **Ubicación** | `src/ui/restore-modal.ts:216` vs `src/backup/backup-engine.ts:202` |
| **Estado** | ✅ Corregido |

**Descripción.** El modal de restauración invocaba un método que no existía en `BackupEngine`:

```
$ grep -rn 'restoreVaultZip\|restoreFromZip' src/
src/ui/restore-modal.ts:216:      const result = await BackupEngine.restoreVaultZip(
src/backup/backup-engine.ts:202:  public static async restoreFromZip(
```

El bundle compilado confirma que el error se Arrastraba hasta producción:

```
main.js:5821:        const result = await BackupEngine.restoreVaultZip(
```

**Impacto.** La función de restauración lanzaba `TypeError` en el momento de ejecutarse: **la recuperación ante desastres era completamente inoperante**. Para un plugin cuyo propósito es la protección de datos, la ausencia de un camino de recuperación verificado es un fallo de seguridad crítico: induce a los usuarios a asumir que están protegidos cuando no pueden recuperar sus datos.

**Parche aplicado.** Se añadió el alias público que la capa de UI espera, delegando en la implementación segura:

```ts
/**
 * Restores vault files from a backup ZIP archive.
 * Alias kept for API compatibility with the UI layer.
 */
public static async restoreVaultZip(
  plugin: MySecretPlugin,
  zipBytes: Uint8Array,
  onProgress?: (currentFile: string, current: number, total: number) => void
): Promise<RestoreResult> {
  return BackupEngine.restoreFromZip(plugin, zipBytes, onProgress);
}
```

**Verificación.** Test `Restore: restoreVaultZip alias exists and behaves like restoreFromZip`.

---

### VUL-03 — Pérdida silenciosa de datos al renombrar o copiar archivos

| | |
|---|---|
| **Severidad** | CRÍTICA |
| **Tipo** | CWE-662 (Gestión incorrecta de recursos) / pérdida de disponibilidad de datos |
| **Ubicación** | `src/adapter/adapter-interceptor.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** El plugin usa el *Additional Authenticated Data* (AAD) del AES-256-GCM para **ligar criptográficamente cada archivo a su ruta**:

```ts
// El AAD es la ruta normalizada del archivo
const encResult = await encryptAesGcm(plainBytes, vaultKey, self.pathFilter.normalizePath(path));
```

Esta es una buena práctica (impide mover un ciphertext a otra ruta). Sin embargo, el interceptor **solo hookeaba `read`, `write`, `readBinary`, `writeBinary`, `append` y `process`**. Los métodos `rename` y `copy` del `DataAdapter` **no estaban hookeados**.

**Impacto.** Al renombrar `Notas/Privada.md` → `Notas/Publica.md`:
1. El archivo en disco conserva su ciphertext, ligado al AAD `Notas/Privada.md`.
2. El interceptor lo lee usando el AAD nuevo `Notas/Publica.md`.
3. La etiqueta de autenticación **falla** → `Decryption failed for Notas/Publica.md: Authentication check failed`.

El contenido se volvía **permanentemente indescifrable** (no recuperable ni con la contraseña maestra ni con la frase BIP-39). Lo mismo ocurría al mover una **carpeta completa**, que invalidate el AAD de todos sus descendientes. Renombrar es una operación cotidiana en un gestor de notas: el impacto es una pérdida de datos irreversible causada por una acción rutinaria.

**Parche aplicado.** Se hookearon `rename` y `copy`, con **re-bind del AAD**: el archivo se descifra con la ruta antigua y se recifra con la nueva. En el caso de una carpeta se recorre todo el subárbol.

```ts
// Hook de rename
a.rename = async function (path: string, newPath: string): Promise<void> {
  const oldNorm = self.pathFilter.normalizePath(path);
  const newNorm = self.pathFilter.normalizePath(newPath);

  // Snapshot del subárbol ANTES del rename
  const affected = await self.collectSubtreeFiles(oldNorm);

  await self.origRename(path, newPath);

  for (const relativePath of affected) {
    const fromAbs = relativePath.length === 0 ? oldNorm : `${oldNorm}/${relativePath}`;
    const toAbs   = relativePath.length === 0 ? newNorm : `${newNorm}/${relativePath}`;
    await self.rebindAad(fromAbs, toAbs);
  }
};
```

`rebindAad()` maneja los cuatro casos: texto cifrado, texto plano, binario cifrado y binario plano; y respeta los cambios de política de cifrado (p. ej. mover un archivo a una carpeta excluida lo **descifra** en disco, y moverlo desde una carpeta excluida lo **cifra**).

Dos decisiones de diseño relevantes:
- Se escribe siempre a través del adaptador **raw** (`origWrite`/`origWriteBinary`) para evitar una doble cifración.
- Si la bóveda está **bloqueada**, la operación **falla de forma explícita** en lugar de dejar el archivo indescifrable.

**Limitación conocida.** El re-bind re-cifra cada archivo movido, lo que añade latencia proporcional al tamaño en operaciones masivas sobre carpetas muy grandes.

##### Revisión de segunda ronda: dos defectos en el propio parche de VUL-03

Al revisar el parche ya aplicado (y no solo el código original), se detectaron **dos defectos en la implementación de la corrección**, ambos verificados empíricamente:

| # | Defecto en el parche | Causa raíz | Impacto del defecto | Corrección aplicada |
|---|----------------------|------------|---------------------|-------------------|
| **A** | `collectSubtreeFiles()` construía rutas **relativas** (`Notas/sub/Notas/sub/f.md`) | `DataAdapter.list()` devuelve **rutas absolutas** según el contrato documentado de `ListedFiles` ("The vault absolute paths of the files directly in the folder"), no nombres relativos | El re-bind de carpetas **nunca encontraba** los archivos → los descendientes quedaban **permanentemente indescifrables** tras renombrar una carpeta | Reescritura de `collectSubtreeFiles()` para devolver rutas absolutas, con recursión sobre `listing.folders` directamente |
| **B** | El hook `DataAdapter.rename()` **no se disparaba** en los renombrados iniciados por Obsidian | `Vault.rename()` y `FileManager.renameFile()` son la API pública; el hook del adaptador solo se activa si Obsidian *por casualidad* enruta la operación por el adaptador, lo cual **no forma parte del contrato público** | Los renombrados por *drag & drop*, explorador de archivos, comando "renombrar" o plugins de sincronización **no re-bindaban el AAD** → pérdida de datos irreversible | El re-bind se mueve al evento público `vault.on('rename', (file, oldPath) => …)`, registrado con `registerEvent()` en `main.ts`. El evento está garantizado por la API para todo renombrado |

**Verificación de la corrección.** Se creó `tests/test-adapter.mjs` (con un stub runtime del módulo `obsidian`, que solo distribuye declaraciones TypeScript) que exercise el flujo real:

```
ok 1 - Adapter: renaming a file re-binds the AAD so the content stays readable
ok 2 - Adapter: renaming a folder re-binds the AAD of every descendant
ok 3 - Adapter: collectSubtreeFiles returns ABSOLUTE paths (Obsidian contract)
ok 4 - Adapter: renaming a file leaves NO stale AAD binding
ok 5 - Adapter: copy re-binds the AAD to the destination path
```

El test 4 es especialmente relevante: verifica que tras el renombrado, el AAD **nuevo** descifra correctamente y el AAD **antiguo** es **rechazado**, es decir, que el re-bind ocurrió de verdad y no solo "parece funcionar".

**Limitación residual del parche.** Obsidian **no expone ningún evento público de `copy`** (verificado en `obsidian.d.ts`: los únicos eventos del `Vault` son `create`, `modify`, `delete`, `rename`). El hook `DataAdapter.copy()` es por tanto el **único** punto de intercepción disponible para las copias, y su disparo no está garantizado por el contrato público. Si Obsidian realizase una copia sin pasar por el adaptador, el duplicado conservaría el AAD de origen y sería indescifrable. *Mitigación futura*: vigilar el evento `create` y detectar archivos cuyo AAD no coincida con su ruta, re-vinculándolos de forma automática.

---


**Defensa en profundidad añadida.** Límites contra *ZIP bombs* en `src/constants.ts`:
`MAX_RESTORE_ENTRIES` (50 000), `MAX_RESTORE_ENTRY_BYTES` (512 MiB), `MAX_RESTORE_TOTAL_BYTES` (2 GiB), `MAX_RESTORE_ARCHIVE_BYTES` (512 MiB).

**Verificación.** Test `Restore: a malicious ZIP cannot escape the vault (Zip Slip regression)` — construye un ZIP con `../../../../tmp/pwned.txt`, `/etc/pwned.txt` y `.obsidian/plugins/evil/main.js`, y comprueba que solo se escribe la nota legítima. Salida real:

```
# [MySecret] Blocked unsafe restore path "../../../../tmp/mysecret_pwned.txt": Path traversal ("..") is not allowed.
# [MySecret] Blocked unsafe restore path "/etc/mysecret_pwned.txt": Absolute paths are not allowed.
# [MySecret] Blocked unsafe restore path ".obsidian/plugins/evil/main.js": Hidden or system directories are not allowed.
```


### VUL-04 — Degradación (downgrade) del KDF Argon2id mediante el sobre de la bóveda

| | |
|---|---|
| **Severidad** | ALTA |
| **Tipo** | CWE-327 (Algoritmo débil) / CWE-325 (Falta de comprobación de clave criptográfica) |
| **Ubicación** | `src/crypto/key-manager.ts`, `src/crypto/argon2.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** Los parámetros de coste de Argon2id se guardan dentro de `vault-envelope.json`, es decir **dentro de la propia bóveda**:

```json
{ "argon2": { "memory": 65536, "iterations": 3, "parallelism": 1, "salt": "…" } }
```

El código los usaba sin validar. `vault-envelope.json` reside en `.obsidian/plugins/mysecret/`, un directorio **legible y editable** por cualquiera que copie la bóveda del disco.

**Impacto.** Un atacante podía editar el sobre y sustituir `memory: 65536` por `memory: 8`, degradando brutalmente la derivación de clave. Medición empírica del coste real:

```
=== TEST C: Argon2id KDF DOWNGRADE via envelope-controlled params ===
  memory=65536KiB iters=3 par=1 -> 238ms  key=6ad10af97f174411...
  memory=1024KiB  iters=1 par=1 ->   3ms  key=c81fbb903532379a...
  memory=8KiB     iters=1 par=1 ->   2ms  key=6d9d4cd2bf048c1f...
```

**Factor ~100× de reducción del coste**, convirtiendo un ataque de diccionario offline (impracticable a 238 ms por intento) en trivial (2 ms por intento). La resistencia de la contraseña maestra —la única barrera que protege la bóveda si el usuario pierde la frase de recuperación— quedaba anulada.

**Parche aplicado.** Función de validación con suelos y techos duros en `src/crypto/argon2.ts`:

```ts
export function assertArgon2CostParams(params: Argon2CostParams): void {
  const { memoryKib, iterations, parallelism } = params;

  if (!Number.isInteger(memoryKib) || memoryKib < MIN_ARGON2_MEMORY_KIB) {
    throw new Error(`[MySecret] Argon2id memory cost is too low (${memoryKib} KiB). …`);
  }
  // …y análogamente para iteraciones, parallelismo y los techos máximos.
}
```

Constantes en `src/constants.ts`:

```ts
export const MIN_ARGON2_MEMORY_KIB = 65536;   // 64 MB
export const MIN_ARGON2_ITERATIONS = 3;
export const MIN_ARGON2_PARALLELISM = 1;
export const MAX_ARGON2_MEMORY_KIB = 1048576; // 1 GiB  (anti-DoS)
export const MAX_ARGON2_ITERATIONS = 20;
export const MAX_ARGON2_PARALLELISM = 16;
```

La validación se invoca en **tres** puntos de `KeyManager`: `unlockWithPassword()`, `unlockWithRecoveryPhrase()` (no aplica, pero mantiene la simetría del contrato) y `changeMasterPassword()`. Además, `deriveKeyArgon2id()` valida internamente, de modo que ningún camino de derivación puede eludir el control.

**Decisión de diseño importante.** El sobre con parámetros *por debajo* del suelo se **rechaza**, nunca se "mejora" automáticamente. Silenciosamente subir los parámetros derivaría una clave **distinta** y la bóveda quedaría ilegible. Es preferible un error explícito y accionable.

Los **techos** superiores son defensa contra denegación de servicio: un sobre manipulado pidiendo 4 GiB de memoria colapsaría el proceso de renderizado de Obsidian.

**Verificación.** Tests `Argon2 Params: rejects downgraded cost parameters`, `Argon2 Params: rejects DoS-inducing (oversized) cost parameters` y `Argon2id: deriveKey refuses downgraded parameters at runtime`.

---

### VUL-05 — `appendBinary` sin hook: fuga de texto plano y corrupción de adjuntos

| | |
|---|---|
| **Severidad** | ALTA |
| **Tipo** | CWE-311 (Cifrado ausente) / CWE-662 |
| **Ubicación** | `src/adapter/adapter-interceptor.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** El `DataAdapter` de Obsidian expone `appendBinary(path, data)`. El interceptor hookeaba `append` (texto) pero **no** `appendBinary`. Una escritura binaria se concatenaba **en crudo** sobre el archivo cifrado ya presente en disco.

**Impacto.** Doble daño:
1. **Fuga de confidencialidad:** el fragmento añadido era visible en claro en el disco, dentro de un archivo que el usuario y el plugin consideran cifrado.
2. **Corrupción:** el resultado no era un envelope AES-GCM válido; el archivo quedaba inutilizable e irrecuperable.

**Parche aplicado.** Hook completo que descifra, concatena en memoria y vuelve a cifrar:

```ts
if (a.appendBinary) {
  a.appendBinary = async function (path: string, data: ArrayBuffer, options?: any): Promise<void> {
    if (!self.pathFilter.shouldEncrypt(path)) {
      return await self.origAppendBinary(path, data, options);
    }
    // …descifrar el contenido actual…
    let existingBytes: Uint8Array = new Uint8Array(0);
    try {
      const rawBuffer = await self.origReadBinary(path);
      const rawBytes = new Uint8Array(rawBuffer);
      if (isBinaryEncrypted(rawBytes)) {
        const payload = deserializeBinary(rawBytes);
        existingBytes = await decryptAesGcm(payload.ciphertext, vaultKey, payload.iv, payload.tag,
                                           self.pathFilter.normalizePath(path));
      } else {
        existingBytes = rawBytes;
      }
    } catch { existingBytes = new Uint8Array(0); }

    // …fusionar y recifrar…
    const merged = new Uint8Array(existingBytes.length + appended.length);
    merged.set(existingBytes, 0);
    merged.set(appended, existingBytes.length);
    // → encryptAesGcm(merged, vaultKey, aad) → serializeBinary → origWriteBinary
  };
}
```

El método también se restaura en `uninstall()` para que la reversión de hooks sea completa.

---

---


### VUL-06 — Claves derivadas no se zeroizaban en las rutas de error

| | |
|---|---|
| **Severidad** | ALTA |
| **Tipo** | CWE-226 / CWE-244 (Gestión del ciclo de vida de la clave) |
| **Ubicación** | `src/crypto/key-manager.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** El módulo `src/utils/zeroize.ts` existía y se usaba, pero la secuencia `zeroize(passKeyBytes)` estaba colocada **después** de la llamada a `decryptAesGcm()`. Si esa llamada lanzaba (contraseña incorrecta, sobre corrupto, AAD incorrecto), la ejecución saltaba por el `catch` y **la clave derivada permanecía en la memoria**, sin borrar.

```ts
// Código vulnerable: el zeroize sólo se alcanzaba en el camino feliz
try {
  passKeyBytes = await deriveKeyArgon2id(...);
  const decryptedRawKey = await decryptAesGcm(...); // ← si lanza, no se borra
  zeroize(passKeyBytes);                            // ← inalcanzable en el error
  …
} catch (err) { return false; }
```

El error es más grave de lo que parece: en un desbloqueo fallido por contraseña incorrecta, la clave derivada de **ese** intento queda residente en el heap.

**Impacto.** Claves derivadas de la contraseña maestra retenidas en memoria tras un fallo de autenticación. La ventana de exposición depende del recolector de basura de JS (no hay garantía de borrado) y del hecho de que el string de la contraseña y sus derivados viven en un segmento de heap que no se puede garantizar que esté liberado.

**Parche aplicado.** Todos los métodos que derivan claves usan `try/finally`, garantizando el borrado en **cualquier** camino de salida:

```ts
let passKeyBytes: Uint8Array | null = null;
try {
  passKeyBytes = await deriveKeyArgon2id(…);
  …
} catch (err) {
  console.warn('[MySecret] Unlock failed (invalid password or corrupted envelope):', err);
  return false;
} finally {
  // Siempre se borra la clave derivada, incluido en el camino de error.
  zeroize(passKeyBytes);
}
```

Aplicado en `unlockWithPassword()`, `unlockWithRecoveryPhrase()`, `changeMasterPassword()` e `initializeVault()` (este último con dos claves: la de contraseña y la de recuperación).

Nota: `zeroize()` acepta `Uint8Array | null | undefined` y no falla con `null`, por lo que el `finally` es seguro incluso si la derivación nunca llegó a completarse.

---

### VUL-07 — Credenciales de nube almacenadas en texto plano dentro de la bóveda

| | |
|---|---|
| **Severidad** | ALTA |
| **Tipo** | CWE-312 (Almacenamiento de información sensible en claro) |
| **Ubicación** | `src/types.ts` (`CloudBackupSettings`), `src/main.ts`, `src/ui/settings-tab.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** Los tokens OAuth de Google Drive / OneDrive y la contraseña WebDAV se guardaban tal cual en `data.json` (el archivo de ajustes del plugin, dentro de `.obsidian/plugins/mysecret/`):

```ts
export interface CloudBackupSettings {
  provider: CloudProviderType;
  googleDrive: { accessToken: string; folderId: string; };
  oneDrive:   { accessToken: string; folderPath: string; };
  webdav:     { serverUrl: string; username: string; password: string; remotePath: string; };
  …
}
```

**Impacto.** Cualquiera con acceso de lectura al disco (copia de la bóveda, disco de respaldo, equipo compartido, sincronización en la nube sin cifrar, acceso forense) obtenía **acceso completo al almacenamiento del usuario**: con el token de Google Drive podía leer, modificar y borrar todos sus archivos en la nube; con la contraseña WebDAV, acceso al servidor NAS/Nextcloud.

La ironía era evidente: el plugin se autodenominaba "cifrado de grado militar" mientras guardaba sus propias credenciales de nube en texto plano en el mismo directorio.

**Parche aplicado.** Nuevo módulo `src/utils/credential-store.ts` que cifra cada credencial con la **vault key** (AES-256-GCM) usando un contexto de AAD **distinto** del usado para los archivos:

```ts
const CREDENTIAL_AAD = 'mysecret-credential-v1'; // ≠ AAD de ruta de archivo

export async function encryptCredential(vaultKey: CryptoKey, plaintext: string): Promise<string> {
  const enc = await encryptAesGcm(stringToBytes(plaintext), vaultKey, CREDENTIAL_AAD);
  const envelope = { iv: bytesToHex(enc.iv), tag: bytesToHex(enc.tag), ciphertext: bytesToHex(enc.ciphertext) };
  return ENCRYPTED_CREDENTIAL_PREFIX + JSON.stringify(envelope); // "enc:v1:{…}"
}
```

El AAD separado garantiza que un sobre de credenciales nunca pueda confundirse con una nota cifrada (ni viceversa).

**Decisiones de diseño.**
- Se usa la **vault key** y no una clave derivada de la contraseña: la vault key nunca cambia cuando el usuario modifica su contraseña maestra (solo se re-envuelve su sobre), por lo que **las credenciales sobreviven a un cambio de contraseña sin necesidad de recifrar**.
- `getDecryptedBackupSettings()` devuelve una **copia** con las credenciales descifradas, para que el material en claro no se propague al estado global del plugin.
- `saveSettings()` cifra **antes** de llamar a `saveData()`: el valor en claro nunca llega al disco.
- `getCredentialDisplayValue()` evita mostrar un valor cifrado como si fuera un token, y los campos de la UI son `type="password"`.
- **Migración compatible:** `isEncryptedCredential()` distingue valores legacy en claro de los cifrados; los legacy se siguen usando y se cifran en el siguiente guardado.

**Efecto secundario corregido.** El auto-respaldo "on-lock" se ejecutaba **después** de `keyManager.lock()`, es decir, cuando la vault key ya había sido borrada de la RAM: las credenciales ya no eran descifrables y la subida fallaba. Se invirtió el orden en `lockVault()`: las credenciales se resuelven **antes** de borrar la clave.

### VUL-08 — Confusión de `byteOffset`/`byteLength` al enviar cuerpos HTTP

| | |
|---|---|
| **Severidad** | MEDIA |
| **Tipo** | CWE-668 (Exposición de recursos a otro ámbito) |
| **Ubicación** | `src/utils/http.ts`, `src/backup/cloud/{webdav,onedrive,google-drive}.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** El cliente HTTP y los proveedores de nube enviaban el cuerpo de la petición como `data.buffer`. En JavaScript, un `Uint8Array` es una **vista** sobre un `ArrayBuffer` potencialmente mayor; `.buffer` devuelve el *backing store* completo, no la vista.

```ts
// Código vulnerable
body: options.body instanceof Uint8Array ? options.body.buffer : options.body
```

**Impacto.** Si la vista ocupaba una porción menor del buffer, se enviaban **bytes ajenos** —potencialmente fragmentos de otros datos en memoria— al servidor remoto. Es una fuga de información hacia terceros y una corrupción silenciosa del archivo subido (el servidor guardaba un ZIP con bytes de más).

**Parche aplicado.** Helper `toExactArrayBuffer()` que copia exactamente el slice de la vista:

```ts
export function toExactArrayBuffer(data: Uint8Array): ArrayBuffer {
  return data.slice().buffer as ArrayBuffer;
}
```

Aplicado en `http.ts` (ruta de `requestUrl` y de `fetch`) y en los tres proveedores que envían binarios.

**Verificación.** Test `HTTP: toExactArrayBuffer returns only the view bytes, not the whole buffer`:
```ts
const backing = new Uint8Array(100);
const view = backing.subarray(10, 20);
assert.strictEqual(view.buffer.byteLength, 100);             // el bug
assert.strictEqual(toExactArrayBuffer(view).byteLength, 10); // la corrección
```

---

### VUL-09 — Ausencia de validación de esquema URL y credenciales WebDAV sobre HTTP

| | |
|---|---|
| **Severidad** | MEDIA |
| **Tipo** | CWE-918 (SSRF) / CWE-319 (Transmisión en claro de información sensible) |
| **Ubicación** | `src/utils/http.ts`, `src/backup/cloud/webdav.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** `requestHttp()` pasaba la URL directamente a `fetch()` sin validar el esquema. La URL del servidor WebDAV provenía de la configuración del usuario y su cabecera `Authorization: Basic` (base64 de usuario:contraseña, es decir, **claro disfrazado**) se enviaba sobre cualquier transporte.

**Impacto.**
- **SSRF / acceso a recursos locales:** esquemas como `file:`, `blob:` o `javascript:` podían dirigir la petición a recursos locales o ejecutar contenido incrustado.
- **Credenciales en claro:** un servidor WebDAV configurado con `http://` recibía la contraseña en base64, decodificable trivialmente por cualquier interceptor de red.

**Parche aplicado.** Validación de esquema antes de adjuntar credenciales:

```ts
const ALLOWED_PROTOCOLS = ['https:', 'http:'];

export function assertSafeUrl(url: string, requireSecure = false): void {
  const parsed = new URL(url);                     // lanza si es malformada
  if (!ALLOWED_PROTOCOLS.includes(parsed.protocol)) {
    throw new Error(`Unsupported URL protocol: ${parsed.protocol}`);
  }
  if (requireSecure && parsed.protocol !== 'https:') {
    throw new Error('Refusing to send credentials over an insecure connection. Use HTTPS.');

### VUL-10 — Contraseña maestra mostrada en claro con `window.prompt()`

| | |
|---|---|
| **Severidad** | MEDIA |
| **Tipo** | CWE-200 (Exposición de información sensible) |
| **Ubicación** | `src/main.ts` → `promptChangePassword()` |
| **Estado** | ✅ Corregido |

**Descripción.** El cambio de contraseña maestra usaba `window.prompt()`, que renderiza la entrada **en texto plano**, sin enmascarar:

```ts
// Código vulnerable
const newPass = prompt('Introduce la nueva contraseña maestra:');
```

**Impacto.** La contraseña maestra quedaba expuesta en: la propia ventana del diálogo, capturas de pantalla, screen sharing, el historial de accesibilidad de algunos sistemas y la lista de ventanas del gestor de ventanas. Además, el flujo solo exigía 8 caracteres, más débil que los 12 exigidos por el asistente de configuración inicial (política inconsistente).

**Parche aplicado.** Nuevo modal dedicado `src/ui/change-password-modal.ts` con:
- Entradas `<input type="password">` (enmascaradas).
- `spellcheck="false"` y `autocomplete="new-password"`.
- Validación de longitud mínima, coincidencia entre los dos campos y **medidor de entropía** (`estimatePasswordEntropy()`), reutilizando la misma política que el asistente inicial.
- **Borrado del DOM**: `wipeInputs()` limpia ambos campos al enviar y al cerrar el modal.
- Envío con la tecla Enter.

---

### VUL-11 — Frase de recuperación BIP-39 perdida permanentemente al cerrar el asistente

| | |
|---|---|
| **Severidad** | MEDIA |
| **Tipo** | CWE-459 (Eliminación de información incompleta) → pérdida de acceso |
| **Ubicación** | `src/crypto/key-manager.ts`, `src/ui/setup-wizard.ts`, `src/main.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** La frase mnemónica se generaba dentro del `SetupWizardModal` y se conservaba solo en el campo privado `generatedMnemonic` del modal. Si el usuario cerraba el modal en el paso 2 (antes de la pantalla de confirmación de respaldo), la frase se destruía con `onClose()`:

```ts
public override onClose(): void {
  this.isClosed = true;
  this.generatedPassword = '';   // ← destruye el único punto de acceso
  this.generatedMnemonic = '';
}
```

**Impacto.** El usuario quedaba **permanentemente bloqueado** fuera de su bóveda: la contraseña maestra aún funcionaba, pero si también se perdía, la frase de recuperación —única vía de recuperación— ya no existía en ninguna parte. Peor aún, `promptShowRecoveryPhrase()` solo mostraba un aviso de que consultara "la copia de seguridad que guardaste", sin forma real de recuperarla.

**Parche aplicado.** La frase se conserva **en RAM dentro del `KeyManager`** (nunca en disco) y se expone mediante un getter:

```ts
private recoveryMnemonic: string | null = null;

public getRecoveryMnemonic(): string | null {
  return this.recoveryMnemonic;
}
```

- Se asigna en `initializeVault()` dentro del callback `commit()`.

### VUL-12 — Política de contraseña maestra inconsistente entre flujos

| | |
|---|---|
| **Severidad** | MEDIA |
| **Tipo** | CWE-521 (Requisitos de contraseña débiles) |
| **Ubicación** | `src/main.ts`, `src/ui/setup-wizard.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** Existían dos políticas divergentes:

| Flujo | Longitud mínima | Comprobación de entropía |
|------|-----------------|---------------------------|
| Asistente de configuración inicial | 12 caracteres | Sí (`estimatePasswordEntropy`) |
| Cambio de contraseña maestra | **8 caracteres** | **No** |

**Impacto.** Un usuario que hubiera configurado una contraseña fuerte podía luego cambiarla por una trivial de 8 caracteres sin ninguna advertencia.

**Parche aplicado.** Constante compartida en `src/constants.ts`:

```ts
export const MIN_MASTER_PASSWORD_LENGTH = 12;
```

El asistente de configuración ahora la importa en lugar de declarar su propio literal, garantizando que ambos flujos apliquen **exactamente la misma política**:

```ts
const MIN_PASSWORD_LENGTH = MIN_MASTER_PASSWORD_LENGTH;
```

El nuevo `ChangePasswordModal` aplica además el medidor de entropía y rechaza contraseñas de calidad `weak`.

---

### VUL-13 — `Math.random()` en el boundary multipart de Google Drive

| | |
|---|---|
| **Severidad** | BAJA |
| **Tipo** | CWE-330 (Uso de PRNG no criptográficamente seguro) |
| **Ubicación** | `src/backup/cloud/google-drive.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** El separador (*boundary*) del cuerpo `multipart/related` se generaba con `Math.random()`:

```ts

### VUL-14 — Prototype pollution y corrupción del mapa de archivos del ZIP

| | |
|---|---|
| **Severidad** | BAJA |
| **Tipo** | CWE-1321 (Prototype pollution) |
| **Ubicación** | `src/backup/backup-engine.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** El mapa de archivos del respaldo era un objeto plano y las rutas se usaban como claves:

```ts
const zipData: Record<string, Uint8Array> = {};
zipData[path] = fileBytes;   // path puede ser "__proto__"
```

En JavaScript, `obj['__proto__'] = x` **no crea una propiedad**: ejecuta el *setter* de `__proto__` del prototype, que —si `x` es un objeto— **reemplaza el prototipo del objeto**. Con un valor primitivo la asignación es un no-op silencioso y el archivo se pierde del respaldo.

**Impacto.** Un archivo de la bóveda llamado `__proto__` (o `constructor`) provocaba: pérdida silenciosa de ese archivo en el respaldo, o bien la inyección de propiedades enumerables en el prototipo de `zipData`, lo que a su vez podía hacer que el iterador `for...in` de `fflate` emitiera entradas no deseadas.

**Parche aplicado.** Detección y omisión explícita de los nombres peligrosos, en `src/utils/path-sanitizer.ts`:

```ts
export function hasForbiddenSegment(rawPath: string): boolean {
  const unified = rawPath.replace(/\\/g, '/');
  for (const segment of unified.split('/')) {
    if (FORBIDDEN_SEGMENTS.has(segment.trim().toLowerCase())) {
      return true;
    }
  }
  return false;
}
```

Y en el motor de respaldo:

```ts
if (hasForbiddenSegment(path)) {
  console.warn(`[MySecret] Skipped unsafe file name in backup: ${path}`);
  continue;
}
```

> **Hallazgo durante el parche.** La primera solución aplicada fue cambiar `zipData` por `Object.create(null)`. Al verificarla se descubrió que **`fflate` no soporta objetos con prototipo nulo**: su `zipSync` acumula internamente en un objeto normal (`t[n] = [val, op]`), por lo que una entrada `__proto__` corrompía el acumulador y `zipSync` fallaba con `Cannot read properties of undefined (reading 'level')` — **rompiendo todos los respaldos**. Se verificó en el código fuente de la librería (`node_modules/fflate/esm/browser.js`, funciones `fltn` y `zipSync`) antes de descartar ese enfoque. La solución final —filtrar los nombres peligrosos en origen y en restauración— es correcta y no altera el comportamiento de la librería.

---

### VUL-15 — Path traversal en el proveedor de carpeta sincronizada local

| | |
|---|---|
| **Severidad** | BAJA |
| **Tipo** | CWE-22 (Path Traversal) |
| **Ubicación** | `src/backup/cloud/local-sync.ts` |
| **Estado** | ✅ Corregido |

**Descripción.** El nombre del archivo de respaldo se componía a partir del **nombre de la bóveda** (`plugin.app.vault.getName()`), que es controlable por el usuario, y se concatenaba directamente con la ruta de destino:

```ts
// Código vulnerable
const targetFilePath = pathMod ? pathMod.join(this.destinationPath, filename)
                               : `${this.destinationPath}/${filename}`;
```

**Impacto.** Un nombre de bóveda malicioso (p. ej. `../../../etc/cron.d/evil`) escapaba del directorio de destino y escribía el archivo en una ubicación arbitraria del sistema de ficheros. El impacto es limitado porque el contenido es un ZIP, pero permite escribir en rutas del sistema (p. ej. `~/.bashrc`, `~/.config/autostart/`) y sobrescribir archivos existentes.

---

### VUL-16 — Fuga de texto claro a Obsidian Sync (descifrado en el adaptador)

| | |
|---|---|
| **Severidad** | CRÍTICA |
| **Tipo** | CWE-200 (Exposure of Sensitive Information) → CWE-319 (Cleartext Transmission) |
| **Ubicación** | `src/adapter/adapter-interceptor.ts` → hook `adapter.readBinary()` |
| **Estado** | ✅ Corregido |

**Descripción.** El descifrado transparente estaba implementado en el hook de `DataAdapter.readBinary()`, es decir, en la **capa más baja** del sistema de ficheros. Esa capa es compartida por *todos* los consumidores de la bóveda, no solo por el indexador de metadatos.

La auditoría del código real de Obsidian (`app.js` del paquete `app.asar`) estableció el mapa exacto de llamadas:

| Consumidor | Ruta real verificada | Bytes que recibía |
|-----------|----------------------|-------------------|
| MetadataCache (notas al pie, enlaces, frontmatter) | `vault.readBinary(file)` → `adapter.readBinary(path)` | texto claro ✅ |
| **Obsidian Sync** | `app.vault.adapter.readBinary(path)` — **llamada directa**, nunca pasa por `vault.readBinary` | texto claro ❌ **FUGA** |
| Obsidian Publish | `vault.readBinary(file)` | texto claro ❌ **FUGA** |

Fragmento del motor de sincronización (`prototype._sync`), que confirma el acceso directo al adaptador:

```js
// Sync: s = o.adapter  (o = this.vault)
n=(t=this).localFiles, i=t.serverFiles, ..., o=t.vault, a=t.filter, s=o.adapter, ...
// y en la subida de archivos:
[4,s.readBinary(Y)]   // ← lee el ciphertext o el texto claro según el hook
```

**Impacto.**
- **Todas** las notas cifradas se subían a la nube de Obsidian Sync **en texto claro**, anulando por completo la protección del plugin.
- La fuga era silenciosa: el usuario veía las notas correctamente en el editor (el indexador recibía texto claro) y no tenía ninguna señal de que su contenido viajaba en claro.
- Con Obsidian Publish, el texto claro se publicaba en un **sitio web público**.

**Parche aplicado.** El descifrado se movió al hook de `Vault.readBinary()` (`installVaultHooks()`), una **superficie distinta** que el indexador de metadatos y Publish comparten pero que Sync nunca toca:

```ts
// src/adapter/adapter-interceptor.ts — hook del ADAPTADOR: ciphertext puro
a.readBinary = async function (path: string): Promise<ArrayBuffer> {
  return await self.origReadBinary(path);
};

// src/adapter/adapter-interceptor.ts — hook de la BÓVEDA: texto claro
v.readBinary = async function (file: TFile): Promise<ArrayBuffer> {
  // ... descifra el contenedor y devuelve el texto plano
};
```

La distinción **no depende del llamante** dentro de `adapter.readBinary` (no se puede inspeccionar la pila de llamadas de forma fiable), sino de hookear por separado las dos APIs públicas. `Vault.readBinary` se restaura en `uninstall()` junto con los hooks del adaptador.

Los consumidores legítimos que necesitaban el texto claro (el respaldo "descifrado" y la migración "Descifrar todo") se adaptaron al nuevo método explícito `readPlaintextBinary()`, en lugar de esperar que el adaptador devolviera texto claro.

---

### VUL-17 — Doble cifrado al reescribir el ciphertext descargado por Sync

| | |
|---|---|
| **Severidad** | CRÍTICA |
| **Tipo** | CWE-662 (Improper Synchronization) → corrupción irreversible de datos |
| **Ubicación** | `src/adapter/adapter-interceptor.ts` → hooks `adapter.write()` y `adapter.writeBinary()` |
| **Estado** | ✅ Corregido |

**Descripción.** Obsidian Sync no solo **descarga** el ciphertext: también lo **reescribe** literalmente en disco cuando el archivo local ha cambiado. El flujo verificado en `syncFileDown()` es:

```js
// Sync descargando un archivo:
[4,e.pull(t.uid)]                        // descarga los bytes (el ciphertext)
...
[4,this.vault.modifyBinary(v,u,{...})]  // los reescribe en disco
// y Vault.modifyBinary acaba en:
[4,this.adapter.writeBinary(e.path,t,n)] // ← el hook de MySecret los cifraba OTRA VEZ
```

Con el hook de escritura cifrándolo todo indiscriminadamente, el ciphertext descargado se **cifraba por segunda vez**. El archivo resultante tenía dos capas de cifrado, y la capa externa autenticaba el *ciphertext* interno en lugar de la nota.

**Impacto.**
- La nota se volvía **permanentemente ilegible**: la segunda capa usaba un AAD (la ruta) correcto, pero el contenido descifrado era el sobre interno, no el texto del usuario.
- **Pérdida irreversible de datos**: el único camino de recuperación era volver a descifrar la bóveda manualmente con la herramienta offline.
- Ocurría de forma **sistemática** en cada archivo que Sync descargara, no solo en casos límite.

**Parche aplicado.** Antes de cifrar, los hooks `write` y `writeBinary` comprueban si los bytes ya son un **contenedor MySecret autenticado para esa ruta concreta**, mediante verificación criptográfica de la etiqueta GCM con el AAD (la ruta) como datos asociados (`isAuthenticContainer()` en `src/adapter/decrypt.ts`):

```ts
if (
  await isAuthenticContainer(
    plainBytes,
    self.pathFilter.normalizePath(path),
    self.keyManager
  )
) {
  return await self.origWriteBinary(path, toArrayBuffer(plainBytes), options);
}
```

La comprobación es **criptográfica, no estructural**: un archivo que solo *parezca* un contenedor (p. ej. una imagen cuyos primeros bytes sean `MYSE`) falla la verificación del tag GCM y se cifra con normalidad, por lo que nunca queda en claro en disco. Este matiz se cubre con un test de regresión explícito.

---

### VUL-18 — Caché en memoria del `TFile` contaminada con el ciphertext

| | |
|---|---|
| **Severidad** | ALTA |
| **Tipo** | CWE-200 (Exposure of Sensitive Information) → fallo funcional de la UI |
| **Ubicación** | `src/adapter/adapter-interceptor.ts` → hook `Vault.readBinary()` |
| **Estado** | ✅ Corregido |

**Descripción.** El `Vault.readBinary()` original de Obsidian no solo devuelve los bytes: **los cachea en el objeto `TFile`**:

```js
// Vault.readBinary (código real de Obsidian)
t.prototype.readBinary=function(e){return y(this,void 0,Promise,(function(n){
  switch(n.label){
    case 0:return[4,this.adapter.readBinary(e.path)];
    case 1:t=n.sent();
    try{"md"===e.extension&&t.byteLength<=this.cacheLimit&&e.cache((new TextDecoder).decode(t))}catch(e){}
    return[2,t]
}))}
```

El hook de MySecret interceptaba `Vault.readBinary` para devolver el texto claro, pero la caché del `TFile` ya había quedado **rellenada con el ciphertext** por la implementación original (que se ejecutaba antes de que el hook devolviera nada).

**Impacto.**
- `Vault.cachedRead()` —que es la ruta que usa el editor para mostrar el contenido— devolvía el **sobre blindado** en lugar de la nota, mostrando al usuario el bloque `-----BEGIN MYSECRET ENCRYPTED FILE-----` en lugar de su texto.
- El problema era intermitente y dependía del orden de las llamadas, lo que lo hacía especialmente difícil de diagnosticar.

**Parche aplicado.** Tras descifrar, el hook **sobrescribe la caché del `TFile` con el texto plano**, dejando `cachedRead()` coherente con `read()`:

```ts
if (typeof (file as any)?.cache === 'function') {
  try {
    (file as any).cache(new TextDecoder().decode(outcome.bytes));
  } catch (err) {
    // Un fallo al refrescar la caché no es fatal: `cachedRead()` releerá el archivo.
    console.warn(`[MySecret] Could not refresh the in-memory cache of ${path}:`, err);
  }
}
```

El error se captura de forma deliberada: si la caché no puede actualizarse, `cachedRead()` simplemente vuelve a leer el archivo del disco.

---

### VUL-19 — Divergencia de hashes entre MetadataCache y Sync (bucle de re-sincronización)

| | |
|---|---|
| **Severidad** | ALTA |
| **Tipo** | CWE-662 (Improper Synchronization) → denegación de servicio y desgaste de la nube |
| **Ubicación** | `src/adapter/adapter-interceptor.ts` → hook `Vault.readBinary()` |
| **Estado** | ✅ Corregido |

**Descripción.** Obsidian calcula **dos hashes distintos** para el mismo archivo, y ambos intervienen en la decisión de sincronización:

| Cálculo | Bytes hasheados | Verificado en |
|---------|-----------------|---------------|
| MetadataCache | `SHA-256(vault.readBinary(file))` → **texto claro** | `computeFileMetadataAsync()`: `[4,this.vault.readBinary(e)]` → `nP(t)` |
| Obsidian Sync | `SHA-256(adapter.readBinary(path))` → **ciphertext** | `_sync()`: `[4,s.readBinary(Y)]` → `nP(Z)` |

Sync **reutiliza el hash cacheado por el indexador** para decidir si un archivo cambió:

```js
// Sync comparando el hash local con el del servidor:
!G.hash&&(this.getHashFromMetadataCache(G),G.hash&&X&&!X.deleted&&X.hash===G.hash)
  ? (this.setStatus("Comparing "+Y), this.setDirty(), [2,!0])   // "no ha cambiado"
  : (this.log("Uploading file",Y), [4,e.push(Y,G.previouspath,!1,!1,Q,$,J,Z)])
```

```js
// getHashFromMetadataCache: toma el hash del CACHE (calculado sobre el texto claro)
t.prototype.getHashFromMetadataCache=function(e){
  var t=this.app.metadataCache.getFileInfo(e.path);
  t&&Math.ceil(t.mtime)===e.mtime&&t.size===e.size&&(e.hash=t.hash);
}
```

Al hashear bytes diferentes, los dos hashes **nunca podían coincidir**.

**Impacto.**
- Sync detectaba un cambio en **todos** los archivos en **cada** ejecución: re-descargaba y reescribía la bóveda entera indefinidamente.
- Consumo de ancho de banda y de cuota de almacenamiento constante, con riesgo de agotar el espacio de Sync.
- Interacción con VUL-17: cada reescritura era una oportunidad para el doble cifrado.
- El hash divergente invalidaba además cualquier estrategia de sincronización incremental.

**Parche aplicado.** `MetadataHashPatch` (`src/adapter/metadata-hash-patch.ts`) sustituye el hash que el cache de metadatos **expone** por el del ciphertext (el que Sync realmente compara), sin mutar la entrada original:

```ts
metadataCache.getFileInfo = function (path: string): any {
  const info = self.origGetFileInfo!(path);
  if (!info) return info;

  const ciphertextHash = self.ciphertextHashes.get(path);
  if (!ciphertextHash || info.hash === ciphertextHash) return info;

  // Se devuelve una COPIA: el hash original es la clave del mapa que
  // contiene los metadatos analizados (`metadataCache[hash]`). Mutarlo
  // haría que la bóveda perdiera enlaces, notas al pie y frontmatter.
  return { ...info, hash: ciphertextHash };
};
```

El hash del ciphertext se registra en el hook de `Vault.readBinary()`, que es donde se lee el archivo del disco:

```ts
await self.metadataHashPatch?.recordCiphertextHashFromBytes(path, rawBytes);
```

El formato del digest se reproduce **exactamente** como lo hace Obsidian (`Tb()`: hexadecimal en minúsculas, dos caracteres por byte, sin separador), en `src/crypto/hash.ts`, para que ambos hashes sean comparables.

---

### VUL-20 — Publicación de notas cifradas en un sitio web público (Obsidian Publish)

| | |
|---|---|
| **Severidad** | ALTA |
| **Tipo** | CWE-200 (Exposure of Sensitive Information) → exposición pública de datos |
| **Ubicación** | `src/adapter/publish-guard.ts` (archivo nuevo) |
| **Estado** | ✅ Corregido |

**Descripción.** Obsidian Publish es un plugin interno (requiere suscripción) que sube las notas a un **sitio web público**. El mapa de llamadas verificado muestra que lee el contenido mediante `vault.readBinary()`, la misma ruta que ahora entrega el texto claro al indexador:

```js
// Publish: apiUploadFile
e.prototype.apiUploadFile=function(e){return y(this,void 0,void 0,(function(){
  ...
  case 0: if(e.stat.size>52428800) throw new HD("TOOLARGE",...);
          return[4,this.getHash(e)];
  case 1: return t=i.sent(), [4,this.vault.readBinary(e)];   // ← TEXTO CLARO
  case 2: return n=i.sent(), [4,GD(XD.token,this.host,this.siteId,e.path,t,n)];
}))}
```

**Impacto.** Cualquier nota blindada publicada quedaba **en claro y accesible públicamente** en Internet, con las consecuencias que eso implica (URLs indexables, cachés de búsqueda, archivadores).

**Parche aplicado.** `PublishGuard` (`src/adapter/publish-guard.ts`) intercepta `apiUploadFile()` del plugin interno `publish` y **rechaza la subida de cualquier archivo cifrado en disco**, con un mensaje accionable:

```ts
instance.apiUploadFile = async function (file: TFile): Promise<unknown> {
  const blocked = await self.assertPublishable(file);
  if (!blocked) {
    return await self.origApiUploadFile!(file);
  }
  throw new Error(
    '[MySecret] Obsidian Publish no puede publicar "' + file.path +
    '" porque la nota está cifrada. ... Usa "Descifrar todo" en MySecret antes de publicar...'
  );
};
```

**Decisión de diseño: por qué no se deshabilita el plugin.** Inicialmente se evaluó desactivar Publish mediante APIs internas. Se descartó por dos razones:

1. `internalPlugins.getPluginById('publish')` es una API **no pública** que puede cambiar sin aviso entre versiones de Obsidian.
2. Deshabilitar un plugin es un cambio **destructivo e invisible** en la configuración del usuario, y la decisión de publicar una bóveda le corresponde a él, no al plugin.

La alternativa adoptada es **interceptar y bloquear la subida**, que es reversible, explica el motivo y deja la puerta abierta al flujo legítimo ("Descifrar todo" → publicar). La detección del plugin se hace con `internalPlugins.getEnabledPluginById('publish')`, que es una **consulta de solo lectura** y no muta nada.

Las notas en texto plano (carpetas excluidas de la cifrado) se publican con normalidad.

---

## 4. Hallazgos evaluados y descartados (falsos positivos)

Una auditoría rigurosa debe documentar también lo que **se investigó y resultó no ser una vulnerabilidad**. Todos los puntos siguientes se verificaron empíricamente y se descartaron:

| Módulo | Hipótesis evaluada | Resultado de la verificación | Decisión |
|--------|--------------------|-------------------------------|----------|
| `src/crypto/bip39.ts` | La implementación pura de SHA-256 podría ser incorrecta y producir mnemónicas inválidas | Un primer banco de pruebas dio 99/100 discrepancias, pero **el harness de comprobación tenía un error de transcripción** de la constante `K`. Repetido contra `node:crypto` y con los vectores oficiales de Trezor: **200/200 vectores aleatorios coinciden** | **Correcto** — sin cambios |
| `src/crypto/bip39.ts` | El PBKDF2 usa 2048 iteraciones (valor bajo frente a las recomendaciones actuales) | Es el valor **de facto de BIP-39**; cambiarlo rompería la compatibilidad con cualquier monedero BIP-39 estándar | **Aceptable** — documentado |
| `src/crypto/aes.ts` | El tag de 16 bytes se separa del ciphertext | El cálculo `length - AES_GCM_TAG_LENGTH` es correcto para WebCrypto, que concatena `ciphertext‖tag` | **Correcto** |
| `src/crypto/aes.ts` | `importAesKey` con `extractable: false` | Correcto: impide exportar la clave desde la CryptoKey | **Correcto** |
| `src/crypto/envelope.ts` | El parser blindado podría aceptar cabeceras manipuladas | Rechaza IV/Tag ausentes; `parseInt` sobre `Version` no da lugar a confusión de tipos porque la versión no altera el descifrado | **Correcto** |
| `src/ui/*.ts` | XSS vía `innerHTML` | Las 8 apariciones de `innerHTML` usan **literales SVG constantes** (`EYE_ICON`, `EYE_ICON_OFF`). Ninguna concatena datos de usuario | **Correcto** |
| `src/ui/*.ts` | XSS vía `setText()` / `createEl({text})` | Obsidian asigna por `textContent`, no por `innerHTML`. Los nombres de archivo y rutas de los flujos de migración/restore se renderizan con `setText` | **Correcto** |
| `src/ui/*.ts` | `eval`, `execScript`, `document.write` | Búsqueda global: **0 coincidencias** | **Correcto** |
| `src/ui/restore-modal.ts` | `JSON.parse` del manifiesto sin validar podría permitir inyección | El manifiesto solo se usa para decidir `mode === 'encrypted'`; nunca se interpola en HTML | **Correcto** |
| `src/main.ts` | Credenciales en `localStorage` | No se usa `localStorage` ni `sessionStorage` en todo el proyecto | **Correcto** |
| `src/backup/backup-engine.ts` | El tamaño de `data.buffer` en el restore podría filtrar bytes ajenos | Se verificó con `unzipSync`: fflate **always** devuelve vistas con `byteOffset === 0` y `buffer.byteLength === length` | **No explotable** — corregido igualmente en el envío HTTP (VUL-08) |
| `src/adapter/path-filter.ts` | `isSystemExcluded` compara `normalized.startsWith(prefix)` con prefijos que acaban en `/` | Correcto: `.obsidian/` exige la barra final, evitando que `.obsidian-backup/` quede excluido. Además `baseName.startsWith('.')` cubre los dotfiles en la raíz | **Correcto** |
| `src/adapter/path-filter.ts` | `isUserExcluded` por `startsWith` podría confundir `Publico` con `Public` | La comprobación es `normalized.startsWith(folder + '/') || normalized === folder`: distingue correctamente los prefijos | **Correcto** |
| `src/crypto/key-manager.ts` | El sobre de la bóveda se guardaba en una ruta fija dentro de `.obsidian/` | Correcto: `.obsidian/` está excluido del cifrado por diseño (contiene la configuración de Obsidian) | **Correcto** (con la salvedad de VUL-04) |
| `manifest.json` | Permisos excesivos para un plugin de Obsidian | El manifiesto de Obsidian no tiene modelo de permisos; `isDesktopOnly: false` es correcto y no expone APIs nativas | **Correcto** |
| Dependencias | Vulnerabilidades en `fflate` / `hash-wasm` | `npm audit --omit=dev` → **0 vulnerabilidades**. `fflate@0.8.3` y `hash-wasm@4.12.0` son las últimas versiones | **Correcto** |

---

## 5. Aspectos positivos destacados

La auditoría no solo encontró defectos; confirmó la solidez de varias decisiones de diseño originales, que se conservaron intactas:

- **AES-256-GCM con AAD ligado a la ruta.** Es una excelente práctica: impide que un ciphertext se traslade a otra ruta y sea descifrado allí. El problema no era el diseño, sino la ausencia de un hook de `rename`/`copy` (VUL-03).
- **Clave de bóveda (DEK) separada de la clave maestra (KEK).** El sobre envuelve una clave de 256 bits generada aleatoriamente; cambiar la contraseña maestra no reescribe las notas. Correcto y bien implementado.
- **BIP-39 con 24 palabras (256 bits de entropía)** y comprobación de checksum verificada contra vectores oficiales.
- **IV aleatorio de 96 bits** generado con `crypto.getRandomValues()` en cada cifrado (nunca reutilizado).
- **`extractable: false`** en la importación de la CryptoKey: la clave no puede extraerse.
- **Uso de Web Crypto API** en lugar de implementaciones criptográficas propias (salvo el SHA-256 de un solo bloque de BIP-39, verificado como correcto).
- **Envoltorio del sobre con AAD separadores** (`'vault-envelope'` / `'recovery-envelope'`), que impide la confused-deputy entre contextos.
- **`zeroize()`** como utilidad criptográfica explícita (aunque mal aplicada en las rutas de error, VUL-06).

---


**Parche aplicado.** Saneo del nombre antes de componer la ruta, con verificación de que no contiene separadores:

```ts
const safeName = sanitizeVaultRelativePath(filename);
if (!safeName.safe || safeName.path.includes('/')) {
  return {
    success: false,
    message: `Nombre de archivo de copia de seguridad no válido: ${safeName.reason || 'la ruta contiene separadores'}`
  };
}
const targetFilePath = pathMod ? pathMod.join(this.destinationPath, safeName.path)
                               : `${this.destinationPath}/${safeName.path}`;
```

---

// Código vulnerable
const boundary = '-------MySecretBackupBoundary' + Math.random().toString(36).substring(2);
```

**Impacto.** `Math.random()` **no** es criptográficamente seguro (implementación V8 con `xorshift128+`, estado de 128 bits recuperable). Un atacante que controle parte del contenido subido podía colocar deliberadamente la cadena del boundary dentro del payload y provocar que el servidor reinterprete el cuerpo y añada partes MIME adicionales (*multipart injection*), o facilitar colisiones de parsing.

**Parche aplicado.** Generación con el CSPRNG de Web Crypto:

```ts
function generateMultipartBoundary(): string {
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }

## 6. Inventario de cambios aplicados

### 6.1 Archivos nuevos

| Archivo | Propósito | Vulnerabilidades |
|---------|-----------|------------------|
| `src/utils/path-sanitizer.ts` | Saneo y validación de rutas no confiables (Zip Slip, plugin drop, prototype pollution) | VUL-01, VUL-14, VUL-15 |
| `src/utils/credential-store.ts` | Cifrado/descifrado de credenciales de nube en reposo (AES-256-GCM + AAD separado) | VUL-07 |
| `src/ui/change-password-modal.ts` | Cambio de contraseña maestra con entrada enmascarada y medidor de entropía | VUL-10, VUL-12 |
| `src/ui/recovery-phrase-modal.ts` | Visualización de la frase BIP-39 con portapapeles con borrado automático | VUL-11 |
| `tests/test-security.mjs` | Suite de 22 tests de regresión de seguridad | todas |
| `tests/test-adapter.mjs` | Suite de 5 tests del interceptor (re-bind del AAD en renombrados y copias) | VUL-03 |
| `tests/obsidian-stub.mjs` | Stub runtime del módulo `obsidian` (el paquete real solo distribuye declaraciones) | VUL-03 |
| `src/adapter/decrypt.ts` | Detección del formato del contenedor sobre bytes crudos; descifrado compartido; `toArrayBuffer()` con copia exacta; `isAuthenticContainer()` (verificación criptográfica del contenedor) | VUL-16, VUL-17 |
| `src/adapter/metadata-hash-patch.ts` | Alineación del hash del MetadataCache con el hash del ciphertext que compara Obsidian Sync | VUL-19 |
| `src/adapter/publish-guard.ts` | Bloqueo de la subida de notas cifradas a Obsidian Publish (sitio web público) | VUL-20 |
| `src/crypto/hash.ts` | SHA-256 con codificación hexadecimal idéntica a la de Obsidian, para hacer comparables ambos hashes | VUL-19 |

### 6.2 Archivos modificados

| Archivo | Cambios | Vulnerabilidades |
|---------|---------|------------------|
| `src/backup/backup-engine.ts` | Validación de rutas antes de escribir; límites anti-ZIP-bomb; alias `restoreVaultZip()`; omisión de nombres con `__proto__`/`constructor`; el respaldo "descifrado" usa `readPlaintextBinary()` | VUL-01, VUL-02, VUL-14, VUL-16 |
| `src/adapter/adapter-interceptor.ts` | Hooks de `appendBinary` y `copy`; re-bind del AAD vía evento público `vault.on('rename')` (`handleVaultRename`, `collectSubtreeFiles` con rutas absolutas); **descifrado movido al hook `Vault.readBinary()`** (`installVaultHooks()`); `adapter.readBinary()` devuelve el ciphertext; verificación anti doble cifrado en `write`/`writeBinary`; refresco de la caché del `TFile`; `readPlaintextBinary()`; restauración completa en `uninstall()` | VUL-03, VUL-05, VUL-16, VUL-17, VUL-18, VUL-19 |
| `src/crypto/key-manager.ts` | Validación de parámetros Argon2id; `try/finally` para zeroize; retención de la frase de recuperación en RAM | VUL-04, VUL-06, VUL-11 |
| `src/crypto/argon2.ts` | `assertArgon2CostParams()` con suelos/techos; validación interna en `deriveKeyArgon2id()` | VUL-04 |
| `src/utils/http.ts` | `assertSafeUrl()`; `toExactArrayBuffer()`; normalización del cuerpo de la petición | VUL-08, VUL-09 |
| `src/backup/cloud/webdav.ts` | HTTPS obligatorio; `toExactArrayBuffer()` | VUL-08, VUL-09 |
| `src/backup/cloud/google-drive.ts` | Boundary multipart con CSPRNG; `toExactArrayBuffer()` | VUL-08, VUL-13 |
| `src/backup/cloud/onedrive.ts` | `toExactArrayBuffer()` | VUL-08 |
| `src/backup/cloud/local-sync.ts` | Saneo del nombre de archivo de respaldo | VUL-15 |
| `src/adapter/media-manager.ts` | Descifrado explícito de los adjuntos (`decryptContainer()`), ya que el adaptador devuelve el ciphertext | VUL-16 |
| `src/main.ts` | Cifrado/descifrado de credenciales; `setEncryptedCredential()`; `getDecryptedBackupSettings()`; orden corregido del auto-respaldo "on-lock"; modal de cambio de contraseña; registro del evento `vault.on('rename')`; instalación del hook `Vault.readBinary()`, del parche de hash y del guard de Publish | VUL-03, VUL-07, VUL-10, VUL-12, VUL-16, VUL-19, VUL-20 |
| `src/ui/migration-modal.ts` | La migración "Descifrar todo" usa `readPlaintextBinary()` en lugar de esperar el texto claro del adaptador | VUL-16 |
| `src/ui/settings-tab.ts` | Campos de credencial en modo contraseña; escritura cifrada | VUL-07, VUL-10 |
| `src/ui/cloud-backup-modal.ts` | Resolución asíncrona del proveedor con credenciales descifradas | VUL-07 |
| `src/ui/setup-wizard.ts` | Constante compartida de longitud mínima | VUL-12 |
| `src/constants.ts` | Suelos/techos de Argon2id; `MIN_MASTER_PASSWORD_LENGTH`; límites de restauración | VUL-01, VUL-04, VUL-12 |
| `package.json` | El script `test` compila y ejecuta ambas suites | — |

### 6.3 Fragmentos de código críticos

**Control de Zip Slip** (`src/utils/path-sanitizer.ts`):
```ts
if (segment === '..') {
  return reject('Path traversal ("..") is not allowed.');
}
if (segment.startsWith('.')) {
  return reject('Hidden or system directories are not allowed.');
}
if (FORBIDDEN_SEGMENTS.has(segment.toLowerCase())) {
  return reject('Reserved segment name is not allowed.');
}
```

**Control de downgrade del KDF** (`src/crypto/argon2.ts`):
```ts
if (!Number.isInteger(memoryKib) || memoryKib < MIN_ARGON2_MEMORY_KIB) {
  throw new Error(`[MySecret] Argon2id memory cost is too low (${memoryKib} KiB). ` +
                  `At least ${MIN_ARGON2_MEMORY_KIB} KiB is required.`);
}
```

**Zeroize garantizado** (`src/crypto/key-manager.ts`):
```ts
} finally {
  // Always wipe the derived pass key, including on the failure path.
  zeroize(passKeyBytes);
}
```

**Credenciales cifradas en reposo** (`src/utils/credential-store.ts`):
```ts
const enc = await encryptAesGcm(stringToBytes(plaintext), vaultKey, CREDENTIAL_AAD);
return ENCRYPTED_CREDENTIAL_PREFIX + JSON.stringify(envelope);
```

**Boundary multipart con CSPRNG** (`src/backup/cloud/google-drive.ts`):
```ts
return `-------MySecretBackupBoundary${hex}`;
}
```
128 bits de entropía real.

**Zeroize garantizado** (`src/crypto/key-manager.ts`):
```ts
} finally {
  // Always wipe the derived pass key, including on the failure path.
  zeroize(passKeyBytes);
}
```

**HTTPS obligatorio en WebDAV** (`src/backup/cloud/webdav.ts`):
```ts
private assertSecureTransport(): void {
  assertSafeUrl(this.serverUrl, true); // requireSecure = true
}
```
Este control se aplica en `testConnection()` y en `uploadBackup()`, comunicando al usuario el motivo del rechazo.

**Verificación.** Tests `HTTP: rejects dangerous URL schemes`, `HTTP: rejects malformed URLs`, `HTTP: accepts http/https, and enforces HTTPS when required`.

**Separación de superficies de lectura** (`src/adapter/adapter-interceptor.ts`):
```ts
// El ADAPTADOR devuelve el ciphertext: Obsidian Sync lo consume directamente.
a.readBinary = async function (path: string): Promise<ArrayBuffer> {
  return await self.origReadBinary(path);
};

// La BÓVEDA devuelve el texto claro: lo consume el indexador de metadatos.
v.readBinary = async function (file: TFile): Promise<ArrayBuffer> {
  // ... descifra el contenedor y devuelve el texto plano
};
```

**Verificación criptográfica anti doble cifrado** (`src/adapter/decrypt.ts`):
```ts
export async function isAuthenticContainer(
  rawBytes: Uint8Array,
  aad: string,
  keyManager: KeyManager
): Promise<boolean> {
  // Descifra y verifica la etiqueta GCM con la ruta como AAD.
  // Solo un contenedor producido por MySecret para esa ruta pasa la prueba.
}
```

**Alineación del hash con Sync** (`src/adapter/metadata-hash-patch.ts`):
```ts
// Se devuelve una COPIA: el hash original indexa los metadatos analizados.
return { ...info, hash: ciphertextHash };
```

## 7. Verificación

### 7.1 Suite de tests

```
$ npm test

# tests 96
# pass 96
# fail 0
# cancelled 0
# duration_ms 1992.781157
```

Detalle de los tests de seguridad añadidos (22 de `test-security.mjs` + 16 de `test-adapter.mjs`):

```
ok 1  - Adapter: renaming a file re-binds the AAD so the content stays readable
ok 2  - Adapter: renaming a folder re-binds the AAD of every descendant
ok 3  - Adapter: collectSubtreeFiles returns ABSOLUTE paths (Obsidian contract)
ok 4  - Adapter: renaming a file leaves NO stale AAD binding
ok 5  - Adapter: copy re-binds the AAD to the destination path
ok 6  - Path Sanitizer: blocks path traversal (Zip Slip)
ok 7  - Path Sanitizer: blocks hidden/system directories (plugin drop)
ok 8  - Path Sanitizer: blocks prototype pollution segment names
ok 9  - Path Sanitizer: blocks null bytes and illegal characters
ok 10 - Path Sanitizer: accepts legitimate vault paths
ok 11 - Path Sanitizer: rejects empty and overlong paths
ok 12 - Argon2 Params: rejects downgraded cost parameters
ok 13 - Argon2 Params: rejects DoS-inducing (oversized) cost parameters
ok 14 - Argon2 Params: accepts the default (secure) parameters
ok 15 - Argon2id: deriveKey refuses downgraded parameters at runtime
ok 16 - Backup: a null-prototype map is not polluted by a "__proto__" file
ok 17 - Backup: a "__proto__" file name cannot pollute Object.prototype
ok 18 - HTTP: rejects dangerous URL schemes
ok 19 - HTTP: rejects malformed URLs
ok 20 - HTTP: accepts http/https, and enforces HTTPS when required
ok 21 - HTTP: toExactArrayBuffer returns only the view bytes, not the whole buffer
ok 22 - Credentials: are encrypted at rest and decryptable with the vault key
ok 23 - Credentials: a different vault key cannot decrypt the envelope
ok 24 - Credentials: a tampered envelope is rejected (authenticated encryption)
ok 25 - Credentials: legacy plain-text values are detected as NOT encrypted
ok 26 - Restore: a malicious ZIP cannot escape the vault (Zip Slip regression)
ok 27 - Restore: restoreVaultZip alias exists and behaves like restoreFromZip
```

Tests de regresión de la tercera ronda (VUL-16..VUL-20), en `tests/test-adapter.mjs`:

```
ok  9 - SECURITY: adapter.readBinary returns the CIPHERTEXT so Obsidian Sync cannot upload the cleartext
ok 10 - SECURITY: vault.readBinary decrypts for the indexer while the adapter keeps the ciphertext
ok 11 - SECURITY: vault.readBinary refreshes the in-memory TFile cache with the plaintext
ok 12 - DATA INTEGRITY: Obsidian Sync writing back the ciphertext does NOT double-encrypt the note
ok 13 - DATA INTEGRITY: a file that merely LOOKS like a container is still encrypted normally
ok 14 - DATA INTEGRITY: append propagates a read failure instead of truncating the note
ok 15 - DATA INTEGRITY: appendBinary refuses to corrupt an armored text note
ok 16 - DATA INTEGRITY: renaming a plaintext, armored and binary file keeps the content readable
ok 17 - SECURITY: the metadata cache hash is aligned with the ciphertext hash used by Obsidian Sync
ok 18 - SECURITY: Obsidian Publish cannot upload the cleartext of an encrypted note
```

### 7.2 Comprobaciones adicionales

| Comprobación | Resultado |
|--------------|-----------|
| `npx tsc --noEmit -p tsconfig.json` | **0 errores** |
| `npm run build` (bundle de producción) | **Éxito** — `main.js` 722 487 bytes |
| `npm audit --omit=dev` | **0 vulnerabilidades** |
| Correcciones presentes en el bundle | `sanitizeVaultRelativePath`, `assertArgon2CostParams`, `toExactArrayBuffer`, `assertSafeUrl`, `encryptCredential`, `rebindAad`, `origAppendBinary`, `restoreVaultZip`, `hasForbiddenSegment` — **todas presentes** |
| Segunda ronda presente en el bundle | `installVaultHooks`, `isAuthenticContainer`, `recordCiphertextHashFromBytes`, `apiUploadFile` — **todas presentes** |
| Ausencia de `prompt()` para contraseñas | **0 coincidencias** |
| Ausencia de `Math.random()` en el boundary multipart | **0 coincidencias** |
| Ausencia de `body: data.buffer` / `body: fullBody.buffer` | **ninguna** |

---

## 8. Tabla resumen de hallazgos

| ID | Severidad | Componente | Vulnerabilidad | Estado |
|----|-----------|------------|----------------|--------|
| VUL-01 | **CRÍTICA** | `backup-engine.ts` | Zip Slip / escritura arbitraria de archivos → RCE | ✅ Corregido |
| VUL-02 | **CRÍTICA** | `restore-modal.ts` | `restoreVaultZip()` inexistente → restauración rota | ✅ Corregido |
| VUL-03 | **CRÍTICA** | `adapter-interceptor.ts` | `rename`/`copy` sin hook → pérdida de datos irreversible | ✅ Corregido |
| VUL-04 | **ALTA** | `key-manager.ts` | Downgrade del KDF Argon2id (238 ms → 2 ms) | ✅ Corregido |
| VUL-05 | **ALTA** | `adapter-interceptor.ts` | `appendBinary` sin hook → fuga de texto plano | ✅ Corregido |
| VUL-06 | **ALTA** | `key-manager.ts` | Claves derivadas no zeroizadas en rutas de error | ✅ Corregido |
| VUL-07 | **ALTA** | `types.ts` / `main.ts` | Credenciales de nube en texto plano en la bóveda | ✅ Corregido |
| VUL-08 | MEDIA | `http.ts` / cloud | Confusión de `byteOffset` al enviar cuerpos | ✅ Corregido |
| VUL-09 | MEDIA | `http.ts` / `webdav.ts` | Sin validación de esquema URL; credenciales sobre HTTP | ✅ Corregido |
| VUL-10 | MEDIA | `main.ts` | Contraseña maestra visible con `window.prompt()` | ✅ Corregido |
| VUL-11 | MEDIA | `key-manager.ts` | Frase BIP-39 perdida al cerrar el asistente | ✅ Corregido |
| VUL-12 | MEDIA | `main.ts` / `setup-wizard.ts` | Política de contraseña inconsistente (8 vs 12) | ✅ Corregido |
| VUL-13 | BAJA | `google-drive.ts` | `Math.random()` en el boundary multipart | ✅ Corregido |
| VUL-14 | BAJA | `backup-engine.ts` | Prototype pollution con `__proto__` | ✅ Corregido |
| VUL-15 | BAJA | `local-sync.ts` | Path traversal en el nombre del respaldo | ✅ Corregido |
| **VUL-16** | **CRÍTICA** | `adapter-interceptor.ts` | Descifrado en el `DataAdapter` → **fuga de texto claro a Obsidian Sync** | ✅ Corregido |
| **VUL-17** | **CRÍTICA** | `adapter-interceptor.ts` | Re-cifrado del ciphertext de Sync → **doble cifrado y pérdida de datos** | ✅ Corregido |
| **VUL-18** | **ALTA** | `adapter-interceptor.ts` | Caché del `TFile` contaminada con el ciphertext → el editor muestra el sobre | ✅ Corregido |
| **VUL-19** | **ALTA** | `adapter-interceptor.ts` | Hash del MetadataCache ≠ hash de Sync → bucle de re-sincronización | ✅ Corregido |
| **VUL-20** | **ALTA** | `publish-guard.ts` | Publicación de notas cifradas en un sitio web público | ✅ Corregido |

**Totales: 20 hallazgos** — 5 CRÍTICA, 9 ALTA, 4 MEDIA, 3 BAJA. **Todos corregidos.**

## 9. Limitaciones conocidas y recomendaciones residuales

Tras la corrección quedan estos puntos, que **no** son vulnerabilidades explotables en el estado actual pero conviene documentar:

1. **Rendimiento del re-bind del AAD (VUL-03).** Renombrar una carpeta con miles de archivos re-cifra cada uno. En carpetas muy grandes la operación puede tardar perceptiblemente. *Mitigación futura*: re-derivar la clave por ruta mediante un *key derivation* determinista, en lugar de re-cifrar el contenido.

2. **La frase de recuperación no persiste entre reinicios de Obsidian (VUL-11).** Se conserva en RAM y se borra al bloquear la bóveda. Si el usuario cierra el asistente sin copiar la frase, debe usar la copia que hizo en el paso 3. *Mitigación futura*: mostrar un aviso persistente en el asistente mientras la frase no se haya confirmado.

3. **Credenciales de nube irrecuperables sin la contraseña maestra.** Es el comportamiento correcto (es el objetivo del cifrado), pero si el usuario pierde la contraseña y la frase, las credenciales cifradas en `data.json` quedan inutilizables de forma permanente. *Mitigación futura*: avisar al usuario de esta consecuencia al activar el respaldo en la nube.

4. **`PBKDF2` con 2048 iteraciones para BIP-39.** Es el estándar de facto y se mantiene por compatibilidad, pero 2048 iteraciones de PBKDF2-HMAC-SHA512 son débiles frente a Argon2id. *Mitigación futura*: evaluar un esquema de derivación propio para la clave de recuperación, conservando la interoperabilidad BIP-39 mediante una función de derivación de clave única.

5. **`vault-envelope.json` no está autenticado.** Su integridad depende de la etiqueta GCM de la clave envuelta, que sí detecta la manipulación (VUL-04 la mitiga). *Mitigación futura*: incluir una firma o un campo de versión por clave.

6. **Restauración sin verificación previa de la integridad del conjunto.** La restauración escribe los archivos y valida cada uno individualmente al descifrar. *Mitigación futura*: ofrecer una opción de "restauración en modo verificación" que no escriba nada en disco.

7. **Ausencia de registro de auditoría.** Los eventos de seguridad (intentos de desbloqueo fallidos, rutas bloqueadas) se registran en la consola del desarrollador, no en un log persistente. *Mitigación futura*: log local cifrado dentro de la bóveda.

8. **El guard de Publish depende de una API interna (VUL-20).** `internalPlugins.getEnabledPluginById('publish')` no forma parte de la API pública de Obsidian y podría cambiar entre versiones. Si el método desapareciera, el guard simplemente no se instalaría y **Publish volvería a publicar en claro** sin ningún aviso. *Mitigación futura*: vigilar la API interna en cada actualización de Obsidian y añadir un aviso en los ajustes cuando Publish esté activo pero no se pueda interceptar.

9. **El hash del MetadataCache depende de la caché de Obsidian (VUL-19).** El parche sustituye el hash **expuesto** por `getFileInfo()`, pero el hash original sigue siendo la clave del mapa `metadataCache[hash]` que guarda los metadatos analizados. Si Obsidian cambiara esa estructura interna, el hash de texto claro y el de texto cifrado volverían a divergir y Sync podría reanudar el ciclo de re-sincronización. *Mitigación futura*: vigilar el cambio de comportamiento de Sync en cada actualización.

10. **El descifrado en `Vault.readBinary()` es una superficie pública (VUL-16).** Cualquier plugin de la comunidad que llame a `vault.readBinary(file)` obtendrá el texto claro de las notas cifradas. MySecret no puede impedirlo sin romper el indexado de notas al pie. *Mitigación futura*: documentar explícitamente esta superficie en la guía para desarrolladores y considerar una API de "contenido descifrado" opt-in para los plugins que la necesiten.

---

## 10. Conclusión

El plugin MySecret tenía una **base criptográfica sólida** (AES-256-GCM con AAD, Argon2id, envoltura DEK/KEK, BIP-39 correcto) pero **defectos graves en las capas de interoperabilidad y de manejo de secretos**.

Las tres vulnerabilidades críticas formaban un patrón común: **el código confiaba en las entradas y en los metadatos**:
- Confianza en los nombres de archivo de un ZIP (VUL-01) → RCE.
- Confianza en un parámetro almacenado en un archivo editable (VUL-04) → KDF inutilizable.
- Confianza en que el AAD acompañaba a la ruta cuando el archivo se movía (VUL-03) → datos irrecuperables.

Las 20 correcciones siguen un principio común: **rechazar en lugar de normalizar, y verificar antes de confiar**. Ninguna sacrifica la usabilidad: las rutas legítimas siguen funcionando, el backup sigue siendo transparente para el usuario, y los únicos cambios visibles son mensajes de error más precisos en situaciones que antes fallaban en silencio.

Una **segunda ronda de revisión sobre los parches ya aplicados** (no solo sobre el código original) detectó **dos defectos en la propia corrección de VUL-03** que habrían dejado los archivos igualmente indescifrables tras renombrar una carpeta. Ambos están documentados y corregidos en §3 → VUL-03, con sus propios tests de regresión. Esta ronda demuestra que un parche de seguridad, por sí solo, **no está verificado hasta que existe un test que lo ejercite**.

Una **tercera ronda** auditó la integración con Obsidian Sync y Publish contra el código real de Obsidian, y reveló los cinco hallazgos VUL-16..VUL-20. La misma lección se repite: el defecto original (descifrar en la capa del adaptador) parecía correcto —de hecho, arreglaba el indexado de notas al pie— y solo se convirtió en una **fuga total de texto claro** al trazar las rutas reales de llamada de Sync. Un parche de seguridad tampoco está verificado hasta que se ha comprobado **contra el comportamiento real del consumidor**, no solo contra la intuición.

**Estado final: 96/96 tests pasan, 0 errores de tipos, bundle de producción compilado, 0 vulnerabilidades en dependencias.**

---

## Apéndice A — Comandos de verificación

```bash
# Suite completa (criptografía + seguridad)
npm test

# Comprobación de tipos
npx tsc --noEmit -p tsconfig.json

# Bundle de producción
npm run build

# Auditoría de dependencias
npm audit --omit=dev
```

## Apéndice B — Referencias CWE

| CWE | Nombre | Hallazgos |
|-----|--------|-----------|
| CWE-22 | Path Traversal | VUL-01, VUL-15 |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | VUL-01 |
| CWE-477 | Use of Obsolete Function | VUL-02 |
| CWE-662 | Improper Synchronization / Resource Mismanagement | VUL-03, VUL-05 |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | VUL-04 |
| CWE-325 | Missing Cryptographic Step | VUL-04 |
| CWE-244 | Improper Clearing of Heap Memory Before Release | VUL-06 |
| CWE-312 | Cleartext Storage of Sensitive Information | VUL-07 |
| CWE-668 | Exposure of Resource to Wrong Sphere | VUL-08 |
| CWE-918 | Server-Side Request Forgery | VUL-09 |
| CWE-319 | Cleartext Transmission of Sensitive Information | VUL-09, VUL-16 |
| CWE-200 | Exposure of Sensitive Information | VUL-10, VUL-16, VUL-18, VUL-20 |
| CWE-459 | Incomplete Cleanup | VUL-11 |
| CWE-521 | Weak Password Requirements | VUL-12 |
| CWE-330 | Use of Insufficiently Random Values | VUL-13 |
| CWE-1321 | Prototype Pollution | VUL-14 |
| CWE-662 | Improper Synchronization / Resource Mismanagement | VUL-03, VUL-05, VUL-17, VUL-19 |

---

## Apéndice C — Nota sobre la frase de recuperación

La frase BIP-39 se conserva **solo en RAM** y se borra en `lock()` (es material sensible; no debe sobrevivir al bloqueo de la bóveda).

- El modal `src/ui/recovery-phrase-modal.ts` muestra las 24 palabras, permite copiarlas al portapapeles con **borrado automático a los 30 segundos**, y ofrece mostrar/ocultar.
- `promptShowRecoveryPhrase()` ahora abre ese modal en lugar de un mensaje inútil.

**Compensación de riesgo.** Al no persistirse en disco, la frase se pierde al reiniciar Obsidian; si el usuario la cerró sin copiarla, deberá **reutilizar la copia que hizo en el paso 3 del asistente**. Esta limitación debe comunicarse en la UI (recomendación pendiente, §9).

---
