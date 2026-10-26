# Informe de Auditoría de Seguridad — Segunda Ronda

**Proyecto**: MySecret (`obsidian-mysecret`)
**Alcance**: `src/` (~9.400 LOC tras los parches), `tools/` (recuperación fuera del plugin), `auth-bridge/`, `.github/workflows/`. Explícitamente **fuera de alcance**: `packages/echo-protocol/` (librería independiente, auditada por separado).
**Fecha**: 25 de octubre de 2026
**Auditor**: Claude (Sonnet 5.5) — análisis estático línea por línea + verificación empírica de cada hipótesis con scripts ejecutables antes de tocar el código.
**Resultado**: **17 hallazgos confirmados y corregidos** (3 ALTOS, 9 MEDIOS, 5 BAJOS). **128/128 tests pasan** (96 preexistentes + 32 nuevos de regresión, en `tests/test-hardening.mjs` y `tests/test-recovery-tools.mjs`).

Esta ronda continúa la numeración de hallazgos de [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md) (que terminó en VUL-20) y usa las mismas convenciones de severidad.

---

## 1. Resumen ejecutivo

Los tres hallazgos más graves de esta ronda:

| ID | Severidad | Resumen |
|----|-----------|---------|
| **VUL-21** | ALTA | Las dos herramientas de recuperación fuera del plugin (`tools/offline-decryptor.html`, `tools/standalone-decryptor.py`) usaban un formato de clave **distinto al real**: no podían descifrar ninguna bóveda genuina. Quien dependiera de ellas sin Obsidian perdía sus notas. |
| **VUL-22** | ALTA | Cambiar la contraseña maestra no exigía la contraseña **actual** y no rotaba la clave de la bóveda; además el identificador usado para la biometría cambiaba con cada cambio de contraseña, huérfanando en silencio cualquier inscripción biométrica previa. |
| **VUL-23** | ALTA | El desbloqueo biométrico en Linux podía caer a un modo que solo leía un secreto ya desbloqueado del llavero del sistema — es decir, **no verificaba nada**: cualquiera con la sesión del SO abierta desbloqueaba la bóveda sin huella ni contraseña. |

> **Nota metodológica.** Cada hallazgo se verificó empíricamente antes de clasificarlo: se forzó un ZIP bomb con tamaño declarado falso (no explotable, fflate lo trunca), se ejecutó una inyección de ruta en el bridge externo de `echo-protocol` (confirmada, pero fuera de alcance de esta ronda), se comparó `'UNAVAILABLE'.includes('AVAILABLE')` en Node (da `true`, confirmando VUL-26), y se generó una bóveda real con el código del propio `KeyManager` para comprobar que las herramientas de `tools/` no la descifraban (confirmado VUL-21) y que sí la descifran tras el parche.

---

## 2. Metodología

1. **Modelado de amenazas** sobre las mismas superficies de la primera ronda (archivos de la bóveda, ZIPs de respaldo, `vault-envelope.json`, credenciales de nube) más dos nuevas: las herramientas de recuperación en `tools/` (ejecutadas fuera del control del plugin) y los proveedores biométricos por plataforma (`linux-provider.ts`, `windows-provider.ts`).
2. **Revisión manual** de los ~40 módulos del plugin, con énfasis en gestión de claves, interceptor del adaptador, motor de backup/restore y biometría.
3. **Verificación empírica** de cada hipótesis con un script Node/Python ejecutable antes del parche, cuando era factible reproducirla sin Obsidian.
4. **Corrección + test de regresión** que falla contra el código vulnerable y pasa contra el corregido. Los 32 tests nuevos viven en `tests/test-hardening.mjs` (17 hallazgos del plugin) y `tests/test-recovery-tools.mjs` (compatibilidad real de las herramientas de `tools/`, incluyendo una ejecución genuina del Python con `cryptography`/`argon2-cffi`).
5. **Re-verificación del build**: `npx tsc --noEmit`, `npm run build` (bundle reproducible byte a byte desde `src/`), `npm audit --omit=dev` (0 vulnerabilidades).

---

## 3. Hallazgos y parches

### VUL-21 — CRÍTICA (para quien las use): herramientas de recuperación incompatibles con el formato real

**Archivos**: `tools/offline-decryptor.html`, `tools/standalone-decryptor.py`
**CWE**: CWE-706 (Use of Incorrectly-Resolved Name), CWE-1288 (Improper Validation of Consistency within Input)

**El problema.** `offline-decryptor.html` derivaba la clave de la bóveda directamente de la frase BIP-39 con PBKDF2 y una sal fija (`"mnemonic"`), igual que el estándar BIP-39 para derivar una *seed* de criptomonedas. Pero MySecret no funciona así: la frase deriva una **clave de recuperación** con una sal aleatoria propia de cada bóveda (`recoveryEnvelope.salt`), y esa clave de recuperación **envuelve** (AES-GCM) la verdadera clave de la bóveda, que es la que cifra las notas. `standalone-decryptor.py` esperaba además un `data.json` con una estructura `vaultEnvelope{salt,iterations,memoryKib,wrappedVaultKey}` que no existe: el formato real está en `vault-envelope.json` con campos `argon2{...}` y `vaultKeyEnvelope{iv,tag,ciphertext}`.

**Por qué importa.** `SECURITY.md` promociona estas herramientas explícitamente como la vía de independencia del plugin ("nunca quedas atrapado en Obsidian"). Documentado con el mensaje de que bastaba la biblioteca estándar de Python, cuando en realidad ni siquiera podían completar un descifrado.

**Verificación (antes del parche).** Generé una bóveda real con `KeyManager.initializeVault()` y intenté descifrarla con la lógica de `offline-decryptor.html`: el resultado fue `OperationError` de WebCrypto (la clave derivada no coincidía con la real).

**El parche.** Reescribí ambas herramientas implementando el flujo real:
```
PBKDF2-HMAC-SHA512(frase, salt=recoveryEnvelope.salt, 2048 it.) -> recoveryKey (32 B)
AES-256-GCM-decrypt(recoveryEnvelope, recoveryKey, AAD="recovery-envelope")  -> vaultKey (32 B)
AES-256-GCM-decrypt(nota/adjunto, vaultKey, AAD=ruta NFC en la bóveda)       -> texto plano
```
- `standalone-decryptor.py` ahora lee `vault-envelope.json` (con `--envelope` para apuntarlo explícitamente), soporta `--mnemonic` y `--password` (Argon2id vía `argon2-cffi`), rechaza parámetros Argon2id fuera de rango (igual que el plugin), y **se niega a escribir fuera de la bóveda** si `--output` queda dentro de ella.
- `offline-decryptor.html` ahora pide pegar el contenido de `vault-envelope.json`, acepta tanto notas armoradas como adjuntos binarios (`<input type=file>`), y no depende de ningún CDN (CSP estricta en el propio archivo).
- Documentación actualizada en `SECURITY.md`/`.es.md` y `USER_GUIDE.md`/`.es.md`: se retiró la afirmación falsa de "cero dependencias externas" (Argon2id y AES-GCM no están en la librería estándar de Python) y se documentó el requisito de `cryptography`/`argon2-cffi`.

**Test de regresión**: `tests/test-recovery-tools.mjs` — genera una bóveda con el código real del plugin y la descifra con ambas herramientas (nota de texto con acentos y emoji, adjunto binario, frase incorrecta, ruta incorrecta, contraseña maestra, archivo único con `--relative-path`, y el rechazo de un `--output` dentro de la bóveda). Los tests de Python se saltan automáticamente si no hay `cryptography` instalado (nunca fallan por eso, solo avisan).

---

### VUL-22 — ALTA: cambio de contraseña sin verificar la actual y sin rotar la clave

**Archivo**: `src/crypto/key-manager.ts`
**CWE**: CWE-620 (Unverified Password Change), CWE-640 (Weak Password Recovery Mechanism)

**El problema.** `changeMasterPassword(newPassword)` solo exigía que la bóveda estuviera *desbloqueada* — no pedía la contraseña vigente. Cualquier código o persona con acceso a una sesión ya desbloqueada (por ejemplo, abierta con biometría, o dejada sin atender) podía cambiar la contraseña sin conocer la anterior. Además, el identificador usado por `getVaultId()` para indexar el slot biométrico local era la sal de Argon2, que **cambia en cada cambio de contraseña**: la inscripción biométrica existente quedaba huérfana en silencio (ligada a un slot que ya no se consulta) sin que el usuario se enterara hasta el siguiente intento de desbloqueo.

**Verificación.** Con un script contra `KeyManager` real: tras `changeMasterPassword()`, `getVaultId()` devolvía un valor distinto al de antes del cambio — confirmando la huérfanía del slot biométrico.

**El parche.**
- `KeyManager.verifyPassword(password)`: nuevo método que comprueba una contraseña contra el sobre **sin** tocar el estado de bloqueo ni la clave en memoria (desenvuelve y descarta).
- `changeMasterPassword(newPassword, currentPassword)` ahora exige y verifica `currentPassword` antes de re-envolver la clave; si falla, lanza y no modifica el sobre.
- `VaultEnvelopeConfig` gana un campo `vaultId` estable, fijado una sola vez al crear la bóveda y **nunca** reescrito por un cambio de contraseña. Para sobres existentes (sin `vaultId`), el primer cambio de contraseña lo fija al valor de la sal *actual* — exactamente el valor con el que ya estaba indexado el slot biométrico, así que las inscripciones existentes no se rompen.
- `getVaultId()` en `main.ts` prioriza `envelope.vaultId` y cae a la sal solo si no existe (compatibilidad con sobres antiguos).
- `isValidEnvelopeShape()`: nuevo validador de forma para el sobre leído de disco (ver VUL-25).
- UI: `ChangePasswordModal` ahora pide la contraseña actual, muestra una advertencia explícita ("cambiar la contraseña NO rota la clave de la bóveda... si la contraseña anterior se filtró, trata la bóveda como expuesta") y revierte el sobre en memoria si el guardado en disco falla.
- `requireReauth()` (nuevo, en `main.ts` + `ReauthModal`): gate de reautenticación de 2 minutos de gracia, usado también para ver/quitar la frase de recuperación, inscribir biometría y exportar en texto plano — estar desbloqueado ya no basta para esas acciones.

**Limitación residual, documentada explícitamente**: la clave de la bóveda (el DEK) **no se rota**. Una copia antigua de `vault-envelope.json` (en el historial de sync o un backup) combinada con la contraseña *anterior* todavía descifra la bóveda. Rotar la clave implicaría re-cifrar todas las notas, con riesgo real de pérdida de datos si se interrumpe a medio camino; quedó documentado en `SECURITY.md` §"Limitaciones Conocidas" en vez de implementarse a medias.

**Tests**: `tests/test-hardening.mjs` — `verifyPassword` no desbloquea ni bloquea; `changeMasterPassword` rechaza la contraseña incorrecta sin alterar el sobre; el `vaultId` sobrevive al cambio; un sobre legado sin `vaultId` lo fija a la sal vigente; `isValidEnvelopeShape` rechaza 11 variantes de sobre corrupto/manipulado.

---

### VUL-23 — ALTA: desbloqueo biométrico en Linux sin verificación real de usuario

**Archivo**: `src/biometrics/linux-provider.ts`
**CWE**: CWE-287 (Improper Authentication), CWE-305 (Authentication Bypass by Primary Weakness)

**El problema.** Cuando no había lector de huellas (`fprintd`) disponible, el proveedor degradaba a un modo `secret-service` que solo leía un secreto del llavero del sistema operativo (GNOME Keyring / KWallet vía `secret-tool`). En una sesión de escritorio típica ese llavero **ya está desbloqueado** desde el login — no hay ningún gesto biométrico ni contraseña que verificar en ese punto. El botón "Desbloqueo biométrico" en la pantalla de bloqueo se disparaba automáticamente al abrirla (`autoPrompt` activo por defecto), así que cualquiera con acceso a una sesión de Linux abierta desbloqueaba la bóveda sin ninguna credencial.

**Verificación.** Leyendo el código de `isAvailable()`/`enroll()`/`verifyAndDecrypt()`: el camino `secret-service` nunca invoca `promptFprintd()` ni ningún otro gate; solo hace `secretToolLookup()` y desenvuelve con lo que encuentra.

**El parche.**
- `isAvailable()` ya solo reporta disponibilidad cuando hay un lector `fprintd` con huellas enroladas (`isFprintdReady()`). El Secret Service deja de ser un sustituto válido de verificación.
- `enroll()` rechaza inscribir si no hay `fprintd` real, con un mensaje explícito.
- `verifyAndDecrypt()` rechaza explícitamente cualquier sobre con `mode !== 'fprintd'` (incluye las inscripciones heredadas en modo `secret-service`), registrando que se requiere la contraseña maestra y volver a inscribir.
- El modo `fprintd` ya no regenera el secreto de dispositivo al desbloquear si el archivo `0600` fue borrado (antes `getOrCreateDeviceSecret` lo recreaba silenciosamente, lo que habría permitido desbloquear sin el secreto original tras cualquier intervención en el archivo); ahora falla cerrado con `readDeviceSecret`.
- Se eliminaron `secretToolStore`/`secretToolLookup` del camino de enrolamiento/desbloqueo (el código de limpieza en `cleanup()` se conserva para borrar entradas de llavero heredadas al desinstalar).

**Tests**: `tests/test-hardening.mjs` — sin `fprintd`, `isAvailable()` es `false` e `enroll()` lanza aunque `secret-tool` exista; un sobre heredado `secret-service` se rechaza sin consultar el llavero; el modo `fprintd` no inventa un secreto nuevo si el archivo fue borrado.

---

### VUL-24 — MEDIA: Windows Hello se reportaba disponible sin estarlo

**Archivo**: `src/biometrics/windows-provider.ts`
**CWE**: CWE-697 (Incorrect Comparison)

**El problema.** `result.stdout.includes('AVAILABLE')` es verdadero tanto para `"AVAILABLE"` como para `"UNAVAILABLE"` (la segunda cadena *contiene* a la primera). El script de PowerShell que comprueba Windows Hello podía reportar `UNAVAILABLE` y el plugin lo interpretaba como disponible, ofreciendo un botón de biometría que luego fallaría de forma confusa (o, peor, en combinación con otro defecto, podría dar una falsa sensación de que el gate biométrico es real).

**Verificación**: `node -e "console.log('UNAVAILABLE'.includes('AVAILABLE'))"` → `true`.

**El parche.** Nuevas funciones exportadas `parseAvailabilityOutput`/`parseVerificationOutput` que comparan **línea completa** (tras recortar espacios) contra `'AVAILABLE'`/`'VERIFIED'`, en vez de una subcadena.

**Tests**: casos para `AVAILABLE`, `UNAVAILABLE`, cadena vacía, `VERIFIED`, `UNVERIFIED`, `FAILED`.

---

### VUL-25 — MEDIA: `vault-envelope.json` sin validar, sin escritura atómica, asistente podía sobrescribir una bóveda ya cifrada

**Archivos**: `src/main.ts`, `src/crypto/key-manager.ts`, `src/ui/setup-wizard.ts`
**CWE**: CWE-20 (Improper Input Validation), CWE-696 (Incorrect Behavior Order: non-atomic write), CWE-665 (Improper Initialization)

**El problema, en tres partes:**
1. `JSON.parse(rawContent)` sobre el sobre leído de disco se asignaba directamente a `KeyManager` sin comprobar su forma. Un sobre truncado o manipulado producía errores confusos (`TypeError`) en lo profundo del flujo de desbloqueo en vez de un mensaje claro.
2. `saveVaultEnvelope()` escribía directamente sobre el archivo final. Una interrupción a mitad de escritura (corte de luz, crash) podía dejar la **única** copia del sobre truncada — pérdida total e irreversible del acceso a la bóveda.
3. Si el sobre se perdía o se borraba pero ya había notas cifradas en disco, el asistente de configuración (`SetupWizardModal`) no lo detectaba: generaba una clave nueva alegremente, dejando esas notas **ilegibles para siempre**.

**El parche.**
- `isValidEnvelopeShape()` (exportado desde `key-manager.ts`) valida que `argon2`, `vaultKeyEnvelope` y, si existe, `recoveryEnvelope` tengan campos hexadecimales de la longitud exacta esperada. `loadVaultEnvelope()` lo invoca y, si falla, **no** marca la bóveda como no inicializada (lo que habría disparado el asistente): guarda el error en `envelopeLoadError` y deja la bóveda en un estado "bloqueada, sin poder arrancar" con una `Notice` persistente explicando que hay que restaurar el archivo o su copia `.bak`.
- `loadVaultEnvelope()` ahora también intenta `vault-envelope.json.bak` si el principal falla.
- `writeEnvelopeFile()`: escribe a `<path>.tmp`, relee y compara byte a byte, conserva la versión previa como `<path>.bak`, y solo entonces reemplaza el archivo final. Si el *rename* atómico no está disponible en la plataforma, cae a una escritura directa como último recurso (documentado) en vez de perder el sobre.
- `openSetupWizard()` ahora escanea hasta 500 archivos buscando contenedores cifrados (`detectContainerFormat`) antes de proceder; si encuentra alguno sin que exista un sobre válido, pide confirmación explícita al usuario advirtiendo que esos archivos quedarán ilegibles. También se bloquea si `keyManager.isInitialized` ya es verdadero (evita sobrescribir una bóveda ya configurada en memoria).

**Tests**: 11 variantes de sobre malformado rechazadas por `isValidEnvelopeShape` (campo faltante, hex de longitud incorrecta, tipo incorrecto, `null`, cadena, objeto vacío...).

---

### VUL-26 — MEDIA: restauración de backup confiaba en el `mode` autodeclarado del propio ZIP

**Archivo**: `src/backup/backup-engine.ts`
**CWE**: CWE-345 (Insufficient Verification of Data Authenticity), CWE-668

**El problema.** `restoreFromZip()` decidía si una entrada era "cifrada" o "en claro" leyendo `manifest.mode` — un campo dentro del propio ZIP que el atacante controla si fabrica el archivo. Con `mode: "encrypted"` declarado, cualquier contenido se escribía **verbatim** en disco sin comprobar que realmente fuera un contenedor cifrado válido para *esta* bóveda. Esto permitía: (a) inyectar texto plano disfrazado de "ya cifrado" (quedaría servido como texto plano real, rompiendo la promesa de cifrado transparente), o (b) restaurar ciphertext robado de **otra** bóveda o de **otra ruta**, que el plugin aceptaría sin más porque "el manifiesto decía que estaba cifrado".

**Verificación.** Cifré una nota con una `KeyManager` ("bóveda B") y la empaqueté con un manifiesto `mode: "encrypted"` apuntando a una ruta distinta a la original; al restaurarla contra una "bóveda A" (clave distinta), el código anterior la habría escrito tal cual en disco sin detectar nada.

**El parche.** La restauración ahora decide por el **contenido real**, nunca por el manifiesto (`void manifest` explícito donde antes se usaba):
- Se detecta el formato (`detectContainerFormat`: `binary`/`armored`/`plain`) de cada entrada por sus bytes crudos.
- Si no es `plain`, se exige que **autentique** (`isAuthenticContainer`) con la clave de la bóveda actual y con la ruta destino exacta como AAD — es decir, debe ser ciphertext producido *para esta bóveda y esta ruta*. Si no autentica, se rechaza y se reporta el motivo (`errors[]`), sin escribir nada.
- Si autentica pero la ruta destino no debe cifrarse por política (carpeta excluida), se descifra y se escribe en claro — nunca se deja un contenedor cifrado huérfano en una zona no gestionada por el plugin.
- Si es `plain` y es una nota de texto, se escribe por el adaptador interceptado (se cifra al entrar, como cualquier escritura normal) en vez de escribirse cruda.
- `restoreFromZip()` ahora **exige la bóveda desbloqueada** desde el principio (antes aceptaba un `KeyManager` inexistente/bloqueado y simplemente fallaba entrada por entrada de forma confusa).
- Se añadió verificación estricta de UTF-8 (`decodeUtf8Strict`) para notas en claro: un archivo en otra codificación se rechaza con un error explícito en vez de corromperse silenciosamente al forzarlo a texto.
- Las entradas rechazadas se muestran ahora en una `Notice` desde `RestoreModal` (antes solo quedaban en el array `errors` sin mostrarse al usuario).

**Tests**: ciphertext de otra clave rechazado sin escribir nada; ciphertext ligado a otra ruta rechazado; ciphertext auténtico se restaura verbatim y sigue cifrado en disco; un manifiesto que *afirma* "encrypted" no logra que texto plano inyectado llegue a disco sin cifrar; restaurar con la bóveda bloqueada no escribe nada; una entrada de texto no-UTF-8 se rechaza en vez de corromperse.

---

### VUL-27 — MEDIA: los respaldos descartaban archivos en silencio

**Archivo**: `src/backup/backup-engine.ts`, `src/main.ts`, `src/ui/export-modal.ts`, `src/ui/cloud-backup-modal.ts`, `src/ui/restore-modal.ts`
**CWE**: CWE-459 (Incomplete Cleanup), CWE-754 (Improper Check for Unusual Conditions)

**El problema, en dos partes:**
1. Con la bóveda bloqueada (sin clave en memoria), `createVaultZip()` simplemente omitía del ZIP cualquier archivo que todavía estuviera en texto plano en disco — sin avisar. Un respaldo "exitoso" podía estar incompleto sin que nadie lo supiera hasta necesitar justo esa nota.
2. El respaldo automático "al bloquear" (`on-lock`) dispara `lockVault()` → el candado borra la clave de memoria **antes** de que el backup en segundo plano termine de construirse, así que ese backup en particular **siempre** perdía en silencio cualquier nota aún no migrada a cifrado.

**El parche.**
- `BackupStats` gana `skippedFiles: {path, reason}[]`. Cada archivo que no pudo incluirse (sin clave, no-UTF-8, error de lectura) se registra ahí en vez de desaparecer.
- `CreateZipOptions` acepta un `vaultKey?: CryptoKey` opcional. `lockVault()` ahora captura la clave vigente **antes** de llamar a `keyManager.lock()` y se la pasa explícitamente al backup "al bloquear", así ese backup sí puede cifrar y empaquetar notas que aún estaban en claro.
- `ExportModal`, `CloudBackupModal` y `runBackgroundAutoBackup` muestran una `Notice` persistente listando cuántos archivos se omitieron y un ejemplo, en vez de un "✅ Éxito" silenciosamente incompleto.

**Tests**: con la bóveda bloqueada, un archivo en claro se reporta en `skippedFiles`; con la clave explícita (como la pasa ahora el flujo "al bloquear"), el mismo archivo se incluye cifrado; una nota no-UTF-8 se reporta en vez de incluirse corrupta.

---

### VUL-28 — MEDIA: cambios de política (excluir carpeta / desactivar cifrado de adjuntos) dejaban ciphertext huérfano

**Archivo**: `src/main.ts`
**CWE**: CWE-668 (Exposure of Resource to Wrong Sphere), CWE-706

**El problema.** Excluir una carpeta del cifrado, o desactivar "cifrar adjuntos", cambiaba la *política* inmediatamente, pero los archivos **ya cifrados** bajo esa política anterior seguían en disco como ciphertext. A partir de ese momento el plugin dejaba de interceptar esas rutas: Obsidian los leería como el contenedor crudo (`-----BEGIN MYSECRET...` o `MYSE...`) en vez de la nota, y la **próxima vez que Obsidian guardara ese archivo** (autoguardado, por ejemplo), lo sobrescribiría con ese contenido crudo tratado como si fuera el texto real — corrompiendo la nota de forma irreversible.

**El parche.**
- `decryptFilesToPlain(paths)` (nuevo, en el interceptor): descifra en memoria y reescribe en disco como texto plano, archivo por archivo, reportando fallos sin abortar el resto.
- `decryptBeforePolicyChange(paths)` (nuevo, en `main.ts`): detecta qué archivos de la lista están realmente cifrados en disco: si la bóveda está bloqueada, pide desbloquearla y aborta el cambio; si falla al descifrar alguno, aborta el cambio entero (todo o nada) y lo informa.
- `setEncryptAttachments(value)` reemplaza la asignación directa: al pasar a `false`, primero descifra todos los adjuntos ya cifrados; solo si eso tiene éxito aplica el cambio.
- `addExcludedFolder(folderPath)` hace lo mismo para el subárbol de la carpeta a excluir antes de añadirla a la lista.
- El toggle de la UI revierte visualmente (`toggle.setValue(!value)`) si la operación se abortó.

**Tests**: `decryptFilesToPlain` convierte correctamente una nota y un adjunto cifrados a texto plano en disco, reporta (sin abortar) un archivo inexistente, y deja sin tocar un archivo que no puede autenticarse con la clave actual.

---

### VUL-29 — MEDIA: renombrados con la bóveda bloqueada dejaban notas permanentemente indescifrables

**Archivo**: `src/adapter/adapter-interceptor.ts`, `src/main.ts`, `src/types.ts`
**CWE**: CWE-662 (Improper Synchronization), CWE-459

**El problema.** El AAD de AES-GCM está ligado a la ruta normalizada del archivo (para impedir sustituir una nota por el ciphertext de otra). Cuando Obsidian dispara el evento `rename` con la bóveda bloqueada (o si `rebindAad()` falla por cualquier otro motivo transitorio: I/O, etc.), el código anterior solo registraba el error en consola — **la nota quedaba renombrada en disco pero con el AAD de la ruta antigua**, es decir, indescifrable para siempre bajo su nueva ruta, sin ninguna indicación visible al usuario de que algo se rompió.

**El parche.**
- `AdapterInterceptor` mantiene ahora una cola `pendingRebinds` (persistida en `settings.pendingRebinds` vía un callback `setPendingRebinds()`), poblada cuando `rebindAad()` falla (`rebindOrQueue()`).
- `processPendingRebinds()` se invoca automáticamente en `unlockVaultSuccess()`: reintenta cada renombrado pendiente ahora que la clave está disponible; si el archivo destino ya no existe, se descarta sin más (ya no hay nada que arreglar); si vuelve a fallar con la bóveda desbloqueada, se descarta y se registra como "irrecuperable" en vez de reintentarlo indefinidamente.
- `rebindAad()` se hizo **idempotente**: si el descifrado con el AAD antiguo falla, intenta autenticar con el AAD nuevo (`authenticatesUnder`) antes de propagar el error — así reproducir la cola no falla sobre un archivo que ya quedó bien re-vinculado por un intento anterior.
- `copy()` también encola en vez de solo registrar el error.

**Tests**: un rename con la bóveda bloqueada queda en la cola persistida; al desbloquear, `processPendingRebinds()` lo aplica y vacía la cola, y la nota vuelve a ser legible; reproducir un re-vínculo ya aplicado es un no-op inocuo que no corrompe nada.

---

### VUL-30 — MEDIA: `process`/`append`/`appendBinary` sin serialización por ruta (actualizaciones perdidas)

**Archivo**: `src/adapter/adapter-interceptor.ts`
**CWE**: CWE-362 (Race Condition), CWE-667 (Improper Locking)

**El problema.** El `DataAdapter.process()` nativo de Obsidian es atómico. La versión interceptada lo implementaba como leer → transformar → escribir en pasos separados (porque necesita descifrar y re-cifrar). Dos llamadas concurrentes sobre la **misma** nota (plausible con autoguardado + un comando, o dos plugins escribiendo a la vez) podían entrelazarse: ambas leen el mismo valor inicial, ambas escriben, y una de las dos actualizaciones se pierde silenciosamente. Lo mismo aplicaba a `append`/`appendBinary`.

**Verificación.** Test de regresión: 12 llamadas concurrentes a `process()` que incrementan un contador en la misma nota; sin la corrección, el valor final es menor a 12 (actualizaciones perdidas).

**El parche.** `AdapterInterceptor.withPathLock(path, task)`: encola `task` tras cualquier tarea previamente encolada para esa misma ruta normalizada (una promesa por ruta, nunca un lock global). `a.process`, `a.append` y `a.appendBinary` ahora pasan por este lock antes de ejecutar su lógica de lectura-transformación-escritura.

**Test**: 12 incrementos concurrentes sobre la misma nota producen exactamente 12 — ninguno se pierde.

---

### VUL-31 — MEDIA: el guardián de Obsidian Publish solo se instalaba una vez, al cargar

**Archivo**: `src/adapter/publish-guard.ts`, `src/main.ts`
**CWE**: CWE-696 (Incorrect Behavior Order)

**El problema.** `PublishGuard.install()` se llamaba una sola vez en `onload()`. Si el usuario activaba Obsidian Publish **después** de que MySecret ya hubiera cargado, o lo desactivaba y volvía a activarlo (lo que crea una instancia **nueva** del plugin interno, con un `apiUploadFile` sin envolver), el guardián quedaba sin aplicar sobre esa instancia — el texto claro de notas cifradas podría subirse a un sitio público sin ningún bloqueo.

**El parche.** `PublishGuard.refresh()` (nuevo): detecta si la instancia actual de Publish cambió o si el método ya no está envuelto, y si es así, reinstala el guardián sobre ella. `main.ts` lo invoca cada 15 segundos vía `registerInterval` (se limpia solo al descargar el plugin).

**Test**: Publish deshabilitado al cargar → se habilita después → `refresh()` lo detecta e instala el guardián; se deshabilita y rehabilita (nueva instancia) → `refresh()` lo vuelve a envolver.

---

### VUL-32 — MEDIA: notas de texto ocultas dentro de carpetas quedaban sin cifrar

**Archivo**: `src/adapter/path-filter.ts`
**CWE**: CWE-668

**El problema.** `isSystemExcluded()` excluía cualquier archivo cuyo nombre empezara por `.`, sin distinguir profundidad ni tipo. Esto era correcto para `.obsidian/`, `.git/`, `.DS_Store`, pero también excluía — incorrectamente — una nota de texto legítima del usuario guardada como oculta dentro de una carpeta (`Notas/.privada.md`), que quedaba permanentemente en texto plano pese a la intención del usuario.

**El parche.** La exclusión de dotfiles ahora distingue: carpetas ocultas a cualquier profundidad (`Proyectos/.git/`, `Notas/.cache/`) siguen excluidas siempre; un dotfile en la **raíz** de la bóveda sigue excluido (es casi siempre un archivo de sistema: `.DS_Store`, `.gitignore`); pero una nota de texto oculta **dentro** de una carpeta (`isTextNote()` verdadero) ya se cifra como cualquier otra nota.

**Test**: `.DS_Store` raíz excluido; `Notes/.gitkeep` (no es nota) excluido; `Projects/.git/config` (carpeta oculta) excluido; `Notes/.cache/x.md` (carpeta oculta a profundidad) excluido; `Notes/.private.md` (nota oculta, no carpeta) **sí** se cifra.

---

### VUL-33 — BAJA: callback del bridge biométrico podía colgar la sesión con un `%` en el mensaje de error

**Archivo**: `src/biometrics/external-bridge-provider.ts`
**CWE**: CWE-20

**El problema.** `decodeURIComponent(error)` se aplicaba sobre un parámetro que Obsidian ya entrega decodificado por el manejador de protocolo (`registerObsidianProtocolHandler`). Un mensaje de error que contuviera un `%` no seguido de dos hex válidos (`%` solo, o un porcentaje literal como "falló al 100%") lanzaba `URIError`, que no estaba capturado en ese punto — la promesa pendiente de la ceremonia biométrica quedaba sin resolver ni rechazar nunca, colgando la UI hasta el timeout de 75 s.

**El parche.** Se eliminó el `decodeURIComponent` redundante; el mensaje de error se sanea (se recortan caracteres de control, se limita a 200 caracteres) y se usa directamente.

**Test**: un callback con `error=Fallo al 100% (%E0%A4%A)` resuelve la promesa pendiente (a `null`) en vez de colgarse.

---

### VUL-34 — BAJA: coincidencia de imágenes por subcadena en `MediaManager`

**Archivo**: `src/adapter/media-manager.ts`
**CWE**: CWE-697

**El problema.** `patchDomForPath()` decidía si un `<img>` del DOM correspondía a un archivo cifrado comprobando si su `src` **contenía** el nombre de archivo (`src.includes(filename)`). Un archivo llamado `data.png` coincidía también con `metadata.png`, aplicando el blob descifrado equivocado a una imagen no relacionada.

**El parche.** La comparación ahora exige coincidencia **exacta** del último segmento de ruta (decodificado, sin query/fragment) contra el nombre de archivo, no una subcadena.

---

### VUL-35 — BAJA: credenciales de nube se cifraban y guardaban en cada pulsación de tecla

**Archivo**: `src/ui/settings-tab.ts`
**CWE**: CWE-400 (Uncontrolled Resource Consumption, menor)

**El problema.** Los campos de token/contraseña de Google Drive, OneDrive y WebDAV disparaban `encryptCredential()` + escritura de `data.json` en cada evento `input` — decenas de cifrados y escrituras a disco al pegar o escribir un token largo.

**El parche.** `debounce(fn, 600ms)` envuelve los tres `onChange`.

---

### VUL-36 — BAJA: CI sin pines de commit, release disparable con cualquier tag, CodeQL anunciado pero ausente en la raíz

**Archivos**: `.github/workflows/release.yml`, `.github/workflows/osv-scanner.yml`, `.github/workflows/codeql.yml`
**CWE**: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)

**El problema.** Las acciones de terceros se referenciaban por tag flotante (`@v4`, `@v2.7.0`) en vez de por SHA de commit — un tag puede ser reescrito por el mantenedor del repositorio de la acción (o, en el peor caso, por quien comprometa su cuenta). El workflow de *release* se disparaba con **cualquier** tag (`tags: ["*"]`), incluyendo tags accidentales que no siguen `X.Y.Z`. Además, `SECURITY.md`/`.es.md` prometían un guardián de CodeQL que **no existía** en la raíz del repositorio (solo en el espejo `Github/`).

**El parche.**
- Las 5 acciones usadas (`actions/checkout`, `actions/setup-node`, `softprops/action-gh-release`, `github/codeql-action/init`, `github/codeql-action/analyze`, y el *reusable workflow* de OSV-Scanner) quedan fijadas por SHA de commit, con el tag como comentario (`@11d5960a... # v4`).
- `release.yml` solo dispara con tags que matchean `[0-9]+.[0-9]+.[0-9]+`.
- Se añadió `.github/workflows/codeql.yml` en la raíz (antes solo existía dentro de `Github/`), con el mismo contenido que ya tenía el espejo, con las acciones fijadas.

---

### VUL-37 — BAJA: CSP de `auth-bridge` con `frame-ancestors` inefectivo

**Archivo**: `auth-bridge/index.html`
**CWE**: CWE-1021 (Improper Restriction of Rendered UI Layers, Clickjacking)

**El problema.** La directiva `frame-ancestors` del `<meta http-equiv="Content-Security-Policy">` se declara pero el estándar la ignora explícitamente cuando se entrega vía `<meta>` en vez de una cabecera HTTP real — el bridge quedaba, en la práctica, sin la protección anti-clickjacking que el comentario del propio código afirmaba tener.

**El parche.** Se añadió `auth-bridge/_headers` (convención de Cloudflare Pages, se aplica automáticamente al desplegar la carpeta) con `Content-Security-Policy` completa incluyendo `frame-ancestors 'none'`, más `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy` y una `Permissions-Policy` que limita `publickey-credentials-*` al propio origen. El comentario en `index.html` ahora aclara la limitación del `<meta>` y remite al archivo real. READMEs actualizados para indicar que hay que desplegar la carpeta completa (no solo `index.html`).

---

## 4. Hallazgos evaluados y descartados (falsos positivos de esta ronda)

- **`data.buffer` en la restauración de ZIP**: hipótesis inicial de que `data.buffer` (de una `Uint8Array` fflate) podría exponer memoria ajena a la vista por ser un `ArrayBuffer` más grande. Verificado con fflate real: tanto para entradas `stored` como `deflate`, la vista devuelta siempre tiene `byteOffset === 0` y `buffer.byteLength === view.length`. Descartado.
- **ZIP bomb vía tamaño declarado falsificado**: se forjó un ZIP con la cabecera de tamaño sin comprimir parcheada a un valor mentiroso (10 bytes declarados, 300 MiB reales). El filtro de `unzipSync({filter})` de fflate recibe el tamaño **declarado** antes de inflar y lo usa para truncar la salida real a ese tamaño — no es explotable como vector de denegación de servicio por memoria. Confirmado con un script que mide el tamaño inflado resultante (10 bytes, no 300 MiB).
- **`echo-protocol`**: se identificaron y **no se corrigieron por decisión explícita del usuario** una inyección de comandos en `loopback-transport.ts` (vía `exec()` con la URL del bridge interpolada) y un salto de la verificación de usuario (`userVerified` del payload, no del flag UV real del autenticador) en `verifier.ts`, además de un `cb` de redirección sin validar en el PWA. Quedan documentados aquí solo a título de registro, para un parche en otro proyecto/sesión.

---

## 5. Verificación

```bash
# Suite completa (168 → 128 tests tras esta ronda, incluye los 32 nuevos)
npm test

# Comprobación de tipos (0 errores)
npx tsc --noEmit -p tsconfig.json

# Bundle de producción reproducible byte a byte desde src/
npm run build

# Auditoría de dependencias de producción (0 vulnerabilidades)
npm audit --omit=dev
```

Los tests de `tools/standalone-decryptor.py` (VUL-21) requieren `pip install cryptography argon2-cffi`; se omiten automáticamente si no están instalados (nunca cuentan como fallo), y se puede apuntar a un intérprete concreto con `MYSECRET_TEST_PYTHON=/ruta/al/python npm test`.

---

## 6. Tabla resumen

| ID | Severidad | Archivo principal | CWE | Test de regresión |
|----|-----------|--------------------|-----|---------------------|
| VUL-21 | ALTA | `tools/offline-decryptor.html`, `tools/standalone-decryptor.py` | CWE-706, CWE-1288 | `test-recovery-tools.mjs` |
| VUL-22 | ALTA | `src/crypto/key-manager.ts` | CWE-620, CWE-640 | `test-hardening.mjs` (A2) |
| VUL-23 | ALTA | `src/biometrics/linux-provider.ts` | CWE-287, CWE-305 | `test-hardening.mjs` (A3) |
| VUL-24 | MEDIA | `src/biometrics/windows-provider.ts` | CWE-697 | `test-hardening.mjs` (W) |
| VUL-25 | MEDIA | `src/main.ts`, `src/crypto/key-manager.ts` | CWE-20, CWE-696 | `test-hardening.mjs` (envelope shape) |
| VUL-26 | MEDIA | `src/backup/backup-engine.ts` | CWE-345, CWE-668 | `test-hardening.mjs` (R) |
| VUL-27 | MEDIA | `src/backup/backup-engine.ts`, `src/main.ts` | CWE-459, CWE-754 | `test-hardening.mjs` (B) |
| VUL-28 | MEDIA | `src/main.ts`, `src/adapter/adapter-interceptor.ts` | CWE-668, CWE-706 | `test-hardening.mjs` (I: decryptFilesToPlain) |
| VUL-29 | MEDIA | `src/adapter/adapter-interceptor.ts` | CWE-662, CWE-459 | `test-hardening.mjs` (I: pending rebinds) |
| VUL-30 | MEDIA | `src/adapter/adapter-interceptor.ts` | CWE-362, CWE-667 | `test-hardening.mjs` (I: process lock) |
| VUL-31 | MEDIA | `src/adapter/publish-guard.ts` | CWE-696 | `test-hardening.mjs` (P) |
| VUL-32 | MEDIA | `src/adapter/path-filter.ts` | CWE-668 | `test-hardening.mjs` (F) |
| VUL-33 | BAJA | `src/biometrics/external-bridge-provider.ts` | CWE-20 | `test-hardening.mjs` (X) |
| VUL-34 | BAJA | `src/adapter/media-manager.ts` | CWE-697 | — (revisión manual) |
| VUL-35 | BAJA | `src/ui/settings-tab.ts` | CWE-400 | — (revisión manual) |
| VUL-36 | BAJA | `.github/workflows/*.yml` | CWE-829 | — (revisión manual) |
| VUL-37 | BAJA | `auth-bridge/index.html` | CWE-1021 | — (revisión manual) |

**Estado final: 128/128 tests pasan, 0 errores de tipos, bundle de producción reproducible, 0 vulnerabilidades en dependencias de producción.**

---

## 7. Limitaciones conocidas que quedan documentadas (no corregidas por diseño)

- **La clave de la bóveda no rota** al cambiar la contraseña maestra (VUL-22, limitación residual). Documentado con advertencia explícita en la UI y en `SECURITY.md`.
- **El bloqueo es de interfaz, no de proceso.** La clave se borra de RAM y las notas abiertas se cierran, pero Obsidian y otros plugins pueden conservar texto plano en caché de metadatos o estado de editor.
- **El AAD solo vincula la ruta del archivo.** Quien pueda escribir en la bóveda puede restaurar una versión antigua del mismo archivo cifrado; el plugin no puede detectar un rollback dentro del mismo par (ruta, clave).
- **La biometría en Windows y Linux es una comodidad reforzada por el sistema operativo** (DPAPI / archivo `0600`), no una ligazón criptográfica al propio hardware biométrico como sí lo es el proveedor WebAuthn (PRF). Malware ejecutándose como el mismo usuario del SO puede saltársela.
- **`packages/echo-protocol`** queda fuera de esta ronda por decisión del usuario; sus hallazgos (inyección de comandos, salto de verificación de usuario, `cb` sin validar) están registrados en §4 para una corrección futura.

---

## Apéndice — Comandos de verificación

```bash
npm test
npx tsc --noEmit -p tsconfig.json
npm run build
npm audit --omit=dev
```
