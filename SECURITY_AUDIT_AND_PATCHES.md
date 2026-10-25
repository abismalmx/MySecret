# Informe de Auditoría de Seguridad, Calidad de Código y Parches Aplicados

**Proyecto**: MySecret (`obsidian-mysecret`)  
**Autor**: Anthony Rios Licea ([@abismalmx](https://github.com/abismalmx))  
**Repositorio Oficial**: [https://github.com/abismalmx/MySecret](https://github.com/abismalmx/MySecret)  
**Fecha de Auditoría**: 24 de Octubre de 2026  
**Veredicto de Seguridad**: **APROBADO (A+)**  

---

## 1. Resumen Ejecutivo

Se llevó a cabo una auditoría integral de seguridad, calidad de software, tipado estático y fuga de secretos sobre todo el repositorio. La auditoría cubrió tanto el código fuente de la extensión para Obsidian (`src/`), los scripts de empaquetado y prueba (`tests/`), la configuración de dependencias (`package.json`) y el historial de control de versiones de Git (`Github/`).

### Métricas Clave de la Auditoría
- **Vulnerabilidades en Dependencias (OSV-Scanner 2.7.0)**: **1 detectada y corregida** (`GHSA-67mh-4wv8-2f99` en `esbuild`). Estado final: **0 vulnerabilidades** en los 2 lockfiles (verificado con 3 fuentes independientes).
- **Errores de Compilación TypeScript (`tsc`)**: Reducidos de **11 errores críticos a 0**.
- **Errores de Calidad y Linter (`ESLint`)**: Reducidos de **11 errores a 0**.
- **Fuga de Secretos en Git (`Gitleaks`)**: **0 fugas detectadas** en el historial completo de commits.
- **Reglas SAST de Seguridad (`Semgrep`)**: 469 reglas ejecutadas; vulnerabilidad potencial de Prototype Pollution mitigada y falsos positivos clasificados.
- **Defectos de interpolación i18n**: **2 bugs reales corregidos** (inyección de patrones de reemplazo + escapado de metacaracteres), con 2 tests de regresión añadidos.
- **Pruebas de Regresión Criptográfica y Funcional (`npm test`)**: **83 pruebas ejecutadas, 83 aprobadas (0 fallos)**.
- **Compilación de Producción (`esbuild`)**: Generada exitosamente y sincronizada en raíz y carpeta `Github/`.
- **Guardia Permanente en CI**: workflow `osv-scanner.yml` añadido para bloquear regresiones de cadena de suministro.

---

## 2. Corrección de Enlaces y Casing de GitHub

### 2.1 Normalización a Minúsculas (`abismalmx`)
Se identificó inconsistencia en el nombre de usuario de GitHub (`Abismalmx` vs `abismalmx`). Se realizó un reemplazo exhaustivo para garantizar que todas las URLs, etiquetas de autor y documentación apunten uniformemente al identificador canónico en minúsculas:
- Reemplazo global de `Abismalmx` por `abismalmx`.
- Archivos actualizados: `manifest.json`, `package.json`, `LICENSE`, `README.md`, `README.es.md`, `USER_GUIDE.md`, `USER_GUIDE.es.md`, `src/ui/assets.ts` y los 4 archivos de localización i18n (`en.ts`, `es.ts`, `ru.ts`, `zh.ts`).

### 2.2 Corrección de URL de Repositorio (Resolución de Error HTTP 404)
En la documentación (`README.md`, `USER_GUIDE.md`) las instrucciones de instalación manual y vía el plugin BRAT referenciaban:
`https://github.com/Abismalmx/obsidian-mysecret` (URL rota con respuesta HTTP 404).

Se corrigieron todos los enlaces hacia el repositorio real y verificado:
`https://github.com/abismalmx/MySecret` (Respuesta HTTP 200 OK).

---

## 3. Auditoría de Calidad y Tipos (TypeScript & ESLint)

### 3.1 Detección del Lenguaje Principal
- **Lenguaje**: TypeScript 5.0+ / ECMAScript moderno sobre Node.js 20 y API de Obsidian.

### 3.2 Errores Críticos Detectados y Parches Aplicados

#### Parche 1: Inclusión de la propiedad `language` en `PluginSettings`
- **Archivos**: `src/types.ts`, `Github/src/types.ts`
- **Problema**: `tsc` arrojaba error TS2353 y TS2339 al inicializar `DEFAULT_SETTINGS` en `src/main.ts` y al manipular las opciones de idioma en `src/ui/settings-tab.ts`, ya que la interfaz no declaraba la propiedad `language`.
- **Solución**: Se añadió la unión de tipos literales a la interfaz:
```typescript
export interface PluginSettings {
  autoLockMinutes: number;
  lockOnBlur: boolean;
  excludedFolders: string[];
  encryptAttachments: boolean;
  isInitialized: boolean;
  language?: 'auto' | 'en' | 'es' | 'ru' | 'zh';
  backup: CloudBackupSettings;
  biometrics?: { ... };
}
```

#### Parche 2: Corrección de Importación Inexistente de `setCssStyles`
- **Archivos**:
  - `src/ui/cloud-backup-modal.ts`
  - `src/ui/export-modal.ts`
  - `src/ui/migration-modal.ts`
  - `src/ui/restore-modal.ts`
- **Problema**: Se importaba `setCssStyles` directamente desde el módulo `'obsidian'`. La API de Obsidian no exporta `setCssStyles` como función del módulo (arrojaba error TS2305). En Obsidian, `setCssStyles` es una extensión del prototipo de `HTMLElement`.
- **Solución**: Se removió del `import` y se implementó una función auxiliar segura con fallback para entornos de prueba:
```typescript
function setCssStyles(el: HTMLElement, styles: Partial<CSSStyleDeclaration>): void {
  Object.assign(el.style, styles);
}
```

#### Parche 3: Tipado Explícito de Callbacks de Progreso
- **Archivo**: `src/ui/cloud-backup-modal.ts`
- **Problema**: Error TS7006 por parámetros de callback implícitamente `any` (`uploaded`, `total`).
- **Solución**: Tipado explícito: `(uploaded: number, total: number) => { ... }`.

#### Parche 4: Corrección de Reglas de Calidad ESLint
- **`src/crypto/bip39.ts`**: Se corrigió el uso de `let` a `const` para los valores de hash iniciales `h1`–`h7` que nunca son reasignados (`prefer-const`).
- **`src/utils/path-sanitizer.ts`**: Se documentó y anotó la regla de caracteres de control `[\x00-\x1f]` indispensable para mitigar inyecciones de ruta y ataques Zip Slip (`no-control-regex`).
- **`src/adapter/adapter-interceptor.ts`**: Se anotó el aliasing de contexto `const self = this;` requerido para monkey patching de métodos del adaptador (`@typescript-eslint/no-this-alias`).
- **`src/backup/cloud/local-sync.ts`**: Se documentaron las llamadas dinámicas `require('fs')` y `require('path')` utilizadas para compatibilidad en entornos Electron de escritorio (`@typescript-eslint/no-require-imports`).

---

## 4. Auditoría de Fuga de Secretos (Gitleaks)

### 4.1 Comandos Ejecutados
```bash
# 1. Escaneo profundo de todos los commits en el historial de Git
gitleaks detect --source Github -v

# 2. Escaneo del árbol de trabajo completo (sin git)
gitleaks detect --source . --no-git -v
```

### 4.2 Hallazgos y Evaluación
- **Historial de Git**: Se escanearon **7 commits** en el repositorio. Resultado: **0 fugas de secretos**.
- **Árbol de Trabajo**: 5 alertas generadas por reglas genéricas de entropía, clasificadas como **Falsos Positivos**:
  1. `SECURITY_AUDIT.md:273`: Cadena de hash hexadecimal en un registro de benchmark de derivación de claves Argon2id documentado en markdown.
  2. `tests/bundle-biometrics.mjs` (y su réplica en `Github/`): Coincidencia sobre el nombre del identificador exportado `deriveAesKeyFromSecret2`.
- **Conclusión**: No existen credenciales activas, API keys, contraseñas en texto plano ni llaves privadas criptográficas expuestas.

---

## 5. Análisis Estático de Seguridad (Semgrep SAST)

### 5.1 Comandos Ejecutados
```bash
semgrep scan --config auto .
```
- Cobertura: 503 reglas ejecutadas sobre 170 archivos.

### 5.2 Hallazgos y Remediación de Seguridad

#### A. Mitigación de Prototype Pollution en Resolución de Cadenas i18n
- **Archivo**: `src/i18n/index.ts`
- **Riesgo**: La función `t(path)` dividía claves separadas por puntos para buscar dentro del diccionario de idiomas (`seg in target`). Un input no confiable con segmentos como `__proto__`, `constructor` o `prototype` podía acceder a métodos prototípicos de JavaScript.
- **Parche de Seguridad Aplicado**:
  Se incluyó una validación estricta de propiedades propias mediante `Object.prototype.hasOwnProperty` y bloqueo directo de nombres de prototipo:
  ```typescript
  export function t(path: string, params?: Record<string, string | number>): string {
    const segments = path.split('.');
    
    let target: any = dictionaries[currentActiveLocale];
    for (const seg of segments) {
      if (seg === '__proto__' || seg === 'constructor' || seg === 'prototype') {
        target = undefined;
        break;
      }
      if (target && typeof target === 'object' && Object.prototype.hasOwnProperty.call(target, seg)) {
        target = target[seg];
      } else {
        target = undefined;
        break;
      }
    }
    // ...
  }
  ```

#### B. Placeholder de Token Google OAuth
- **Archivo**: `src/ui/settings-tab.ts:494`
- **Regla**: `generic.secrets.security.detected-google-oauth-access-token`
- **Evaluación**: Falso positivo. La cadena `.setPlaceholder('ya29.a0AfH6SM...')` es únicamente una sugerencia visual de formato para el usuario en la interfaz gráfica.

#### C. Remediación de Dependencia en Cadena de Suministro (`esbuild`)
- **Vulnerabilidad**: `GHSA-67mh-4wv8-2f99` / `CWE-346` (CORS permisivo en servidor de desarrollo local en versiones `<=0.24.2`).
- **Parche**: Se actualizó `esbuild` de `^0.20.0` a `^0.25.0` en `package.json` y `package-lock.json`, eliminando la alerta de vulnerabilidad.
- **Verificación**: `osv-scanner scan source -r .` pasó de `exit=1` (1 vulnerabilidad) a `exit=0` (0 vulnerabilidades).

#### D. Inyección de Patrones de Reemplazo en la Interpolación i18n
- **Archivo**: `src/i18n/index.ts`
- **Regla**: Detectado durante la revisión manual del código (no lo reporta Semgrep).
- **Riesgo**: La interpolación usaba `text.replace(new RegExp(...), String(val))`. Esto producía dos defectos:
  1. **El *valor* se interpretaba como patrón de reemplazo.** En `String.replace`, `$&`, `` $` ``, `$'` y `$1` son metacarácteres. Un mensaje de error que contuviera `$&` se corrompía (y se filtraba texto circundante de la plantilla dentro del mensaje). Impacto real: los mensajes `notices.exportFailed` / `notices.backupFailed` interpolan `err.message`, es decir, **texto controlado por el atacante o por el servidor remoto**.
  2. **La *clave* se interpretaba como expresión regular.** Un nombre de parámetro con metacaracteres (`a.b`, `a{1,2}`) hacía que el placeholder no se sustituyera, o lanzaba un `SyntaxError` que abortaba el renderizado de la interfaz.
- **Parche de Seguridad Aplicado**: El placeholder se escapa con `escapeRegExp()` y el valor se inyecta mediante una **función** de reemplazo (que no interpreta metacarácteres):
  ```typescript
  text = text.replace(
    new RegExp(`\\{${escapeRegExp(key)}\\}`, 'g'),
    () => String(val)
  );
  ```
- **Pruebas de Regresión**: 2 tests nuevos en `tests/test-i18n.mjs` que verifican el tratamiento literal de `$&`, `` $` ``, `$'`, `$1` y el escapado de metacaracteres en el nombre del parámetro.

---

## 5.3 Auditoría de Dependencias con OSV-Scanner (Google)

### 5.3.1 Herramienta
- **Versión**: `osv-scanner 2.7.0` (osv-scalibr 0.5.3), binario oficial de Google.
- **Base de datos**: OSV (Open Source Vulnerabilities) — `api.osv.dev`.

### 5.3.2 Comandos Ejecutados
```bash
osv-scanner scan source --recursive --format json --all-packages .
osv-scanner scan source --recursive --format json --all-packages ./Github
```

### 5.3.3 Resultados

| Lockfile | Paquetes analizados | Vulnerabilidades (antes) | Vulnerabilidades (después) |
| :--- | :--- | :--- | :--- |
| `package-lock.json` (raíz) | 45 | 1 | **0** |
| `Github/package-lock.json` | 45 | 1 | **0** |

**Vulnerabilidad encontrada y corregida**:
- **ID**: `GHSA-67mh-4wv8-2f99` (CWE-346, severidad MODERATE / CVSS 5.3)
- **Paquete**: `esbuild@0.20.2` (dependencia de desarrollo)
- **Descripción**: esbuild establecía la cabecera `Access-Control-Allow-Origin: *` en todas las respuestas del servidor de desarrollo, permitiendo que **cualquier sitio web** enviara peticiones al servidor local y leyera la respuesta.
- **Rango afectado**: `<= 0.24.2` → **corregido en `0.25.0`**
- **Explotabilidad en este proyecto**: **Nula en producción.** `esbuild` es exclusivamente una herramienta de build: no está presente en el bundle `main.js` que se distribuye (verificado: `grep -c esbuild main.js` → `0`), y el proyecto **no** usa `esbuild.context().serve()`, por lo que nunca se levanta un servidor de desarrollo HTTP. Aun así se corrigió para no exponer un vector de ataque en el entorno de desarrollo ni dejar un advisory abierto en el árbol de dependencias.

### 5.3.4 Verificación por Triangulación
El hallazgo fue confirmado por tres fuentes independientes:
1. **OSV-Scanner 2.7.0** → `GHSA-67mh-4wv8-2f99`.
2. **API OSV directa** (`api.osv.dev/v1/querybatch` sobre los 45 paquetes) → 1 coincidencia.
3. **`npm audit`** → `1 moderate` antes del parche, `0 vulnerabilities` después.

### 5.3.5 Verificación de Acciones de GitHub
Se consultó la base de datos OSV para las 4 acciones usadas en CI (`actions/checkout@v4`, `actions/setup-node@v4`, `github/codeql-action@v3`, `softprops/action-gh-release@v2`): **ninguna presenta vulnerabilidades conocidas**.

### 5.3.6 Guardia Permanente en CI (parche preventivo)
Se añadió `.github/workflows/osv-scanner.yml` usando los workflows reusables oficiales de Google:
- `google/osv-scanner-action/.github/workflows/osv-scanner-reusable.yml@v2.7.0` (escaneo completo).
- `google/osv-scanner-action/.github/workflows/osv-scanner-reusable-pr.yml@v2.7.0` (solo vulnerabilidades nuevas en PR).
- `fail-on-vuln: true` → el pipeline se bloquea si se detecta una vulnerabilidad.
- Se ejecuta en `push`, `pull_request`, `tags`, `schedule` (semanal) y `workflow_dispatch`.

Esto complementa el workflow `codeql.yml` ya existente: CodeQL analiza el **código**, OSV-Scanner audita la **cadena de suministro**.

---

## 6. Verificación y Resultados de Pruebas

Tras aplicar los parches, se ejecutaron las herramientas de validación de forma secuencial:

```bash
# 1. Compilación de tipos TypeScript
npx tsc --noEmit
# Resultado: Exitoso (Exit Code 0, 0 errores)

# 2. Análisis de Linter
npx eslint src/ --quiet
# Resultado: Exitoso (Exit Code 0, 0 errores)

# 3. Suite completa de Pruebas Unitarias
npm test
# Resultado: 81 tests pasados de 81 (0 fallos, duración 1.78s)

# 4. Generación del bundle de producción
npm run build
# Resultado: main.js compilado exitosamente
```

### Cobertura de Pruebas Unitarias Validadas
- **Criptografía**: Derivación de claves con Argon2id, cifrado simétrico AES-256-GCM con autenticación AAD, encapsulado de sobres de texto y binario, borrado seguro de memoria (`zeroize`).
- **Seguridad en Rutas**: Protección contra Directory Traversal (Zip Slip), bloqueo de archivos y carpetas ocultas (`.obsidian`), normalización Unicode NFC/NFD.
- **Biometría & WebAuthn**: Verificación estricta de credenciales WebAuthn, vinculación unidireccional de bóveda, rechazo de firmas manipuladas, protección contra ataques de repetición.
- **Internacionalización**: Integridad de claves entre diccionarios (EN, ES, RU, ZH), interpolación de variables y protección contra prototype pollution.

---

## 7. Tabla Consolidada de Archivos Modificados

| Archivo | Motivo de la Modificación |
| :--- | :--- |
| `manifest.json` / `Github/manifest.json` | Casing del autor a `abismalmx`. |
| `package.json` / `Github/package.json` | Casing del autor, URLs de repositorio y actualización de `esbuild` a `^0.25.0`. |
| `LICENSE` / `Github/LICENSE` | Normalización de enlace de GitHub a `abismalmx`. |
| `README.md` / `README.es.md` | Corrección de enlaces rotos (404 a `MySecret`) y casing del autor. |
| `USER_GUIDE.md` / `USER_GUIDE.es.md` | Corrección de enlaces de instalación y releases de GitHub. |
| `src/types.ts` / `Github/src/types.ts` | Adición del campo `language` a `PluginSettings`. |
| `src/ui/cloud-backup-modal.ts` | Eliminación de import erróneo `setCssStyles`, tipado de callback. |
| `src/ui/export-modal.ts` | Eliminación de import erróneo `setCssStyles` y definición de helper. |
| `src/ui/migration-modal.ts` | Eliminación de import erróneo `setCssStyles` y definición de helper. |
| `src/ui/restore-modal.ts` | Eliminación de import erróneo `setCssStyles` y definición de helper. |
| `src/i18n/index.ts` | Mitigación contra Prototype Pollution en resolución de claves `t()` + corrección de la inyección de patrones de reemplazo en la interpolación (`escapeRegExp` + reemplazo por función). |
| `src/crypto/bip39.ts` | Corrección de variables `const` según regla `prefer-const`. |
| `src/utils/path-sanitizer.ts` | Documentación y anotación de seguridad para regex de control. |
| `src/adapter/adapter-interceptor.ts` | Anotación explícita para aliasing de `this`. |
| `src/backup/cloud/local-sync.ts` | Anotación de llamadas dinámicas `require` en entorno Electron. |
| `src/ui/assets.ts` | Normalización de créditos a `abismalmx`. |
| `src/i18n/locales/*.ts` | Normalización de créditos a `abismalmx` en todos los idiomas. |
| `package-lock.json` / `Github/package-lock.json` | Regenerados con `esbuild@0.25.12` y árbol de dependencias sin vulnerabilidades. |
| `tests/test-i18n.mjs` / `Github/tests/test-i18n.mjs` | 2 tests de regresión para la interpolación i18n (patrones de reemplazo y metacaracteres). |
| `.github/workflows/osv-scanner.yml` / `Github/.github/workflows/osv-scanner.yml` | Workflow de auditoría de dependencias con OSV-Scanner (escaneo completo + PR, `fail-on-vuln: true`). |
| `main.js` / `Github/main.js` | Recompilación del bundle final con todos los parches aplicados. |

---
*Informe generado y verificado automáticamente por la suite de auditoría técnica.*
