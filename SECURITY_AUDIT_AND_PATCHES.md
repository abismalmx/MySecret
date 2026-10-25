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
- **Errores de Compilación TypeScript (`tsc`)**: Reducidos de **11 errores críticos a 0**.
- **Errores de Calidad y Linter (`ESLint`)**: Reducidos de **11 errores a 0**.
- **Fuga de Secretos en Git (`Gitleaks`)**: **0 fugas detectadas** en el historial completo de commits.
- **Reglas SAST de Seguridad (`Semgrep`)**: 503 reglas ejecutadas; vulnerabilidad potencial de Prototype Pollution mitigada y falsos positivos clasificados.
- **Pruebas de Regresión Criptográfica y Funcional (`npm test`)**: **81 pruebas ejecutadas, 81 aprobadas (0 fallos)**.
- **Compilación de Producción (`esbuild`)**: Generada exitosamente y sincronizada en raíz y carpeta `Github/`.

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
| `src/i18n/index.ts` | Mitigación contra Prototype Pollution en resolución de claves `t()`. |
| `src/crypto/bip39.ts` | Corrección de variables `const` según regla `prefer-const`. |
| `src/utils/path-sanitizer.ts` | Documentación y anotación de seguridad para regex de control. |
| `src/adapter/adapter-interceptor.ts` | Anotación explícita para aliasing de `this`. |
| `src/backup/cloud/local-sync.ts` | Anotación de llamadas dinámicas `require` en entorno Electron. |
| `src/ui/assets.ts` | Normalización de créditos a `abismalmx`. |
| `src/i18n/locales/*.ts` | Normalización de créditos a `abismalmx` en todos los idiomas. |
| `main.js` / `Github/main.js` | Recompilación del bundle final con todos los parches aplicados. |

---
*Informe generado y verificado automáticamente por la suite de auditoría técnica.*
