# Por qué MySecret: Comparativa y Ventajas Clave

[English Version](COMPARISON.md) • **Español**

Al buscar una solución de seguridad y cifrado para tus notas en [Obsidian](https://obsidian.md), tradicionalmente tenías que elegir entre **seguridad** o **comodidad**. La mayoría de las opciones existentes te obligan a bloquear notas una por una (rompiendo las búsquedas, la vista gráfica y los enlaces) o requieren programas externos complejos (como Cryptomator o VeraCrypt) que son muy difíciles e incómodos de sincronizar en teléfonos móviles.

**MySecret elimina este dilema.** Integra **cifrado transparente en disco, de grado militar y con arquitectura de Cero Conocimiento** directamente dentro de Obsidian, sin alterar tu ritmo de trabajo diario.

---

## 📊 Tabla Comparativa de Características

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

## 🌟 Las 7 Grandes Ventajas de MySecret Explicadas de Forma Simple

### 1. 🪄 Cifrado Totalmente Invisible (Obsidian Sigue Funcionando)
- **El problema de los plugins tradicionales:** Plugins como *Meld Encrypt* convierten tus notas en bloques feos de caracteres incomprensibles (Base64) en la pantalla. Como Obsidian no puede leer lo que hay dentro, **la búsqueda global no encuentra nada, las etiquetas desaparecen y la vista de gráfico (Graph View) queda totalmente rota**.
- **La solución de MySecret:** MySecret trabaja silenciosamente por debajo, en el adaptador de archivos (`app.vault.adapter`). Mientras tu bóveda esté desbloqueada, Obsidian se comporta como siempre: buscas cualquier frase en milisegundos, tus enlaces conectan tus ideas y los lienzos Canvas se abren fluidos. Al momento en que el archivo se guarda en el disco duro, se sella herméticamente con AES-256-GCM.

---

### 2. 📸 Fotos, Documentos y Audios También Están Protegidos
- **El problema de los plugins tradicionales:** La mayoría de plugins solo cifran texto `.md`. Si adjuntas una foto de una identificación personal, un contrato en PDF confidencial o una grabación de voz sensible, esos archivos se quedan en texto claro en tu disco duro, totalmente expuestos a cualquiera.
- **La solución de MySecret:** MySecret cifra **todos los tipos de archivo**. Las notas de texto usan un contenedor protegido y los archivos multimedia (PNG, JPG, PDF, MP3, MP4) utilizan una cabecera binaria compacta (`MYSE`). Tus documentos adjuntos están tan protegidos como tus notas escritas.

---

### 3. 🛡️ Criptografía Resistente a Supercomputadoras (Argon2id vs. PBKDF2)
- **El problema de los plugins tradicionales:** Casi todos los plugins usan **PBKDF2** con pocas iteraciones. Una tarjeta gráfica moderna para videojuegos (como una NVIDIA RTX 4090) puede probar decenas de millones de contraseñas por segundo contra este algoritmo.
- **La solución de MySecret:** MySecret implementa **Argon2id** (el algoritmo estándar ganador del Password Hashing Competition) compilado en WebAssembly. Este algoritmo obliga a cualquier atacante a gastar **64 Megabytes de memoria RAM por cada intento**, anulando matemáticamente los ataques de fuerza bruta con tarjetas gráficas o granjas de minería.

---

### 4. 🔑 Frase de Rescate de 24 Palabras (Como una Billetera Cripto)
- **El problema de los plugins tradicionales:** En otros plugins, si olvidas tu contraseña maestra, has perdido toda tu información para siempre sin ninguna alternativa.
- **La solución de MySecret:** Al configurar tu bóveda por primera vez, MySecret te entrega una frase estandarizada de **24 palabras mnemónicas BIP-39** basada en 256 bits de entropía. Si un día olvidas tu clave, introduces tus 24 palabras y tu bóveda se recupera en tu dispositivo sin depender de ningún servidor ni soporte técnico.

---

### 5. 👆 Desbloqueo por Huella y Rostro en Todos tus Equipos (¡Incluyendo Android!)
- **El problema en dispositivos móviles:** En Android, Obsidian funciona dentro de un contenedor (WebView) donde Google bloquea el acceso a la huella dactilar. Por esta razón, **ningún otro plugin de Obsidian había logrado ofrecer desbloqueo biométrico en Android**.
- **La solución de MySecret:**
  - **En Windows:** Desbloqueo nativo e instantáneo con **Windows Hello** (huella, rostro o PIN) vía DPAPI. Cero configuración.
  - **En macOS y Linux:** Soporte local con Touch ID y `fprintd`.
  - **En Android:** Un puente PWA complementario y gratuito desplegable en 1 clic en Cloudflare Pages. Utiliza **criptografía efímera ECDH P-256** para validar tu huella en el navegador de tu móvil y desbloquear Obsidian en segundos, sin que tu clave salga jamás del dispositivo.

---

### 6. ☁️ Copias de Seguridad Cifradas en la Nube con 1 Clic
- **El problema con herramientas externas:** Intentar sincronizar carpetas cifradas complejas mediante servicios externos suele provocar archivos corruptos, conflictos de sincronización o bloqueos de ficheros.
- **La solución de MySecret:** MySecret incluye su propio motor de respaldos. Con un clic o un comando puedes exportar copias completas o enviarlas cifradas automáticamente a **Nextcloud / WebDAV, Google Drive o Microsoft OneDrive**. Las credenciales de acceso a tu nube se guardan a su vez fuertemente cifradas con la clave de tu bóveda.

---

### 7. 🧹 Limpieza Activa de Memoria RAM (Zeroize)
- **El problema con las aplicaciones comunes:** Cuando cierras una app o dejas tu equipo encendido, las contraseñas y claves de descifrado a menudo permanecen en la memoria RAM durante horas, donde programas maliciosos pueden extraerlas.
- **La solución de MySecret:** MySecret sobrescribe activamente con ceros (`zeroize()`) todos los buffers de claves en la memoria RAM en bloques estrictos `finally`, tanto al bloquearse la bóveda, al agotarse el tiempo de inactividad o ante cualquier error imprevisto.

---

### 8. 🔓 Cero Cautiverio de Proveedor (Sin Vendor Lock-in): Recupera tus Notas sin Obsidian
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

## 🎯 ¿Para Quién es MySecret?

- **Escritores y Diarios Personales:** Mantén tus pensamientos íntimos, registros de salud mental y notas familiares a salvo de miradas indiscretas o robo de dispositivos.
- **Profesionales y Científicos:** Almacena código confidencial, notas clínicas de pacientes, borradores de patentes y expedientes legales cumpliendo con los estándares de privacidad más exigentes.
- **Entusiastas de la Privacidad:** Disfruta de la misma filosofía de seguridad de Cero Conocimiento que utilizan las billeteras frías de criptomonedas, directamente en tu segundo cerebro digital.
