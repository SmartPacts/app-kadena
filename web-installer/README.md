# Kadena Ledger Web Installer / Instalador web de Kadena para Ledger

**English below · Español primero**

---

## 🇪🇸 Español

Instalador web de la app **Kadena v1.3.0** para **Ledger Nano S+**: se instala desde el navegador (Chrome, Edge o Brave) usando WebHID. Sin Python, sin terminal, sin dependencias.

### Cómo funciona

1. La página calcula **en tu navegador** el SHA-256 del binario (`app.hex`) y el hash de aplicación que verá el dispositivo, y te pide compararlos con los publicados en la [release oficial](https://github.com/SmartPacts/app-kadena/releases/tag/v1.3.0) antes de continuar.
2. Conectas el Ledger por USB (desbloqueado, en la pantalla principal).
3. El dispositivo muestra **«Allow unsafe manager»** — es lo esperado en una carga manual: significa que la app la cargas tú y no viene firmada por Ledger. La instalación no toca tu semilla ni tus otras apps.

### Confianza

- **Sin servidor**: todo ocurre en tu navegador; el hosting solo entrega ficheros estáticos.
- **Esta web es solo un medio de paso**: el código y los binarios residen en el repositorio git; la página es un espejo de él. Verifica siempre los hashes contra la release oficial de GitHub, no contra esta página.
- **Nunca** te pediremos la frase de recuperación (24 palabras). Ninguna web legítima la pide.
- Criptografía: librerías [noble](https://paulmillr.com/noble/) (MIT, auditadas) vendorizadas en `vendor/` — sin CDNs externos.

### Detalles técnicos

Es un port a JavaScript de `ledgerblue.loadApp` (la herramienta oficial de carga de Ledger, Apache-2.0):

| Módulo | Origen | Verificación |
|---|---|---|
| `js/hexparser.js` | `ledgerblue/hexParser.py` | salida idéntica sobre el app.hex real |
| `js/scp.js` | `deployed.py` + `hexLoader.py` (SCP) | vectores de prueba generados con ledgerblue |
| `js/loader.js` | `hexLoader.py` (comandos) | stream de 277 APDUs idéntico byte a byte a `loadApp --offline` |
| `js/transport.js` | framing HID de Ledger | probado en hardware real |

Limitaciones: solo navegadores con WebHID (Chrome/Edge/Brave de escritorio). De momento solo Nano S+ (`targetId 0x33100004`); ampliable a otros modelos parametrizando `APP` en `js/app.js`.

---

## 🇬🇧 English

Web installer for the **Kadena v1.3.0** app on **Ledger Nano S+**: installs from the browser (Chrome, Edge or Brave) using WebHID. No Python, no terminal, no dependencies.

### How it works

1. The page computes **in your browser** the SHA-256 of the binary (`app.hex`) and the application hash the device will see, and asks you to compare them with the ones published in the [official release](https://github.com/SmartPacts/app-kadena/releases/tag/v1.3.0) before continuing.
2. You connect the Ledger via USB (unlocked, on the dashboard).
3. The device shows **“Allow unsafe manager”** — expected for a manual load: it means you are loading the app yourself and it is not signed by Ledger. The installation does not touch your seed or your other apps.

### Trust

- **No server**: everything happens in your browser; the hosting only serves static files.
- **This site is only a passing medium**: the code and binaries live in the git repository; the page is a mirror of it. Always verify the hashes against the official GitHub release, not against this page.
- We will **never** ask for your recovery phrase (24 words). No legitimate site ever does.
- Cryptography: [noble](https://paulmillr.com/noble/) libraries (MIT, audited) vendored in `vendor/` — no external CDNs.

### Technical details

A JavaScript port of `ledgerblue.loadApp` (Ledger's official loading tool, Apache-2.0):

| Module | Source | Verification |
|---|---|---|
| `js/hexparser.js` | `ledgerblue/hexParser.py` | identical output on the real app.hex |
| `js/scp.js` | `deployed.py` + `hexLoader.py` (SCP) | test vectors generated with ledgerblue |
| `js/loader.js` | `hexLoader.py` (commands) | 277-APDU stream byte-identical to `loadApp --offline` |
| `js/transport.js` | Ledger HID framing | tested on real hardware |

Limitations: WebHID browsers only (desktop Chrome/Edge/Brave). Nano S+ only for now (`targetId 0x33100004`); extendable to other models by parameterizing `APP` in `js/app.js`.
