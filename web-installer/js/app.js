// Orquestador de la instalación + interfaz bilingüe ES/EN
import { IntelHexParser, bytesToHex } from './hexparser.js';
import { getDeployedSecretV2, ScpSession, concat, u32be } from './scp.js';
import { HexLoader } from './loader.js';
import { WebHidTransport, StatusWordError } from './transport.js';
import { sha256 } from '@noble/hashes/sha2.js';

// ── Parámetros de la app a instalar (Kadena v1.3.0, Nano S+) ──
const APP = {
  name: 'Kadena',
  version: '1.3.0',
  targetId: 0x33100004,
  targetVersion: '',
  apiLevel: 26,
  appFlags: 0x0,
  dataSize: 16896,
  installparamsSize: 62,
  bootAddr: 0,
  hexUrl: './app.hex',
  releaseUrl: 'https://github.com/SmartPacts/app-kadena/releases/tag/v1.3.0',
};

// ── Textos ES/EN ──
const STRINGS = {
  es: {
    title: 'Instalador web — app Kadena para Ledger',
    subtitle: 'Instala la app Kadena v' + APP.version + ' en tu Ledger Nano S+ desde el navegador. Sin Python, sin terminal.',
    warnBrowser: 'Tu navegador no soporta WebHID. Usa Chrome, Edge o Brave.',
    step1: 'Paso 1 — Verifica el binario',
    step1Body: 'Hemos descargado el binario y calculado sus huellas (hashes) aquí, en tu navegador. Compáralas con las publicadas en la página oficial de la release antes de continuar:',
    hashFile: 'SHA-256 del fichero app.hex (compárala con SHA256SUMS.txt):',
    hashApp: 'Hash de aplicación que verá el dispositivo (tabla "Device hashes", fila nanos2):',
    openRelease: 'Abrir la página de la release en GitHub',
    approve: 'He comprobado que ambos hashes coinciden con los oficiales',
    step2: 'Paso 2 — Conecta tu Ledger',
    step2Body: 'Conecta el Ledger Nano S+ por USB, desbloquéalo con tu PIN y déjalo en la pantalla principal (donde se ven las apps). Después pulsa:',
    connect: 'Conectar Ledger',
    step3: 'Paso 3 — Instalación',
    install: 'Instalar app Kadena',
    installing: 'Instalando…',
    unsafePrompt: 'Mira tu Ledger: mostrará «Allow unsafe manager». Acéptalo con los botones del dispositivo. Es normal: significa que la app la cargas tú y no viene firmada por Ledger.',
    deleting: 'Borrando versión anterior (si existe)…',
    loading: 'Cargando la app en el dispositivo…',
    committing: 'Finalizando instalación…',
    done: 'Instalación completada',
    doneBody: 'La app Kadena debe aparecer ya en el menú de tu Ledger. Nada de esto ha tocado tu semilla ni tus otras apps.',
    errPrefix: 'Error: ',
    errNoDevice: 'No se seleccionó ningún dispositivo.',
    retry: 'Reintentar',
    langBtn: 'English',
    hexLoadError: 'No se pudo descargar app.hex',
    connected: 'Ledger conectado.',
    security1: 'Esta página no tiene servidor: todo ocurre en tu navegador y puedes auditar el código fuente en este mismo repositorio.',
    security2: 'Nunca te pediremos la frase de recuperación (24 palabras). Ninguna web legítima la pide.',
    security3: 'Esta web es solo un medio de paso: el código y los binarios residen en el repositorio git y esta página es un espejo de él. Verifica siempre los hashes contra la release oficial de GitHub, no contra esta página.',
  },
  en: {
    title: 'Web installer — Kadena app for Ledger',
    subtitle: 'Install the Kadena app v' + APP.version + ' on your Ledger Nano S+ from the browser. No Python, no terminal.',
    warnBrowser: 'Your browser does not support WebHID. Use Chrome, Edge or Brave.',
    step1: 'Step 1 — Verify the binary',
    step1Body: 'We downloaded the binary and computed its fingerprints (hashes) here, in your browser. Compare them with the ones published on the official release page before continuing:',
    hashFile: 'SHA-256 of the app.hex file (compare with SHA256SUMS.txt):',
    hashApp: 'Application hash the device will see ("Device hashes" table, nanos2 row):',
    openRelease: 'Open the release page on GitHub',
    approve: 'I verified that both hashes match the official ones',
    step2: 'Step 2 — Connect your Ledger',
    step2Body: 'Connect the Ledger Nano S+ via USB, unlock it with your PIN and leave it on the dashboard (where the apps are shown). Then press:',
    connect: 'Connect Ledger',
    step3: 'Step 3 — Installation',
    install: 'Install Kadena app',
    installing: 'Installing…',
    unsafePrompt: 'Look at your Ledger: it will show “Allow unsafe manager”. Accept it with the device buttons. This is expected: it means you are loading the app yourself and it is not signed by Ledger.',
    deleting: 'Deleting previous version (if any)…',
    loading: 'Loading the app onto the device…',
    committing: 'Finalizing installation…',
    done: 'Installation complete',
    doneBody: 'The Kadena app should now appear in your Ledger menu. Nothing in this process touched your seed or your other apps.',
    errPrefix: 'Error: ',
    errNoDevice: 'No device was selected.',
    retry: 'Retry',
    langBtn: 'Español',
    hexLoadError: 'Could not download app.hex',
    connected: 'Ledger connected.',
    security1: 'This page has no server: everything happens in your browser and you can audit the source code in this very repository.',
    security2: 'We will never ask for your recovery phrase (24 words). No legitimate site ever does.',
    security3: 'This site is only a passing medium: the code and binaries live in the git repository and this page is a mirror of it. Always verify the hashes against the official GitHub release, not against this page.',
  },
};

let lang = navigator.language && navigator.language.startsWith('es') ? 'es' : 'en';
let hexText = null;
let parser = null;
let transport = null;

const $ = (id) => document.getElementById(id);
const t = (k) => STRINGS[lang][k];

function renderTexts() {
  document.documentElement.lang = lang;
  for (const el of document.querySelectorAll('[data-i18n]')) el.textContent = t(el.dataset.i18n);
  $('lang-toggle').textContent = t('langBtn');
  document.title = t('title');
}

// hash de aplicación como lo calcula el dispositivo (= ledgerblue load stream):
// sha256( targetId(4BE) || targetVersion || createappParams || chunks de código )
function computeAppHash(p) {
  const codeLength = p.maxAddr() - p.minAddr() - APP.dataSize - APP.installparamsSize;
  const createappParams = concat(
    new Uint8Array([APP.apiLevel]),
    u32be(codeLength),
    u32be(APP.dataSize),
    u32be(APP.installparamsSize),
    u32be(APP.appFlags),
    u32be(APP.bootAddr | 1)
  );
  const parts = [u32be(APP.targetId), new TextEncoder().encode(APP.targetVersion), createappParams];
  for (const area of p.getAreas()) parts.push(area.data);
  return bytesToHex(sha256(concat(...parts)));
}

async function init() {
  renderTexts();
  $('lang-toggle').onclick = () => {
    lang = lang === 'es' ? 'en' : 'es';
    renderTexts();
  };

  if (!WebHidTransport.isSupported()) {
    $('browser-warn').hidden = false;
  }

  let hexBytes;
  try {
    const resp = await fetch(APP.hexUrl);
    if (!resp.ok) throw new Error(String(resp.status));
    hexBytes = new Uint8Array(await resp.arrayBuffer());
  } catch (e) {
    $('hash-file').textContent = t('hexLoadError');
    return;
  }
  hexText = new TextDecoder().decode(hexBytes);
  parser = new IntelHexParser(hexText);
  $('hash-file').textContent = bytesToHex(sha256(hexBytes));
  $('hash-app').textContent = computeAppHash(parser);

  $('approve-check').onchange = () => {
    $('connect-btn').disabled = !$('approve-check').checked;
  };

  $('connect-btn').onclick = async () => {
    try {
      transport = await WebHidTransport.request();
      $('connect-status').textContent = t('connected');
      $('install-btn').disabled = false;
    } catch (e) {
      $('connect-status').textContent = t('errPrefix') + (e.message === 'no-device-selected' ? t('errNoDevice') : e.message);
    }
  };

  $('install-btn').onclick = install;
}

function showStatus(msg, isError = false) {
  const el = $('install-status');
  el.textContent = msg;
  el.classList.toggle('error', isError);
}

async function install() {
  $('install-btn').disabled = true;
  const bar = $('progress');
  bar.hidden = false;
  bar.value = 0;
  try {
    showStatus(t('unsafePrompt'));
    const secret = await getDeployedSecretV2(transport, APP.targetId);
    const session = new ScpSession(secret.ecdhSecret);
    const loader = new HexLoader(transport, 0xe0, session);

    showStatus(t('deleting'));
    await loader.deleteApp(APP.name);

    const codeLength = parser.maxAddr() - parser.minAddr() - APP.dataSize - APP.installparamsSize;
    await loader.createApp(codeLength, APP.apiLevel, APP.dataSize, APP.installparamsSize, APP.appFlags, APP.bootAddr | 1);

    showStatus(t('loading'));
    await loader.load(parser, {
      targetId: APP.targetId,
      targetVersion: APP.targetVersion,
      onProgress: (f) => {
        bar.value = f * 100;
      },
    });

    showStatus(t('committing'));
    await loader.commit(null);

    bar.value = 100;
    showStatus('');
    $('done-panel').hidden = false;
  } catch (e) {
    let msg = e.message;
    if (e instanceof StatusWordError && e.messages) msg = e.messages[lang];
    showStatus(t('errPrefix') + msg, true);
    $('install-btn').disabled = false;
    $('install-btn').textContent = t('retry');
  }
}

init();
