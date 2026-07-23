// Orquestador de la instalación + interfaz bilingüe ES/EN
// Los modelos, parámetros y hashes oficiales se cargan de models.json (fuente: el repositorio git)
import { IntelHexParser, bytesToHex } from './hexparser.js';
import { getDeployedSecretV2, ScpSession, concat, u32be } from './scp.js';
import { HexLoader } from './loader.js';
import { WebHidTransport, StatusWordError } from './transport.js';
import { sha256 } from '@noble/hashes/sha2.js';

// ── Textos ES/EN ──
const STRINGS = {
  es: {
    title: 'Instalador web — app Kadena para Ledger',
    subtitle: 'Instala la app Kadena en tu Ledger desde el navegador. Sin Python, sin terminal.',
    warnBrowser: 'Tu navegador no soporta WebHID. Usa Chrome, Edge o Brave.',
    step0: 'Paso 1 — Elige tu modelo de Ledger',
    modelUnavailable: '(binario aún no publicado en la release)',
    step1: 'Paso 2 — Verifica el binario',
    step1Body: 'Hemos descargado el binario y calculado sus huellas (hashes) aquí, en tu navegador. Junto a cada una se muestra la oficial publicada en git. Compruébalo también tú contra la página de la release antes de continuar:',
    hashFile: 'SHA-256 del fichero app.hex:',
    hashApp: 'Hash de aplicación que verá el dispositivo:',
    official: 'Oficial (git):',
    computed: 'Calculado aquí:',
    match: '✓ coinciden',
    mismatch: '✗ NO COINCIDEN — no instales',
    openRelease: 'Abrir la página de la release en GitHub',
    approve: 'He comprobado que los hashes coinciden con los oficiales de la release',
    step2: 'Paso 3 — Conecta tu Ledger',
    step2Body: 'Conecta el Ledger por USB, desbloquéalo con tu PIN y déjalo en la pantalla principal (donde se ven las apps, sin entrar en ninguna). Después pulsa:',
    connect: 'Conectar Ledger',
    step3: 'Paso 4 — Instalación',
    install: 'Instalar app Kadena',
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
    hexLoadError: 'No se pudo descargar el binario',
    connected: 'Ledger conectado.',
    security1: 'Esta página no tiene servidor: todo ocurre en tu navegador y puedes auditar el código fuente en este mismo repositorio.',
    security2: 'Nunca te pediremos la frase de recuperación (24 palabras). Ninguna web legítima la pide.',
    security3: 'Esta web es solo un medio de paso: el código, los binarios y los hashes oficiales residen en el repositorio git y esta página es un espejo de él. Verifica siempre los hashes contra la release oficial de GitHub, no contra esta página.',
  },
  en: {
    title: 'Web installer — Kadena app for Ledger',
    subtitle: 'Install the Kadena app on your Ledger from the browser. No Python, no terminal.',
    warnBrowser: 'Your browser does not support WebHID. Use Chrome, Edge or Brave.',
    step0: 'Step 1 — Choose your Ledger model',
    modelUnavailable: '(binary not yet published in the release)',
    step1: 'Step 2 — Verify the binary',
    step1Body: 'We downloaded the binary and computed its fingerprints (hashes) here, in your browser. Next to each one you see the official value published in git. Double-check them yourself against the release page before continuing:',
    hashFile: 'SHA-256 of the app.hex file:',
    hashApp: 'Application hash the device will see:',
    official: 'Official (git):',
    computed: 'Computed here:',
    match: '✓ match',
    mismatch: '✗ DO NOT MATCH — do not install',
    openRelease: 'Open the release page on GitHub',
    approve: 'I verified that the hashes match the official ones in the release',
    step2: 'Step 3 — Connect your Ledger',
    step2Body: 'Connect the Ledger via USB, unlock it with your PIN and leave it on the dashboard (where the apps are shown, without opening any). Then press:',
    connect: 'Connect Ledger',
    step3: 'Step 4 — Installation',
    install: 'Install Kadena app',
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
    hexLoadError: 'Could not download the binary',
    connected: 'Ledger connected.',
    security1: 'This page has no server: everything happens in your browser and you can audit the source code in this very repository.',
    security2: 'We will never ask for your recovery phrase (24 words). No legitimate site ever does.',
    security3: 'This site is only a passing medium: the code, binaries and official hashes live in the git repository and this page is a mirror of it. Always verify the hashes against the official GitHub release, not against this page.',
  },
};

let lang = navigator.language && navigator.language.startsWith('es') ? 'es' : 'en';
let manifest = null;
let model = null;
let parser = null;
let transport = null;

const $ = (id) => document.getElementById(id);
const t = (k) => STRINGS[lang][k];

function renderTexts() {
  document.documentElement.lang = lang;
  for (const el of document.querySelectorAll('[data-i18n]')) el.textContent = t(el.dataset.i18n);
  $('lang-toggle').textContent = t('langBtn');
  document.title = t('title');
  if (manifest) populateModels(); // re-render etiquetas del selector en el idioma nuevo
}

// hash de aplicación tal y como lo calcula el dispositivo:
// sha256( targetId(4BE) || targetVersion || createappParams || código por áreas )
function computeAppHash(p, m) {
  const codeLength = p.maxAddr() - p.minAddr() - m.dataSize - m.installparamsSize;
  const createappParams = concat(
    new Uint8Array([m.apiLevel]),
    u32be(codeLength),
    u32be(m.dataSize),
    u32be(m.installparamsSize),
    u32be(m.appFlags),
    u32be(m.bootAddr | 1)
  );
  const parts = [u32be(parseInt(m.targetId, 16)), new Uint8Array(0), createappParams];
  for (const area of p.getAreas()) parts.push(area.data);
  return bytesToHex(sha256(concat(...parts)));
}

function populateModels() {
  const sel = $('model-select');
  const current = sel.value;
  sel.innerHTML = '';
  for (const m of manifest.models) {
    const opt = document.createElement('option');
    opt.value = m.key;
    opt.textContent = m.available ? m.label : `${m.label} ${t('modelUnavailable')}`;
    opt.disabled = !m.available;
    sel.appendChild(opt);
  }
  const firstAvailable = manifest.models.find((m) => m.available);
  sel.value = current && manifest.models.some((m) => m.key === current && m.available) ? current : firstAvailable.key;
}

function renderHashRow(rowId, official, computed) {
  const el = $(rowId);
  const ok = official && computed && official === computed;
  el.innerHTML = '';
  const mk = (label, value, cls) => {
    const d = document.createElement('div');
    d.className = 'hashline' + (cls ? ' ' + cls : '');
    const s = document.createElement('span');
    s.className = 'hlabel';
    s.textContent = label;
    d.appendChild(s);
    d.appendChild(document.createTextNode(value));
    return d;
  };
  el.appendChild(mk(t('official'), official));
  el.appendChild(mk(t('computed'), computed));
  const verdict = document.createElement('div');
  verdict.className = 'verdict ' + (ok ? 'ok' : 'bad');
  verdict.textContent = ok ? t('match') : t('mismatch');
  el.appendChild(verdict);
  return ok;
}

async function selectModel(key) {
  model = manifest.models.find((m) => m.key === key);
  parser = null;
  $('approve-check').checked = false;
  $('connect-btn').disabled = true;
  $('install-btn').disabled = true;
  if (!model || !model.available) return;

  let hexBytes;
  try {
    const resp = await fetch(model.hexUrl);
    if (!resp.ok) throw new Error(String(resp.status));
    hexBytes = new Uint8Array(await resp.arrayBuffer());
  } catch (e) {
    $('hash-file').textContent = t('hexLoadError');
    return;
  }
  parser = new IntelHexParser(new TextDecoder().decode(hexBytes));

  const okFile = renderHashRow('hash-file', model.officialFileSha256, bytesToHex(sha256(hexBytes)));
  const okApp = renderHashRow('hash-app', model.officialAppHash, computeAppHash(parser, model));
  // si algo no cuadra, ni siquiera dejamos marcar la casilla
  $('approve-check').disabled = !(okFile && okApp);
}

async function init() {
  $('lang-toggle').onclick = () => {
    lang = lang === 'es' ? 'en' : 'es';
    renderTexts();
    if (model) selectModel(model.key);
  };

  if (!WebHidTransport.isSupported()) $('browser-warn').hidden = false;

  const resp = await fetch('./models.json');
  manifest = await resp.json();
  renderTexts();
  populateModels();
  $('model-select').onchange = (e) => selectModel(e.target.value);
  await selectModel($('model-select').value);

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
    const targetId = parseInt(model.targetId, 16);
    const secret = await getDeployedSecretV2(transport, targetId);
    const session = new ScpSession(secret.ecdhSecret);
    const loader = new HexLoader(transport, 0xe0, session);

    showStatus(t('deleting'));
    await loader.deleteApp(manifest.appName);

    const codeLength = parser.maxAddr() - parser.minAddr() - model.dataSize - model.installparamsSize;
    await loader.createApp(codeLength, model.apiLevel, model.dataSize, model.installparamsSize, model.appFlags, model.bootAddr | 1);

    showStatus(t('loading'));
    await loader.load(parser, {
      targetId,
      targetVersion: '',
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
