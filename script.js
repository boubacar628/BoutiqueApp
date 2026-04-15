/* =============================================
   BOUTIQUEAPP v2.0 — script.js
   Sécurité maximale · Fonctionnalités complètes
   Aucune donnée de démo · Production-ready
   ============================================= */

'use strict';

// ================================================================
// SECTION 1 — CONSTANTES & CONFIGURATION SÉCURITÉ
// ================================================================

const APP_VERSION    = '2.0';
const MAX_PIN_TRIES  = 5;          // Tentatives avant blocage
const LOCKOUT_MS     = 5 * 60 * 1000; // 5 min de blocage
const SESSION_TTL    = 30 * 60 * 1000; // Session 30 min
const PAGE_SIZE      = 10;         // Items par page
const KEYS = Object.freeze({
  config:     'bapp_config',
  stock:      'bapp_stock',
  ventes:     'bapp_ventes',
  dettes:     'bapp_dettes',
  livraisons: 'bapp_livraisons',
  activity:   'bapp_activity',
  pin:        'bapp_pin_hash',
  pinTries:   'bapp_pin_tries',
  lockUntil:  'bapp_lock_until',
  sessionExp: 'bapp_session_exp',
});

/* Limites de validation */
const LIMITS = {
  nom_max: 80, client_max: 60, desc_max: 120,
  note_max: 100, addr_max: 100,
  price_max: 100_000_000, qty_max: 100_000,
};

// ================================================================
// SECTION 2 — SÉCURITÉ : HACHAGE PIN (SHA-256 via Web Crypto)
// ================================================================

async function hashPin(pin) {
  const enc  = new TextEncoder();
  const salt = 'bapp_salt_v2';                      // Salt statique embarqué
  const data = enc.encode(salt + pin);
  const buf  = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPin(pin) {
  const stored = localStorage.getItem(KEYS.pin);
  if (!stored) return false;
  return (await hashPin(pin)) === stored;
}

async function savePin(pin) {
  const h = await hashPin(pin);
  localStorage.setItem(KEYS.pin, h);
}

// ================================================================
// SECTION 3 — SÉCURITÉ : SESSION & TENTATIVES
// ================================================================

function setSession() {
  localStorage.setItem(KEYS.sessionExp, Date.now() + SESSION_TTL);
}

function isSessionValid() {
  const exp = parseInt(localStorage.getItem(KEYS.sessionExp) || '0');
  return Date.now() < exp;
}

function invalidateSession() {
  localStorage.removeItem(KEYS.sessionExp);
}

function recordFailedAttempt() {
  let tries = parseInt(localStorage.getItem(KEYS.pinTries) || '0') + 1;
  localStorage.setItem(KEYS.pinTries, tries);
  if (tries >= MAX_PIN_TRIES) {
    localStorage.setItem(KEYS.lockUntil, Date.now() + LOCKOUT_MS);
    localStorage.setItem(KEYS.pinTries, '0');
  }
  return tries;
}

function isLockedOut() {
  const until = parseInt(localStorage.getItem(KEYS.lockUntil) || '0');
  if (Date.now() < until) return until;
  return false;
}

function clearFailedAttempts() {
  localStorage.removeItem(KEYS.pinTries);
  localStorage.removeItem(KEYS.lockUntil);
}

// Auto-verrouillage si inactivité
let activityTimer = null;
function resetActivityTimer() {
  clearTimeout(activityTimer);
  if (isSessionValid()) setSession();
  activityTimer = setTimeout(() => {
    if (document.getElementById('app') && !document.getElementById('app').classList.contains('hidden')) {
      verrouillerApp();
    }
  }, SESSION_TTL);
}
['click','touchstart','keydown','input'].forEach(ev =>
  document.addEventListener(ev, resetActivityTimer, { passive: true })
);

// ================================================================
// SECTION 4 — STOCKAGE SÉCURISÉ
// ================================================================

function sauvegarder(key, val) {
  if (!Object.values(KEYS).includes(key)) {
    console.warn('Clé de stockage non autorisée :', key);
    return;
  }
  try {
    localStorage.setItem(key, JSON.stringify(val));
  } catch (e) {
    if (e.name === 'QuotaExceededError') {
      showToast('Stockage plein ! Supprimez des données.', 'error');
    }
  }
}

function charger(key) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function chargerConfig() {
  try {
    const raw = localStorage.getItem(KEYS.config);
    if (!raw) return null;
    const cfg = JSON.parse(raw);
    return (cfg && typeof cfg === 'object') ? cfg : null;
  } catch { return null; }
}

function sauvegarderConfig(cfg) {
  localStorage.setItem(KEYS.config, JSON.stringify(cfg));
}

// ================================================================
// SECTION 5 — VALIDATION & SANITISATION
// ================================================================

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g,'&amp;')
    .replace(/</g,'&lt;')
    .replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;')
    .replace(/'/g,'&#x27;')
    .replace(/\//g,'&#x2F;');
}

function sanitizeStr(val, maxLen = 120) {
  return String(val ?? '').trim().slice(0, maxLen);
}

function sanitizeNum(val, min = 0, max = LIMITS.price_max) {
  const n = parseFloat(val);
  if (isNaN(n) || n < min || n > max) return null;
  return n;
}

function sanitizeInt(val, min = 0, max = LIMITS.qty_max) {
  const n = parseInt(val);
  if (isNaN(n) || n < min || n > max) return null;
  return n;
}

function isValidDate(str) {
  if (!str) return true;
  const d = new Date(str);
  return d instanceof Date && !isNaN(d);
}

// ================================================================
// SECTION 6 — UTILITAIRES
// ================================================================

function genId() {
  const arr = new Uint32Array(2);
  crypto.getRandomValues(arr);
  return arr[0].toString(36) + arr[1].toString(36) + Date.now().toString(36);
}

function fcfa(n) {
  const num = Number(n ?? 0);
  if (num >= 1_000_000) return (num / 1_000_000).toFixed(1).replace('.0','') + 'M F';
  if (num >= 1_000)     return (num / 1_000).toFixed(0) + 'k F';
  return num.toLocaleString('fr-FR') + ' F';
}

function fcfaFull(n) {
  return Number(n ?? 0).toLocaleString('fr-FR') + ' FCFA';
}

function fmtDate(ts) {
  const d = new Date(ts);
  return d.toLocaleDateString('fr-FR', { day:'2-digit', month:'short', hour:'2-digit', minute:'2-digit' });
}

function fmtDateShort(ts) {
  return new Date(ts).toLocaleDateString('fr-FR', { day:'2-digit', month:'short' });
}

function todayStart() {
  const d = new Date(); d.setHours(0,0,0,0); return d.getTime();
}

function weekStart() {
  const d = new Date(); d.setHours(0,0,0,0);
  d.setDate(d.getDate() - d.getDay()); return d.getTime();
}

function monthStart() {
  const d = new Date(); d.setHours(0,0,0,0);
  d.setDate(1); return d.getTime();
}

function getConfig() {
  return chargerConfig() || { shopName: 'BoutiqueApp', owner: '', threshold: 5 };
}

// ================================================================
// SECTION 7 — TOAST
// ================================================================

let toastTimer = null;
function showToast(msg, type = 'success') {
  const t  = document.getElementById('toast');
  const ic = document.getElementById('toast-icon');
  const m  = document.getElementById('toast-msg');
  const icons = { success:'fa-circle-check', error:'fa-circle-xmark', info:'fa-circle-info' };
  t.className = 'toast ' + type;
  ic.className = 'fa-solid ' + (icons[type] || icons.info);
  m.textContent = sanitizeStr(msg, 100);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 3000);
}

// ================================================================
// SECTION 8 — CONFIRM DIALOG
// ================================================================

let _confirmResolve = null;
function showConfirm(title, msg) {
  return new Promise(resolve => {
    _confirmResolve = resolve;
    document.getElementById('confirm-title').textContent = sanitizeStr(title, 60);
    document.getElementById('confirm-msg').textContent   = sanitizeStr(msg, 200);
    document.getElementById('confirm-overlay').classList.remove('hidden');
  });
}
function confirmReply(val) {
  document.getElementById('confirm-overlay').classList.add('hidden');
  if (_confirmResolve) { _confirmResolve(val); _confirmResolve = null; }
}

// ================================================================
// SECTION 9 — NAVIGATION
// ================================================================

let currentSection = 'dashboard';
const sectionRefresh = {
  dashboard:  renderDashboard,
  caisse:     renderCaisse,
  stock:      renderStock,
  dettes:     renderDettes,
  livraisons: renderLivraisons,
  settings:   renderSettings,
};

function navTo(name) {
  if (!sectionRefresh[name]) return;
  document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('section-' + name)?.classList.add('active');

  const btns = document.querySelectorAll('.nav-btn');
  const map  = ['dashboard','caisse','stock','dettes','livraisons'];
  const idx  = map.indexOf(name);
  if (idx >= 0) btns[idx]?.classList.add('active');

  currentSection = name;
  sectionRefresh[name]();
}

function switchTab(section, tab, btn) {
  document.querySelectorAll(`[id^="${section}-tab-"]`).forEach(el => el.classList.add('hidden'));
  document.querySelectorAll(`#section-${section} .tab`).forEach(b => b.classList.remove('active'));
  document.getElementById(`${section}-tab-${tab}`)?.classList.remove('hidden');
  btn.classList.add('active');
  if (section === 'caisse') {
    rafraichirSelects();
  }
}

function fermerModal(id) {
  document.getElementById(id)?.classList.add('hidden');
}

// ================================================================
// SECTION 10 — PIN UI (clavier numérique)
// ================================================================

let pinBuffer = '';
let pinStage  = 'login'; // 'setup1' | 'setup2' | 'login'
let pinFirstEntry = '';

function buildPinPad(containerId, onKey) {
  const c = document.getElementById(containerId);
  if (!c) return;
  c.innerHTML = '';
  const layout = ['1','2','3','4','5','6','7','8','9','','0','⌫'];
  layout.forEach(k => {
    const btn = document.createElement('button');
    btn.className = 'pin-key' + (k === '' ? ' empty' : k === '⌫' ? ' del' : '');
    btn.textContent = k;
    if (k !== '') btn.addEventListener('click', () => onKey(k));
    c.appendChild(btn);
  });
}

function updateDots(dotId, len, isError = false) {
  const dots = document.querySelectorAll(`#${dotId} span`);
  dots.forEach((d, i) => {
    d.className = '';
    if (i < len) d.classList.add(isError ? 'error' : 'filled');
  });
}

// Initialiser l'écran de verrouillage
function initLockScreen() {
  const cfg = chargerConfig();
  const hasPIN = !!localStorage.getItem(KEYS.pin);

  if (!cfg || !hasPIN) {
    // Première visite : setup
    document.getElementById('step-shopname').classList.remove('hidden');
  } else {
    // Login
    const lockUntil = isLockedOut();
    if (lockUntil) {
      const secs = Math.ceil((lockUntil - Date.now()) / 1000);
      const el = document.getElementById('pin-error');
      el.textContent = `Trop de tentatives. Réessayez dans ${secs}s.`;
      el.classList.remove('hidden');
    }
    showLoginPin();
  }
}

function setupGotoPin() {
  const name = sanitizeStr(document.getElementById('setup-shop-name').value, 50);
  const owner = sanitizeStr(document.getElementById('setup-owner').value, 50);
  const thr   = sanitizeInt(document.getElementById('setup-threshold').value, 1, 999) || 5;
  if (!name) return showSetupError('Entrez le nom de votre boutique.');

  // Sauvegarde temporaire
  window._pendingConfig = { shopName: name, owner, threshold: thr };
  document.getElementById('step-shopname').classList.add('hidden');
  document.getElementById('step-create-pin').classList.remove('hidden');
  pinStage = 'setup1';
  pinBuffer = '';
  buildPinPad('create-pin-pad', handleCreatePin);
}

function showSetupError(msg) {
  showToast(msg, 'error');
}

function handleCreatePin(key) {
  if (isLockedOut()) return;
  if (key === '⌫') {
    pinBuffer = pinBuffer.slice(0, -1);
  } else if (/^\d$/.test(key) && pinBuffer.length < 4) {
    pinBuffer += key;
  }
  const subEl = document.getElementById('create-pin-sub');

  if (pinStage === 'setup1') {
    updateDots('create-pin-dots', pinBuffer.length);
    if (pinBuffer.length === 4) {
      pinFirstEntry = pinBuffer;
      pinBuffer = '';
      pinStage = 'setup2';
      subEl.textContent = 'Confirmez votre PIN';
      updateDots('create-pin-dots', 0);
    }
  } else if (pinStage === 'setup2') {
    updateDots('create-pin-dots', pinBuffer.length);
    if (pinBuffer.length === 4) {
      if (pinBuffer === pinFirstEntry) {
        finaliserSetup(pinBuffer);
      } else {
        pinBuffer = '';
        pinFirstEntry = '';
        pinStage = 'setup1';
        updateDots('create-pin-dots', 0, true);
        subEl.textContent = 'PINs différents. Recommencez.';
        setTimeout(() => { subEl.textContent = 'Choisissez un code à 4 chiffres'; }, 1500);
      }
    }
  }
}

async function finaliserSetup(pin) {
  const cfg = window._pendingConfig || { shopName: 'BoutiqueApp', owner: '', threshold: 5 };
  sauvegarderConfig(cfg);
  await savePin(pin);
  clearFailedAttempts();
  delete window._pendingConfig;
  demarrerApp();
}

function showLoginPin() {
  document.getElementById('step-login').classList.remove('hidden');
  pinBuffer = '';
  buildPinPad('login-pin-pad', handleLoginPin);
}

async function handleLoginPin(key) {
  const lockUntil = isLockedOut();
  const errorEl = document.getElementById('pin-error');

  if (lockUntil) {
    const secs = Math.ceil((lockUntil - Date.now()) / 1000);
    errorEl.textContent = `Bloqué. Réessayez dans ${secs}s.`;
    errorEl.classList.remove('hidden');
    return;
  }

  if (key === '⌫') {
    pinBuffer = pinBuffer.slice(0, -1);
  } else if (/^\d$/.test(key) && pinBuffer.length < 4) {
    pinBuffer += key;
  }

  updateDots('login-pin-dots', pinBuffer.length);

  if (pinBuffer.length === 4) {
    const ok = await verifyPin(pinBuffer);
    if (ok) {
      clearFailedAttempts();
      demarrerApp();
    } else {
      const tries = recordFailedAttempt();
      updateDots('login-pin-dots', 4, true);
      const remaining = MAX_PIN_TRIES - tries;

      if (isLockedOut()) {
        errorEl.textContent = `Trop d'erreurs. Application bloquée 5 min.`;
      } else {
        errorEl.textContent = `PIN incorrect. ${remaining} tentative${remaining > 1 ? 's' : ''} restante${remaining > 1 ? 's' : ''}.`;
      }
      errorEl.classList.remove('hidden');

      setTimeout(() => {
        pinBuffer = '';
        updateDots('login-pin-dots', 0);
      }, 800);
    }
  } else {
    errorEl.classList.add('hidden');
  }
}

function demarrerApp() {
  setSession();
  resetActivityTimer();
  document.getElementById('lock-screen').style.display = 'none';
  document.getElementById('app').classList.remove('hidden');
  const cfg = getConfig();
  document.getElementById('shop-name-header').textContent = escHtml(cfg.shopName);
  updateHeaderDate();
  setInterval(updateHeaderDate, 60000);
  navTo('dashboard');
}

function verrouillerApp() {
  invalidateSession();
  clearTimeout(activityTimer);
  document.getElementById('app').classList.add('hidden');
  document.getElementById('lock-screen').style.display = '';

  // Reset tous les champs PIN
  document.querySelectorAll('.pin-box').forEach(b => b.classList.add('hidden'));
  document.getElementById('step-login').classList.remove('hidden');
  document.getElementById('pin-error').classList.add('hidden');
  pinBuffer = '';
  buildPinPad('login-pin-pad', handleLoginPin);
  updateDots('login-pin-dots', 0);
}

function updateHeaderDate() {
  const el = document.getElementById('header-date');
  if (!el) return;
  const now = new Date();
  el.textContent = now.toLocaleDateString('fr-FR', { weekday:'short', day:'2-digit', month:'short' });
}

// ================================================================
// SECTION 11 — LOG D'ACTIVITÉ
// ================================================================

function logActivity(type, msg) {
  const logs = charger(KEYS.activity);
  logs.unshift({ type, msg: sanitizeStr(msg, 100), date: Date.now() });
  sauvegarder(KEYS.activity, logs.slice(0, 50));
}

// ================================================================
// SECTION 12 — STOCK
// ================================================================

function getStock()       { return charger(KEYS.stock); }
function saveStock(data)  { sauvegarder(KEYS.stock, data); }

function ajouterProduit() {
  const nom       = sanitizeStr(document.getElementById('prod-nom').value, LIMITS.nom_max);
  const qteRaw    = sanitizeInt(document.getElementById('prod-qte').value, 0, LIMITS.qty_max);
  const cat       = sanitizeStr(document.getElementById('prod-cat').value, 30);
  const achatRaw  = sanitizeNum(document.getElementById('prod-achat').value, 0, LIMITS.price_max);
  const venteRaw  = sanitizeNum(document.getElementById('prod-vente').value, 0, LIMITS.price_max);
  const fourn     = sanitizeStr(document.getElementById('prod-fournisseur').value, 60);
  const seuilRaw  = sanitizeInt(document.getElementById('prod-seuil').value, 1, 999);

  if (!nom)              return showToast('Nom du produit requis.', 'error');
  if (qteRaw === null)   return showToast('Quantité invalide.', 'error');
  if (venteRaw === null) return showToast('Prix de vente invalide.', 'error');
  if (achatRaw !== null && venteRaw < achatRaw) {
    if (!confirm('Prix vente < prix achat. Continuer quand même ?')) return;
  }

  const stock = getStock();
  const exist  = stock.find(p => p.nom.toLowerCase() === nom.toLowerCase());

  if (exist) {
    exist.qte   += qteRaw;
    exist.achat  = achatRaw ?? exist.achat;
    exist.vente  = venteRaw;
    exist.cat    = cat;
    exist.fourn  = fourn || exist.fourn;
    exist.seuil  = seuilRaw || exist.seuil;
    exist.updatedAt = Date.now();
    saveStock(stock);
    showToast(`Stock "${nom}" mis à jour.`);
    logActivity('stock', `Réapprovisionnement: ${nom} +${qteRaw}`);
  } else {
    stock.push({
      id: genId(), nom, qte: qteRaw,
      achat: achatRaw ?? 0, vente: venteRaw,
      cat, fourn, seuil: seuilRaw || null,
      createdAt: Date.now(), updatedAt: Date.now()
    });
    saveStock(stock);
    showToast(`"${nom}" ajouté au stock !`);
    logActivity('stock', `Nouveau produit: ${nom}`);
  }

  ['prod-nom','prod-qte','prod-achat','prod-vente','prod-fournisseur','prod-seuil']
    .forEach(id => { document.getElementById(id).value = ''; });
  document.getElementById('prod-cat').value = 'Général';
  renderStock();
  rafraichirSelects();
}

async function supprimerProduit(id) {
  const ok = await showConfirm('Supprimer le produit', 'Cette action est irréversible. Continuer ?');
  if (!ok) return;
  const stock = getStock().filter(p => p.id !== id);
  saveStock(stock);
  renderStock();
  rafraichirSelects();
  showToast('Produit supprimé.', 'error');
  logActivity('stock', `Produit supprimé`);
}

function ouvrirEditProduit(id) {
  const p = getStock().find(x => x.id === id);
  if (!p) return;
  document.getElementById('ep-id').value          = p.id;
  document.getElementById('ep-nom').value         = p.nom;
  document.getElementById('ep-qte').value         = p.qte;
  document.getElementById('ep-cat').value         = p.cat || 'Général';
  document.getElementById('ep-achat').value       = p.achat;
  document.getElementById('ep-vente').value       = p.vente;
  document.getElementById('ep-fournisseur').value = p.fourn || '';
  document.getElementById('ep-seuil').value       = p.seuil || '';
  document.getElementById('modal-prod').classList.remove('hidden');
}

function sauvegarderProduit() {
  const id   = sanitizeStr(document.getElementById('ep-id').value, 50);
  const nom  = sanitizeStr(document.getElementById('ep-nom').value, LIMITS.nom_max);
  const qte  = sanitizeInt(document.getElementById('ep-qte').value, 0, LIMITS.qty_max);
  const cat  = sanitizeStr(document.getElementById('ep-cat').value, 30);
  const ach  = sanitizeNum(document.getElementById('ep-achat').value, 0, LIMITS.price_max);
  const ven  = sanitizeNum(document.getElementById('ep-vente').value, 0, LIMITS.price_max);
  const four = sanitizeStr(document.getElementById('ep-fournisseur').value, 60);
  const seu  = sanitizeInt(document.getElementById('ep-seuil').value, 1, 999);

  if (!nom)       return showToast('Nom requis.', 'error');
  if (qte === null) return showToast('Quantité invalide.', 'error');
  if (!ven)       return showToast('Prix de vente requis.', 'error');

  const stock = getStock();
  const idx   = stock.findIndex(p => p.id === id);
  if (idx === -1) return;

  stock[idx] = { ...stock[idx], nom, qte, cat, achat: ach ?? 0, vente: ven, fourn: four, seuil: seu || null, updatedAt: Date.now() };
  saveStock(stock);
  fermerModal('modal-prod');
  renderStock();
  rafraichirSelects();
  showToast('Produit modifié !');
  logActivity('stock', `Produit modifié: ${nom}`);
}

let stockPage = 1;
function renderStock() {
  const cfg     = getConfig();
  let   stock   = getStock();
  const listEl  = document.getElementById('stock-list');
  const countEl = document.getElementById('stock-count');
  const q       = sanitizeStr(document.getElementById('search-stock')?.value || '', 60).toLowerCase();
  const cat     = document.getElementById('filter-stock-cat')?.value || '';
  const etat    = document.getElementById('filter-stock-etat')?.value || '';
  const thresh  = cfg.threshold || 5;

  if (q)    stock = stock.filter(p => p.nom.toLowerCase().includes(q));
  if (cat)  stock = stock.filter(p => (p.cat || 'Général') === cat);
  if (etat === 'low')   stock = stock.filter(p => p.qte > 0 && p.qte <= (p.seuil || thresh));
  if (etat === 'empty') stock = stock.filter(p => p.qte === 0);

  const total    = getStock().length;
  const lowCount = getStock().filter(p => p.qte <= (p.seuil || thresh)).length;
  countEl.textContent = `${total} produit${total > 1 ? 's' : ''} · ${lowCount} en alerte`;

  renderList(listEl, stock, stockPage, 'pg-stock', (page) => { stockPage = page; renderStock(); },
    p => {
      const thresh2 = p.seuil || thresh;
      const isEmpty = p.qte === 0;
      const isLow   = p.qte > 0 && p.qte <= thresh2;
      const border  = isEmpty ? 'border-red' : isLow ? 'border-orange' : 'border-green';
      const badgeCls = isEmpty ? 'badge-red' : isLow ? 'badge-orange' : 'badge-green';
      const badgeTxt = isEmpty ? '🔴 Rupture' : isLow ? `⚠️ ${p.qte}` : `✅ ${p.qte}`;
      const marge    = p.vente - (p.achat || 0);
      return `
        <div class="list-item ${border}">
          <div class="list-row">
            <div>
              <div class="list-name">${escHtml(p.nom)}</div>
              <div class="list-meta">
                ${escHtml(p.cat || 'Général')} ${p.fourn ? '· ' + escHtml(p.fourn) : ''}
                <br>Achat: ${fcfaFull(p.achat)} · Vente: ${fcfaFull(p.vente)} · Marge: ${fcfaFull(marge)}
              </div>
            </div>
            <span class="badge ${badgeCls}">${badgeTxt}</span>
          </div>
          <div class="list-actions">
            <button class="btn-edit" onclick="ouvrirEditProduit('${escHtml(p.id)}')"><i class="fa-solid fa-pen"></i> Modifier</button>
            <button class="btn-del"  onclick="supprimerProduit('${escHtml(p.id)}')"><i class="fa-solid fa-trash"></i> Suppr.</button>
          </div>
        </div>`;
    }
  );
}

// ================================================================
// SECTION 13 — CAISSE (VENTES)
// ================================================================

function getVentes()      { return charger(KEYS.ventes); }
function saveVentes(data) { sauvegarder(KEYS.ventes, data); }

function rafraichirSelects() {
  const stock = getStock().filter(p => p.qte > 0);
  ['v-produit','r-produit','c-produit'].forEach(id => {
    const sel = document.getElementById(id);
    if (!sel) return;
    sel.innerHTML = '<option value="">— Sélectionner un produit —</option>';
    stock.forEach(p => {
      const opt = document.createElement('option');
      opt.value = p.id;
      opt.dataset.prix = p.vente;
      opt.textContent = `${p.nom} (${p.qte} dispo · ${fcfaFull(p.vente)})`;
      sel.appendChild(opt);
    });
  });
  // Mise à jour select paiements partiels
  rafraichirSelectDettes();
}

function onVenteProdChange(pfx) {
  const sel = document.getElementById(`${pfx}-produit`);
  const opt = sel?.options[sel.selectedIndex];
  const prix = parseFloat(opt?.dataset?.prix || '0');
  const prixEl = document.getElementById(`${pfx}-prix`);
  if (prixEl) prixEl.value = prix || '';
  calcTotal(pfx);
  if (pfx === 'r') calcRemise();
}

function calcTotal(pfx) {
  const qte   = parseFloat(document.getElementById(`${pfx}-qte`)?.value) || 0;
  const prix  = parseFloat(document.getElementById(`${pfx}-prix`)?.value) || 0;
  const total = qte * prix;
  const el    = document.getElementById(`${pfx}-total`);
  if (el) el.textContent = `Total : ${fcfaFull(total)}`;
}

function calcRemise() {
  const qte   = parseFloat(document.getElementById('r-qte')?.value) || 0;
  const prix  = parseFloat(document.getElementById('r-prix')?.value) || 0;
  const pct   = parseFloat(document.getElementById('r-pct')?.value) || 0;
  const rFcfa = parseFloat(document.getElementById('r-fcfa')?.value) || 0;
  const sousTotal  = qte * prix;
  const remiseMtnt = pct > 0 ? (sousTotal * pct / 100) : rFcfa;
  const final      = Math.max(0, sousTotal - remiseMtnt);
  const el         = document.getElementById('r-total');
  if (el) el.textContent = `Total après remise : ${fcfaFull(final)} (remise ${fcfaFull(remiseMtnt)})`;
}

function validerVente(mode) {
  const stock = getStock();

  if (mode === 'normal') {
    const sel    = document.getElementById('v-produit');
    const prodId = sanitizeStr(sel?.value || '', 50);
    const qte    = sanitizeInt(document.getElementById('v-qte')?.value, 1, LIMITS.qty_max);
    const prix   = sanitizeNum(document.getElementById('v-prix')?.value, 0, LIMITS.price_max);
    const modePay = sanitizeStr(document.getElementById('v-mode')?.value, 30);
    const client  = sanitizeStr(document.getElementById('v-client')?.value, LIMITS.client_max);
    const note    = sanitizeStr(document.getElementById('v-note')?.value, LIMITS.note_max);

    if (!prodId)    return showToast('Sélectionnez un produit.', 'error');
    if (!qte)       return showToast('Quantité invalide.', 'error');
    if (prix === null) return showToast('Prix invalide.', 'error');
    const prod = stock.find(p => p.id === prodId);
    if (!prod)      return showToast('Produit introuvable.', 'error');
    if (prod.qte < qte) return showToast(`Stock insuffisant ! (${prod.qte} disponible${prod.qte > 1 ? 's' : ''})`, 'error');

    const total = prix * qte;
    enregistrerVente({ prodId, prodNom: prod.nom, qte, prix, total, mode: modePay, client, note, type: 'normal' });
    prod.qte -= qte;
    saveStock(stock);

    ['v-produit','v-qte','v-client','v-note'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
    document.getElementById('v-prix').value = '';
    document.getElementById('v-total').textContent = 'Total : 0 FCFA';
    document.getElementById('v-mode').value = 'Espèces';
    showToast(`Vente validée ! +${fcfaFull(total)}`);

  } else if (mode === 'remise') {
    const sel    = document.getElementById('r-produit');
    const prodId = sanitizeStr(sel?.value || '', 50);
    const qte    = sanitizeInt(document.getElementById('r-qte')?.value, 1, LIMITS.qty_max);
    const prix   = sanitizeNum(document.getElementById('r-prix')?.value, 0, LIMITS.price_max);
    const pct    = sanitizeNum(document.getElementById('r-pct')?.value, 0, 100) || 0;
    const rFcfa  = sanitizeNum(document.getElementById('r-fcfa')?.value, 0, LIMITS.price_max) || 0;
    const modePay = sanitizeStr(document.getElementById('r-mode')?.value, 30);
    const client  = sanitizeStr(document.getElementById('r-client')?.value, LIMITS.client_max);

    if (!prodId) return showToast('Sélectionnez un produit.', 'error');
    if (!qte)    return showToast('Quantité invalide.', 'error');
    if (prix === null) return showToast('Prix invalide.', 'error');
    const prod = stock.find(p => p.id === prodId);
    if (!prod)   return showToast('Produit introuvable.', 'error');
    if (prod.qte < qte) return showToast(`Stock insuffisant ! (${prod.qte} dispo)`, 'error');

    const sousTotal   = prix * qte;
    const remiseMtnt  = pct > 0 ? (sousTotal * pct / 100) : rFcfa;
    const total       = Math.max(0, sousTotal - remiseMtnt);

    enregistrerVente({ prodId, prodNom: prod.nom, qte, prix, total, remise: remiseMtnt, mode: modePay, client, type: 'remise' });
    prod.qte -= qte;
    saveStock(stock);

    ['r-produit','r-qte','r-pct','r-fcfa','r-client'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
    document.getElementById('r-prix').value = '';
    document.getElementById('r-total').textContent = 'Total après remise : 0 FCFA';
    showToast(`Vente avec remise ! +${fcfaFull(total)}`);

  } else if (mode === 'credit') {
    const sel    = document.getElementById('c-produit');
    const prodId = sanitizeStr(sel?.value || '', 50);
    const qte    = sanitizeInt(document.getElementById('c-qte')?.value, 1, LIMITS.qty_max);
    const prix   = sanitizeNum(document.getElementById('c-prix')?.value, 0, LIMITS.price_max);
    const client = sanitizeStr(document.getElementById('c-client')?.value, LIMITS.client_max);
    const tel    = sanitizeStr(document.getElementById('c-tel')?.value, 20);
    const ech    = sanitizeStr(document.getElementById('c-echeance')?.value, 20);

    if (!prodId)  return showToast('Sélectionnez un produit.', 'error');
    if (!qte)     return showToast('Quantité invalide.', 'error');
    if (prix === null) return showToast('Prix invalide.', 'error');
    if (!client)  return showToast('Nom du client requis.', 'error');
    if (!isValidDate(ech)) return showToast('Date d\'échéance invalide.', 'error');
    const prod = stock.find(p => p.id === prodId);
    if (!prod)    return showToast('Produit introuvable.', 'error');
    if (prod.qte < qte) return showToast(`Stock insuffisant ! (${prod.qte} dispo)`, 'error');

    const total = prix * qte;
    enregistrerVente({ prodId, prodNom: prod.nom, qte, prix, total, mode: 'Crédit', client, type: 'credit' });
    prod.qte -= qte;
    saveStock(stock);

    // Créer la dette automatiquement
    const dettes = getDettes();
    dettes.unshift({
      id: genId(), client, montant: total, paye: 0,
      desc: `Vente crédit: ${qte}x ${prod.nom}`,
      tel, echeance: ech || '', date: Date.now()
    });
    saveDettes(dettes);
    rafraichirSelectDettes();

    ['c-produit','c-qte','c-client','c-tel','c-echeance'].forEach(id => { const el = document.getElementById(id); if(el) el.value = ''; });
    document.getElementById('c-prix').value = '';
    document.getElementById('c-total').textContent = 'Total à crédit : 0 FCFA';
    showToast(`Vente à crédit ! Dette créée pour ${client}`);
  }

  rafraichirSelects();
  renderCaisse();
  renderDashboard();
}

function enregistrerVente(data) {
  const ventes = getVentes();
  ventes.unshift({ id: genId(), ...data, date: Date.now() });
  saveVentes(ventes);
  logActivity('vente', `Vente: ${data.qte}x ${data.prodNom} = ${fcfaFull(data.total)}`);
}

let ventesPage = 1;
function renderCaisse() {
  const ventes = getVentes();
  const today  = todayStart();
  const vAujourd = ventes.filter(v => v.date >= today);
  const totalAujourd = vAujourd.reduce((s,v) => s + v.total, 0);
  document.getElementById('caisse-today').textContent =
    `${vAujourd.length} vente${vAujourd.length > 1 ? 's' : ''} · ${fcfaFull(totalAujourd)} aujourd'hui`;

  const q      = sanitizeStr(document.getElementById('search-ventes')?.value || '', 60).toLowerCase();
  const fDate  = document.getElementById('filter-ventes-date')?.value || 'today';
  const fMode  = document.getElementById('filter-ventes-mode')?.value || '';

  let filt = ventes;
  if (fDate === 'today')  filt = filt.filter(v => v.date >= today);
  else if (fDate === 'week')   filt = filt.filter(v => v.date >= weekStart());
  else if (fDate === 'month')  filt = filt.filter(v => v.date >= monthStart());

  if (q)     filt = filt.filter(v => v.prodNom?.toLowerCase().includes(q) || v.client?.toLowerCase().includes(q));
  if (fMode) filt = filt.filter(v => v.mode === fMode);

  const listEl = document.getElementById('ventes-list');
  renderList(listEl, filt, ventesPage, 'pg-ventes', (p) => { ventesPage = p; renderCaisse(); },
    v => {
      const modeColor = { 'Espèces':'badge-green','Mobile Money':'badge-purple','Virement':'badge-blue','Crédit':'badge-orange' };
      return `
        <div class="list-item">
          <div class="list-row">
            <div>
              <div class="list-name">${escHtml(v.prodNom)}</div>
              <div class="list-meta">
                ${v.qte} × ${fcfaFull(v.prix)}
                ${v.remise ? ` · Remise: ${fcfaFull(v.remise)}` : ''}
                ${v.client ? ` · ${escHtml(v.client)}` : ''}
                <br>${fmtDate(v.date)}
                ${v.note ? ` · ${escHtml(v.note)}` : ''}
              </div>
            </div>
            <div style="text-align:right">
              <div class="badge ${modeColor[v.mode] || 'badge-gray'}">${escHtml(v.mode || 'Espèces')}</div>
              <div style="font-size:13px;font-weight:800;color:var(--green);margin-top:4px">${fcfaFull(v.total)}</div>
            </div>
          </div>
        </div>`;
    }
  );
  rafraichirSelects();
}

// ================================================================
// SECTION 14 — DETTES
// ================================================================

function getDettes()      { return charger(KEYS.dettes); }
function saveDettes(data) { sauvegarder(KEYS.dettes, data); }

function ajouterDette() {
  const client  = sanitizeStr(document.getElementById('dette-client').value, LIMITS.client_max);
  const montant = sanitizeNum(document.getElementById('dette-montant').value, 1, LIMITS.price_max);
  const ech     = sanitizeStr(document.getElementById('dette-echeance').value, 20);
  const desc    = sanitizeStr(document.getElementById('dette-desc').value, LIMITS.desc_max);
  const tel     = sanitizeStr(document.getElementById('dette-tel').value, 20);

  if (!client)         return showToast('Nom du client requis.', 'error');
  if (montant === null) return showToast('Montant invalide.', 'error');
  if (!isValidDate(ech)) return showToast('Date d\'échéance invalide.', 'error');

  const dettes = getDettes();
  dettes.unshift({ id: genId(), client, montant, paye: 0, desc, tel, echeance: ech, date: Date.now() });
  saveDettes(dettes);

  ['dette-client','dette-montant','dette-echeance','dette-desc','dette-tel']
    .forEach(id => { document.getElementById(id).value = ''; });
  showToast(`Dette de ${client} enregistrée.`);
  logActivity('dette', `Nouvelle dette: ${client} ${fcfaFull(montant)}`);
  renderDettes();
  rafraichirSelectDettes();
}

function paiementPartiel() {
  const id     = sanitizeStr(document.getElementById('paiement-select')?.value || '', 50);
  const mtnt   = sanitizeNum(document.getElementById('paiement-montant')?.value, 1, LIMITS.price_max);
  if (!id)       return showToast('Sélectionnez un client.', 'error');
  if (!mtnt)     return showToast('Montant invalide.', 'error');

  const dettes = getDettes();
  const d = dettes.find(x => x.id === id);
  if (!d) return showToast('Dette introuvable.', 'error');

  const restant = d.montant - d.paye;
  if (mtnt > restant) return showToast(`Montant > reste dû (${fcfaFull(restant)})`, 'error');

  d.paye += mtnt;
  saveDettes(dettes);
  document.getElementById('paiement-montant').value = '';
  document.getElementById('paiement-select').value  = '';
  showToast(`Paiement de ${fcfaFull(mtnt)} enregistré !`);
  logActivity('dette', `Paiement: ${d.client} ${fcfaFull(mtnt)}`);
  renderDettes();
  rafraichirSelectDettes();
}

async function supprimerDette(id) {
  const ok = await showConfirm('Supprimer la dette', 'Cette action est irréversible. Continuer ?');
  if (!ok) return;
  saveDettes(getDettes().filter(d => d.id !== id));
  renderDettes();
  rafraichirSelectDettes();
  showToast('Dette supprimée.', 'error');
}

function ouvrirEditDette(id) {
  const d = getDettes().find(x => x.id === id);
  if (!d) return;
  document.getElementById('ed-id').value      = d.id;
  document.getElementById('ed-client').value  = d.client;
  document.getElementById('ed-montant').value = d.montant;
  document.getElementById('ed-paye').value    = d.paye;
  document.getElementById('ed-desc').value    = d.desc || '';
  document.getElementById('ed-tel').value     = d.tel || '';
  document.getElementById('ed-ech').value     = d.echeance || '';
  document.getElementById('modal-dette').classList.remove('hidden');
}

function sauvegarderDette() {
  const id      = sanitizeStr(document.getElementById('ed-id').value, 50);
  const client  = sanitizeStr(document.getElementById('ed-client').value, LIMITS.client_max);
  const montant = sanitizeNum(document.getElementById('ed-montant').value, 0, LIMITS.price_max);
  const paye    = sanitizeNum(document.getElementById('ed-paye').value, 0, LIMITS.price_max);
  const desc    = sanitizeStr(document.getElementById('ed-desc').value, LIMITS.desc_max);
  const tel     = sanitizeStr(document.getElementById('ed-tel').value, 20);
  const ech     = sanitizeStr(document.getElementById('ed-ech').value, 20);

  if (!client || montant === null || paye === null) return showToast('Champs invalides.', 'error');
  if (paye > montant) return showToast('Montant payé > montant total.', 'error');

  const dettes = getDettes();
  const idx = dettes.findIndex(d => d.id === id);
  if (idx === -1) return;
  dettes[idx] = { ...dettes[idx], client, montant, paye, desc, tel, echeance: ech };
  saveDettes(dettes);
  fermerModal('modal-dette');
  renderDettes();
  rafraichirSelectDettes();
  showToast('Dette modifiée !');
}

function rafraichirSelectDettes() {
  const sel    = document.getElementById('paiement-select');
  if (!sel) return;
  const dettes = getDettes().filter(d => d.paye < d.montant);
  sel.innerHTML = '<option value="">— Client avec dette —</option>';
  dettes.forEach(d => {
    const opt = document.createElement('option');
    opt.value = d.id;
    opt.textContent = `${d.client} (reste: ${fcfaFull(d.montant - d.paye)})`;
    sel.appendChild(opt);
  });
}

let dettesPage = 1;
function renderDettes() {
  let dettes = getDettes();
  const listEl  = document.getElementById('dettes-list');
  const totalEl = document.getElementById('dettes-total');
  const now     = Date.now();

  const nonPayees   = dettes.filter(d => d.paye < d.montant);
  const totalImpaye = nonPayees.reduce((s,d) => s + (d.montant - d.paye), 0);
  totalEl.textContent = `${nonPayees.length} client${nonPayees.length > 1 ? 's' : ''} · ${fcfaFull(totalImpaye)} impayé${totalImpaye > 0 ? 's' : ''}`;

  const q    = sanitizeStr(document.getElementById('search-dettes')?.value || '', 60).toLowerCase();
  const fSt  = document.getElementById('filter-dettes-statut')?.value || '';
  const fEch = document.getElementById('filter-dettes-ech')?.value || '';

  if (q)    dettes = dettes.filter(d => d.client.toLowerCase().includes(q));
  if (fSt === 'active')  dettes = dettes.filter(d => d.paye === 0);
  if (fSt === 'partiel') dettes = dettes.filter(d => d.paye > 0 && d.paye < d.montant);
  if (fSt === 'paye')    dettes = dettes.filter(d => d.paye >= d.montant);
  if (fEch === 'overdue') dettes = dettes.filter(d => d.echeance && new Date(d.echeance) < new Date() && d.paye < d.montant);
  if (fEch === 'soon') {
    const soon = now + 3 * 24 * 60 * 60 * 1000;
    dettes = dettes.filter(d => d.echeance && new Date(d.echeance) >= new Date() && new Date(d.echeance).getTime() <= soon);
  }

  renderList(listEl, dettes, dettesPage, 'pg-dettes', (p) => { dettesPage = p; renderDettes(); },
    d => {
      const solde    = d.montant - d.paye;
      const soldee   = solde <= 0;
      const partiel  = !soldee && d.paye > 0;
      const overdue  = d.echeance && new Date(d.echeance) < new Date() && !soldee;
      const border   = soldee ? 'border-green' : overdue ? 'border-red' : partiel ? 'border-orange' : '';
      const pct      = Math.round((d.paye / d.montant) * 100);
      return `
        <div class="list-item ${border}">
          <div class="list-row">
            <div>
              <div class="list-name">${escHtml(d.client)}</div>
              <div class="list-meta">
                ${escHtml(d.desc || '—')}
                ${d.tel ? ` · ${escHtml(d.tel)}` : ''}
                <br>${fmtDate(d.date)}
                ${d.echeance ? ` · Échéance: ${d.echeance}` : ''}
              </div>
            </div>
            <div style="text-align:right">
              <span class="badge ${soldee ? 'badge-green' : overdue ? 'badge-red' : partiel ? 'badge-orange' : 'badge-gray'}">
                ${soldee ? '✅ Soldé' : overdue ? '⚠️ En retard' : partiel ? `${pct}%` : 'Impayé'}
              </span>
              <div style="font-size:12px;font-weight:700;color:var(--red);margin-top:4px">
                ${soldee ? fcfaFull(d.montant) : `Reste: ${fcfaFull(solde)}`}
              </div>
            </div>
          </div>
          ${partiel ? `<div style="background:var(--bg);border-radius:4px;height:4px;margin-top:8px"><div style="background:var(--green);height:4px;border-radius:4px;width:${pct}%"></div></div>` : ''}
          <div class="list-actions">
            <button class="btn-edit" onclick="ouvrirEditDette('${escHtml(d.id)}')"><i class="fa-solid fa-pen"></i> Modifier</button>
            <button class="btn-del"  onclick="supprimerDette('${escHtml(d.id)}')"><i class="fa-solid fa-trash"></i> Suppr.</button>
          </div>
        </div>`;
    }
  );
}

// ================================================================
// SECTION 15 — LIVRAISONS
// ================================================================

function getLivraisons()      { return charger(KEYS.livraisons); }
function saveLivraisons(data) { sauvegarder(KEYS.livraisons, data); }

function ajouterLivraison() {
  const client  = sanitizeStr(document.getElementById('livr-client').value, LIMITS.client_max);
  const tel     = sanitizeStr(document.getElementById('livr-tel').value, 20);
  const produit = sanitizeStr(document.getElementById('livr-produit').value, LIMITS.desc_max);
  const adresse = sanitizeStr(document.getElementById('livr-adresse').value, LIMITS.addr_max);
  const statut  = sanitizeStr(document.getElementById('livr-statut').value, 20);
  const montant = sanitizeNum(document.getElementById('livr-montant').value, 0, LIMITS.price_max);
  const dateP   = sanitizeStr(document.getElementById('livr-date').value, 20);
  const notes   = sanitizeStr(document.getElementById('livr-notes').value, LIMITS.note_max);

  if (!client)  return showToast('Nom du client requis.', 'error');
  if (!produit) return showToast('Produit(s) requis.', 'error');
  if (!isValidDate(dateP)) return showToast('Date invalide.', 'error');

  const livraisons = getLivraisons();
  livraisons.unshift({
    id: genId(), client, tel, produit, adresse, statut,
    montant: montant ?? 0, datePrevue: dateP, notes, date: Date.now()
  });
  saveLivraisons(livraisons);

  ['livr-client','livr-tel','livr-produit','livr-adresse','livr-montant','livr-date','livr-notes']
    .forEach(id => { document.getElementById(id).value = ''; });
  document.getElementById('livr-statut').value = 'Préparation';
  showToast('Livraison créée !');
  logActivity('livraison', `Nouvelle livraison: ${client}`);
  renderLivraisons();
}

function ouvrirEditLivraison(id) {
  const l = getLivraisons().find(x => x.id === id);
  if (!l) return;
  document.getElementById('el-id').value     = l.id;
  document.getElementById('el-statut').value = l.statut;
  document.getElementById('el-notes').value  = l.notes || '';
  document.getElementById('modal-livr').classList.remove('hidden');
}

function sauvegarderLivraison() {
  const id     = sanitizeStr(document.getElementById('el-id').value, 50);
  const statut = sanitizeStr(document.getElementById('el-statut').value, 20);
  const notes  = sanitizeStr(document.getElementById('el-notes').value, LIMITS.note_max);
  const livraisons = getLivraisons();
  const idx = livraisons.findIndex(l => l.id === id);
  if (idx === -1) return;
  livraisons[idx] = { ...livraisons[idx], statut, notes, updatedAt: Date.now() };
  saveLivraisons(livraisons);
  fermerModal('modal-livr');
  renderLivraisons();
  showToast(`Statut → ${statut}`);
  logActivity('livraison', `Livraison mise à jour: ${livraisons[idx].client} → ${statut}`);
}

async function supprimerLivraison(id) {
  const ok = await showConfirm('Supprimer la livraison', 'Cette action est irréversible. Continuer ?');
  if (!ok) return;
  saveLivraisons(getLivraisons().filter(l => l.id !== id));
  renderLivraisons();
  showToast('Livraison supprimée.', 'error');
}

const STATUT_COLORS = {
  'Préparation':'badge-blue',
  'En cours':'badge-purple',
  'Livré':'badge-green',
  'Annulé':'badge-red'
};
const STATUT_ICONS = {
  'Préparation':'📦','En cours':'🚚','Livré':'✅','Annulé':'❌'
};

let livraisonsPage = 1;
function renderLivraisons() {
  let livraisons = getLivraisons();
  const countEl = document.getElementById('livraisons-count');
  const enCours = livraisons.filter(l => ['Préparation','En cours'].includes(l.statut)).length;
  countEl.textContent = `${enCours} en cours · ${livraisons.filter(l => l.statut === 'Livré').length} livrée(s)`;

  const q    = sanitizeStr(document.getElementById('search-livr')?.value || '', 60).toLowerCase();
  const fSt  = document.getElementById('filter-livr-statut')?.value || '';
  if (q)   livraisons = livraisons.filter(l => l.client.toLowerCase().includes(q) || l.produit?.toLowerCase().includes(q));
  if (fSt) livraisons = livraisons.filter(l => l.statut === fSt);

  const listEl = document.getElementById('livraisons-list');
  renderList(listEl, livraisons, livraisonsPage, 'pg-livraisons', (p) => { livraisonsPage = p; renderLivraisons(); },
    l => `
      <div class="list-item">
        <div class="list-row">
          <div>
            <div class="list-name">${escHtml(l.client)}</div>
            <div class="list-meta">
              ${escHtml(l.produit)}
              ${l.tel ? ` · ${escHtml(l.tel)}` : ''}
              ${l.adresse ? ` · ${escHtml(l.adresse)}` : ''}
              <br>${fmtDate(l.date)}
              ${l.datePrevue ? ` · Prévue: ${l.datePrevue}` : ''}
              ${l.montant ? ` · ${fcfaFull(l.montant)}` : ''}
              ${l.notes ? `<br>📝 ${escHtml(l.notes)}` : ''}
            </div>
          </div>
          <span class="badge ${STATUT_COLORS[l.statut] || 'badge-gray'}">
            ${STATUT_ICONS[l.statut] || ''} ${escHtml(l.statut)}
          </span>
        </div>
        <div class="list-actions">
          <button class="btn-edit" onclick="ouvrirEditLivraison('${escHtml(l.id)}')"><i class="fa-solid fa-pen"></i> Modifier</button>
          <button class="btn-del"  onclick="supprimerLivraison('${escHtml(l.id)}')"><i class="fa-solid fa-trash"></i> Suppr.</button>
        </div>
      </div>`
  );
}

// ================================================================
// SECTION 16 — DASHBOARD
// ================================================================

function renderDashboard() {
  const cfg       = getConfig();
  const ventes    = getVentes();
  const stock     = getStock();
  const dettes    = getDettes();
  const livraisons = getLivraisons();
  const thresh    = cfg.threshold || 5;
  const today     = todayStart();
  const now       = new Date();

  // Salutation
  const h = now.getHours();
  const greet = h < 12 ? 'Bonjour' : h < 18 ? 'Bon après-midi' : 'Bonsoir';
  const owner = cfg.owner ? `, ${escHtml(cfg.owner)}` : '';
  document.getElementById('dashboard-greeting').innerHTML = `${greet}${owner} 👋`;

  // KPIs
  const vAujourd = ventes.filter(v => v.date >= today);
  document.getElementById('kpi-ventes').textContent    = fcfa(vAujourd.reduce((s,v) => s+v.total, 0));
  document.getElementById('kpi-stock').textContent     = stock.length;
  const nonPayeesMtnt = dettes.filter(d => d.paye < d.montant).reduce((s,d) => s + (d.montant - d.paye), 0);
  document.getElementById('kpi-dettes').textContent    = fcfa(nonPayeesMtnt);
  document.getElementById('kpi-livraisons').textContent = livraisons.filter(l => ['Préparation','En cours'].includes(l.statut)).length;

  // Alertes stock
  const lowStock = stock.filter(p => p.qte <= (p.seuil || thresh));
  const alertBox = document.getElementById('dashboard-alerts');
  const alertList = document.getElementById('alerts-list');
  if (lowStock.length > 0) {
    alertBox.classList.remove('hidden');
    alertList.innerHTML = lowStock.map(p =>
      `<div class="alert-item">
        <span>${escHtml(p.nom)}</span>
        <span class="badge ${p.qte === 0 ? 'badge-red' : 'badge-orange'}">${p.qte === 0 ? 'Rupture' : p.qte + ' restant(s)'}</span>
      </div>`
    ).join('');
  } else {
    alertBox.classList.add('hidden');
  }

  // Résumé financier du mois
  const ms = monthStart();
  const ventesMois = ventes.filter(v => v.date >= ms);
  const recettes   = ventesMois.reduce((s,v) => s + v.total, 0);
  const couts      = ventesMois.reduce((s,v) => {
    const prod = stock.find(p => p.id === v.prodId);
    return s + (v.qte * (prod?.achat || 0));
  }, 0);
  const marge = recettes - couts;
  document.getElementById('fin-recettes').textContent = fcfa(recettes);
  document.getElementById('fin-couts').textContent    = fcfa(couts);
  document.getElementById('fin-marge').textContent    = fcfa(marge);

  // Graphique 7 jours
  renderChart(ventes);

  // Activité récente
  const recent = charger(KEYS.activity).slice(0, 8);
  const recentEl = document.getElementById('dashboard-recent');
  if (!recent.length) {
    recentEl.innerHTML = '<div class="list-empty"><i class="fa-solid fa-clock"></i>Aucune activité</div>';
  } else {
    const icons = { vente:'fa-cash-register', stock:'fa-boxes-stacked', dette:'fa-file-invoice-dollar', livraison:'fa-truck' };
    recentEl.innerHTML = recent.map(a =>
      `<div class="list-item" style="padding:9px 12px">
        <div class="list-row">
          <div style="display:flex;gap:9px;align-items:center">
            <i class="fa-solid ${icons[a.type] || 'fa-circle'}" style="color:var(--primary);width:14px"></i>
            <div>
              <div class="list-name" style="font-size:12px">${escHtml(a.msg)}</div>
              <div class="list-meta">${fmtDate(a.date)}</div>
            </div>
          </div>
        </div>
      </div>`
    ).join('');
  }
}

// ================================================================
// SECTION 17 — GRAPHIQUE CANVAS (sans librairie)
// ================================================================

function renderChart(ventes) {
  const canvas = document.getElementById('chart-ventes');
  if (!canvas) return;
  const ctx    = canvas.getContext('2d');
  const W      = canvas.offsetWidth || 340;
  const H      = 150;
  canvas.width  = W;
  canvas.height = H;

  // 7 jours
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setHours(0,0,0,0); d.setDate(d.getDate() - i);
    days.push(d.getTime());
  }
  const totals = days.map(start => {
    const end = start + 86400000;
    return ventes.filter(v => v.date >= start && v.date < end).reduce((s,v) => s + v.total, 0);
  });
  const maxVal = Math.max(...totals, 1);
  const labels = days.map(ts => new Date(ts).toLocaleDateString('fr-FR', { weekday:'short' }));

  ctx.clearRect(0, 0, W, H);
  const pad = { t: 16, r: 10, b: 28, l: 10 };
  const bW   = (W - pad.l - pad.r) / 7;
  const bGap = bW * 0.25;
  const bRealW = bW - bGap;

  // Bars
  totals.forEach((val, i) => {
    const x   = pad.l + i * bW + bGap / 2;
    const bH  = ((val / maxVal) * (H - pad.t - pad.b));
    const y   = H - pad.b - bH;
    const r   = 4;

    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + bRealW - r, y);
    ctx.quadraticCurveTo(x + bRealW, y, x + bRealW, y + r);
    ctx.lineTo(x + bRealW, y + bH);
    ctx.lineTo(x, y + bH);
    ctx.lineTo(x, y + r);
    ctx.quadraticCurveTo(x, y, x + r, y);
    ctx.closePath();

    const grad = ctx.createLinearGradient(0, y, 0, y + bH);
    const today = new Date(); today.setHours(0,0,0,0);
    const isToday = days[i] === today.getTime();
    grad.addColorStop(0, isToday ? '#1A6EFF' : '#93C5FD');
    grad.addColorStop(1, isToday ? '#4A90FF' : '#BFDBFE');
    ctx.fillStyle = grad;
    ctx.fill();

    // Label jour
    ctx.fillStyle = '#64748B';
    ctx.font      = `600 9px 'Plus Jakarta Sans', sans-serif`;
    ctx.textAlign = 'center';
    ctx.fillText(labels[i], x + bRealW / 2, H - 8);

    // Valeur
    if (val > 0) {
      ctx.fillStyle = isToday ? '#1A6EFF' : '#94A3B8';
      ctx.font      = `700 8px 'Plus Jakarta Sans', sans-serif`;
      ctx.fillText(fcfa(val), x + bRealW / 2, y - 4);
    }
  });
}

// ================================================================
// SECTION 18 — PARAMÈTRES
// ================================================================

function renderSettings() {
  const cfg = getConfig();
  document.getElementById('settings-name').value      = cfg.shopName || '';
  document.getElementById('settings-owner').value     = cfg.owner || '';
  document.getElementById('settings-threshold').value = cfg.threshold || 5;
}

function sauvegarderSettings() {
  const name  = sanitizeStr(document.getElementById('settings-name').value, 50);
  const owner = sanitizeStr(document.getElementById('settings-owner').value, 50);
  const thr   = sanitizeInt(document.getElementById('settings-threshold').value, 1, 999) || 5;
  if (!name)  return showToast('Nom de boutique requis.', 'error');
  sauvegarderConfig({ shopName: name, owner, threshold: thr });
  document.getElementById('shop-name-header').textContent = escHtml(name);
  showToast('Paramètres enregistrés !');
}

async function changerPIN() {
  const oldP = sanitizeStr(document.getElementById('old-pin').value, 4);
  const newP = sanitizeStr(document.getElementById('new-pin').value, 4);
  const conf = sanitizeStr(document.getElementById('confirm-pin').value, 4);

  if (!/^\d{4}$/.test(oldP)) return showToast('Ancien PIN invalide (4 chiffres).', 'error');
  if (!/^\d{4}$/.test(newP)) return showToast('Nouveau PIN invalide (4 chiffres).', 'error');
  if (newP !== conf)          return showToast('Les nouveaux PINs ne correspondent pas.', 'error');

  const ok = await verifyPin(oldP);
  if (!ok) return showToast('Ancien PIN incorrect.', 'error');

  await savePin(newP);
  ['old-pin','new-pin','confirm-pin'].forEach(id => { document.getElementById(id).value = ''; });
  showToast('PIN changé avec succès !');
}

function exporterJSON() {
  const data = {
    version: APP_VERSION,
    exportDate: new Date().toISOString(),
    config: getConfig(),
    stock: getStock(),
    ventes: getVentes(),
    dettes: getDettes(),
    livraisons: getLivraisons(),
  };
  telecharger(JSON.stringify(data, null, 2), 'bapp_export_' + Date.now() + '.json', 'application/json');
  showToast('Export JSON téléchargé !');
}

function triggerImport() {
  document.getElementById('import-file').click();
}

function importerJSON(event) {
  const file = event.target.files?.[0];
  if (!file) return;
  if (!file.name.endsWith('.json')) return showToast('Fichier JSON requis.', 'error');
  if (file.size > 5 * 1024 * 1024) return showToast('Fichier trop volumineux (max 5 Mo).', 'error');
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const data = JSON.parse(e.target.result);
      if (!data.version || !data.stock) return showToast('Format de fichier invalide.', 'error');
      const ok = await showConfirm('Importer des données', 'Ceci remplacera toutes vos données actuelles. Continuer ?');
      if (!ok) return;
      if (Array.isArray(data.stock))      saveStock(data.stock);
      if (Array.isArray(data.ventes))     saveVentes(data.ventes);
      if (Array.isArray(data.dettes))     saveDettes(data.dettes);
      if (Array.isArray(data.livraisons)) saveLivraisons(data.livraisons);
      if (data.config) sauvegarderConfig(data.config);
      showToast('Import réussi !');
      navTo('dashboard');
    } catch {
      showToast('Fichier corrompu ou invalide.', 'error');
    }
    event.target.value = '';
  };
  reader.readAsText(file, 'UTF-8');
}

async function reinitialiserApp() {
  const ok = await showConfirm(
    '⚠️ Réinitialiser',
    'Toutes les données (ventes, stock, dettes, livraisons) seront supprimées définitivement. Êtes-vous certain ?'
  );
  if (!ok) return;
  [KEYS.stock, KEYS.ventes, KEYS.dettes, KEYS.livraisons, KEYS.activity].forEach(k => localStorage.removeItem(k));
  showToast('Données réinitialisées.', 'info');
  navTo('dashboard');
}

// ================================================================
// SECTION 19 — EXPORT CSV
// ================================================================

function exporterCSV(type) {
  let rows = [], headers = [], data = [];

  if (type === 'ventes') {
    headers = ['Date','Produit','Client','Quantité','Prix','Total','Mode','Note'];
    data    = getVentes();
    rows    = data.map(v => [fmtDate(v.date), v.prodNom, v.client||'', v.qte, v.prix, v.total, v.mode||'', v.note||'']);
  } else if (type === 'stock') {
    headers = ['Nom','Catégorie','Quantité','Prix Achat','Prix Vente','Marge','Fournisseur'];
    data    = getStock();
    rows    = data.map(p => [p.nom, p.cat||'', p.qte, p.achat, p.vente, p.vente - p.achat, p.fourn||'']);
  } else if (type === 'dettes') {
    headers = ['Client','Téléphone','Montant','Payé','Reste','Description','Échéance','Date'];
    data    = getDettes();
    rows    = data.map(d => [d.client, d.tel||'', d.montant, d.paye, d.montant - d.paye, d.desc||'', d.echeance||'', fmtDate(d.date)]);
  } else if (type === 'livraisons') {
    headers = ['Client','Téléphone','Produit','Adresse','Statut','Montant','Date prévue','Date création'];
    data    = getLivraisons();
    rows    = data.map(l => [l.client, l.tel||'', l.produit, l.adresse||'', l.statut, l.montant||0, l.datePrevue||'', fmtDate(l.date)]);
  }

  const csvContent = [headers, ...rows]
    .map(r => r.map(c => `"${String(c ?? '').replace(/"/g,'""')}"`).join(';'))
    .join('\n');

  telecharger('\uFEFF' + csvContent, `bapp_${type}_${Date.now()}.csv`, 'text/csv;charset=utf-8;');
  showToast(`Export ${type} CSV téléchargé !`);
}

function telecharger(contenu, nom, type) {
  const blob = new Blob([contenu], { type });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = nom;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); document.body.removeChild(a); }, 500);
}

// ================================================================
// SECTION 20 — PAGINATION GÉNÉRIQUE
// ================================================================

function renderList(container, items, page, pgId, onPage, renderItem) {
  if (!container) return;
  if (!items.length) {
    container.innerHTML = '<div class="list-empty"><i class="fa-solid fa-inbox"></i>Aucun résultat</div>';
    const pg = document.getElementById(pgId);
    if (pg) pg.innerHTML = '';
    return;
  }

  const totalPages = Math.ceil(items.length / PAGE_SIZE);
  const p          = Math.max(1, Math.min(page, totalPages));
  const slice      = items.slice((p - 1) * PAGE_SIZE, p * PAGE_SIZE);

  container.innerHTML = slice.map(renderItem).join('');

  const pg = document.getElementById(pgId);
  if (!pg) return;
  if (totalPages <= 1) { pg.innerHTML = ''; return; }

  let html = '';
  if (p > 1)    html += `<button class="pg-btn" onclick="(${onPage.toString()})(${p - 1})">&laquo;</button>`;
  for (let i = Math.max(1, p - 2); i <= Math.min(totalPages, p + 2); i++) {
    html += `<button class="pg-btn ${i === p ? 'active' : ''}" onclick="(${onPage.toString()})(${i})">${i}</button>`;
  }
  if (p < totalPages) html += `<button class="pg-btn" onclick="(${onPage.toString()})(${p + 1})">&raquo;</button>`;
  pg.innerHTML = html;
}

// ================================================================
// SECTION 21 — INITIALISATION
// ================================================================

document.addEventListener('DOMContentLoaded', () => {
  // Vérification session active
  if (isSessionValid() && localStorage.getItem(KEYS.pin) && chargerConfig()) {
    demarrerApp();
  } else {
    initLockScreen();
  }
});

// Fermer modal en appuyant sur Échap
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    ['modal-prod','modal-dette','modal-livr','confirm-overlay'].forEach(id => {
      document.getElementById(id)?.classList.add('hidden');
    });
  }
});
