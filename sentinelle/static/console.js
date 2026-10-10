/* Console Sentinelle — tout le comportement de la page principale.

   Plan du fichier :
     1. Petits outils (el, api)
     2. Prénom (gardé dans le navigateur)
     3. Affichage : compteurs, journal « Informations », messages du compagnon
     4. Dépôt rapide d'un mail
     5. Écran de démarrage
     6. Assistant IA (clic sur le cercle)
     7. start() : ce qui se lance à l'ouverture de la page

   RÈGLE DE SÉCURITÉ N°1 : on n'utilise JAMAIS innerHTML avec des données.
   Un nom de fichier ou une raison d'analyse peut contenir du HTML piégé
   (ex. un fichier nommé "<img src=x onerror=...>.eml"). Avec innerHTML, ce code
   s'exécuterait dans la page : c'est une faille XSS. On passe toujours par
   textContent (via la fonction el()), qui affiche le texte tel quel.

   RÈGLE N°2 : chaque requête qui modifie quelque chose envoie l'en-tête X-Sentinelle
   (protection CSRF, expliquée dans sentinelle/routes/api.py). */
"use strict";

// ==================== 1. Petits outils ====================

/** Crée un élément HTML avec un texte sûr (jamais interprété comme du HTML). */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

/** Appelle l'API et renvoie le JSON. Lève une Error avec un message lisible si ça échoue. */
async function api(path, options = {}) {
  const headers = { "X-Sentinelle": "1", ...(options.headers || {}) };
  const resp = await fetch(path, { ...options, headers });
  if (resp.status === 413) throw new Error("Fichier trop gros (2 Mo maximum).");
  let data = {};
  try { data = await resp.json(); } catch (_) { /* réponse non JSON */ }
  if (!resp.ok) throw new Error(data.error || `Erreur du serveur (${resp.status}).`);
  return data;
}

const VERDICT_LABEL = { safe: "Mail sûr", suspect: "Mail suspect", dangerous: "Mail dangereux" };

// ==================== 2. Prénom (gardé UNIQUEMENT dans ce navigateur) ====================
// Rien n'est envoyé au serveur : sur un autre PC ou un autre navigateur, l'appli
// redemandera le prénom. Le stockage peut être bloqué (navigation privée) : on
// entoure donc chaque accès d'un try/catch.

const NAME_KEY = "sentinelle-user-name";
const BOOT_FLAG = "sentinelle-boot-done";   // démarrage déjà joué dans cet onglet
const NAME_MAX_LENGTH = 40;
const NAME_RE = /^[A-Za-zÀ-ÖØ-öø-ÿ' -]+$/;   // liste blanche : lettres, espaces, tirets, apostrophes

function cleanName(raw) {
  const name = String(raw).split(/\s+/).filter(Boolean).join(" ");
  if (!name) throw new Error("Écris ton prénom.");
  if (name.length > NAME_MAX_LENGTH) throw new Error(`Prénom trop long (${NAME_MAX_LENGTH} caractères maximum).`);
  if (!NAME_RE.test(name)) throw new Error("Utilise seulement des lettres, des espaces, des tirets ou des apostrophes.");
  return name;
}

function loadName() {
  try {
    const saved = localStorage.getItem(NAME_KEY) || "";
    return saved ? cleanName(saved) : "";   // on revalide : le stockage peut être modifié à la main
  } catch (_) {
    return "";
  }
}

function saveName(name) {
  try { localStorage.setItem(NAME_KEY, name); return true; } catch (_) { return false; }
}

function forgetName() {
  try { localStorage.removeItem(NAME_KEY); sessionStorage.removeItem(BOOT_FLAG); } catch (_) { /* rien */ }
  location.reload();
}

// ==================== 3. Affichage ====================

function renderStats(counts) {
  for (const key of ["total", "safe", "suspect", "dangerous"]) {
    document.getElementById(`stat-${key}`).textContent = counts[key];
  }
}

/** Ajoute une ligne en haut du journal « Informations ». */
function addInfo(kind, title, text, details) {
  const item = el("li", kind);
  item.append(el("strong", null, title));
  if (text) item.append(el("span", null, text));
  if (details && details.length) {
    const ul = el("ul");
    for (const line of details) ul.append(el("li", null, line));
    item.append(ul);
  }
  const heure = new Date().toLocaleTimeString("fr-FR");
  item.append(el("time", null, heure));
  document.getElementById("feed").prepend(item);
}

/** Le compagnon affiche un message dans la colonne de droite. */
function say(text) {
  const chat = document.getElementById("chat");
  chat.append(el("li", "bot", text));
  chat.scrollTop = chat.scrollHeight;
}

function setBusy(busy, status) {
  document.querySelector(".col-center .orb").classList.toggle("is-busy", busy);
  document.getElementById("companion-status").textContent = status || "Prêt à analyser";
}

// ==================== 4. Dépôt rapide d'un mail ====================

async function analyzeFile(file) {
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".eml")) {
    say("Je n'accepte que les fichiers .eml. Enregistre le mail depuis ta messagerie avec « Télécharger ».");
    return;
  }
  const zone = document.getElementById("dropzone");
  zone.classList.add("is-busy");
  setBusy(true, "Analyse du mail…");

  const form = new FormData();
  form.append("eml_file", file);
  try {
    const v = await api("/api/mail", { method: "POST", body: form });
    addInfo(v.verdict, `${VERDICT_LABEL[v.verdict]} · ${v.score}/100`, v.filename, v.reasons);
    say(v.explanation);
    renderStats(v.counts);
  } catch (err) {
    addInfo("warning", "Analyse du mail impossible", err.message);
  } finally {
    zone.classList.remove("is-busy");
    setBusy(false);
  }
}

function setupDropzone() {
  const zone = document.getElementById("dropzone");
  const input = document.getElementById("eml-input");
  input.addEventListener("change", () => { analyzeFile(input.files[0]); input.value = ""; });
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("is-over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("is-over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("is-over");
    analyzeFile(e.dataTransfer.files[0]);
  });
}

// ==================== 5. Écran de démarrage ====================
// Chaque étape fait un vrai travail et affiche ce qu'elle a trouvé, avec la durée
// mesurée. Aucune attente artificielle. Si une étape échoue, elle s'affiche en rouge.

/** Ajoute une ligne au journal de démarrage et renvoie de quoi la terminer. */
function logStep(label) {
  const log = document.getElementById("boot-log");
  const item = el("li", "active");
  const line = el("div", "step-line");
  const icon = el("span", "step-icon", "◌");
  const time = el("span", "step-time");
  line.append(icon, el("span", "step-label", label), time);
  const detail = el("ul", "step-detail");
  item.append(line, detail);
  log.append(item);
  return {
    finish(state, ms, lines) {
      item.className = state;
      icon.textContent = { done: "✓", warn: "!", failed: "✗" }[state];
      time.textContent = `${ms} ms`;
      for (const l of lines) detail.append(el("li", null, l));
      log.scrollTop = log.scrollHeight;
    },
  };
}

/** Lance une étape : mesure sa durée, affiche son résultat, ne plante jamais. */
async function runStep(label, action) {
  const step = logStep(label);
  const t0 = performance.now();
  try {
    const result = await action();
    const ms = Math.round(performance.now() - t0);
    const state = result.ok === false ? "failed" : result.warn ? "warn" : "done";
    step.finish(state, ms, [result.detail, ...(result.lines || [])].filter(Boolean));
    return result;
  } catch (err) {
    step.finish("failed", Math.round(performance.now() - t0), [err.message]);
    return { ok: false, error: err.message };
  }
}

async function playBoot() {
  const steps = [
    ["Connexion au serveur local", async () => ({ ...(await api("/api/etat")), detail: "Serveur Flask joignable" })],
    ["Vérification de la base de données", () => api("/api/demarrage/base")],
    ["Auto-test du moteur d'analyse mail", () => api("/api/demarrage/moteur-mail")],
    ["Chargement du profil (stocké dans ce navigateur)", async () => {
      const name = loadName();
      return { name, warn: !name, detail: name ? `Profil trouvé : ${name}` : "Aucun profil : première visite" };
    }],
  ];
  const t0 = performance.now();
  const results = [];
  for (const [i, [label, action]] of steps.entries()) {
    results.push(await runStep(label, action));
    document.getElementById("boot-progress").style.width = `${Math.round(((i + 1) / steps.length) * 100)}%`;
  }
  const total = Math.round(performance.now() - t0);
  document.getElementById("boot-log").append(el("li", "ready", `> Système prêt en ${total} ms`));
  return { etat: results[0], name: results[3].name };
}

/** Premier démarrage : affiche le formulaire et attend un prénom valide. */
function askName() {
  const form = document.getElementById("boot-name");
  const input = document.getElementById("boot-name-input");
  const error = document.getElementById("boot-name-error");
  form.hidden = false;
  input.focus();
  return new Promise((resolve) => {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      try {
        const name = cleanName(input.value);
        saveName(name);
        resolve(name);
      } catch (err) {
        error.textContent = err.message;
      }
    });
  });
}

function showWelcome(name) {
  document.getElementById("boot-welcome-name").textContent = name;   // textContent : pas de XSS
  document.getElementById("boot-welcome").hidden = false;
  document.getElementById("boot").classList.add("is-welcome");
}

/** Compte à rebours avant d'ouvrir la console (le bouton « Entrer » l'interrompt). */
function waitForEnter(seconds) {
  const hint = document.getElementById("boot-hint");
  const skip = document.getElementById("boot-skip");
  skip.hidden = false;
  return new Promise((resolve) => {
    let left = seconds;
    hint.textContent = `Ouverture de la console dans ${left} s…`;
    const timer = setInterval(() => {
      left -= 1;
      if (left <= 0) { clearInterval(timer); resolve(); }
      else hint.textContent = `Ouverture de la console dans ${left} s…`;
    }, 1000);
    skip.addEventListener("click", () => { clearInterval(timer); resolve(); }, { once: true });
  });
}

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function hideBoot() {
  document.getElementById("boot").classList.add("is-done");
  document.getElementById("console").classList.add("is-ready");
}

// ==================== 6. Assistant IA (clic sur le cercle) ====================
// Le déroulé : le cercle tourne très vite et tout disparaît -> il ralentit ->
// « Bienvenue, prénom » -> un terminal tape la présentation.

/** Le texte du terminal. Chaque ligne : [classe CSS, texte]. */
const ASSISTANT_TEXT = [
  ["prompt", "> Je suis ton assistant IA."],
  ["", ""],
  ["", "Voici ce que Sentinelle sait faire aujourd'hui :"],
  ["ok", "  [✓] Analyser un mail : dépose un fichier .eml, je calcule un score de risque sur 100 et je t'explique pourquoi, en langage simple."],
  ["ok", "  [✓] Garder l'historique des analyses, sans jamais stocker le contenu de tes mails."],
  ["ok", "  [✓] Vérifier mon propre moteur à chaque démarrage, sur 20 mails d'essai."],
  ["soon-line", "  [ ] Surveiller les appareils de ton réseau : en construction."],
  ["soon-line", "  [ ] Répondre à tes questions : en construction."],
  ["", ""],
  ["prompt", "> Le projet"],
  ["", "Sentinelle est un compagnon de sécurité qui tourne uniquement sur ton ordinateur. Il aide un particulier ou un petit entrepreneur à repérer les mails piégés, et bientôt les appareils inconnus sur son réseau, en expliquant tout simplement."],
  ["", "Aucune donnée ne quitte ton PC."],
  ["", ""],
  ["last", "Pour le moment, je ne suis pas encore fonctionnel, mais j'espère l'être très bientôt."],
];

let assistantRun = 0;   // numéro de la séquence en cours : permet d'arrêter une séquence si on ferme

const prefersReducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Change la vitesse de rotation des anneaux SANS saut : on modifie la vitesse de lecture
    (playbackRate) des animations CSS déjà en cours, au lieu de les redémarrer. */
function setSpin(rate) {
  for (const anim of document.querySelector(".col-center .orb").getAnimations({ subtree: true })) {
    anim.playbackRate = rate;
  }
}

/** Fait passer la vitesse de `from` à `to` en douceur pendant `ms` millisecondes. */
function rampSpin(from, to, ms, run) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    const timer = setInterval(() => {   // ~60 fois par seconde
      if (run !== assistantRun) { clearInterval(timer); return resolve(); }
      const t = Math.min((performance.now() - t0) / ms, 1);
      const eased = 1 - (1 - t) ** 3;   // ralentit de plus en plus vers la fin
      setSpin(from + (to - from) * eased);
      if (t >= 1) { clearInterval(timer); resolve(); }
    }, 16);
  });
}

/** Tape le texte lettre par lettre. Le texte passe par textContent : aucun risque XSS. */
async function typeTerminal(run) {
  const screen = document.getElementById("terminal-screen");
  screen.replaceChildren();
  let instant = false;
  document.getElementById("terminal-skip").onclick = () => { instant = true; };

  for (const [cls, text] of ASSISTANT_TEXT) {
    const line = el("span", cls);
    if (screen.childNodes.length) screen.append("\n");   // retour à la ligne AVANT : le curseur reste au bout du texte
    screen.append(line);
    for (const char of text) {
      if (run !== assistantRun) return;
      line.textContent += char;
      if (!instant) await pause(14);
    }
    screen.scrollTop = screen.scrollHeight;
    if (!instant) await pause(120);
  }
  document.getElementById("terminal-skip").hidden = true;
}

async function openAssistant() {
  const body = document.body;
  if (body.classList.contains("assistant-mode")) return;
  const run = ++assistantRun;
  const still = () => run === assistantRun;
  const quick = prefersReducedMotion();
  const name = loadName();

  // 1. Tout disparaît, le cercle s'emballe
  body.classList.add("assistant-mode");
  if (!quick) {
    await rampSpin(1, 14, 400, run);
    await pause(1100);
    if (!still()) return;
  }
  body.classList.add("assistant-stage");

  // 2. Le cercle ralentit, puis « Bienvenue, prénom »
  if (!quick) await rampSpin(14, 1, 1600, run);
  if (!still()) return;
  const welcome = document.getElementById("assistant-welcome");
  document.getElementById("assistant-welcome-name").textContent = name ? `, ${name}` : "";
  welcome.hidden = false;
  void welcome.offsetWidth;   // force le navigateur à afficher l'élément avant de lancer le fondu
  welcome.classList.add("is-visible");
  await pause(quick ? 600 : 2000);
  welcome.classList.remove("is-visible");
  await pause(quick ? 0 : 600);
  if (!still()) return;
  welcome.hidden = true;

  // 3. Le terminal apparaît et tape la présentation
  body.classList.add("assistant-terminal-on");   // le cercle rétrécit d'abord…
  await pause(quick ? 0 : 700);
  if (!still()) return;
  const terminal = document.getElementById("assistant-terminal");
  document.getElementById("terminal-skip").hidden = false;
  terminal.hidden = false;
  document.getElementById("assistant-close").focus({ preventScroll: true });
  await typeTerminal(run);
}

function closeAssistant() {
  assistantRun += 1;   // arrête la séquence en cours, où qu'elle en soit
  setSpin(1);
  document.body.classList.remove("assistant-mode", "assistant-stage", "assistant-terminal-on");
  const welcome = document.getElementById("assistant-welcome");
  welcome.hidden = true;
  welcome.classList.remove("is-visible");
  document.getElementById("assistant-terminal").hidden = true;
}

function setupAssistant() {
  document.getElementById("orb-button").addEventListener("click", openAssistant);
  document.getElementById("assistant-close").addEventListener("click", closeAssistant);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && document.body.classList.contains("assistant-mode")) closeAssistant();
  });
}

// ==================== 7. Au chargement de la page ====================

async function start() {
  setupDropzone();
  setupAssistant();
  document.getElementById("forget-name").addEventListener("click", forgetName);

  let alreadyPlayed = false;
  try { alreadyPlayed = sessionStorage.getItem(BOOT_FLAG) === "1"; } catch (_) { /* rien */ }

  // Démarrage déjà vu dans cet onglet : on ouvre directement la console
  if (alreadyPlayed) {
    hideBoot();
    try {
      renderStats((await api("/api/etat")).counts);
    } catch (err) {
      addInfo("danger", "Serveur injoignable", err.message);
    }
    const name = loadName();
    say(`Je suis là${name ? `, ${name}` : ""}. Dépose un mail à gauche pour que je l'analyse.`);
    return;
  }

  document.getElementById("boot-skip").hidden = true;
  const { etat, name: savedName } = await playBoot();

  let name = savedName;
  if (name) {
    document.getElementById("boot-hint").textContent = "Système prêt.";
    await pause(1500);   // pause de lecture (pas un faux chargement)
  } else {
    name = await askName();
  }
  showWelcome(name);
  await waitForEnter(2);

  try { sessionStorage.setItem(BOOT_FLAG, "1"); } catch (_) { /* rien */ }
  hideBoot();

  if (etat.counts) renderStats(etat.counts);
  else addInfo("danger", "Serveur injoignable", "Vérifie que « python run.py » tourne toujours.");
  addInfo("info", "Système prêt", "Dépose un mail .eml pour l'analyser.");
  say(`Bonjour ${name} ! Je suis ton compagnon de sécurité.`);
  say("Dépose un mail suspect dans la zone à gauche : je te dirai s'il est dangereux, et pourquoi.");
}

document.addEventListener("DOMContentLoaded", start);
