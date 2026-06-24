'use strict';

require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieSession = require('cookie-session');
const rateLimit = require('express-rate-limit');

const dbApi = require('./db');

const app = express();

const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';
const TRUST_HTTPS = process.env.TRUST_PROXY_HTTPS === 'true';

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.randomBytes(48).toString('hex');

if (!ADMIN_PASSWORD) {
  console.warn(
    '[ATTENTION] ADMIN_PASSWORD non defini : l\'espace administrateur sera inaccessible. ' +
      'Copiez .env.example vers .env et definissez un mot de passe.'
  );
}

// ---------------------------------------------------------------------------
// Securite : en-tetes HTTP durcis (Helmet) + politique de securite de contenu.
// ---------------------------------------------------------------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        upgradeInsecureRequests: IS_PROD ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
  })
);

if (TRUST_HTTPS) {
  app.set('trust proxy', 1);
}

app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.json({ limit: '64kb' }));

app.use(
  cookieSession({
    name: 'mufid.sid',
    keys: [SESSION_SECRET],
    httpOnly: true,
    sameSite: 'strict',
    secure: TRUST_HTTPS,
    maxAge: 1000 * 60 * 60 * 8, // 8 heures
  })
);

// ---------------------------------------------------------------------------
// Protection CSRF : double jeton stocke en session, valide a chaque POST.
// ---------------------------------------------------------------------------
function ensureCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  }
  return req.session.csrfToken;
}

function verifyCsrf(req, res, next) {
  const sent = req.body && req.body._csrf;
  const expected = req.session.csrfToken;
  if (
    !expected ||
    !sent ||
    sent.length !== expected.length ||
    !crypto.timingSafeEqual(Buffer.from(sent), Buffer.from(expected))
  ) {
    return res.status(403).json({ error: 'Jeton de securite invalide. Rechargez la page.' });
  }
  return next();
}

// ---------------------------------------------------------------------------
// Limitation de debit (anti-abus / anti-bruteforce).
// ---------------------------------------------------------------------------
const submitLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Trop de soumissions. Reessayez dans une minute.' },
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Trop de tentatives de connexion. Reessayez plus tard.',
});

// ---------------------------------------------------------------------------
// Fichiers statiques (page formulaire, CSS, JS, logo).
// ---------------------------------------------------------------------------
app.use(
  '/static',
  express.static(path.join(__dirname, 'public'), {
    index: false,
    maxAge: IS_PROD ? '1h' : 0,
  })
);

// ---------------------------------------------------------------------------
// Utilitaires.
// ---------------------------------------------------------------------------
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function cleanField(value, maxLen) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, maxLen);
}

function validateSubmission(body) {
  const errors = [];
  const data = {
    nom: cleanField(body.nom, 80),
    prenom: cleanField(body.prenom, 80),
    service: cleanField(body.service, 120),
    fonction: cleanField(body.fonction, 120),
    reponse: cleanField(body.reponse, 5000),
  };

  if (data.nom.length < 2) errors.push('Le nom est requis.');
  if (data.prenom.length < 2) errors.push('Le prenom est requis.');
  if (data.service.length < 2) errors.push('Le service est requis.');
  if (data.fonction.length < 2) errors.push('La fonction est requise.');
  if (data.reponse.length < 5) errors.push('Une reponse a la question est requise.');

  return { data, errors };
}

// ---------------------------------------------------------------------------
// Routes publiques.
// ---------------------------------------------------------------------------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Fournit un jeton CSRF au formulaire cote client.
app.get('/api/init', (req, res) => {
  res.json({ csrfToken: ensureCsrfToken(req) });
});

app.post('/api/submit', submitLimiter, verifyCsrf, async (req, res) => {
  const { data, errors } = validateSubmission(req.body);
  if (errors.length) {
    return res.status(400).json({ error: errors.join(' ') });
  }

  try {
    await dbApi.addParticipation({
      ...data,
      ip: req.ip,
      user_agent: cleanField(req.get('user-agent') || '', 255),
    });
  } catch (err) {
    console.error('Erreur enregistrement :', err.message);
    return res.status(500).json({ error: 'Erreur interne. Reessayez plus tard.' });
  }

  return res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Espace administrateur.
// ---------------------------------------------------------------------------
function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect('/admin/login');
}

function safeEqual(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function renderLoginPage(error) {
  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Administration - MUFID UNION</title>
  <link rel="stylesheet" href="/static/styles.css" />
</head>
<body class="admin-body">
  <main class="admin-card">
    <div class="admin-card-hero">
      <img src="/static/mufid-union-logo.webp" alt="MUFID UNION" class="admin-logo" />
      <h1>Espace administrateur</h1>
      <p class="admin-sub">Acces reserve &mdash; campagne de sensibilisation</p>
    </div>
    ${error ? `<p class="error-box">${escapeHtml(error)}</p>` : ''}
    <form method="POST" action="/admin/login" class="admin-login-form">
      <label>Identifiant
        <input type="text" name="username" autocomplete="username" required />
      </label>
      <label>Mot de passe
        <input type="password" name="password" autocomplete="current-password" required />
      </label>
      <button type="submit">Se connecter</button>
    </form>
  </main>
</body>
</html>`;
}

app.get('/admin/login', (req, res) => {
  if (req.session.isAdmin) return res.redirect('/admin');
  res.set('Content-Type', 'text/html; charset=utf-8').send(renderLoginPage(null));
});

app.post('/admin/login', loginLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const okUser = safeEqual(username || '', ADMIN_USERNAME);
  const okPass = ADMIN_PASSWORD && safeEqual(password || '', ADMIN_PASSWORD);
  if (okUser && okPass) {
    req.session.isAdmin = true;
    return res.redirect('/admin');
  }
  return res
    .status(401)
    .set('Content-Type', 'text/html; charset=utf-8')
    .send(renderLoginPage('Identifiants incorrects.'));
});

app.post('/admin/logout', requireAdmin, (req, res) => {
  req.session = null;
  res.redirect('/admin/login');
});

app.post('/admin/delete', requireAdmin, verifyCsrf, async (req, res) => {
  const id = String((req.body && req.body.id) || '').trim();
  if (!id) {
    return res.status(400).send('Identifiant manquant.');
  }
  try {
    await dbApi.deleteParticipation(id);
  } catch (err) {
    console.error('Erreur suppression :', err.message);
    return res.status(500).send('Erreur lors de la suppression.');
  }
  return res.redirect('/admin');
});

app.get('/admin', requireAdmin, async (req, res) => {
  let rows;
  try {
    rows = await dbApi.listParticipations();
  } catch (err) {
    console.error('Erreur lecture participations :', err.message);
    return res
      .status(500)
      .set('Content-Type', 'text/html; charset=utf-8')
      .send('<p>Erreur de lecture des donnees. Reessayez plus tard.</p>');
  }
  const total = rows.length;
  const csrfToken = ensureCsrfToken(req);

  const tableRows = rows
    .map(
      (r, i) => `<tr>
      <td>${i + 1}</td>
      <td>${escapeHtml(r.nom)}</td>
      <td>${escapeHtml(r.prenom)}</td>
      <td>${escapeHtml(r.service)}</td>
      <td>${escapeHtml(r.fonction)}</td>
      <td class="reponse-cell">${escapeHtml(r.reponse)}</td>
      <td>${escapeHtml(r.cree_le)}</td>
      <td class="actions-cell">
        <form method="POST" action="/admin/delete" class="delete-form">
          <input type="hidden" name="_csrf" value="${escapeHtml(csrfToken)}" />
          <input type="hidden" name="id" value="${escapeHtml(r.id)}" />
          <button type="submit" class="btn-delete" title="Supprimer cette participation">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg>
            Supprimer
          </button>
        </form>
      </td>
    </tr>`
    )
    .join('');

  const html = `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Participants - MUFID UNION</title>
  <link rel="stylesheet" href="/static/styles.css" />
</head>
<body class="admin-body">
  <header class="admin-header">
    <div class="admin-header-left">
      <img src="/static/mufid-union-logo.webp" alt="MUFID UNION" class="admin-logo-sm" />
      <h1>Tableau des participants</h1>
    </div>
    <div class="admin-header-right">
      <a class="btn-export" href="/admin/export.csv">
        <svg class="ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        Exporter en CSV (Excel)
      </a>
      <form method="POST" action="/admin/logout" class="logout-form">
        <button type="submit" class="btn-logout">
          <svg class="ico" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
          Deconnexion
        </button>
      </form>
    </div>
  </header>
  <main class="admin-main">
    <div class="stat-card">
      <span class="stat-ico">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      </span>
      <span>
        <span class="stat-num">${total}</span>
        <span class="stat-label">participation(s) enregistree(s)</span>
      </span>
    </div>
    <div class="table-wrap">
      <table class="participants-table">
        <thead>
          <tr>
            <th>#</th><th>Nom</th><th>Prenom</th><th>Service</th>
            <th>Fonction</th><th>Reponse</th><th>Date</th><th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${tableRows || '<tr><td colspan="8" class="empty">Aucune participation pour le moment.</td></tr>'}
        </tbody>
      </table>
    </div>
  </main>
  <script src="/static/admin.js"></script>
</body>
</html>`;

  res.set('Content-Type', 'text/html; charset=utf-8').send(html);
});

function csvCell(value) {
  let s = String(value == null ? '' : value);
  // Anti-injection de formules : neutralise les cellules commencant par =, +, -, @, tab.
  if (/^[=+\-@\t\r]/.test(s)) {
    s = "'" + s;
  }
  if (/[";\n\r]/.test(s)) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

app.get('/admin/export.csv', requireAdmin, async (req, res) => {
  let rows;
  try {
    rows = await dbApi.listParticipations();
  } catch (err) {
    console.error('Erreur export CSV :', err.message);
    return res.status(500).send('Erreur de lecture des donnees.');
  }
  const header = ['ID', 'Nom', 'Prenom', 'Service', 'Fonction', 'Reponse', 'Date'];
  const lines = [header.map(csvCell).join(';')];
  for (const r of rows) {
    lines.push(
      [r.id, r.nom, r.prenom, r.service, r.fonction, r.reponse, r.cree_le]
        .map(csvCell)
        .join(';')
    );
  }
  // BOM UTF-8 pour qu'Excel affiche correctement les accents.
  const csv = '﻿' + lines.join('\r\n');
  const stamp = new Date().toISOString().slice(0, 10);
  res.set({
    'Content-Type': 'text/csv; charset=utf-8',
    'Content-Disposition': `attachment; filename="participants-mufid-${stamp}.csv"`,
  });
  res.send(csv);
});

// 404
app.use((req, res) => {
  res.status(404).send('Page introuvable.');
});

app.listen(PORT, () => {
  console.log(`MUFID UNION - sensibilisation : http://localhost:${PORT}`);
  console.log(`Espace administrateur : http://localhost:${PORT}/admin`);
});
