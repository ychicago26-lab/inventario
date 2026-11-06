const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
// Render sits in front of the app behind its own proxy; without this,
// every request looks like it comes from that proxy's IP, which would make
// the rate limiters below throttle all visitors together as one.
app.set('trust proxy', 1);
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      // blob: is required: the logo upload and the skin-tone photo both read
      // the chosen file through URL.createObjectURL, which produces a blob:
      // URL. Without it the browser blocks the image and both features fail.
      imgSrc: ["'self'", "data:", "blob:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'self'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  }
}));
// The owner's restore endpoint receives the whole database as one file,
// so it gets its own, larger limit. Everything else stays at 2mb.
app.use('/api/admin/import', express.json({ limit: '64mb' }));
app.use(express.json({ limit: '2mb' }));

// Generic limiters for the auth surface (login/register/recovery) and the
// chat endpoint, which otherwise has no cost control of its own.
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ error: 'too_many_requests' })
});
const chatLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ error: 'too_many_requests' })
});

function isTooLong(value, max) {
  return typeof value === 'string' && value.length > max;
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Signs session tokens. Falls back to a random value generated at startup
// when SESSION_SECRET isn't set, which simply means everyone is signed out
// on the next deploy or restart — a fair trade-off for needing zero setup.
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

// Phone keyboards add a space when you paste, and a space at the end of a
// password is invisible: the form looks right and the answer is just
// "wrong password". Trimming on the way in and on the way out means the
// two always agree, and nobody is locked out by something they cannot see.
// Cuatro caracteres se adivinan en minutos. Diez no es una cifra magica,
// pero saca la contraseña del alcance de quien prueba a mano y del diccionario
// corto. Solo se exige al CREAR o CAMBIAR una contraseña: al entrar no se mide
// nada, para no dejar fuera a quien ya tiene una mas corta.
const MIN_PASSWORD = 10;

function cleanPassword(v) {
  return typeof v === 'string' ? v.trim() : v;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  if (!stored || stored.indexOf(':') === -1) return false;
  const [salt, hash] = stored.split(':');
  const candidate = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(candidate, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function normalizeAnswer(s) {
  return (s || '').trim().toLowerCase();
}
function signToken(slug, userId) {
  const payload = Buffer.from(JSON.stringify({ slug, userId, exp: Date.now() + TOKEN_TTL_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verifyToken(token, slug) {
  if (!token || token.indexOf('.') === -1) return null;
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  if (sig !== expected) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (data.slug !== slug || !(data.exp > Date.now())) return null;
    return data;
  } catch (e) {
    return null;
  }
}
function getBearerToken(req) {
  const header = req.headers.authorization || '';
  return header.startsWith('Bearer ') ? header.slice(7) : null;
}
function requireAuth(req, res, next) {
  if (isReservedSlug(req.params.slug)) return res.status(404).json({ error: 'not_found' });
  const data = verifyToken(getBearerToken(req), req.params.slug);
  if (!data) return res.status(401).json({ error: 'unauthorized' });
  req.userId = data.userId;
  // A session opened before the salon was suspended must stop working too,
  // so the check happens on every request rather than only at sign-in.
  isSuspended(req.params.slug)
    .then((off) => {
      if (off) return res.status(403).json({ error: 'salon_suspended' });
      next();
    })
    .catch(next);
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS documents (
      salon_id TEXT NOT NULL,
      collection TEXT NOT NULL,
      id TEXT NOT NULL,
      data JSONB NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (salon_id, collection, id)
    );
  `);
}

function genId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

async function upsertDoc(salonId, collection, id, data) {
  await pool.query(
    `INSERT INTO documents (salon_id, collection, id, data, updated_at)
     VALUES ($1,$2,$3,$4, now())
     ON CONFLICT (salon_id, collection, id)
     DO UPDATE SET data = $4, updated_at = now()`,
    [salonId, collection, id, data]
  );
}

async function getConfig(slug) {
  const r = await pool.query(
    'SELECT data FROM documents WHERE salon_id=$1 AND collection=$2 AND id=$3',
    [slug, 'config', 'main']
  );
  return r.rows[0] ? r.rows[0].data : null;
}
async function getUsers(slug) {
  const r = await pool.query(
    'SELECT id, data FROM documents WHERE salon_id=$1 AND collection=$2 ORDER BY updated_at ASC',
    [slug, 'users']
  );
  return r.rows.map((row) => Object.assign({ id: row.id }, row.data));
}
function findUserByName(users, fullName) {
  const target = normalizeAnswer(fullName);
  return users.find((u) => normalizeAnswer(u.fullName) === target) || null;
}

/* ---- quien manda dentro de un salon ----
   La primera cuenta, la que se crea al abrir el salon, es la dueña. Las que
   entran despues con el codigo de invitacion son del equipo.

   Las cuentas creadas antes de que existieran los roles no traen el campo,
   asi que se decide por antiguedad: la mas vieja es la dueña y el resto,
   equipo. Se mira createdAt y no el orden de la tabla, porque updated_at
   cambia cada vez que alguien cambia su contraseña y eso moveria la dueña. */
function oldestUnroledId(users) {
  let oldest = null;
  for (const u of users) {
    if (u.role === 'owner' || u.role === 'staff') continue;
    if (!oldest || String(u.createdAt || '') < String(oldest.createdAt || '')) oldest = u;
  }
  return oldest ? oldest.id : null;
}
function ownerCount(users) {
  return users.filter((u) => isOwner(users, u.id)).length;
}
function isOwner(users, userId) {
  const u = users.find((x) => x.id === userId);
  if (!u) return false;
  if (u.role === 'owner') return true;
  if (u.role === 'staff') return false;
  /* Sin campo, la cuenta mas antigua de las que tampoco lo tienen es la
     dueña. Se miran solo las cuentas sin campo a proposito: si se mirara a
     todas, el dia que la consola crea una cuenta de rescate (que si trae
     el campo) la dueña de siempre perderia su lugar sin haber hecho nada. */
  return oldestUnroledId(users) === userId;
}

/* ================= email (Gmail) =================
   Sending runs through a Gmail account with an App Password, which is the
   simplest setup that does not need a verified domain. Set GMAIL_USER and
   GMAIL_APP_PASSWORD and the three messages below start going out; leave
   either unset and the app behaves exactly as before, silently skipping
   them. A failed send is never allowed to fail the request that triggered
   it: a booking is still saved even if the confirmation email bounces.

   The App Password is generated by the salon owner in their own Google
   account (Security, 2-Step Verification, App passwords) and pasted into
   Render. It is never stored in this repository or in the database. */
const nodemailer = require('nodemailer');

const GMAIL_USER = (process.env.GMAIL_USER || '').trim();
const GMAIL_APP_PASSWORD = (process.env.GMAIL_APP_PASSWORD || '').replace(/\s/g, '');
const MAIL_FROM_NAME = (process.env.MAIL_FROM_NAME || '').trim();
const mailEnabled = !!(GMAIL_USER && GMAIL_APP_PASSWORD);

let mailer = null;
if (mailEnabled) {
  mailer = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: GMAIL_USER, pass: GMAIL_APP_PASSWORD }
  });
  console.log('Email enabled, sending as', GMAIL_USER);
} else {
  console.log('Email disabled (set GMAIL_USER and GMAIL_APP_PASSWORD to turn it on)');
}

function looksLikeEmail(v) {
  return typeof v === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(v.trim());
}

// Never throws and never blocks the caller's own work.
async function sendMail(to, subject, body, fromName) {
  if (!mailer || !looksLikeEmail(to)) return { sent: false, reason: 'disabled' };
  try {
    const name = (fromName || MAIL_FROM_NAME || 'Salón').replace(/["\\\\\\r\\n]/g, '');
    await mailer.sendMail({
      from: '"' + name + '" <' + GMAIL_USER + '>',
      to: to.trim(),
      subject: subject,
      text: body
    });
    return { sent: true };
  } catch (e) {
    console.error('Email send failed:', e && e.message);
    return { sent: false, reason: 'error' };
  }
}

function fmtDateHuman(dateISO, timeHHMM) {
  if (!dateISO) return '';
  const [y, m, d] = dateISO.split('-');
  const months = ['enero','febrero','marzo','abril','mayo','junio','julio',
                  'agosto','septiembre','octubre','noviembre','diciembre'];
  const month = months[parseInt(m, 10) - 1] || m;
  return `${parseInt(d, 10)} de ${month} de ${y}` + (timeHHMM ? ` a las ${timeHHMM}` : '');
}

function salonContactLine(cfg) {
  const L = (cfg && cfg.landing) || {};
  const bits = [];
  if (L.phone) bits.push(`teléfono ${L.phone}`);
  if (L.whatsapp) bits.push(`WhatsApp ${L.whatsapp}`);
  if (L.address || L.city) bits.push([L.address, L.city].filter(Boolean).join(', '));
  return bits.length ? bits.join(' · ') : '';
}

/* ================= owner console: invitations and suspension =================
   Access to the whole application is handed out one salon at a time. Each
   invitation is a code that works exactly once: the moment a salon is
   opened with it, it is consumed, so passing it on afterwards gets nobody
   in. Suspension is the other half, and it is deliberately stored outside
   the salon's own config, in a namespace the salon has no route to, so a
   suspended salon cannot switch itself back on.

   ADMIN_PASSWORD turns the console on. Without it there is no console and
   no invitations, and the app falls back to the shared SIGNUP_CODE. */

const ADMIN_NS = '__owner__';            // reserved, never a real salon
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || '').trim();
const adminEnabled = !!ADMIN_PASSWORD;
const ADMIN_TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

// A salon slug may never reach into the reserved namespace. Anything
// starting with two underscores is refused on every per-salon route, so
// nobody can "open a salon" on top of the owner's own records.
const RESERVED_SLUGS = new Set(['admin', 'cron', 'api', 's', 'p', 'nuevo', 'healthz', 'signup-info']);
function isReservedSlug(slug) {
  if (typeof slug !== 'string' || !slug) return true;
  return slug.startsWith('__') || RESERVED_SLUGS.has(slug.toLowerCase());
}


function signAdminToken() {
  const payload = Buffer.from(JSON.stringify({ owner: true, exp: Date.now() + ADMIN_TOKEN_TTL_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verifyAdminToken(token) {
  if (!token || token.indexOf('.') === -1) return false;
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  if (sig !== expected) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return data.owner === true && data.exp > Date.now();
  } catch (e) {
    return false;
  }
}
function requireOwner(req, res, next) {
  if (!adminEnabled) return res.status(503).json({ error: 'console_not_configured' });
  if (!verifyAdminToken(getBearerToken(req))) return res.status(401).json({ error: 'unauthorized' });
  next();
}

// The document id is derived from the code itself, so looking an invitation
// up is one indexed read instead of a scan of every invitation ever issued.
function inviteId(code) {
  return crypto.createHash('sha256').update('invite:' + normalizeCode(code), 'utf8').digest('hex').slice(0, 40);
}
// Readable, unambiguous when dictated: no O, I, L, 0 or 1.
const CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
function newInviteCode() {
  const pick = () => CODE_ALPHABET[crypto.randomInt(CODE_ALPHABET.length)];
  const group = (n) => Array.from({ length: n }, pick).join('');
  return group(4) + '-' + group(4) + '-' + group(4);
}

async function getAdminDoc(collection, id) {
  const r = await pool.query(
    'SELECT data FROM documents WHERE salon_id=$1 AND collection=$2 AND id=$3',
    [ADMIN_NS, collection, id]
  );
  return r.rows[0] ? r.rows[0].data : null;
}
async function listAdminDocs(collection) {
  const r = await pool.query(
    'SELECT id, data FROM documents WHERE salon_id=$1 AND collection=$2 ORDER BY updated_at DESC',
    [ADMIN_NS, collection]
  );
  return r.rows.map((row) => Object.assign({ id: row.id }, row.data));
}

function inviteState(inv) {
  if (!inv) return 'missing';
  if (inv.revokedAt) return 'revoked';
  if (inv.usedAt) return 'used';
  if (inv.expiresAt && inv.expiresAt < new Date().toISOString().slice(0, 10)) return 'expired';
  return 'open';
}

/* Claims an invitation for one salon, or explains why it cannot.
   The claim is a single conditional UPDATE, so if two people race with the
   same code the database lets exactly one of them through. */
async function claimInvite(code, slug, salonName) {
  const id = inviteId(code);
  const inv = await getAdminDoc('invites', id);
  const state = inviteState(inv);
  if (state !== 'open') return { ok: false, reason: state };

  const r = await pool.query(
    `UPDATE documents
        SET data = data || jsonb_build_object(
              'usedAt', $3::text, 'usedBySlug', $4::text, 'usedByName', $5::text),
            updated_at = now()
      WHERE salon_id = $1 AND collection = 'invites' AND id = $2
        AND COALESCE(data->>'usedAt', '') = ''
        AND COALESCE(data->>'revokedAt', '') = ''`,
    [ADMIN_NS, id, new Date().toISOString(), slug, salonName || '']
  );
  if (!r.rowCount) return { ok: false, reason: 'used' };
  return { ok: true, id };
}
// Only used when a salon fails to be created after its invitation was
// claimed, so a code is never burned for a salon that does not exist.
async function releaseInvite(id) {
  await pool.query(
    `UPDATE documents
        SET data = data - 'usedAt' - 'usedBySlug' - 'usedByName', updated_at = now()
      WHERE salon_id = $1 AND collection = 'invites' AND id = $2`,
    [ADMIN_NS, id]
  );
}

// Suspension lives here, not in the salon's config, so the salon has no
// route that can reach it.
async function isSuspended(slug) {
  const rec = await getAdminDoc('salons', slug);
  return !!(rec && rec.suspended);
}
async function recordSalon(slug, patch) {
  const existing = (await getAdminDoc('salons', slug)) || {};
  await upsertDoc(ADMIN_NS, 'salons', slug, Object.assign({}, existing, patch));
}

// ---- opening a new salon ----
// SIGNUP_CODE turns this from an open sign-up into an invitation-only one:
// when it is set, creating a brand-new salon requires that exact code.
// Leaving it unset keeps the old behaviour, where anyone with the address
// can open their own salon. It never affects salons that already exist.
const SIGNUP_CODE = (process.env.SIGNUP_CODE || '').trim();

// Lets the welcome screen know whether to ask for a code, without ever
// revealing the code itself.
app.get('/api/signup-info', (req, res) => {
  res.json({ codeRequired: !!SIGNUP_CODE });
});

// Forgives how a code was typed, not what it is. Upper-cases it and drops
// spaces and hyphens, because phone keyboards often don't auto-capitalise
// this kind of field and a pasted code tends to carry a stray space. The
// code itself is unchanged; only the comparison is tolerant.
function normalizeCode(v) {
  return String(v == null ? '' : v).toUpperCase().replace(/[\s\u00A0-]/g, '');
}

// Constant time whatever the two lengths are: comparing digests means
// neither the content nor the length of the real code leaks from how long
// the answer takes.
function codesMatch(given, expected) {
  if (typeof given !== 'string' || typeof expected !== 'string') return false;
  if (given.length > 200) return false;

  let a = normalizeCode(given);
  let b = normalizeCode(expected);
  // A code written only with punctuation would normalise to nothing, and
  // an empty answer must never be accepted, so compare it exactly instead.
  if (!b) { a = given.trim(); b = expected.trim(); }
  if (!a || !b) return false;

  const ha = crypto.createHash('sha256').update(a, 'utf8').digest();
  const hb = crypto.createHash('sha256').update(b, 'utf8').digest();
  return crypto.timingSafeEqual(ha, hb);
}

/* Decides whether a brand-new salon may be opened.
   An invitation is tried first and consumed if it matches. The shared
   SIGNUP_CODE stays as a fallback so nothing breaks while moving over, but
   once invitations are in use it should be removed from the environment:
   a shared code can be passed on, which is the whole thing invitations
   exist to prevent. */
async function signupAccess(body, slug, salonName) {
  const given = ((body && body.signupCode) || '').toString();

  if (adminEnabled && given.trim()) {
    const claim = await claimInvite(given, slug, salonName);
    if (claim.ok) return { ok: true, inviteId: claim.id };
    // Not an invitation at all: fall through and let the shared code try.
    if (claim.reason !== 'missing') {
      return { ok: false, reason: claim.reason };
    }
  }

  if (SIGNUP_CODE) {
    return codesMatch(given, SIGNUP_CODE)
      ? { ok: true }
      : { ok: false, reason: 'missing' };
  }
  // No gate configured at all. A brand-new installation has to let the
  // first salon in somehow, so that one is allowed. After that the door
  // closes by itself: leaving sign-up open to the whole internet is never
  // what someone wants, and it would otherwise happen silently if the
  // shared code were removed before the console password was set.
  if (!adminEnabled) {
    const any = await pool.query(
      `SELECT 1 FROM documents WHERE collection='config' AND id='main' AND salon_id <> $1 LIMIT 1`,
      [ADMIN_NS]
    );
    if (!any.rowCount) return { ok: true };
    return { ok: false, reason: 'no_gate' };
  }
  return { ok: false, reason: 'missing' };
}

/* ================= owner console API =================
   Everything here is the owner's, not a salon's. It never exposes a
   salon's inventory, clients or agenda: only who exists, when they were
   let in and whether they are switched on. */

app.get('/api/admin/status', (req, res) => {
  res.json({ enabled: adminEnabled });
});

app.post('/api/admin/login', authLimiter, (req, res) => {
  if (!adminEnabled) return res.status(503).json({ error: 'console_not_configured' });
  const given = cleanPassword(((req.body && req.body.password) || '').toString());
  if (!given || given.length > 300) return res.status(401).json({ error: 'invalid_password' });
  const a = crypto.createHash('sha256').update(given, 'utf8').digest();
  const b = crypto.createHash('sha256').update(ADMIN_PASSWORD, 'utf8').digest();
  if (!crypto.timingSafeEqual(a, b)) return res.status(401).json({ error: 'invalid_password' });
  res.json({ token: signAdminToken() });
});

app.get('/api/admin/overview', requireOwner, async (req, res) => {
  try {
    const invites = await listAdminDocs('invites');
    const live = new Set(
      (await pool.query(`SELECT salon_id FROM documents WHERE collection='config' AND id='main'`))
        .rows.map((r) => r.salon_id)
    );
    // A record left behind by a salon that no longer exists would otherwise
    // show as a ghost row the owner can neither open nor remove.
    const salons = (await listAdminDocs('salons')).filter((x) => live.has(x.id));

    // Salons opened before the console existed have no record yet; show
    // them anyway so nothing is invisible to the owner.
    const known = new Set(salons.map((x) => x.id));
    const all = await pool.query(
      `SELECT salon_id, data->>'name' AS name FROM documents
        WHERE collection='config' AND id='main' AND salon_id <> $1`,
      [ADMIN_NS]
    );
    const extra = all.rows
      .filter((r) => !known.has(r.salon_id))
      .map((r) => ({ id: r.salon_id, name: r.name || '', suspended: false, createdAt: null, legacy: true }));

    const counts = await pool.query(
      `SELECT salon_id, collection, count(*)::int AS n FROM documents
        WHERE salon_id <> $1 GROUP BY salon_id, collection`,
      [ADMIN_NS]
    );
    const byId = {};
    counts.rows.forEach((r) => {
      byId[r.salon_id] = byId[r.salon_id] || {};
      byId[r.salon_id][r.collection] = r.n;
    });

    res.json({
      invites: invites.map((i) => Object.assign({}, i, { state: inviteState(i) })),
      salons: salons.concat(extra).map((sal) =>
        Object.assign({}, sal, { counts: byId[sal.id] || {} })
      )
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/invites', requireOwner, async (req, res) => {
  try {
    const { label, note, expiresAt } = req.body || {};
    if (isTooLong(label, 160) || isTooLong(note, 400) || isTooLong(expiresAt, 20)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    const code = newInviteCode();
    const id = inviteId(code);
    await upsertDoc(ADMIN_NS, 'invites', id, {
      code,
      label: (label || '').trim(),
      note: (note || '').trim(),
      expiresAt: (expiresAt || '').trim(),
      createdAt: new Date().toISOString(),
      usedAt: null,
      usedBySlug: null,
      usedByName: null,
      revokedAt: null
    });
    res.json({ id, code });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// Revoking only stops an unused invitation. A salon already opened with it
// is untouched: closing that one down is what suspension is for.
app.post('/api/admin/invites/:id/revoke', requireOwner, async (req, res) => {
  try {
    const inv = await getAdminDoc('invites', req.params.id);
    if (!inv) return res.status(404).json({ error: 'not_found' });
    if (inv.usedAt) return res.status(409).json({ error: 'already_used' });
    await upsertDoc(ADMIN_NS, 'invites', req.params.id,
      Object.assign({}, inv, { revokedAt: new Date().toISOString() }));
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.delete('/api/admin/invites/:id', requireOwner, async (req, res) => {
  try {
    await pool.query(
      'DELETE FROM documents WHERE salon_id=$1 AND collection=$2 AND id=$3',
      [ADMIN_NS, 'invites', req.params.id]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

/* ---------- backup and restore ----------
   The whole database as one JSON file the owner can keep. It exists so
   the data is never tied to one hosting provider: export here, point
   DATABASE_URL somewhere else, import there, and nothing is lost. It is
   also the only backup a free database plan gives you.

   Owner-only, like everything else in this section. */
app.get('/api/admin/export', requireOwner, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT salon_id, collection, id, data, updated_at FROM documents ORDER BY salon_id, collection, id'
    );
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="inventario-copia-${stamp}.json"`);
    res.send(JSON.stringify({
      format: 'inventario-backup',
      version: 1,
      exportedAt: new Date().toISOString(),
      count: r.rows.length,
      documents: r.rows
    }));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

/* Sends the same backup as an email attachment.
   Downloading a file is awkward on a phone and on iOS often just opens the
   JSON in a tab instead of saving it. Mailing it to yourself always works,
   and it puts the copy somewhere that is not the phone, which is what a
   backup is for. */
/* Arma la copia completa y la manda por correo. La usan dos sitios: el
   boton de la consola y el trabajo semanal pegado a los recordatorios.
   Devuelve cuantos registros llevaba, o lanza si algo falla, para que cada
   quien decida que hacer con el fallo. */
async function enviarCopiaPorCorreo(destino) {
  const to = (destino || GMAIL_USER || '').toString().trim();
  if (!looksLikeEmail(to)) {
    const e = new Error('invalid_email');
    e.code = 'invalid_email';
    throw e;
  }

  const r = await pool.query(
    'SELECT salon_id, collection, id, data, updated_at FROM documents ORDER BY salon_id, collection, id'
  );
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
  const contenido = JSON.stringify({
    format: 'inventario-backup',
    version: 1,
    exportedAt: new Date().toISOString(),
    count: r.rows.length,
    documents: r.rows
  });

  const salones = new Set(r.rows.map((x) => x.salon_id).filter((x) => x !== ADMIN_NS));
  await mailer.sendMail({
    from: '"' + (MAIL_FROM_NAME || 'Inventario').replace(/["\\\r\n]/g, '') + '" <' + GMAIL_USER + '>',
    to,
    subject: `Copia de seguridad — ${r.rows.length} registros`,
    text:
      `Adjunta va la copia de seguridad completa de la aplicación.\n\n` +
      `Registros: ${r.rows.length}\n` +
      `Salones: ${salones.size}\n` +
      `Fecha: ${new Date().toLocaleString('es')}\n\n` +
      `Guarda este correo. Para restaurar, entra a la consola, pulsa ` +
      `"Restaurar desde un archivo" y elige el archivo adjunto.`,
    attachments: [{
      filename: `inventario-copia-${stamp}.json`,
      content: contenido,
      contentType: 'application/json'
    }]
  });

  return { to, count: r.rows.length };
}

app.post('/api/admin/email-backup', requireOwner, async (req, res) => {
  try {
    if (!mailEnabled) return res.status(503).json({ error: 'mail_not_configured' });
    const hecho = await enviarCopiaPorCorreo((req.body && req.body.to) || '');
    res.json({ ok: true, to: hecho.to, count: hecho.count });
  } catch (e) {
    if (e && e.code === 'invalid_email') return res.status(400).json({ error: 'invalid_email' });
    console.error('Backup email failed:', e && e.message);
    res.status(502).json({ error: 'send_failed' });
  }
});

/* La copia semanal viaja pegada al trabajo diario de recordatorios, que ya
   existe y ya funciona. Asi no hace falta montar un segundo trabajo ni
   guardar otra contraseña en ningun sitio.

   No se mira si hoy es domingo sino cuanto hace de la ultima: si el dia que
   tocaba el servicio estaba caido, la copia sale al dia siguiente en vez de
   perderse una semana entera. Y como queda anotada, ejecutar el trabajo
   varias veces el mismo dia no manda varias copias. */
const DIAS_ENTRE_COPIAS = 7;
async function copiaSemanalSiTocaba() {
  if (!mailEnabled) return { hecha: false, motivo: 'sin_correo' };
  try {
    const marca = await getAdminDoc('meta', 'backup');
    const ultima = marca && marca.lastAt ? Date.parse(marca.lastAt) : NaN;
    const dias = Number.isFinite(ultima) ? (Date.now() - ultima) / 86400000 : Infinity;
    if (dias < DIAS_ENTRE_COPIAS) return { hecha: false, motivo: 'reciente' };

    const hecho = await enviarCopiaPorCorreo('');
    // Se anota despues de enviar: si el envio falla, la proxima vuelta lo
    // reintenta en vez de dar por hecha una copia que nunca salio.
    await upsertDoc(ADMIN_NS, 'meta', 'backup', {
      lastAt: new Date().toISOString(),
      count: hecho.count
    });
    return { hecha: true, count: hecho.count };
  } catch (e) {
    // Nunca estropea los recordatorios: son lo que esperan las clientas.
    console.error('Weekly backup failed:', e && e.message);
    return { hecha: false, motivo: 'fallo' };
  }
}

// Restoring writes each row back by its own key, so running it twice does
// nothing the second time and it can be pointed at an empty database or at
// one that already holds some of the same records.
app.post('/api/admin/import', requireOwner, async (req, res) => {
  try {
    const body = req.body || {};
    if (body.format !== 'inventario-backup' || !Array.isArray(body.documents)) {
      return res.status(400).json({ error: 'not_a_backup' });
    }
    if (body.documents.length > 100000) {
      return res.status(413).json({ error: 'too_large' });
    }

    let written = 0, skipped = 0;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const row of body.documents) {
        if (!row || typeof row.salon_id !== 'string' || typeof row.collection !== 'string' ||
            typeof row.id !== 'string' || row.data === null || typeof row.data !== 'object') {
          skipped++;
          continue;
        }
        await client.query(
          `INSERT INTO documents (salon_id, collection, id, data, updated_at)
           VALUES ($1,$2,$3,$4, COALESCE($5::timestamptz, now()))
           ON CONFLICT (salon_id, collection, id)
           DO UPDATE SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at`,
          [row.salon_id, row.collection, row.id, row.data, row.updated_at || null]
        );
        written++;
      }
      await client.query('COMMIT');
    } catch (e) {
      await client.query('ROLLBACK');
      throw e;
    } finally {
      client.release();
    }

    res.json({ ok: true, written, skipped });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

/* Gives a salon a fresh code so somebody can get back in.
   Passwords are hashed and cannot be read or handed back, not even by the
   owner of the installation, so recovery works the other way round: this
   sets a new invite code on that salon, and whoever has it can create a
   new named account there from the salon's own sign-in screen.

   It never opens an existing account and never hides itself. The new
   account shows up in that salon's team list like any other, so the salon
   can see that someone was let in. Use it when a salon asks for help, or
   to get back into your own. */
app.post('/api/admin/salons/:slug/recovery-code', requireOwner, async (req, res) => {
  try {
    const slug = req.params.slug;
    if (isReservedSlug(slug)) return res.status(404).json({ error: 'not_found' });
    const cfg = await getConfig(slug);
    if (!cfg) return res.status(404).json({ error: 'not_found' });

    const code = newInviteCode();
    await upsertDoc(slug, 'config', 'main', Object.assign({}, cfg, { inviteCode: code }));
    res.json({ ok: true, code, signInUrl: `/s/${slug}` });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

/* Creates a ready-made account in a salon and shows its name and password
   once. The short way round the same problem the recovery code solves:
   instead of handing over a code and asking someone to fill in a form,
   the account already exists and they just sign in.

   The password is generated here and returned once, never stored in the
   clear: what the database keeps is the same hash as any other account.
   The account appears in that salon's team list like any other, so access
   can never be granted invisibly.

   There is no way back into an existing account, by design. Passwords are
   hashed and this does not change anyone else's. */
app.post('/api/admin/salons/:slug/access-account', requireOwner, async (req, res) => {
  try {
    const slug = req.params.slug;
    if (isReservedSlug(slug)) return res.status(404).json({ error: 'not_found' });
    const cfg = await getConfig(slug);
    if (!cfg) return res.status(404).json({ error: 'not_found' });

    const users = await getUsers(slug);
    let name = ((req.body && req.body.fullName) || 'Acceso').toString().trim().slice(0, 100) || 'Acceso';
    if (findUserByName(users, name)) {
      // Never silently take over a name that already exists.
      let n = 2;
      while (findUserByName(users, name + ' ' + n) && n < 100) n++;
      name = name + ' ' + n;
    }

    const password = newInviteCode(); // readable, unambiguous when dictated
    const id = genId();
    await upsertDoc(slug, 'users', id, {
      fullName: name,
      // Entra como dueña a proposito: se crea desde la consola con la
      // contraseña de administracion, y existe justamente para destrabar
      // un salon. Una cuenta de equipo no podria hacerlo.
      role: 'owner',
      passwordHash: hashPassword(password),
      recoveryQuestion: '',
      // Unguessable on purpose: this account has no recovery answer until
      // its owner sets one. Losing it is not a dead end, because this
      // button can always make another.
      recoveryAnswerHash: hashPassword(crypto.randomBytes(32).toString('hex')),
      createdAt: new Date().toISOString(),
      createdByOwner: true
    });

    res.json({ ok: true, fullName: name, password, signInUrl: `/s/${slug}` });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

/* Permanently removes one salon and everything in it. Suspension is the
   reversible option and should be the usual one; this exists for salons
   that were never really used, abandoned sign-ups and leftovers from
   testing. The caller has to repeat the salon's own slug back, so a
   mis-click cannot wipe a working salon. */
app.delete('/api/admin/salons/:slug', requireOwner, async (req, res) => {
  try {
    const slug = req.params.slug;
    if (isReservedSlug(slug)) return res.status(404).json({ error: 'not_found' });
    if (((req.body && req.body.confirm) || '') !== slug) {
      return res.status(400).json({ error: 'confirm_mismatch' });
    }
    const cfg = await getConfig(slug);
    if (!cfg) return res.status(404).json({ error: 'not_found' });

    const r = await pool.query('DELETE FROM documents WHERE salon_id = $1', [slug]);
    await pool.query(
      'DELETE FROM documents WHERE salon_id = $1 AND collection = $2 AND id = $3',
      [ADMIN_NS, 'salons', slug]
    );
    // The invitation it came from is left alone on purpose: the record of
    // who was given access, and when, outlives the salon itself.
    res.json({ ok: true, removed: r.rowCount });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/admin/salons/:slug/suspend', requireOwner, async (req, res) => {
  try {
    const slug = req.params.slug;
    if (isReservedSlug(slug)) return res.status(404).json({ error: 'not_found' });
    const cfg = await getConfig(slug);
    if (!cfg) return res.status(404).json({ error: 'not_found' });

    const suspended = !!(req.body && req.body.suspended);
    const note = ((req.body && req.body.note) || '').toString().slice(0, 400);
    await recordSalon(slug, {
      name: cfg.name || '',
      suspended,
      note,
      suspendedAt: suspended ? new Date().toISOString() : null
    });
    res.json({ ok: true, suspended });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- access: public lookup, per-user accounts, login, recovery ----
// Minimal, unauthenticated: just enough for the login screen to know which
// form to show, without exposing anything else.
app.get('/api/:slug/public', async (req, res) => {
  try {
    const slug = req.params.slug;
    const cfg = await getConfig(slug);
    if (!cfg) return res.json({ exists: false });
    if (await isSuspended(slug)) return res.json({ exists: true, suspended: true, name: cfg.name });
    const users = await getUsers(slug);
    res.json({
      exists: true,
      name: cfg.name,
      language: cfg.language,
      logoUrl: cfg.logoUrl || null,
      hasUsers: users.length > 0,
      legacyPassword: !users.length && !!cfg.passwordHash
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// Public landing data for one salon. Explicitly whitelisted: only the
// fields the salon chose to publish ever leave this endpoint, so adding a
// private field to the config later can never leak it by accident.
const LANDING_TEXT_FIELDS = [
  'tagline', 'heroTitle', 'heroText', 'about', 'servicesIntro',
  'experienceTitle', 'experienceText', 'coursesTitle', 'coursesText',
  'phone', 'whatsapp', 'email', 'email2', 'city', 'address',
  'instagram', 'hours', 'footerNote'
];
app.get('/api/:slug/landing', async (req, res) => {
  try {
    const cfg = await getConfig(req.params.slug);
    if (!cfg) return res.status(404).json({ error: 'not_found' });
    // A suspended salon's page goes quiet rather than announcing why.
    if (await isSuspended(req.params.slug)) return res.status(404).json({ error: 'not_found' });
    const src = cfg.landing || {};
    /* Apagar la portada en Ajustes tiene que apagarla de verdad. Antes se
       seguian enviando el telefono, la direccion y el correo del salon, y
       era la pagina la que decidia no pintarlos: quien pidiera esta
       direccion a mano los veia igual. */
    if (src.enabled === false) return res.status(404).json({ error: 'not_found' });
    const landing = {};
    LANDING_TEXT_FIELDS.forEach((k) => {
      landing[k] = typeof src[k] === 'string' ? src[k] : '';
    });
    landing.enabled = src.enabled !== false;
    landing.showGallery = src.showGallery !== false;
    landing.showBooking = src.showBooking !== false;
    landing.showChat = src.showChat !== false;
    res.json({
      name: cfg.name || '',
      logoUrl: cfg.logoUrl || null,
      language: cfg.language || 'es',
      services: Array.isArray(cfg.services) ? cfg.services.slice(0, 60) : [],
      servicesNote: typeof cfg.servicesNote === 'string' ? cfg.servicesNote : '',
      landing: landing
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// Creates a user account. Three cases:
//  - brand-new salon (no users yet, no legacy password): anyone can create
//    the first account (this is the owner, right after onboarding).
//  - legacy salon (no users yet, but has an old shared passwordHash): must
//    prove the old password once, then this becomes the first named user.
//  - salon that already has users: needs either a valid session (an
//    already-signed-in user adding a teammate from Settings) or the
//    salon's own invite code, which the owner sets in Settings and shares
//    directly with trusted staff. No code set means registration is closed
//    to anyone not already signed in.
app.post('/api/:slug/register', authLimiter, async (req, res) => {
  try {
    const slug = req.params.slug;
    if (await isSuspended(slug)) return res.status(403).json({ error: 'salon_suspended' });
    let { fullName, password, recoveryQuestion, recoveryAnswer, oldPassword, inviteCode } = req.body || {};
    password = cleanPassword(password);
    oldPassword = cleanPassword(oldPassword);
    if (!fullName || !fullName.trim() || !password || password.length < MIN_PASSWORD || !recoveryQuestion || !recoveryAnswer) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    if (isTooLong(fullName, 120) || isTooLong(password, 200) || isTooLong(recoveryQuestion, 300) || isTooLong(recoveryAnswer, 300) || isTooLong(oldPassword, 200) || isTooLong(inviteCode, 100)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    const users = await getUsers(slug);
    if (users.length === 0) {
      const cfg = await getConfig(slug);
      if (cfg && cfg.passwordHash) {
        if (!oldPassword || !verifyPassword(oldPassword, cfg.passwordHash)) {
          return res.status(401).json({ error: 'invalid_password' });
        }
      }
    } else {
      const cfg = await getConfig(slug);
      const validInvite = !!(cfg && cfg.inviteCode && codesMatch(inviteCode || '', cfg.inviteCode));
      if (!validInvite) {
        const authData = verifyToken(getBearerToken(req), slug);
        if (!authData) return res.status(401).json({ error: 'unauthorized' });
        // Agregar a alguien a mano desde Ajustes es cosa de la dueña. Sin
        // esto, una empleada podria abrir cuentas sin saber el codigo.
        if (!isOwner(users, authData.userId)) return res.status(403).json({ error: 'owner_only' });
      }
    }
    if (findUserByName(users, fullName)) {
      return res.status(409).json({ error: 'name_taken' });
    }
    const id = genId();
    await upsertDoc(slug, 'users', id, {
      fullName: fullName.trim(),
      role: users.length === 0 ? 'owner' : 'staff',
      passwordHash: hashPassword(password),
      recoveryQuestion: recoveryQuestion.trim(),
      recoveryAnswerHash: hashPassword(normalizeAnswer(recoveryAnswer)),
      createdAt: new Date().toISOString()
    });
    res.json({ id, token: signToken(slug, id) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/:slug/login', authLimiter, async (req, res) => {
  try {
    const slug = req.params.slug;
    let { fullName, password } = req.body || {};
    password = cleanPassword(password);
    if (!fullName || !password || isTooLong(fullName, 120) || isTooLong(password, 200)) {
      return res.status(401).json({ error: 'invalid_password' });
    }
    if (await isSuspended(slug)) return res.status(403).json({ error: 'salon_suspended' });
    const users = await getUsers(slug);
    const user = findUserByName(users, fullName);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      return res.status(401).json({ error: 'invalid_password' });
    }
    res.json({ token: signToken(slug, user.id) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/:slug/forgot-password/start', authLimiter, async (req, res) => {
  try {
    const slug = req.params.slug;
    const { fullName } = req.body || {};
    if (!fullName || isTooLong(fullName, 120)) return res.status(404).json({ error: 'user_not_found' });
    const users = await getUsers(slug);
    const user = findUserByName(users, fullName);
    if (!user) return res.status(404).json({ error: 'user_not_found' });
    res.json({ question: user.recoveryQuestion });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/:slug/forgot-password/reset', authLimiter, async (req, res) => {
  try {
    const slug = req.params.slug;
    let { fullName, answer, newPassword } = req.body || {};
    newPassword = cleanPassword(newPassword);
    if (!newPassword || newPassword.length < MIN_PASSWORD) return res.status(400).json({ error: 'invalid_request' });
    if (isTooLong(fullName, 120) || isTooLong(answer, 300) || isTooLong(newPassword, 200)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    const users = await getUsers(slug);
    const user = findUserByName(users, fullName);
    if (!user || !verifyPassword(normalizeAnswer(answer), user.recoveryAnswerHash)) {
      return res.status(401).json({ error: 'invalid_answer' });
    }
    user.passwordHash = hashPassword(newPassword);
    await upsertDoc(slug, 'users', user.id, user);
    res.json({ token: signToken(slug, user.id) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// La respuesta de recuperacion es una segunda contraseña: quien la acierta
// cambia la clave y entra, sin pasar por el correo. Hasta ahora se fijaba al
// crear la cuenta y ya no habia forma de tocarla, asi que una respuesta
// adivinable -- el nombre de la mascota, el de la primera clienta -- quedaba
// ahi para siempre. Pide la contraseña actual para que no baste con una
// sesion abierta en un telefono prestado.
app.post('/api/:slug/change-recovery', authLimiter, requireAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    const users = await getUsers(slug);
    const user = users.find((u) => u.id === req.userId);
    let { currentPassword, recoveryQuestion, recoveryAnswer } = req.body || {};
    currentPassword = cleanPassword(currentPassword);
    if (!user || !verifyPassword(currentPassword, user.passwordHash)) {
      return res.status(401).json({ error: 'invalid_password' });
    }
    if (!recoveryQuestion || !String(recoveryQuestion).trim() ||
        !recoveryAnswer || !String(recoveryAnswer).trim()) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    if (isTooLong(recoveryQuestion, 300) || isTooLong(recoveryAnswer, 300)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    user.recoveryQuestion = String(recoveryQuestion).trim();
    user.recoveryAnswerHash = hashPassword(normalizeAnswer(recoveryAnswer));
    await upsertDoc(slug, 'users', user.id, user);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/api/:slug/users', requireAuth, async (req, res) => {
  try {
    const users = await getUsers(req.params.slug);
    res.json(users.map((u) => ({
      id: u.id,
      fullName: u.fullName,
      role: isOwner(users, u.id) ? 'owner' : 'staff'
    })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.delete('/api/:slug/users/:id', requireAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    const users = await getUsers(slug);
    if (!isOwner(users, req.userId)) return res.status(403).json({ error: 'owner_only' });
    if (users.length <= 1) {
      return res.status(400).json({ error: 'last_user' });
    }
    // Una dueña se puede quitar, pero nunca la ultima: un salon sin dueña
    // se queda sin quien cambie el codigo ni administre al equipo.
    if (isOwner(users, req.params.id) && ownerCount(users) <= 1) {
      return res.status(400).json({ error: 'cannot_remove_owner' });
    }
    await pool.query('DELETE FROM documents WHERE salon_id=$1 AND collection=$2 AND id=$3', [slug, 'users', req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/:slug/change-password', authLimiter, requireAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    const users = await getUsers(slug);
    const user = users.find((u) => u.id === req.userId);
    let { currentPassword, newPassword } = req.body || {};
    currentPassword = cleanPassword(currentPassword);
    newPassword = cleanPassword(newPassword);
    if (!user || !verifyPassword(currentPassword, user.passwordHash)) {
      return res.status(401).json({ error: 'invalid_password' });
    }
    if (!newPassword || newPassword.length < MIN_PASSWORD || isTooLong(newPassword, 200)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    user.passwordHash = hashPassword(newPassword);
    await upsertDoc(slug, 'users', user.id, user);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- config (singleton doc per salon) ----
app.get('/api/:slug/config', requireAuth, async (req, res) => {
  try {
    const cfg = await getConfig(req.params.slug);
    if (cfg) delete cfg.passwordHash;
    res.json(cfg);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});
app.put('/api/:slug/config', async (req, res) => {
  try {
    const slug = req.params.slug;
    const existing = await getConfig(slug);
    const body = Object.assign({}, req.body || {});
    delete body.passwordHash; // legacy field; never accepted directly from a client

    if (isReservedSlug(slug)) return res.status(404).json({ error: 'not_found' });

    if (!existing) {
      // Creating a brand-new salon. The owner's own account is created
      // right after this, via a separate /register call.
      const access = await signupAccess(req.body, slug, body.name);
      if (!access.ok) {
        return res.status(403).json({ error: 'invalid_signup_code', reason: access.reason });
      }
      delete body.signupCode; // never stored
      try {
        await upsertDoc(slug, 'config', 'main', body);
      } catch (e) {
        // The invitation was already claimed above; give it back rather
        // than burning a code on a salon that does not exist.
        if (access.inviteId) await releaseInvite(access.inviteId).catch(() => {});
        throw e;
      }
      await recordSalon(slug, {
        name: body.name || '',
        createdAt: new Date().toISOString(),
        suspended: false,
        inviteId: access.inviteId || null
      });
      res.json({ ok: true });

      if (body.ownerEmail) {
        const base = `${req.protocol}://${req.get('host')}`;
        sendMail(
          body.ownerEmail,
          `Bienvenida a ${body.name || 'su nuevo salón'}`,
          `Hola,\n\n` +
          `Su salón ya está abierto y es solo suyo: nadie más puede ver su inventario, sus clientas ni su agenda.\n\n` +
          `Su panel: ${base}/s/${slug}\n` +
          `Su página pública: ${base}/p/${slug}\n\n` +
          `Entre con su nombre completo y la contraseña que acaba de elegir.\n\n` +
          `Para empezar, le sugerimos tres cosas:\n` +
          `1. Agregar sus primeros tintes en Inventario.\n` +
          `2. Revisar la lista de servicios en Ajustes.\n` +
          `3. Completar su portada en Ajustes, Portada pública, y compartir el enlace con sus clientas.\n\n` +
          `Para que otra persona de su equipo pueda entrar, use el código de invitación que encontrará en Ajustes.`,
          body.name
        );
      }
      return;
    }
    delete body.signupCode;

    // Updating an existing salon's config requires a valid session tied to
    // one of its users.
    const data = verifyToken(getBearerToken(req), slug);
    if (!data) return res.status(401).json({ error: 'unauthorized' });
    if (await isSuspended(slug)) return res.status(403).json({ error: 'salon_suspended' });

    /* El equipo puede ajustar marcas, servicios y la portada, pero no la
       llave de entrada al salon ni la direccion a la que llegan los avisos.
       Se conservan los valores guardados en vez de rechazar el envio, para
       que un formulario que no trae esos campos no los borre sin querer. */
    const salonUsers = await getUsers(slug);
    if (!isOwner(salonUsers, data.userId)) {
      for (const field of ['inviteCode', 'ownerEmail']) {
        if (existing[field] === undefined) delete body[field];
        else body[field] = existing[field];
      }
    }

    if (existing.passwordHash) body.passwordHash = existing.passwordHash; // preserve legacy field until migrated
    await upsertDoc(slug, 'config', 'main', body);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- chat assistant ----
// Uses Anthropic (ANTHROPIC_API_KEY) whenever that key is set, and falls
// back to Gemini (GEMINI_API_KEY) only when it isn't. Both may be present:
// Anthropic wins. Registered before the generic /:collection routes below
// so a POST to /chat isn't swallowed by the generic "create a document in
// this collection" handler.
async function callGemini(apiKey, system, messages) {
  const contents = messages.map((m) => ({
    role: m.role === 'assistant' ? 'model' : 'user',
    parts: [{ text: m.content }]
  }));
  const upstream = await fetch(
    'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' +
      encodeURIComponent(apiKey),
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        contents,
        systemInstruction: system ? { parts: [{ text: system }] } : undefined,
        generationConfig: { maxOutputTokens: 700 }
      })
    }
  );
  if (upstream.status === 429) return { rateLimited: true };
  if (!upstream.ok) {
    const errText = await upstream.text();
    console.error('Gemini API error', upstream.status, errText);
    return { error: true };
  }
  const data = await upstream.json();
  const parts = (data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts) || [];
  const text = parts.map((p) => p.text || '').join('\n');
  return { text };
}

async function callAnthropic(apiKey, system, messages) {
  const upstream = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01'
    },
    body: JSON.stringify({
      model: 'claude-sonnet-5',
      max_tokens: 700,
      system: system || undefined,
      messages
    })
  });
  if (upstream.status === 429) return { rateLimited: true };
  if (!upstream.ok) {
    const errText = await upstream.text();
    console.error('Anthropic API error', upstream.status, errText);
    return { error: true };
  }
  const data = await upstream.json();
  const text = (data.content || [])
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n');
  return { text };
}

app.post('/api/:slug/chat', chatLimiter, requireAuth, async (req, res) => {
  try {
    const geminiKey = process.env.GEMINI_API_KEY;
    const anthropicKey = process.env.ANTHROPIC_API_KEY;
    if (!geminiKey && !anthropicKey) {
      return res.status(503).json({ error: 'chat_not_configured' });
    }

    const { system, messages } = req.body || {};
    if (!Array.isArray(messages) || !messages.length) {
      return res.status(400).json({ error: 'invalid_request' });
    }

    const result = anthropicKey
      ? await callAnthropic(anthropicKey, system, messages)
      : await callGemini(geminiKey, system, messages);

    if (result.rateLimited) return res.status(429).json({ error: 'rate_limited' });
    if (result.error) return res.status(502).json({ error: 'upstream_error' });
    res.json({ text: result.text || '' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// Public, unauthenticated chat for the marketing landing page. Deliberately
// never told anything private (inventory, clients, sales) — only the fixed
// public-facing description below, the same information already printed on
// the landing page itself — so there is nothing sensitive for it to leak.
const PUBLIC_CHAT_SYSTEM = `Eres el asistente virtual de KY Nature Beauty, un salón de belleza y spa en Cicero, Illinois.
Responde siempre en un tono formal, cordial y profesional. No hagas chistes ni bromas bajo ninguna circunstancia.
Tu única función es responder preguntas sobre este salón (servicios, horario, ubicación, contacto, cursos y el proceso de reserva), usando exclusivamente la información de este mensaje.
Si la pregunta no tiene relación con el salón, NUNCA la respondas, así tengas o no esa información: ni la capital de un país, ni el clima, ni temas generales ni de cualquier otro tema ajeno al salón. En su lugar, responde únicamente que no cuenta con esa información y que su función es ayudar con temas del salón.
Si la pregunta sí es sobre el salón pero la respuesta no está en la información de este mensaje, responde con honestidad que no cuenta con esa información en este momento, y sugiera contactar directamente al salón. Nunca inventes datos que no estén aquí.

Servicios que ofrece el salón:
- Cabello: corte de cabello para dama y para caballero, color, balayage, rayos, colores de fantasía, permanente para dama y para caballero (los cortes se realizan según las facciones del cliente o su preferencia personal).
- Rostro y piel: faciales profesionales adaptados a cada tipo de piel, trabajando con colágeno, máquinas LED o aparatología/galvánicas, y mascarillas orgánicas de calidad spa.
- Maquillaje profesional para cualquier ocasión.
- Uñas personalizadas: acrílico, no-chip y tech gel, con diseños a la medida.
- Pestañas y cejas: rizado de pestañas y planchado de cejas.
- Bienestar: masaje relajante, masaje de piedras calientes y masaje con ventosas, de 45 minutos a una hora, en un ambiente relajante con aromaterapia.

El salón también ofrece cursos personalizados de maquillaje, faciales profesionales, uñas, masajes y más, para quienes quieren aprender la técnica de manera profesional. Si preguntan por cursos o clases, responde que sí se ofrecen cursos personalizados en esas áreas y que, para más información, contacten directamente al salón.

Horario: lunes a viernes de 9:00 am a 7:00 pm, sábados de 9:00 am a 5:00 pm, domingos cerrado.
Ubicación: Cicero, Illinois.
Contacto: teléfono y WhatsApp 773-241-1224, correo nailskybeauty2021@gmail.com.

No inventes precios exactos: indica que varían según el servicio y que se puede solicitar una cotización por WhatsApp.
No confirmes horarios específicos de citas: para eso existe un formulario de reserva en la misma página, o puede escribir por WhatsApp.
Mantén las respuestas breves y claras.
Escribe en texto plano, sin ningún formato de markdown: nunca uses asteriscos, guiones como viñetas, numeración, encabezados ni ningún otro símbolo de formato. Si necesitas enumerar varias cosas, hazlo dentro de la misma oración o en frases separadas por puntos.`;

// Builds the public assistant's brief from what this salon published on
// its own page. It is given nothing else: no inventory, no clients, no
// sales. Everything here is already visible to any visitor, so there is
// nothing private for the assistant to leak.
function buildPublicChatSystem(cfg) {
  const L = (cfg && cfg.landing) || {};
  const name = cfg.name || 'este salón';
  const services = Array.isArray(cfg.services) ? cfg.services.filter(Boolean) : [];
  const lines = [];

  lines.push(`Eres el asistente virtual de ${name}, un salón de belleza.`);
  lines.push('Responde siempre en un tono formal, cordial y profesional. No hagas chistes ni bromas bajo ninguna circunstancia.');
  lines.push('Tu única función es responder preguntas sobre este salón, usando exclusivamente la información de este mensaje.');
  lines.push('Si la pregunta no tiene relación con el salón, NUNCA la respondas, tengas o no esa información: ni la capital de un país, ni el clima, ni temas generales. Responde únicamente que no cuenta con esa información y que su función es ayudar con temas del salón.');
  lines.push('Si la pregunta sí es sobre el salón pero la respuesta no está aquí, responde con honestidad que no cuenta con ese dato en este momento y sugiere contactar directamente al salón. Nunca inventes datos.');
  lines.push('');

  if (L.about) lines.push(`Sobre el salón: ${L.about}`);
  if (L.heroText) lines.push(`Presentación: ${L.heroText}`);
  if (services.length) lines.push(`Servicios que ofrece: ${services.join(', ')}.`);
  if (cfg.servicesNote) lines.push(`Cómo se realizan los servicios: ${cfg.servicesNote}`);
  if (L.experienceText) lines.push(`La experiencia en el salón: ${L.experienceText}`);
  if (L.coursesText) lines.push(`Cursos y formación: ${L.coursesText}`);
  if (L.hours) lines.push(`Horario: ${String(L.hours).replace(/\n/g, '; ')}`);
  if (L.city || L.address) lines.push(`Ubicación: ${[L.address, L.city].filter(Boolean).join(', ')}`);

  const contact = [];
  if (L.phone) contact.push(`teléfono ${L.phone}`);
  if (L.whatsapp) contact.push(`WhatsApp ${L.whatsapp}`);
  if (L.email) contact.push(`correo ${L.email}`);
  if (contact.length) lines.push(`Contacto: ${contact.join(', ')}.`);

  lines.push('');
  lines.push('No inventes precios exactos: indica que varían según el servicio y que se puede pedir una cotización por los medios de contacto.');
  lines.push('No confirmes horarios específicos de citas: para eso existe el formulario de reserva en la misma página.');
  lines.push('Mantén las respuestas breves y claras.');
  lines.push('Escribe en texto plano, sin ningún formato de markdown: nunca uses asteriscos, viñetas, numeración ni encabezados. Si necesitas enumerar varias cosas, hazlo dentro de la misma oración o en frases separadas por puntos.');

  return lines.join('\n');
}

app.post('/api/:slug/public-chat', chatLimiter, async (req, res) => {
  try {
    const slug = req.params.slug;
    const cfg = await getConfig(slug);
    if (!cfg) return res.status(404).json({ error: 'not_found' });
    if (await isSuspended(slug)) return res.status(404).json({ error: 'not_found' });

    /* Si el salon apago su portada, o apago el chat dentro de ella, aqui no
       se atiende a nadie. Ademas de respetar lo que eligio, evita que una
       portada apagada siga gastando saldo de la cuenta de IA. */
    const landingCfg = cfg.landing || {};
    if (landingCfg.enabled === false || landingCfg.showChat === false) {
      return res.status(404).json({ error: 'not_found' });
    }

    const geminiKey = process.env.GEMINI_API_KEY;
    const anthropicKey = process.env.ANTHROPIC_API_KEY;
    if (!geminiKey && !anthropicKey) {
      return res.status(503).json({ error: 'chat_not_configured' });
    }

    const { messages } = req.body || {};
    if (!Array.isArray(messages) || !messages.length || messages.length > 12) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    for (const m of messages) {
      if (!m || typeof m.content !== 'string' || isTooLong(m.content, 600)) {
        return res.status(400).json({ error: 'invalid_request' });
      }
    }

    // KY Nature Beauty's hand-written page carries detail that never went
    // into the config, so that salon keeps its original brief. Every other
    // salon gets one built from its own published page.
    const system = slug === 'ky-nature-beauty-2g5w'
      ? PUBLIC_CHAT_SYSTEM
      : buildPublicChatSystem(cfg);

    const result = anthropicKey
      ? await callAnthropic(anthropicKey, system, messages)
      : await callGemini(geminiKey, system, messages);

    if (result.rateLimited) return res.status(429).json({ error: 'rate_limited' });
    if (result.error) return res.status(502).json({ error: 'upstream_error' });
    res.json({ text: result.text || '' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- public booking requests (no login needed) ----
// Registered before the generic /:collection routes below so this POST
// isn't swallowed by the generic "create a document" handler, which
// requires auth — the same mistake already made once with /chat.
app.post('/api/:slug/booking-requests', authLimiter, async (req, res) => {
  try {
    const slug = req.params.slug;
    const cfg = await getConfig(slug);
    if (!cfg) return res.status(404).json({ error: 'not_found' });
    if (await isSuspended(slug)) return res.status(404).json({ error: 'not_found' });
    const { clientName, phone, service, date, time, notes, email } = req.body || {};
    if (!clientName || !clientName.trim() || !phone || !phone.trim() || !service || !date) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    if (isTooLong(clientName, 120) || isTooLong(phone, 40) || isTooLong(service, 120) || isTooLong(date, 20) || isTooLong(time, 20) || isTooLong(notes, 500) || isTooLong(email, 160)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    const clientEmail = looksLikeEmail(email) ? email.trim() : '';
    const id = genId();
    await upsertDoc(slug, 'booking_requests', id, {
      clientName: clientName.trim(),
      phone: phone.trim(),
      email: clientEmail,
      service: service.trim(),
      date,
      time: time || '',
      notes: (notes || '').trim(),
      createdAt: new Date().toISOString()
    });
    res.json({ id });

    // Everything below is after the answer: the visitor never waits on an
    // email, and a mail failure can never lose a booking request.
    const when = fmtDateHuman(date, time);
    const contact = salonContactLine(cfg);
    if (clientEmail) {
      sendMail(
        clientEmail,
        `Recibimos tu solicitud de cita — ${cfg.name || ''}`.trim(),
        `Hola ${clientName.trim()},\n\n` +
        `Recibimos tu solicitud de cita para ${service.trim()} el ${when}.\n\n` +
        `Todavía no está confirmada. Revisamos la agenda y te avisamos en cuanto tengamos el horario exacto.\n\n` +
        (contact ? `Si necesitas cambiar algo, escríbenos: ${contact}\n\n` : '') +
        `${cfg.name || ''}`,
        cfg.name
      );
    }
    // The salon hears about it too, so a request never sits unseen.
    if (cfg.ownerEmail) {
      sendMail(
        cfg.ownerEmail,
        `Nueva solicitud de cita: ${clientName.trim()}`,
        `${clientName.trim()} pidió una cita para ${service.trim()} el ${when}.\n\n` +
        `Teléfono: ${phone.trim()}\n` +
        (clientEmail ? `Correo: ${clientEmail}\n` : '') +
        ((notes || '').trim() ? `Notas: ${notes.trim()}\n` : '') +
        `\nEntra a tu panel para confirmarla.`,
        cfg.name
      );
    }
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- confirming an appointment to the client ----
// Called by the panel right after a booking request is turned into a real
// appointment, or whenever the salon wants to resend the confirmation.
app.post('/api/:slug/notify-appointment', authLimiter, requireAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    const { id } = req.body || {};
    if (!id || isTooLong(id, 80)) return res.status(400).json({ error: 'invalid_request' });

    const r = await pool.query(
      'SELECT data FROM documents WHERE salon_id=$1 AND collection=$2 AND id=$3',
      [slug, 'appointments', id]
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'not_found' });
    const appt = r.rows[0].data || {};
    if (!looksLikeEmail(appt.clientEmail)) return res.json({ sent: false, reason: 'no_email' });

    const cfg = await getConfig(slug);
    const contact = salonContactLine(cfg);
    const result = await sendMail(
      appt.clientEmail,
      `Cita confirmada — ${(cfg && cfg.name) || ''}`.trim(),
      `Hola ${appt.clientName || ''},\n\n` +
      `Tu cita está confirmada.\n\n` +
      `Servicio: ${appt.service || ''}\n` +
      `Cuándo: ${fmtDateHuman(appt.date, appt.time)}\n\n` +
      (contact ? `Dónde y cómo localizarnos: ${contact}\n\n` : '') +
      `Si necesitas cambiarla o cancelarla, avísanos con tiempo.\n\n` +
      `${(cfg && cfg.name) || ''}`,
      cfg && cfg.name
    );
    res.json(result);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- appointment reminders ----
// Run by an external scheduler once a day. It is deliberately a plain HTTP
// endpoint rather than a timer inside this process, because on Render's
// free plan the service sleeps after 15 minutes and an in-process timer
// would simply never fire. CRON_SECRET keeps it from being triggered by
// anyone who finds the address.
function tomorrowISO() {
  const d = new Date();
  d.setDate(d.getDate() + 1);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

app.post('/api/cron/reminders', async (req, res) => {
  const secret = (process.env.CRON_SECRET || '').trim();
  if (!secret) return res.status(503).json({ error: 'cron_not_configured' });
  const given = (req.get('x-cron-secret') || '').trim();
  const a = Buffer.from(given);
  const b = Buffer.from(secret);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  try {
    const target = tomorrowISO();
    // Only tomorrow's appointments, and only those not already reminded,
    // so running the job twice in one day never emails anyone twice.
    const rows = await pool.query(
      `SELECT salon_id, id, data FROM documents
       WHERE collection = 'appointments'
         AND data->>'date' = $1
         AND COALESCE(data->>'reminderSentAt', '') = ''`,
      [target]
    );

    const configs = new Map();
    let sent = 0, skipped = 0;

    for (const row of rows.rows) {
      const appt = row.data || {};
      if (!looksLikeEmail(appt.clientEmail)) { skipped++; continue; }

      if (!configs.has(row.salon_id)) {
        configs.set(row.salon_id, await getConfig(row.salon_id));
      }
      const cfg = configs.get(row.salon_id);
      const contact = salonContactLine(cfg);

      const result = await sendMail(
        appt.clientEmail,
        `Recordatorio: tu cita de mañana — ${(cfg && cfg.name) || ''}`.trim(),
        `Hola ${appt.clientName || ''},\n\n` +
        `Te recordamos tu cita de mañana.\n\n` +
        `Servicio: ${appt.service || ''}\n` +
        `Cuándo: ${fmtDateHuman(appt.date, appt.time)}\n\n` +
        (contact ? `Dónde y cómo localizarnos: ${contact}\n\n` : '') +
        `Si no puedes venir, avísanos para liberar el horario.\n\n` +
        `${(cfg && cfg.name) || ''}`,
        cfg && cfg.name
      );

      if (result.sent) {
        sent++;
        await upsertDoc(row.salon_id, 'appointments', row.id,
          Object.assign({}, appt, { reminderSentAt: new Date().toISOString() }));
      } else {
        skipped++;
      }
    }

    const copia = await copiaSemanalSiTocaba();

    res.json({ date: target, found: rows.rows.length, sent, skipped, mailEnabled, copia });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- generic collections (products, usage, clients, appointments) ----
/* Estas cuatro rutas sirven para cualquier coleccion que se les pida, y ahi
   estaba el agujero: 'config' y 'users' tambien son colecciones. Quien
   tuviera sesion en el salon podia escribir en ellas por aqui y saltarse
   todos los controles de las rutas propias de cada una. Daba para ponerse
   el codigo de invitacion que quisiera, fabricarse una cuenta de dueña, o
   escribir encima de la contraseña de la dueña y entrar como ella.

   Por eso ahora solo se aceptan las colecciones del trabajo diario. Es una
   lista cerrada y no una lista de prohibidas: una coleccion nueva que se
   agregue mañana no queda abierta por olvido. */
const DATA_COLLECTIONS = new Set([
  'products', 'usage', 'clients', 'color_records',
  'visits', 'appointments', 'booking_requests'
]);
function onlyDataCollections(req, res, next) {
  if (!DATA_COLLECTIONS.has(req.params.collection)) {
    return res.status(404).json({ error: 'not_found' });
  }
  next();
}
app.get('/api/:slug/:collection', requireAuth, onlyDataCollections, async (req, res) => {
  try {
    const { slug, collection } = req.params;
    const r = await pool.query(
      'SELECT id, data FROM documents WHERE salon_id=$1 AND collection=$2 ORDER BY updated_at ASC',
      [slug, collection]
    );
    res.json(r.rows.map((row) => Object.assign({ id: row.id }, row.data)));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/:slug/:collection', requireAuth, onlyDataCollections, async (req, res) => {
  try {
    const { slug, collection } = req.params;
    const id = genId();
    await pool.query(
      'INSERT INTO documents (salon_id, collection, id, data) VALUES ($1,$2,$3,$4)',
      [slug, collection, id, req.body || {}]
    );
    res.json({ id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.put('/api/:slug/:collection/:id', requireAuth, onlyDataCollections, async (req, res) => {
  try {
    await upsertDoc(req.params.slug, req.params.collection, req.params.id, req.body || {});
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.patch('/api/:slug/:collection/:id', requireAuth, onlyDataCollections, async (req, res) => {
  try {
    const { slug, collection, id } = req.params;
    const existing = await pool.query(
      'SELECT data FROM documents WHERE salon_id=$1 AND collection=$2 AND id=$3',
      [slug, collection, id]
    );
    const base = existing.rows[0] ? existing.rows[0].data : {};
    const merged = Object.assign({}, base, req.body || {});
    await upsertDoc(slug, collection, id, merged);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.delete('/api/:slug/:collection/:id', requireAuth, onlyDataCollections, async (req, res) => {
  try {
    const { slug, collection, id } = req.params;
    await pool.query(
      'DELETE FROM documents WHERE salon_id=$1 AND collection=$2 AND id=$3',
      [slug, collection, id]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));
// index:false — otherwise this would auto-serve public/index.html for GET /,
// before our own "/" route below ever runs, and the landing page would
// never be reachable.
app.use(express.static(path.join(__dirname, 'public'), { index: false }));
// These three pages change on every deploy, so never let a browser (or a
// phone carrier's data-saving proxy) serve a stale cached copy after one —
// always revalidate with the server first.
function sendFresh(res, file) {
  res.set('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', file));
}
app.get('/s/:slug', (req, res) => sendFresh(res, 'index.html'));
// Public marketing page. New-salon onboarding (previously at "/") moved to
// "/nuevo" since the client-side app treats any path other than "/s/:slug"
// as "no salon yet" and shows the onboarding screen either way.
app.get('/nuevo', (req, res) => sendFresh(res, 'index.html'));
// Every salon's own public page, built from what it filled in under
// Settings. KY Nature Beauty keeps its hand-built page at "/" below.
app.get('/p/:slug', (req, res) => sendFresh(res, 'salon.html'));
// The owner's own console. Nothing links to it from anywhere in the app.
app.get('/admin', (req, res) => sendFresh(res, 'admin.html'));
app.get('/', (req, res) => sendFresh(res, 'landing.html'));

function errorPage(code, title, message) {
  return `<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} — KY Nature Beauty</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:#15110d;color:#ece6da;font-family:Georgia,'Times New Roman',serif;text-align:center;padding:24px;box-sizing:border-box}
  .card{max-width:420px}
  .code{color:#c8a35f;font-size:15px;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px}
  h1{font-size:26px;margin:0 0 12px}
  p{color:#bdb3a2;line-height:1.5;margin:0 0 22px}
  a{display:inline-block;color:#15110d;background:#c8a35f;text-decoration:none;padding:10px 22px;border-radius:6px;font-size:14px}
</style></head><body><div class="card">
  <div class="code">Error ${code}</div>
  <h1>${title}</h1>
  <p>${message}</p>
  <a href="/">Volver al inicio</a>
</div></body></html>`;
}

// Anything not matched above: JSON for the API surface, a branded page for
// everything else. Keeps unmatched routes from falling through to Express's
// default plain-text 404.
app.use((req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: 'not_found' });
  res.status(404).send(errorPage(404, 'Página no encontrada', 'El enlace al que intentó acceder no existe o ya no está disponible.'));
});

// Final safety net for anything thrown outside the per-route try/catch
// blocks. Never leaks stack traces or error details to the client.
app.use((err, req, res, next) => {
  /* Un cuerpo mal formado es culpa de quien llama, no del servidor: pasa
     cuando se corta la conexion a medio envio, que con un telefono en
     mala cobertura es de lo mas normal. Devolver 500 por eso confunde a
     quien lo ve y, peor, esconde los fallos de verdad entre ruido cuando
     hay que revisar los registros. */
  const codigo = Number(err && (err.statusCode || err.status));
  if (codigo >= 400 && codigo < 500) {
    if (req.path.startsWith('/api/')) return res.status(codigo).json({ error: 'invalid_request' });
    return res.status(codigo).send(errorPage(codigo, 'Petición incorrecta', 'No se pudo leer la petición. Vuelva a intentarlo.'));
  }

  console.error('Unhandled error:', err);
  if (req.path.startsWith('/api/')) return res.status(500).json({ error: 'server_error' });
  res.status(500).send(errorPage(500, 'Algo salió mal', 'Ocurrió un error inesperado. Por favor intente de nuevo en unos momentos.'));
});

// Start serving immediately; never crash the process over a slow/unready
// database (common right after the DB is first provisioned). Connect in
// the background and keep retrying — requests made before it's ready just
// get a clean 500, which the frontend already handles gracefully.
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log('Server listening on port', PORT);
  if (adminEnabled) {
    console.log('Owner console enabled at /admin. New salons need a one-time invitation.');
  } else if (SIGNUP_CODE) {
    console.log('WARNING: sign-up uses the shared SIGNUP_CODE. Anyone it is given to can pass it on.');
    console.log('         Set ADMIN_PASSWORD to issue one-time invitations instead, then remove SIGNUP_CODE.');
  } else {
    console.log('WARNING: no ADMIN_PASSWORD and no SIGNUP_CODE are set.');
    console.log('         Only the very first salon can be opened; after that sign-up is closed.');
    console.log('         Set ADMIN_PASSWORD to hand out invitations from /admin.');
  }
  if (!process.env.SESSION_SECRET) {
    console.log('WARNING: SESSION_SECRET is not set, so everyone is signed out on every restart.');
  }
});

function connectDbWithRetry() {
  initDb()
    .then(() => console.log('Database ready'))
    .catch((e) => {
      console.error('Database not ready yet, retrying in 5s:', e.message);
      setTimeout(connectDbWithRetry, 5000);
    });
}
connectDbWithRetry();

process.on('unhandledRejection', (e) => console.error('Unhandled rejection:', e));
