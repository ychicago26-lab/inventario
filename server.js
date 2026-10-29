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
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'self'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  }
}));
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
  const data = verifyToken(getBearerToken(req), req.params.slug);
  if (!data) return res.status(401).json({ error: 'unauthorized' });
  req.userId = data.userId;
  next();
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

// ---- access: public lookup, per-user accounts, login, recovery ----
// Minimal, unauthenticated: just enough for the login screen to know which
// form to show, without exposing anything else.
app.get('/api/:slug/public', async (req, res) => {
  try {
    const slug = req.params.slug;
    const cfg = await getConfig(slug);
    if (!cfg) return res.json({ exists: false });
    const users = await getUsers(slug);
    res.json({
      exists: true,
      name: cfg.name,
      language: cfg.language,
      hasUsers: users.length > 0,
      legacyPassword: !users.length && !!cfg.passwordHash
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
    const { fullName, password, recoveryQuestion, recoveryAnswer, oldPassword, inviteCode } = req.body || {};
    if (!fullName || !fullName.trim() || !password || password.length < 4 || !recoveryQuestion || !recoveryAnswer) {
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
      const validInvite = !!(cfg && cfg.inviteCode && inviteCode && inviteCode === cfg.inviteCode);
      if (!validInvite) {
        const authData = verifyToken(getBearerToken(req), slug);
        if (!authData) return res.status(401).json({ error: 'unauthorized' });
      }
    }
    if (findUserByName(users, fullName)) {
      return res.status(409).json({ error: 'name_taken' });
    }
    const id = genId();
    await upsertDoc(slug, 'users', id, {
      fullName: fullName.trim(),
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
    const { fullName, password } = req.body || {};
    if (!fullName || !password || isTooLong(fullName, 120) || isTooLong(password, 200)) {
      return res.status(401).json({ error: 'invalid_password' });
    }
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
    const { fullName, answer, newPassword } = req.body || {};
    if (!newPassword || newPassword.length < 4) return res.status(400).json({ error: 'invalid_request' });
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

app.get('/api/:slug/users', requireAuth, async (req, res) => {
  try {
    const users = await getUsers(req.params.slug);
    res.json(users.map((u) => ({ id: u.id, fullName: u.fullName })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.delete('/api/:slug/users/:id', requireAuth, async (req, res) => {
  try {
    const slug = req.params.slug;
    const users = await getUsers(slug);
    if (users.length <= 1) {
      return res.status(400).json({ error: 'last_user' });
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
    const { currentPassword, newPassword } = req.body || {};
    if (!user || !verifyPassword(currentPassword, user.passwordHash)) {
      return res.status(401).json({ error: 'invalid_password' });
    }
    if (!newPassword || newPassword.length < 4 || isTooLong(newPassword, 200)) {
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

    if (!existing) {
      // Creating a brand-new salon. The owner's own account is created
      // right after this, via a separate /register call.
      await upsertDoc(slug, 'config', 'main', body);
      return res.json({ ok: true });
    }

    // Updating an existing salon's config requires a valid session tied to
    // one of its users.
    const data = verifyToken(getBearerToken(req), slug);
    if (!data) return res.status(401).json({ error: 'unauthorized' });
    if (existing.passwordHash) body.passwordHash = existing.passwordHash; // preserve legacy field until migrated
    await upsertDoc(slug, 'config', 'main', body);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- chat assistant ----
// Tries Gemini first (GEMINI_API_KEY), then falls back to Anthropic
// (ANTHROPIC_API_KEY) if that's the one configured instead. Registered
// before the generic /:collection routes below so a POST to /chat isn't
// swallowed by the generic "create a document in this collection" handler.
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

    const result = geminiKey
      ? await callGemini(geminiKey, system, messages)
      : await callAnthropic(anthropicKey, system, messages);

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
    const { clientName, phone, service, date, time, notes } = req.body || {};
    if (!clientName || !clientName.trim() || !phone || !phone.trim() || !service || !date) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    if (isTooLong(clientName, 120) || isTooLong(phone, 40) || isTooLong(service, 120) || isTooLong(date, 20) || isTooLong(time, 20) || isTooLong(notes, 500)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    const id = genId();
    await upsertDoc(slug, 'booking_requests', id, {
      clientName: clientName.trim(),
      phone: phone.trim(),
      service: service.trim(),
      date,
      time: time || '',
      notes: (notes || '').trim(),
      createdAt: new Date().toISOString()
    });
    res.json({ id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- generic collections (products, usage, clients, appointments) ----
app.get('/api/:slug/:collection', requireAuth, async (req, res) => {
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

app.post('/api/:slug/:collection', requireAuth, async (req, res) => {
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

app.put('/api/:slug/:collection/:id', requireAuth, async (req, res) => {
  try {
    await upsertDoc(req.params.slug, req.params.collection, req.params.id, req.body || {});
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.patch('/api/:slug/:collection/:id', requireAuth, async (req, res) => {
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

app.delete('/api/:slug/:collection/:id', requireAuth, async (req, res) => {
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
  console.error('Unhandled error:', err);
  if (req.path.startsWith('/api/')) return res.status(500).json({ error: 'server_error' });
  res.status(500).send(errorPage(500, 'Algo salió mal', 'Ocurrió un error inesperado. Por favor intente de nuevo en unos momentos.'));
});

// Start serving immediately; never crash the process over a slow/unready
// database (common right after the DB is first provisioned). Connect in
// the background and keep retrying — requests made before it's ready just
// get a clean 500, which the frontend already handles gracefully.
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log('Server listening on port', PORT));

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
