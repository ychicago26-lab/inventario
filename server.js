const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '2mb' }));

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
function signToken(slug) {
  const payload = Buffer.from(JSON.stringify({ slug, exp: Date.now() + TOKEN_TTL_MS })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function verifyToken(token, slug) {
  if (!token || token.indexOf('.') === -1) return false;
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  if (sig !== expected) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return data.slug === slug && data.exp > Date.now();
  } catch (e) {
    return false;
  }
}
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!verifyToken(token, req.params.slug)) {
    return res.status(401).json({ error: 'unauthorized' });
  }
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

// ---- access: public lookup, login, password change ----
// Minimal, unauthenticated: just enough for the login screen to greet the
// salon by name without exposing anything else.
app.get('/api/:slug/public', async (req, res) => {
  try {
    const cfg = await getConfig(req.params.slug);
    if (!cfg) return res.json({ exists: false });
    res.json({ exists: true, name: cfg.name, language: cfg.language, hasPassword: !!cfg.passwordHash });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/:slug/login', async (req, res) => {
  try {
    const slug = req.params.slug;
    const cfg = await getConfig(slug);
    const { password } = req.body || {};
    if (!cfg || !password) {
      return res.status(401).json({ error: 'invalid_password' });
    }
    if (!cfg.passwordHash) {
      // Salon created before password protection existed: whoever holds
      // this private link sets the password now, on this first access.
      if (password.length < 4) return res.status(400).json({ error: 'invalid_request' });
      cfg.passwordHash = hashPassword(password);
      await upsertDoc(slug, 'config', 'main', cfg);
      return res.json({ token: signToken(slug) });
    }
    if (!verifyPassword(password, cfg.passwordHash)) {
      return res.status(401).json({ error: 'invalid_password' });
    }
    res.json({ token: signToken(slug) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.post('/api/:slug/change-password', requireAuth, async (req, res) => {
  try {
    const cfg = await getConfig(req.params.slug);
    const { currentPassword, newPassword } = req.body || {};
    if (!cfg || !verifyPassword(currentPassword, cfg.passwordHash)) {
      return res.status(401).json({ error: 'invalid_password' });
    }
    if (!newPassword || newPassword.length < 4) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    cfg.passwordHash = hashPassword(newPassword);
    await upsertDoc(req.params.slug, 'config', 'main', cfg);
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
    const plainPassword = body.password;
    delete body.password;
    delete body.passwordHash; // never accepted directly from a client

    if (!existing) {
      // Creating a brand-new salon: requires a password, bootstraps it,
      // and logs the creator in immediately.
      if (!plainPassword || plainPassword.length < 4) {
        return res.status(400).json({ error: 'password_required' });
      }
      body.passwordHash = hashPassword(plainPassword);
      await upsertDoc(slug, 'config', 'main', body);
      return res.json({ ok: true, token: signToken(slug) });
    }

    // Updating an existing salon's config requires a valid session;
    // its password is only ever changed via /change-password.
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!verifyToken(token, slug)) return res.status(401).json({ error: 'unauthorized' });
    body.passwordHash = existing.passwordHash;
    await upsertDoc(slug, 'config', 'main', body);
    res.json({ ok: true });
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

// ---- chat assistant ----
// Tries Gemini first (GEMINI_API_KEY), then falls back to Anthropic
// (ANTHROPIC_API_KEY) if that's the one configured instead.
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

app.post('/api/:slug/chat', requireAuth, async (req, res) => {
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

app.get('/healthz', (req, res) => res.status(200).send('ok'));
app.use(express.static(path.join(__dirname, 'public')));
app.get('/s/:slug', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
