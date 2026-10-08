const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.use(express.json({ limit: '2mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

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

// ---- config (singleton doc per salon) ----
app.get('/api/:slug/config', async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT data FROM documents WHERE salon_id=$1 AND collection=$2 AND id=$3',
      [req.params.slug, 'config', 'main']
    );
    res.json(r.rows[0] ? r.rows[0].data : null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});
app.put('/api/:slug/config', async (req, res) => {
  try {
    await upsertDoc(req.params.slug, 'config', 'main', req.body || {});
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// ---- generic collections (products, usage, clients, appointments) ----
app.get('/api/:slug/:collection', async (req, res) => {
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

app.post('/api/:slug/:collection', async (req, res) => {
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

app.put('/api/:slug/:collection/:id', async (req, res) => {
  try {
    await upsertDoc(req.params.slug, req.params.collection, req.params.id, req.body || {});
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

app.patch('/api/:slug/:collection/:id', async (req, res) => {
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

app.delete('/api/:slug/:collection/:id', async (req, res) => {
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

app.post('/api/:slug/chat', async (req, res) => {
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
