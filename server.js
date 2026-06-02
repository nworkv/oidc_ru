require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 8085;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// ─── In-memory log store (max 200 entries) ────────────────────────────────────
let requestLog = [];
const MAX_LOG  = 200;

function maskSecret(val) {
  if (!val || typeof val !== 'string') return val;
  if (val.length <= 8) return '****';
  return val.slice(0, 6) + '…[MASKED]';
}

function addLogEntry(entry) {
  requestLog.unshift(entry);
  if (requestLog.length > MAX_LOG) requestLog = requestLog.slice(0, MAX_LOG);
}

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Global request logger ────────────────────────────────────────────────────
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ─── /capture ─────────────────────────────────────────────────────────────────
app.all('/capture', (req, res) => {
  const query  = req.query  || {};
  const body   = req.body   || {};
  const merged = { ...query, ...body };

  const raw_code         = merged.code              || null;
  const raw_state        = merged.state             || null;
  const raw_access_token = merged.access_token      || null;
  const raw_id_token     = merged.id_token          || null;
  const raw_error        = merged.error             || null;
  const raw_error_desc   = merged.error_description || null;

  const entry = {
    id:        Date.now(),
    timestamp: new Date().toISOString(),
    method:    req.method,
    full_url:  `${req.protocol}://${req.get('host')}${req.originalUrl}`,
    path:      req.path,
    ip:        req.headers['x-forwarded-for'] || req.socket.remoteAddress,

    oauth: {
      code:              raw_code         ? maskSecret(raw_code)         : null,
      state:             raw_state        || null,
      access_token:      raw_access_token ? maskSecret(raw_access_token) : null,
      id_token:          raw_id_token     ? maskSecret(raw_id_token)     : null,
      error:             raw_error        || null,
      error_description: raw_error_desc   || null,
    },

    query_raw: query,
    body_raw:  body,

    headers: {
      referer:    req.headers['referer']    || null,
      user_agent: req.headers['user-agent'] || null,
      host:       req.headers['host']       || null,
    },

    analysis: {
      has_code:         !!raw_code,
      has_access_token: !!raw_access_token,
      has_id_token:     !!raw_id_token,
      has_error:        !!raw_error,
      risk: raw_code || raw_access_token || raw_id_token
        ? 'УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: сервер авторизации перенаправил токены/код на неавторизованный URI'
        : raw_error
          ? 'Сервер авторизации вернул ошибку (redirect_uri отклонён или другая проблема)'
          : 'Запрос получен, OAuth-параметры отсутствуют',
    },
  };

  addLogEntry(entry);
  console.log('CAPTURE EVENT:', JSON.stringify(entry.analysis));

  res.status(200).send(`
    <!doctype html><html lang="ru"><head><meta charset="UTF-8">
    <title>Observer: capture</title>
    <style>
      body{font-family:monospace;background:#fff8f8;color:#231f20;padding:32px}
      pre{background:#f3e8e8;padding:20px;border-radius:8px;border:1px solid #d47b7b;overflow:auto}
      h2{color:#c0392b}
    </style></head><body>
    <h2>Запрос перехвачен исследовательским сервером</h2>
    <p>Параметры сохранены в журнале. Откройте <a href="/">главную страницу</a> для просмотра.</p>
    <pre>${JSON.stringify(entry, null, 2)}</pre>
    </body></html>
  `);
});

// ─── API: журнал ──────────────────────────────────────────────────────────────
app.get('/api/log', (req, res) => {
  res.json({ total: requestLog.length, items: requestLog });
});

app.delete('/api/log', (req, res) => {
  requestLog = [];
  res.json({ ok: true, message: 'Журнал очищен' });
});

app.get('/api/status', (req, res) => {
  res.json({
    ok:          true,
    port:        PORT,
    app_url:     APP_URL,
    log_size:    requestLog.length,
    capture_uri: `${APP_URL}/capture`,
  });
});

// ─── SPA fallback ─────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`Observer server running on ${APP_URL}`);
  console.log(`Capture URI: ${APP_URL}/capture`);
});
