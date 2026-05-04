// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server for mhr-cfw
// سازگار ۱۰۰٪ با mhr-cfw Python client
// Node.js 18+ (fetch داخلی)
// ═══════════════════════════════════════════════════════════════════
//
// Environment Variables:
//   API_KEY = کلید_قوی (همان auth_key در config.json)
//   PORT    = 3000 (پیش‌فرض)
//
// فرمت ورودی (از GAS):
//   POST / { k, u, m, h, b, ct, r }
//
// فرمت خروجی (به GAS):
//   { s, h, b }
// ═══════════════════════════════════════════════════════════════════

import express from 'express';

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

// هدرهایی که نباید به upstream فرستاده شوند
const BLOCKED_HEADERS = new Set([
  'host', 'connection', 'transfer-encoding',
  'content-length', 'x-relay-hop', 'x-fwd-hop', 'proxy-authorization',
  'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
  'forwarded', 'via',
]);

const ALLOWED_METHODS = new Set([
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS',
]);

const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50MB

// ─── Middleware ────────────────────────────────────────────────────
app.set('trust proxy', false);
app.use(express.json({ limit: '20mb' }));

// ─── Health Check ─────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    server: 'france-relay',
    node: process.version,
    uptime: Math.floor(process.uptime()),
    ts: Date.now(),
  });
});

// ─── Main Relay Endpoint ──────────────────────────────────────────
app.post('/', async (req, res) => {

  // ── ۱. Loop detection — جلوگیری از self-fetch ────────────────────
  if (req.headers['x-relay-hop'] === '1' || req.headers['x-fwd-hop'] === '1') {
    return res.status(508).json({ e: 'loop detected' });
  }

  // ── ۲. احراز هویت ────────────────────────────────────────────────
  const key = req.body?.k || req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    return res.status(401).json({ e: 'unauthorized' });
  }

  // ── ۳. پارامترها ──────────────────────────────────────────────────
  const { u, m, h, b, ct, r } = req.body;

  if (!u || typeof u !== 'string') {
    return res.status(400).json({ e: 'missing url' });
  }

  // ── ۴. URL validation ─────────────────────────────────────────────
  let targetUrl;
  try {
    targetUrl = new URL(u);
  } catch {
    return res.status(400).json({ e: 'invalid url' });
  }

  if (!['http:', 'https:'].includes(targetUrl.protocol)) {
    return res.status(400).json({ e: 'protocol not allowed' });
  }

  // ── ۵. Self-fetch block — جلوگیری از loop از طریق URL ─────────────
  const selfHost = req.headers['host'] || '';
  if (selfHost && targetUrl.hostname === selfHost.split(':')[0]) {
    return res.status(400).json({ e: 'self-fetch blocked' });
  }

  // ── ۶. Method ─────────────────────────────────────────────────────
  const method = (m || 'GET').toUpperCase();
  if (!ALLOWED_METHODS.has(method)) {
    return res.status(400).json({ e: 'method not allowed' });
  }

  // ── ۷. Headers — ساخت از صفر، فقط از فیلد h (body) ───────────────
  const headers = {};
  if (h && typeof h === 'object') {
    for (const [k, v] of Object.entries(h)) {
      if (typeof k === 'string' && typeof v === 'string'
          && !BLOCKED_HEADERS.has(k.toLowerCase())) {
        headers[k] = v;
      }
    }
  }

  // content-type از فیلد ct اولویت داره
  if (ct && typeof ct === 'string') {
    headers['content-type'] = ct;
  } else if (b && !headers['content-type']) {
    headers['content-type'] = 'application/octet-stream';
  }

  // دفاع دوم — اطمینان از پاک بودن هدرها قبل از ارسال
  ['x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'forwarded', 'via']
    .forEach(hdr => delete headers[hdr]);

  // ── ۸. Body decode (base64 → Buffer) ─────────────────────────────
  let reqBody;
  if (b && typeof b === 'string') {
    try {
      reqBody = Buffer.from(b, 'base64');
    } catch {
      return res.status(400).json({ e: 'invalid base64 body' });
    }
  }

  // ── ۹. Fetch با timeout 25s (کمتر از GAS timeout 30s) ────────────
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25_000);

  try {
    const upstream = await fetch(targetUrl.toString(), {
      method,
      headers,
      body: ['GET', 'HEAD'].includes(method) ? undefined : reqBody,
      redirect: r === false ? 'manual' : 'follow',
      signal: controller.signal,
    });

    clearTimeout(timer);

    // ── ۱۰. چک حجم response قبل از خوندن ─────────────────────────────
    const cl = parseInt(upstream.headers.get('content-length') || '0', 10);
    if (cl > MAX_BODY_SIZE) {
      return res.status(413).json({ e: 'response too large' });
    }

    // ── ۱۱. خوندن body ────────────────────────────────────────────────
    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > MAX_BODY_SIZE) {
      return res.status(413).json({ e: 'response too large' });
    }

    // ── ۱۲. جمع‌آوری response headers ──────────────────────────────────
    const respHeaders = {};
    upstream.headers.forEach((v, k) => { respHeaders[k] = v; });

    // ── ۱۳. خروجی — فرمت دقیق mhr-cfw: { s, h, b } ────────────────────
    return res.json({
      s: upstream.status,
      h: respHeaders,
      b: buf.toString('base64'),
    });

  } catch (err) {
    clearTimeout(timer);

    if (err.name === 'AbortError') {
      return res.status(504).json({ e: 'upstream timeout' });
    }

    const code = err.cause?.code;
    if (code === 'ECONNREFUSED') return res.status(502).json({ e: 'connection refused' });
    if (code === 'ENOTFOUND')    return res.status(502).json({ e: 'dns lookup failed' });
    if (code === 'ETIMEDOUT')    return res.status(504).json({ e: 'connection timeout' });

    console.error('[relay] fetch error:', err.message);
    return res.status(502).json({ e: 'fetch failed' });
  }
});

// ─── 404 ──────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ e: 'not found' }));

// ─── Start ────────────────────────────────────────────────────────
const server = app.listen(+PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ┌──────────────────────────────────────┐');
  console.log('  │   GR  GERMANY Relay — mhr-cfw        │');
  console.log('  └──────────────────────────────────────┘');
  console.log('  Port   : ' + PORT);
  console.log('  Node   : ' + process.version);
  console.log('  Auth   : ' + (API_KEY !== 'changeme' ? '✅ configured' : '⚠️  CHANGE API_KEY!'));
  console.log('  Health : http://localhost:' + PORT + '/health');
  console.log('');
  if (API_KEY === 'changeme') {
    console.log('  ⚠️  WARNING: API_KEY is default — set it in environment!');
    console.log('');
  }
});

// ─── Graceful Shutdown ────────────────────────────────────────────
const shutdown = (sig) => {
  console.log('\n  ' + sig + ' — shutting down...');
  server.close(() => {
    console.log('  Server closed.');
    process.exit(0);
  });
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
