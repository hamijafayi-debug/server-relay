// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server for mhr-cfw (SECURE VERSION)
// سازگار ۱۰۰٪ با mhr-cfw Python client
// بهینه‌شده برای سرعت و امنیت — جلوگیری از نشت IP و Headers
// Node.js 18+ (fetch داخلی)
// ═══════════════════════════════════════════════════════════════════

import express from 'express';
import dns from 'node:dns';

// اجبار به استفاده از IPv4 برای جلوگیری از نشت اطلاعات در شبکه IPv6
dns.setDefaultResultOrder('ipv4first');

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

const ALLOWED_METHODS = new Set([
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS',
]);

const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50MB — کافی برای هر chunk

// ─── Middleware ────────────────────────────────────────────────────
// جلوگیری قطعی از اضافه شدن هدرهای x-forwarded-* توسط Express
app.set("trust proxy", false);

app.use(express.json({ limit: "20mb" }));

// ─── Health Check ─────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    server: 'france-relay-secure',
    node: process.version,
    uptime: Math.floor(process.uptime()),
    ts: Date.now(),
  });
});

// ─── Main Relay Endpoint ──────────────────────────────────────────
app.post('/', async (req, res) => {

  // ── ۱. احراز هویت ────────────────────────────────────────────────
  const key = req.body?.k || req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    return res.status(401).json({ e: 'unauthorized' });
  }

  // ── ۲. پارامترها ──────────────────────────────────────────────────
  const { u, m, h, b, ct, r } = req.body;

  if (!u || typeof u !== 'string') {
    return res.status(400).json({ e: 'missing url' });
  }

  // ── ۳. URL validation ─────────────────────────────────────────────
  let targetUrl;
  try {
    targetUrl = new URL(u);
  } catch {
    return res.status(400).json({ e: 'invalid url' });
  }

  if (!['http:', 'https:'].includes(targetUrl.protocol)) {
    return res.status(400).json({ e: 'protocol not allowed' });
  }

  // ── ۴. Method ─────────────────────────────────────────────────────
  const method = (m || 'GET').toUpperCase();
  if (!ALLOWED_METHODS.has(method)) {
    return res.status(400).json({ e: 'method not allowed' });
  }

  // ── ۵. Headers (رویکرد لیست سفید برای امنیت ۱۰۰٪) ─────────────────
  const headers = {};
  
  // لیست سفید: فقط این هدرهای استاندارد مرورگر اجازه عبور دارند
  const WHITELIST = new Set([
    'accept', 'accept-encoding', 'accept-language', 'authorization',
    'cache-control', 'cookie', 'origin', 'referer', 'user-agent',
    'dnt', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
    'upgrade-insecure-requests'
  ]);

  if (h && typeof h === 'object') {
    for (const [k, v] of Object.entries(h)) {
      const lowerKey = k.toLowerCase();
      // فقط هدرهایی کپی می‌شوند که در لیست سفید بالا باشند
      if (WHITELIST.has(lowerKey)) {
        headers[lowerKey] = v;
      }
    }
  }

  // تنظیم محتوا
  if (ct && typeof ct === 'string') {
    headers['content-type'] = ct;
  } else if (b && !headers['content-type']) {
    headers['content-type'] = 'application/octet-stream';
  }

  // اجبار به عدم استفاده از Keep-Alive برای کاهش ریسک ردیابی کانکشن
  headers['connection'] = 'close';

  // ── ۶. Body decode (base64 → Buffer) ─────────────────────────────
  let reqBody;
  if (b && typeof b === 'string') {
    try {
      reqBody = Buffer.from(b, 'base64');
    } catch {
      return res.status(400).json({ e: 'invalid base64 body' });
    }
  }

  // توقف لاگ‌گیری: کدهای لاگ‌گیری حذف شدند تا کوکی‌ها و API Key لو نروند

  // ── ۷. Fetch با timeout 25s ───────────────────────────────────────
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

    // ── ۸. چک content-length قبل از خوندن ───────────────────────────
    const cl = parseInt(upstream.headers.get('content-length') || '0', 10);
    if (cl > MAX_BODY_SIZE) {
      return res.status(413).json({ e: 'response too large' });
    }

    // ── ۹. خوندن body ─────────────────────────────────────────────────
    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > MAX_BODY_SIZE) {
      return res.status(413).json({ e: 'response too large' });
    }

    // ── ۱۰. جمع‌آوری response headers ─────────────────────────────────
    const respHeaders = {};
    upstream.headers.forEach((v, k) => { respHeaders[k] = v; });

    // ── ۱۱. خروجی — فرمت دقیق mhr-cfw: { s, h, b } ───────────────────
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
  console.log('  │   🇫🇷 France Relay (Secure) — mhr-cfw │');
  console.log('  └──────────────────────────────────────┘');
  console.log('  Port   : ' + PORT);
  console.log('  Node   : ' + process.version);
  console.log('  Auth   : ' + (API_KEY !== 'changeme' ? '✅ configured' : '⚠️  CHANGE API_KEY!'));
  console.log('  Health : http://localhost:' + PORT + '/health');
  console.log('');
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
