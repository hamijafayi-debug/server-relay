// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server for mhr-cfw
// v3.0 — با فیلتر کامل + IPv4-first + جلوگیری از نشت IP
// ═══════════════════════════════════════════════════════════════════

import express from 'express';
import dns from 'node:dns';

// ── اولین خط دفاعی: اجبار IPv4 قبل از هر چیز دیگه ───────────────
// گوگل روی IPv6 نشت ایجاد میکنه — این خط باید اول از همه باشه
dns.setDefaultResultOrder('ipv4first');

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

// ═══════════════════════════════════════════════════════════════════
// فیلتر هدرها
// ═══════════════════════════════════════════════════════════════════

const BLOCKED_HEADERS_EXACT = new Set([
  // ── زیرساخت HTTP ──────────────────────────────────────────────
  'host',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'content-length',
  'te',
  'trailer',
  'upgrade',

  // ── پروکسی / relay identity ───────────────────────────────────
  'proxy-authorization',
  'proxy-connection',
  'x-relay-hop',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-real-ip',
  'forwarded',
  'via',

  // ── احراز هویت / کوکی (مهم‌ترین بخش) ────────────────────────
  'cookie',
  'set-cookie',
  'authorization',

  // ── هدرهای اختصاصی گوگل ───────────────────────────────────────
  'x-client-data',
  'x-goog-authuser',
  'x-goog-encode-response-if-executable',
  'x-goog-request-params',
  'x-goog-spatula',
  'x-goog-visitor-id',
  'x-google-apps-metadata',
  'x-origin',

  // ── browser fingerprint ────────────────────────────────────────
  'sec-fetch-site',
  'sec-fetch-mode',
  'sec-fetch-dest',
  'sec-fetch-user',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
  'sec-ch-ua-arch',
  'sec-ch-ua-bitness',
  'sec-ch-ua-full-version',
  'sec-ch-ua-full-version-list',
  'sec-ch-ua-model',
  'sec-ch-ua-platform-version',
  'sec-ch-ua-wow64',

  // ── GAS خاص ───────────────────────────────────────────────────
  'x-javascript-user-agent',
  'x-requested-with',
  'origin',
  'referer',
]);

// هر هدری با این پیشوندها → حذف
const BLOCKED_PREFIXES = [
  'x-goog-',
  'x-google-',
  'x-firebase-',
  'sec-ch-',
  'sec-fetch-',
];

function isHeaderBlocked(name) {
  const lower = name.toLowerCase();
  if (BLOCKED_HEADERS_EXACT.has(lower)) return true;
  for (const prefix of BLOCKED_PREFIXES) {
    if (lower.startsWith(prefix)) return true;
  }
  return false;
}

// ═══════════════════════════════════════════════════════════════════
// هدرهای ثابت relay — جای هدرهای هویتی کلاینت رو میگیرن
// ═══════════════════════════════════════════════════════════════════

const RELAY_FIXED_HEADERS = {
  // ── مهم‌ترین: اجبار بستن connection بعد از هر درخواست ──────────
  // Keep-Alive میتونه هدرهای مشکوک رو در تونل نگه داره
  'connection': 'close',

  // ── user-agent بی‌طرف — نه گوگل، نه مرورگر خاص ──────────────
  'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
};

const ALLOWED_METHODS = new Set([
  'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS',
]);

const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50MB

// ─── Middleware ────────────────────────────────────────────────────
app.use(express.json({ limit: '20mb' }));

// ─── Health Check ─────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    server: 'france-relay',
    node: process.version,
    uptime: Math.floor(process.uptime()),
    ts: Date.now(),
    // نمایش تنظیمات امنیتی فعال
    security: {
      ipv4_forced: true,
      connection_close: true,
      identity_headers_blocked: true,
    },
  });
});

// ─── Dev Logger ───────────────────────────────────────────────────
function logHeaderFiltering(rawHeaders, cleanHeaders) {
  if (process.env.NODE_ENV !== 'development') return;

  const rawKeys   = Object.keys(rawHeaders);
  const cleanKeys = Object.keys(cleanHeaders);
  const removed   = rawKeys.filter(k => !cleanKeys.includes(k.toLowerCase()));

  if (removed.length > 0) {
    console.log(`[relay] 🔒 فیلترشده (${removed.length}):`, removed.join(', '));
  }
  console.log(`[relay] ✅ upstream (${cleanKeys.length}):`, cleanKeys.join(', '));
}

// ═══════════════════════════════════════════════════════════════════
// Main Relay Endpoint
// ═══════════════════════════════════════════════════════════════════

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

  // ── ۵. ساخت هدرها — سه لایه ──────────────────────────────────────
  //
  //  لایه ۱: هدرهای ثابت relay (connection:close + user-agent)
  //  لایه ۲: هدرهای مجاز از کلاینت (بعد از فیلتر)
  //  لایه ۳: content-type
  //
  //  ⚠️  ترتیب مهمه: لایه ۱ آخر اعمال میشه
  //     تا کلاینت نتونه connection رو override کنه
  // ─────────────────────────────────────────────────────────────────

  // لایه ۲: هدرهای فیلترشده کلاینت
  const clientHeaders = {};
  const rawHeaders = (h && typeof h === 'object') ? h : {};

  for (const [name, value] of Object.entries(rawHeaders)) {
    if (typeof name !== 'string' || typeof value !== 'string') continue;
    if (name.length > 100 || value.length > 8192) continue;
    if (!/^[\w\-]+$/.test(name)) continue;

    if (!isHeaderBlocked(name)) {
      clientHeaders[name.toLowerCase()] = value;
    }
  }

  // لایه ۳: content-type
  if (ct && typeof ct === 'string') {
    clientHeaders['content-type'] = ct;
  } else if (b && !clientHeaders['content-type']) {
    clientHeaders['content-type'] = 'application/octet-stream';
  }

  // ترکیب نهایی: لایه ۱ آخر — تا هدرهای relay override نشن
  // connection: 'close' اینجا قطعی میشه
  const headers = {
    ...clientHeaders,
    ...RELAY_FIXED_HEADERS,   // ← این همیشه آخره — override میکنه
  };

  logHeaderFiltering(rawHeaders, headers);

  // ── ۶. Body decode ────────────────────────────────────────────────
  let reqBody;
  if (b && typeof b === 'string') {
    try {
      reqBody = Buffer.from(b, 'base64');
      if (reqBody.length > MAX_BODY_SIZE) {
        return res.status(413).json({ e: 'request body too large' });
      }
    } catch {
      return res.status(400).json({ e: 'invalid base64 body' });
    }
  }

  // ── ۷. Fetch ──────────────────────────────────────────────────────
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25_000);

  try {
    const upstream = await fetch(targetUrl.toString(), {
      method,
      headers,
      body  : ['GET', 'HEAD'].includes(method) ? undefined : reqBody,
      // ── مهم: keepalive را خاموش کن ──────────────────────────────
      // با connection:close در هدر کافیه، ولی این هم اضافه میشه
      keepalive: false,
      redirect : r === false ? 'manual' : 'follow',
      signal   : controller.signal,
    });

    clearTimeout(timer);

    // ── ۸. چک سایز ───────────────────────────────────────────────────
    const cl = parseInt(upstream.headers.get('content-length') || '0', 10);
    if (cl > MAX_BODY_SIZE) {
      return res.status(413).json({ e: 'response too large' });
    }

    // ── ۹. خوندن body ─────────────────────────────────────────────────
    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > MAX_BODY_SIZE) {
      return res.status(413).json({ e: 'response too large' });
    }

    // ── ۱۰. response headers ──────────────────────────────────────────
    // set-cookie رو فیلتر میکنیم — جلوگیری از session hijack
    const respHeaders = {};
    upstream.headers.forEach((v, k) => {
      if (k !== 'set-cookie') {
        respHeaders[k] = v;
      }
    });

    // ── ۱۱. خروجی ────────────────────────────────────────────────────
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
  console.log('  ┌──────────────────────────────────────────┐');
  console.log('  │   🇫🇷  France Relay v3.0 — mhr-cfw      │');
  console.log('  └──────────────────────────────────────────┘');
  console.log('  Port      : ' + PORT);
  console.log('  Node      : ' + process.version);
  console.log('  Auth      : ' + (API_KEY !== 'changeme' ? '✅ configured' : '⚠️  CHANGE API_KEY!'));
  console.log('  IPv4-first: ✅ فعال (جلوگیری از نشت IPv6)');
  console.log('  Conn-close: ✅ فعال (بستن تونل بعد هر req)');
  console.log('  Headers   : ✅ فیلتر کامل هدرهای هویتی');
  console.log('  Health    : http://localhost:' + PORT + '/health');
  console.log('');
  if (API_KEY === 'changeme') {
    console.log('  ⚠️  WARNING: API_KEY is default!');
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
