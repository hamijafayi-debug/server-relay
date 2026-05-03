// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server for mhr-cfw
// v2.0 — با فیلتر کامل هدرهای هویتی و امنیتی
// ═══════════════════════════════════════════════════════════════════

import express from 'express';

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

// ─── لیست سیاه: هدرهایی که هرگز نباید به upstream برسن ──────────
//
// BLOCKED_HEADERS_EXACT  → تطبیق دقیق (lowercase)
// BLOCKED_PREFIXES       → هر هدری که با این پیشوندها شروع شه حذف میشه
// ─────────────────────────────────────────────────────────────────

const BLOCKED_HEADERS_EXACT = new Set([
  // ── زیرساخت HTTP ──────────────────────────────────────────────
  'host',
  'connection',
  'keep-alive',
  'transfer-encoding',
  'content-length',         // fetch خودش محاسبه می‌کنه
  'te',
  'trailer',
  'upgrade',

  // ── پروکسی/relay identity ─────────────────────────────────────
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

  // ── احراز هویت / کوکی ─────────────────────────────────────────
  // 🚨 اینا مهم‌ترین بخشن — هویت کاربر گوگل رو لو میدن
  'cookie',
  'set-cookie',
  'authorization',

  // ── هدرهای اختصاصی گوگل (شناسه دستگاه/اکانت/session) ─────────
  'x-client-data',
  'x-goog-authuser',
  'x-goog-encode-response-if-executable',
  'x-goog-request-params',
  'x-goog-spatula',
  'x-goog-visitor-id',
  'x-google-apps-metadata',
  'x-origin',

  // ── هدرهای browser fingerprint ────────────────────────────────
  // Sec-Fetch-* اطلاعات context مرورگر رو می‌فرستن
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

  // ── هدرهای GAS/Apps Script خاص ────────────────────────────────
  'x-javascript-user-agent',
  'x-requested-with',
  'origin',                 // origin اصلی کلاینت رو پنهان کن
  'referer',               // منبع اصلی رو لو نده
]);

// هر هدری که با این پیشوندها شروع شه → حذف
const BLOCKED_PREFIXES = [
  'x-goog-',        // تمام هدرهای گوگل
  'x-google-',      // نسخه قدیمی‌تر هدرهای گوگل
  'x-firebase-',    // Firebase
  'sec-ch-',        // Client Hints
  'sec-fetch-',     // Fetch metadata
];

/**
 * بررسی می‌کنه که آیا یک هدر باید فیلتر بشه یا نه
 * @param {string} name - نام هدر (lowercase)
 * @returns {boolean} - true یعنی باید حذف بشه
 */
function isHeaderBlocked(name) {
  const lower = name.toLowerCase();

  // بررسی تطبیق دقیق
  if (BLOCKED_HEADERS_EXACT.has(lower)) return true;

  // بررسی پیشوندها
  for (const prefix of BLOCKED_PREFIXES) {
    if (lower.startsWith(prefix)) return true;
  }

  return false;
}

// ─── هدرهایی که relay خودش تنظیم می‌کنه (نه کلاینت) ─────────────
const RELAY_DEFAULT_HEADERS = {
  'user-agent': 'Mozilla/5.0 (compatible; relay/2.0)',
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
  });
});

// ─── Debug: نمایش هدرهای فیلترشده (فقط در dev mode) ─────────────
function logHeaderFiltering(rawHeaders, cleanHeaders) {
  if (process.env.NODE_ENV !== 'development') return;

  const rawKeys   = Object.keys(rawHeaders);
  const cleanKeys = Object.keys(cleanHeaders);
  const removed   = rawKeys.filter(k => !cleanKeys.includes(k));

  if (removed.length > 0) {
    console.log(`[relay] 🔒 فیلتر شد (${removed.length} هدر):`, removed.join(', '));
  }
  console.log(`[relay] ✅ ارسال به upstream (${cleanKeys.length} هدر):`, cleanKeys.join(', '));
}

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

  // ── ۵. Headers — فیلتر سه‌لایه ────────────────────────────────────
  //
  //  لایه ۱: شروع با هدرهای پیش‌فرض relay (نه کلاینت)
  //  لایه ۲: اضافه کردن هدرهای مجاز از کلاینت
  //  لایه ۳: اعمال content-type
  // ─────────────────────────────────────────────────────────────────

  // لایه ۱: هدرهای پایه relay
  const headers = { ...RELAY_DEFAULT_HEADERS };

  // لایه ۲: پردازش هدرهای ورودی از کلاینت
  const rawHeaders = (h && typeof h === 'object') ? h : {};

  for (const [name, value] of Object.entries(rawHeaders)) {
    // بررسی type safety
    if (typeof name !== 'string' || typeof value !== 'string') continue;

    // بررسی طول غیرعادی (محافظت از header injection)
    if (name.length > 100 || value.length > 8192) continue;

    // بررسی کاراکترهای غیرمجاز در نام هدر
    if (!/^[\w\-]+$/.test(name)) continue;

    // فیلتر اصلی
    if (!isHeaderBlocked(name)) {
      headers[name.toLowerCase()] = value;
    }
  }

  // لایه ۳: content-type (اولویت با مقدار صریح)
  if (ct && typeof ct === 'string') {
    headers['content-type'] = ct;
  } else if (b && !headers['content-type']) {
    headers['content-type'] = 'application/octet-stream';
  }

  // لاگ در dev mode
  logHeaderFiltering(rawHeaders, headers);

  // ── ۶. Body decode (base64 → Buffer) ─────────────────────────────
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

    // ── ۸. چک content-length ─────────────────────────────────────────
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
    //   set-cookie رو حذف می‌کنیم — کوکی upstream نباید به کلاینت اصلی برسه
    const respHeaders = {};
    upstream.headers.forEach((v, k) => {
      if (k !== 'set-cookie') {          // 🔒 جلوگیری از session hijack
        respHeaders[k] = v;
      }
    });

    // ── ۱۱. خروجی — { s, h, b } ──────────────────────────────────────
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
  console.log('  │   🇫🇷  France Relay v2.0 — mhr-cfw      │');
  console.log('  └──────────────────────────────────────────┘');
  console.log('  Port   : ' + PORT);
  console.log('  Node   : ' + process.version);
  console.log('  Auth   : ' + (API_KEY !== 'changeme' ? '✅ configured' : '⚠️  CHANGE API_KEY!'));
  console.log('  Filter : ✅ identity headers blocked');
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
