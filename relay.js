// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server for mhr-cfw
// v4.0 — حل کامل نشت X-Forwarded-For و via
// ═══════════════════════════════════════════════════════════════════

import express from 'express';
import dns from 'node:dns';
import { createServer } from 'node:https';
import { Agent } from 'node:https';
import { Agent as HttpAgent } from 'node:http';

// ── اول از همه: اجبار IPv4 ────────────────────────────────────────
dns.setDefaultResultOrder('ipv4first');

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

// ── Custom HTTP/HTTPS Agent ────────────────────────────────────────
// این مهمه — Agent جداگانه برای کنترل دقیق connection
const httpsAgent = new Agent({
  keepAlive: false,      // هر request یک connection جدید
  timeout: 25000,
  family: 4,             // ← اجبار IPv4 در سطح socket
});

const httpAgent = new HttpAgent({
  keepAlive: false,
  timeout: 25000,
  family: 4,             // ← اجبار IPv4 در سطح socket
});

// ════════════════════════════════════════════════════════════════════
// فیلتر هدرها
// ════════════════════════════════════════════════════════════════════

const BLOCKED_HEADERS_EXACT = new Set([
  'host', 'connection', 'keep-alive', 'transfer-encoding',
  'content-length', 'te', 'trailer', 'upgrade',
  'proxy-authorization', 'proxy-connection', 'x-relay-hop',

  // ── اینا مهم‌ترین هستن برای جلوگیری از نشت ──────────────────
  'x-forwarded-for',    // ← Google IP chain
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-real-ip',
  'forwarded',
  'via',                // ← "1.1 google" را حذف کن

  // ── هویت گوگل ─────────────────────────────────────────────────
  'cookie', 'set-cookie', 'authorization',
  'x-client-data', 'x-goog-authuser',
  'x-goog-encode-response-if-executable',
  'x-goog-request-params', 'x-goog-spatula',
  'x-goog-visitor-id', 'x-google-apps-metadata',
  'x-origin', 'x-javascript-user-agent',
  'x-requested-with', 'origin', 'referer',

  // ── browser fingerprint ────────────────────────────────────────
  'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest',
  'sec-fetch-user', 'sec-ch-ua', 'sec-ch-ua-mobile',
  'sec-ch-ua-platform', 'sec-ch-ua-arch', 'sec-ch-ua-bitness',
  'sec-ch-ua-full-version', 'sec-ch-ua-full-version-list',
  'sec-ch-ua-model', 'sec-ch-ua-platform-version', 'sec-ch-ua-wow64',
]);

const BLOCKED_PREFIXES = [
  'x-goog-', 'x-google-', 'x-firebase-', 'sec-ch-', 'sec-fetch-',
];

function isHeaderBlocked(name) {
  const lower = name.toLowerCase();
  if (BLOCKED_HEADERS_EXACT.has(lower)) return true;
  for (const p of BLOCKED_PREFIXES) {
    if (lower.startsWith(p)) return true;
  }
  return false;
}

// ════════════════════════════════════════════════════════════════════
// هدرهای ثابت relay
// هر چیزی که اینجاست، override میکنه هدرهای کلاینت را
// ════════════════════════════════════════════════════════════════════

function buildCleanHeaders(clientHeaders, ct, hasBody) {
  // ── لایه ۱: هدرهای مجاز از کلاینت ──────────────────────────────
  const headers = {};
  for (const [name, value] of Object.entries(clientHeaders)) {
    if (typeof name !== 'string' || typeof value !== 'string') continue;
    if (name.length > 100 || value.length > 8192) continue;
    if (!/^[\w\-]+$/.test(name)) continue;
    if (!isHeaderBlocked(name)) {
      headers[name.toLowerCase()] = value;
    }
  }

  // ── لایه ۲: content-type ─────────────────────────────────────────
  if (ct && typeof ct === 'string') {
    headers['content-type'] = ct;
  } else if (hasBody && !headers['content-type']) {
    headers['content-type'] = 'application/octet-stream';
  }

  // ── لایه ۳: هدرهای اجباری relay — اینا آخر اعمال میشن ──────────
  // هیچ چیزی نمیتونه اینا رو override کنه
  headers['connection']       = 'close';
  headers['user-agent']       = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

  // ── صریحاً حذف: مطمئن میشیم این هدرها وجود ندارن ───────────────
  delete headers['via'];
  delete headers['forwarded'];
  delete headers['x-forwarded-for'];
  delete headers['x-forwarded-host'];
  delete headers['x-forwarded-proto'];
  delete headers['x-forwarded-port'];
  delete headers['x-real-ip'];

  return headers;
}

// ════════════════════════════════════════════════════════════════════
// Custom fetch با agent کنترل‌شده
// Node.js built-in fetch از agent پشتیبانی نمیکنه
// از undici که داخل Node.js 18+ هست استفاده میکنیم
// ════════════════════════════════════════════════════════════════════

import { request as undiciRequest } from 'undici';

async function relayFetch(url, { method, headers, body, signal }) {
  const parsed = new URL(url);

  const result = await undiciRequest(url, {
    method,
    headers,
    body: body || null,
    signal,
    maxRedirections: 10,

    // ── مهم‌ترین بخش: کنترل connection ───────────────────────────
    headersTimeout: 25000,
    bodyTimeout: 25000,

    // اجبار IPv4 در سطح undici
    connect: {
      rejectUnauthorized: false,
      // undici از این تنظیم برای انتخاب IP family استفاده میکنه
      lookup: (hostname, options, callback) => {
        // اجبار IPv4
        const dnsOptions = { ...options, family: 4 };
        dns.lookup(hostname, dnsOptions, callback);
      },
    },
  });

  return result;
}

// ════════════════════════════════════════════════════════════════════
// Middleware
// ════════════════════════════════════════════════════════════════════

app.use(express.json({ limit: '20mb' }));

// ─── Health Check ─────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    server: 'france-relay',
    node: process.version,
    uptime: Math.floor(process.uptime()),
    ts: Date.now(),
    security: {
      ipv4_forced:              true,
      connection_close:         true,
      identity_headers_blocked: true,
      via_header_stripped:      true,
      forwarded_stripped:       true,
    },
  });
});

// ════════════════════════════════════════════════════════════════════
// Main Relay
// ════════════════════════════════════════════════════════════════════

app.post('/', async (req, res) => {

  // ── ۱. احراز هویت ────────────────────────────────────────────────
  const key = req.body?.k || req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    return res.status(401).json({ e: 'unauthorized' });
  }

  const { u, m, h, b, ct, r } = req.body;

  // ── ۲. URL validation ─────────────────────────────────────────────
  if (!u || typeof u !== 'string') {
    return res.status(400).json({ e: 'missing url' });
  }

  let targetUrl;
  try {
    targetUrl = new URL(u);
  } catch {
    return res.status(400).json({ e: 'invalid url' });
  }

  if (!['http:', 'https:'].includes(targetUrl.protocol)) {
    return res.status(400).json({ e: 'protocol not allowed' });
  }

  // ── ۳. Method ─────────────────────────────────────────────────────
  const method = (m || 'GET').toUpperCase();
  const ALLOWED = new Set(['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS']);
  if (!ALLOWED.has(method)) {
    return res.status(400).json({ e: 'method not allowed' });
  }

  // ── ۴. ساخت هدرهای تمیز ──────────────────────────────────────────
  const rawHeaders = (h && typeof h === 'object') ? h : {};
  const headers = buildCleanHeaders(rawHeaders, ct, !!b);

  // ── ۵. Body ───────────────────────────────────────────────────────
  const MAX = 50 * 1024 * 1024;
  let reqBody;
  if (b && typeof b === 'string') {
    try {
      reqBody = Buffer.from(b, 'base64');
      if (reqBody.length > MAX) {
        return res.status(413).json({ e: 'request body too large' });
      }
    } catch {
      return res.status(400).json({ e: 'invalid base64 body' });
    }
  }

  // ── ۶. Fetch ──────────────────────────────────────────────────────
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25_000);

  try {
    const upstream = await relayFetch(targetUrl.toString(), {
      method,
      headers,
      body  : ['GET', 'HEAD'].includes(method) ? undefined : reqBody,
      signal: controller.signal,
    });

    clearTimeout(timer);

    // ── ۷. Response ───────────────────────────────────────────────────
    const chunks = [];
    for await (const chunk of upstream.body) {
      chunks.push(chunk);
    }
    const buf = Buffer.concat(chunks);

    if (buf.length > MAX) {
      return res.status(413).json({ e: 'response too large' });
    }

    // ── ۸. Response headers — بدون set-cookie ────────────────────────
    const respHeaders = {};
    for (const [k, v] of Object.entries(upstream.headers)) {
      if (k !== 'set-cookie') {
        respHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
      }
    }

    return res.json({
      s: upstream.statusCode,
      h: respHeaders,
      b: buf.toString('base64'),
    });

  } catch (err) {
    clearTimeout(timer);

    if (err.name === 'AbortError') {
      return res.status(504).json({ e: 'upstream timeout' });
    }

    const code = err.code;
    if (code === 'ECONNREFUSED') return res.status(502).json({ e: 'connection refused' });
    if (code === 'ENOTFOUND')    return res.status(502).json({ e: 'dns lookup failed' });
    if (code === 'ETIMEDOUT')    return res.status(504).json({ e: 'connection timeout' });
    if (code === 'UND_ERR_CONNECT_TIMEOUT') return res.status(504).json({ e: 'connect timeout' });

    console.error('[relay] error:', err.message, err.code);
    return res.status(502).json({ e: 'fetch failed' });
  }
});

// ─── 404 ──────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ e: 'not found' }));

// ─── Start ────────────────────────────────────────────────────────
const server = app.listen(+PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ┌────────────────────────────────────────────┐');
  console.log('  │   🇫🇷  France Relay v4.0 — mhr-cfw        │');
  console.log('  └────────────────────────────────────────────┘');
  console.log('  Port         : ' + PORT);
  console.log('  Node         : ' + process.version);
  console.log('  Auth         : ' + (API_KEY !== 'changeme' ? '✅' : '⚠️  CHANGE API_KEY!'));
  console.log('  IPv4-only    : ✅ (dns + socket level)');
  console.log('  via stripped : ✅');
  console.log('  XFF stripped : ✅');
  console.log('  Conn-close   : ✅');
  console.log('');
});

const shutdown = (sig) => {
  console.log('\n  ' + sig + ' received...');
  server.close(() => process.exit(0));
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
