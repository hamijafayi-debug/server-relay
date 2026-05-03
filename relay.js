// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server for mhr-cfw
// v4.1 — بدون dependency خارجی، حل کامل نشت via و X-Forwarded-For
// فقط: express + node:http + node:https + node:dns
// ═══════════════════════════════════════════════════════════════════

import express  from 'express';
import dns      from 'node:dns';
import http     from 'node:http';
import https    from 'node:https';

// ── اول از همه: اجبار IPv4 ────────────────────────────────────────
dns.setDefaultResultOrder('ipv4first');

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50MB

// ════════════════════════════════════════════════════════════════════
// HTTP/HTTPS Agent — keepAlive:false + family:4
// ════════════════════════════════════════════════════════════════════

const HTTP_AGENT = new http.Agent({
  keepAlive : false,   // هر request یک connection جدید
  family    : 4,       // ← اجبار IPv4 در سطح socket
  timeout   : 25000,
});

const HTTPS_AGENT = new https.Agent({
  keepAlive          : false,
  family             : 4,    // ← اجبار IPv4 در سطح socket
  timeout            : 25000,
  rejectUnauthorized : true,
});

// ════════════════════════════════════════════════════════════════════
// فیلتر هدرها
// ════════════════════════════════════════════════════════════════════

const BLOCKED_EXACT = new Set([
  // زیرساخت HTTP
  'host', 'connection', 'keep-alive', 'transfer-encoding',
  'content-length', 'te', 'trailer', 'upgrade',

  // پروکسی / relay identity — مهم‌ترین بخش
  'proxy-authorization', 'proxy-connection', 'x-relay-hop',
  'x-forwarded-for',    // ← Google IP chain را حذف کن
  'x-forwarded-host',
  'x-forwarded-proto',
  'x-forwarded-port',
  'x-real-ip',
  'forwarded',
  'via',                // ← "1.1 google" را حذف کن

  // هویت گوگل
  'cookie', 'set-cookie', 'authorization',
  'x-client-data', 'x-goog-authuser',
  'x-goog-encode-response-if-executable',
  'x-goog-request-params', 'x-goog-spatula',
  'x-goog-visitor-id', 'x-google-apps-metadata',
  'x-origin', 'x-javascript-user-agent',
  'x-requested-with', 'origin', 'referer',

  // browser fingerprint
  'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-user',
  'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
  'sec-ch-ua-arch', 'sec-ch-ua-bitness', 'sec-ch-ua-full-version',
  'sec-ch-ua-full-version-list', 'sec-ch-ua-model',
  'sec-ch-ua-platform-version', 'sec-ch-ua-wow64',
]);

const BLOCKED_PREFIXES = [
  'x-goog-', 'x-google-', 'x-firebase-', 'sec-ch-', 'sec-fetch-',
];

function isBlocked(name) {
  const l = name.toLowerCase();
  if (BLOCKED_EXACT.has(l)) return true;
  for (const p of BLOCKED_PREFIXES) {
    if (l.startsWith(p)) return true;
  }
  return false;
}

// ════════════════════════════════════════════════════════════════════
// ساخت هدرهای تمیز
// ════════════════════════════════════════════════════════════════════

function buildHeaders(rawHeaders, ct, hasBody) {
  const out = {};

  // لایه ۱: هدرهای مجاز از کلاینت
  if (rawHeaders && typeof rawHeaders === 'object') {
    for (const [k, v] of Object.entries(rawHeaders)) {
      if (typeof k !== 'string' || typeof v !== 'string') continue;
      if (k.length > 100 || v.length > 8192)             continue;
      if (!/^[\w\-]+$/.test(k))                           continue;
      if (!isBlocked(k)) out[k.toLowerCase()] = v;
    }
  }

  // لایه ۲: content-type
  if (ct && typeof ct === 'string') {
    out['content-type'] = ct;
  } else if (hasBody && !out['content-type']) {
    out['content-type'] = 'application/octet-stream';
  }

  // لایه ۳: هدرهای اجباری relay — آخر اعمال میشن (override میکنن)
  out['connection']  = 'close';
  out['user-agent']  = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

  // لایه ۴: حذف صریح — دفاع آخر
  delete out['via'];
  delete out['forwarded'];
  delete out['x-forwarded-for'];
  delete out['x-forwarded-host'];
  delete out['x-forwarded-proto'];
  delete out['x-forwarded-port'];
  delete out['x-real-ip'];

  return out;
}

// ════════════════════════════════════════════════════════════════════
// relayFetch — با node:http/https مستقیم
// دلیل: fetch داخلی Node.js از agent پشتیبانی نمیکنه
//        و ما به family:4 در سطح socket نیاز داریم
// ════════════════════════════════════════════════════════════════════

function relayFetch(targetUrl, { method, headers, body, signal }) {
  return new Promise((resolve, reject) => {
    const parsed  = new URL(targetUrl);
    const isHttps = parsed.protocol === 'https:';
    const agent   = isHttps ? HTTPS_AGENT : HTTP_AGENT;
    const mod     = isHttps ? https : http;

    const options = {
      hostname : parsed.hostname,
      port     : parsed.port || (isHttps ? 443 : 80),
      path     : parsed.pathname + parsed.search,
      method   : method,
      headers  : headers,
      agent    : agent,
      timeout  : 25000,
    };

    const reqHandle = mod.request(options, (upstream) => {
      const chunks = [];
      let totalSize = 0;

      upstream.on('data', (chunk) => {
        totalSize += chunk.length;
        if (totalSize > MAX_BODY_SIZE) {
          reqHandle.destroy();
          reject(new Error('RESPONSE_TOO_LARGE'));
          return;
        }
        chunks.push(chunk);
      });

      upstream.on('end', () => {
        resolve({
          statusCode : upstream.statusCode,
          headers    : upstream.headers,
          body       : Buffer.concat(chunks),
        });
      });

      upstream.on('error', reject);
    });

    // ── signal (AbortController) ──────────────────────────────────
    if (signal) {
      signal.addEventListener('abort', () => {
        reqHandle.destroy();
        reject(Object.assign(new Error('AbortError'), { name: 'AbortError' }));
      }, { once: true });
    }

    reqHandle.on('timeout', () => {
      reqHandle.destroy();
      reject(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }));
    });

    reqHandle.on('error', reject);

    // ── body ─────────────────────────────────────────────────────
    if (body && !['GET', 'HEAD'].includes(method)) {
      reqHandle.write(body);
    }

    reqHandle.end();
  });
}

// ════════════════════════════════════════════════════════════════════
// Middleware
// ════════════════════════════════════════════════════════════════════

app.use(express.json({ limit: '20mb' }));

// ─── Health Check ─────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    ok     : true,
    server : 'france-relay',
    node   : process.version,
    uptime : Math.floor(process.uptime()),
    ts     : Date.now(),
    security: {
      ipv4_forced   : true,
      connection_close: true,
      via_stripped  : true,
      xff_stripped  : true,
    },
  });
});

// ════════════════════════════════════════════════════════════════════
// Main Relay Endpoint
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
  const ALLOWED_METHODS = new Set(['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS']);
  if (!ALLOWED_METHODS.has(method)) {
    return res.status(400).json({ e: 'method not allowed' });
  }

  // ── ۴. هدرها ──────────────────────────────────────────────────────
  const headers = buildHeaders(h || {}, ct, !!b);

  // ── ۵. Body ───────────────────────────────────────────────────────
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

  // ── ۶. Fetch ──────────────────────────────────────────────────────
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25_000);

  try {
    const upstream = await relayFetch(targetUrl.toString(), {
      method,
      headers,
      body  : reqBody,
      signal: controller.signal,
    });

    clearTimeout(timer);

    if (upstream.body.length > MAX_BODY_SIZE) {
      return res.status(413).json({ e: 'response too large' });
    }

    // ── response headers — بدون set-cookie ────────────────────────
    const respHeaders = {};
    for (const [k, v] of Object.entries(upstream.headers)) {
      if (k === 'set-cookie') continue;
      respHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
    }

    return res.json({
      s: upstream.statusCode,
      h: respHeaders,
      b: upstream.body.toString('base64'),
    });

  } catch (err) {
    clearTimeout(timer);

    if (err.name === 'AbortError')          return res.status(504).json({ e: 'upstream timeout' });
    if (err.message === 'RESPONSE_TOO_LARGE') return res.status(413).json({ e: 'response too large' });

    const code = err.code;
    if (code === 'ECONNREFUSED') return res.status(502).json({ e: 'connection refused' });
    if (code === 'ENOTFOUND')    return res.status(502).json({ e: 'dns lookup failed' });
    if (code === 'ETIMEDOUT')    return res.status(504).json({ e: 'connection timeout' });

    console.error('[relay] error:', err.message, err.code || '');
    return res.status(502).json({ e: 'fetch failed' });
  }
});

// ─── 404 ──────────────────────────────────────────────────────────
app.use((_req, res) => res.status(404).json({ e: 'not found' }));

// ─── Start ────────────────────────────────────────────────────────
const server = app.listen(+PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  ┌────────────────────────────────────────────┐');
  console.log('  │   🇫🇷  France Relay v4.1 — mhr-cfw        │');
  console.log('  └────────────────────────────────────────────┘');
  console.log('  Port      : ' + PORT);
  console.log('  Node      : ' + process.version);
  console.log('  Auth      : ' + (API_KEY !== 'changeme' ? '✅ configured' : '⚠️  CHANGE API_KEY!'));
  console.log('  IPv4-only : ✅ (dns + socket level)');
  console.log('  via       : ✅ stripped');
  console.log('  XFF       : ✅ stripped');
  console.log('  Conn-close: ✅');
  console.log('  undici    : ❌ not needed (pure node:http)');
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
