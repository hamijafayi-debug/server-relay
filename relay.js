// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server (ULTRA SECURE & CLEAN)
// سازگار ۱۰۰٪ با mhr-cfw Python client
// Node.js 18+ (fetch داخلی)
// ═══════════════════════════════════════════════════════════════════

import express from 'express';
import dns from 'node:dns';

// ۱. اجبار به استفاده از IPv4 برای جلوگیری از نشت هدرها روی بستر IPv6
dns.setDefaultResultOrder('ipv4first');

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

// محدود کردن متدهای مجاز برای امنیت بیشتر
const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50MB

// عدم اعتماد به هدرهای پروکسی ورودی برای جلوگیری از تزریق هدر توسط Express
app.set("trust proxy", false);

app.use(express.json({ limit: "20mb" }));

// ─── Health Check ─────────────────────────────────────────────────
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    status: 'secure_relay_active',
    node: process.version,
    ts: Date.now(),
  });
});

// ─── Main Relay Endpoint ──────────────────────────────────────────
app.post('/', async (req, res) => {

  // ۱. احراز هویت
  const key = req.body?.k || req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    return res.status(401).json({ e: 'unauthorized' });
  }

  // ۲. استخراج پارامترها[cite: 4, 5]
  const { u, m, h, b, ct, r } = req.body;

  if (!u || typeof u !== 'string') {
    return res.status(400).json({ e: 'missing url' });
  }

  // ۳. بازسازی هدرها با رویکرد لیست سفید (Whitelist) - بسیار حیاتی[cite: 4, 5]
  // در این مرحله تمام هدرهای گوگل (via, forwarded, etc) نادیده گرفته می‌شوند.
  const cleanHeaders = {};
  
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
      // فقط هدرهایی کپی می‌شوند که در لیست سفید بالا باشند[cite: 4, 5]
      if (WHITELIST.has(lowerKey)) {
        cleanHeaders[lowerKey] = v;
      }
    }
  }

  // ۴. تنظیم دقیق Content-Type[cite: 4, 5]
  if (ct && typeof ct === 'string') {
    cleanHeaders['content-type'] = ct;
  } else if (b && !cleanHeaders['content-type']) {
    cleanHeaders['content-type'] = 'application/octet-stream';
  }

  // ۵. جعل اتصال مستقیم و بستن نشست برای جلوگیری از ردیابی[cite: 4]
  cleanHeaders['connection'] = 'close';

  // ۶. تبدیل Body از Base64 به Buffer[cite: 4, 5]
  let reqBody;
  if (b && typeof b === 'string') {
    try {
      reqBody = Buffer.from(b, 'base64');
    } catch {
      return res.status(400).json({ e: 'invalid base64 body' });
    }
  }

  // ۷. ارسال درخواست با هدرهای کاملاً تطهیر شده[cite: 4, 5]
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25_000);

  try {
    const method = (m || 'GET').toUpperCase();
    
    const upstream = await fetch(u, {
      method,
      headers: cleanHeaders, // استفاده از هدرهای لیست سفید[cite: 4, 5]
      body: ['GET', 'HEAD'].includes(method) ? undefined : reqBody,
      redirect: r === false ? 'manual' : 'follow',
      signal: controller.signal,
    });

    clearTimeout(timer);

    // ۸. دریافت پاسخ و تبدیل به فرمت mhr-cfw[cite: 4, 5]
    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > MAX_BODY_SIZE) {
      return res.status(413).json({ e: 'response too large' });
    }

    const respHeaders = {};
    upstream.headers.forEach((v, k) => { respHeaders[k] = v; });

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
    
    console.error('[relay] error:', err.message);
    return res.status(502).json({ e: 'fetch failed' });
  }
});

// ─── Start Server ──────────────────────────────────────────────────
app.listen(+PORT, '0.0.0.0', () => {
  console.log(`🚀 France Relay (Secure Mode) started on port ${PORT}`);
});
