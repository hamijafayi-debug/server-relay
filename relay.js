// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server (FINAL SECURE VERSION)
// ═══════════════════════════════════════════════════════════════════

import express from 'express';
import dns from 'node:dns';

// ۱. اجبار به استفاده از IPv4 برای جلوگیری از نشت اطلاعات در شبکه IPv6[cite: 4]
dns.setDefaultResultOrder('ipv4first');

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50MB[cite: 4]

// ۲. جلوگیری از تزریق هدر توسط Express
app.set("trust proxy", false);
app.use(express.json({ limit: "20mb" }));

// --- Health Check ---
app.get('/health', (_req, res) => res.json({ ok: true, server: 'secure-relay' }));

// --- Main Relay Endpoint ---
app.post('/', async (req, res) => {

  // ۳. احراز هویت
  const key = req.body?.k || req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    return res.status(401).json({ e: 'unauthorized' });
  }

  // ۴. دریافت پارامترها
  const { u, m, h, b, ct, r } = req.body;
  if (!u) return res.status(400).json({ e: 'missing url' });

  // ۵. تطهیر هدرها با رویکرد لیست سفید (Whitelist)
  // این بخش باعث می‌شود هدرهای گوگل (via, forwarded) به مقصد نرسند.
  const cleanHeaders = {};
  const WHITELIST = new Set([
    'accept', 'accept-encoding', 'accept-language', 'authorization',
    'cache-control', 'cookie', 'origin', 'referer', 'user-agent',
    'dnt', 'sec-ch-ua', 'sec-ch-ua-mobile', 'sec-ch-ua-platform',
    'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site'
  ]);

  if (h && typeof h === 'object') {
    for (const [k, v] of Object.entries(h)) {
      const lowerKey = k.toLowerCase();
      if (WHITELIST.has(lowerKey)) {
        cleanHeaders[lowerKey] = v;
      }
    }
  }

  if (ct) cleanHeaders['content-type'] = ct;
  cleanHeaders['connection'] = 'close';

  // ۶. ارسال درخواست نهایی به اینترنت[cite: 5]
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25_000); // Timeout 25s[cite: 5]

  try {
    const method = (m || 'GET').toUpperCase();
    const upstream = await fetch(u, {
      method,
      headers: cleanHeaders,
      body: ['GET', 'HEAD'].includes(method) ? undefined : Buffer.from(b || '', 'base64'),
      redirect: r === false ? 'manual' : 'follow',
      signal: controller.signal,
    });

    clearTimeout(timer);

    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > MAX_BODY_SIZE) return res.status(413).json({ e: 'too large' });

    const respHeaders = {};
    upstream.headers.forEach((v, k) => { respHeaders[k] = v; });

    // ۷. بازگرداندن پاسخ به GAS[cite: 5]
    return res.json({
      s: upstream.status,
      h: respHeaders,
      b: buf.toString('base64'),
    });

  } catch (err) {
    clearTimeout(timer);
    return res.status(502).json({ e: 'fetch failed', msg: err.message });
  }
});

app.listen(+PORT, '0.0.0.0', () => {
  console.log(`🚀 Secure Relay is running on port ${PORT}`);
});
