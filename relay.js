// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server (Streaming & Long-Polling Edition)
// ═══════════════════════════════════════════════════════════════════

import express from 'express';
import crypto from 'crypto';

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

const BLOCKED_HEADERS = new Set([
  'host', 'connection', 'transfer-encoding', 'content-length', 'x-relay-hop',
  'x-fwd-hop', 'proxy-authorization', 'x-forwarded-for', 'x-forwarded-host',
  'x-forwarded-proto', 'forwarded', 'via',
]);

const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50MB

const sessions = new Map();
const SESSION_TIMEOUT = 60 * 1000;

// Garbage Collector برای جلوگیری از Memory Leak
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions.entries()) {
    if (now - session.lastAccessed > SESSION_TIMEOUT) {
      sessions.delete(id);
    }
  }
}, 10000);

app.set('trust proxy', false);
app.use(express.json({ limit: '20mb' }));

// ── روت Health Check برای Coolify و Docker ──
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', streaming: 'active' });
});

app.post('/', async (req, res) => {
  if (req.headers['x-relay-hop'] === '1') return res.status(508).json({ e: 'loop detected' });

  const key = req.body?.k || req.headers['x-api-key'];
  if (!key || key !== API_KEY) return res.status(401).json({ e: 'unauthorized' });

  // ── ۱. هندل کردن Long-Polling ──────────────────────────────────────
  if (req.body.poll_session_id) {
    const session = sessions.get(req.body.poll_session_id);
    if (!session) return res.status(404).json({ e: 'session expired or invalid' });

    session.lastAccessed = Date.now();

    // Long Polling: اگر چانکی نداریم و استریم باز است، تا 15 ثانیه منتظر می‌مانیم
    // این کار مصرف Quota در GAS را به شدت کاهش می‌دهد
    let waited = 0;
    while (session.chunks.length === 0 && !session.done && waited < 15000) {
      await new Promise(r => setTimeout(r, 250));
      waited += 250;
    }

    const chunks = session.chunks.splice(0, session.chunks.length);
    const responseData = { 
      s: 200, 
      session_id: req.body.poll_session_id, 
      chunks, 
      done: session.done,
      stream_error: session.error // ارسال ارور احتمالی قطعی
    };

    if (session.done && chunks.length === 0) sessions.delete(req.body.poll_session_id);
    return res.json(responseData);
  }

  // ── ۲. بررسی و آماده‌سازی درخواست اصلی ──────────────────────────────
  const { u, m, h, b, ct, r, stream } = req.body;
  if (!u || typeof u !== 'string') return res.status(400).json({ e: 'missing url' });

  let targetUrl;
  try { targetUrl = new URL(u); } catch { return res.status(400).json({ e: 'invalid url' }); }

  const method = (m || 'GET').toUpperCase();
  if (!ALLOWED_METHODS.has(method)) return res.status(400).json({ e: 'method not allowed' });

  const headers = {};
  if (h && typeof h === 'object') {
    for (const [k, v] of Object.entries(h)) {
      if (typeof k === 'string' && typeof v === 'string' && !BLOCKED_HEADERS.has(k.toLowerCase())) {
        headers[k] = v;
      }
    }
  }
  if (ct && typeof ct === 'string') headers['content-type'] = ct;
  else if (b && !headers['content-type']) headers['content-type'] = 'application/octet-stream';

  let reqBody;
  if (b && typeof b === 'string') {
    try { reqBody = Buffer.from(b, 'base64'); } catch { return res.status(400).json({ e: 'invalid base64 body' }); }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 25_000); // تایم‌اوت اتصال اولیه

  try {
    const upstream = await fetch(targetUrl.toString(), {
      method,
      headers,
      body: ['GET', 'HEAD'].includes(method) ? undefined : reqBody,
      redirect: r === false ? 'manual' : 'follow',
      signal: controller.signal,
    });

    clearTimeout(timer); // کانکشن برقرار شد، تایم‌اوت باطل می‌شود

    // ── ۳. پردازش حالت Streaming (بدون اختلال در RAM) ──────────────────
    if (stream) {
      const sessionId = crypto.randomUUID();
      sessions.set(sessionId, { chunks: [], done: false, lastAccessed: Date.now(), error: null });

      (async () => {
        try {
          if (!upstream.body) {
              sessions.get(sessionId).done = true;
              return;
          }
          const reader = upstream.body.getReader();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            const session = sessions.get(sessionId);
            if (!session) break; // سشن بخاطر تایم‌اوت بسته شده
            
            // تبدیل امن بایت‌ها به Base64
            session.chunks.push(Buffer.from(value).toString('base64'));
          }
        } catch (err) {
          const session = sessions.get(sessionId);
          if (session) session.error = err.message;
        } finally {
          const session = sessions.get(sessionId);
          if (session) session.done = true;
        }
      })();

      // ── مکث اولیه تطبیق‌پذیر (Adaptive Wait) ──
      // به جای 1 ثانیه صبر مطلق، تا زمانی که اولین چانک آماده شود (نهایت 2 ثانیه) چک می‌کنیم
      let waitedInit = 0;
      while (
        sessions.get(sessionId)?.chunks.length === 0 && 
        !sessions.get(sessionId)?.done && 
        waitedInit < 2000
      ) {
        await new Promise(r => setTimeout(r, 100)); // هر 100 میلی‌ثانیه وضعیت را چک کن
        waitedInit += 100;
      }
      // ──────────────────────────────────────────
      
      const session = sessions.get(sessionId);
      const chunks = session ? session.chunks.splice(0, session.chunks.length) : [];
      const respHeaders = {};
      upstream.headers.forEach((v, k) => { respHeaders[k] = v; });

      return res.json({
        s: upstream.status,
        h: respHeaders,
        session_id: sessionId,
        chunks: chunks,
        done: session ? session.done : true
      });
    }

    // ── ۴. پردازش حالت عادی (غیر استریم) ──────────────────────────────
    const cl = parseInt(upstream.headers.get('content-length') || '0', 10);
    if (cl > MAX_BODY_SIZE) return res.status(413).json({ e: 'response too large' });

    const buf = Buffer.from(await upstream.arrayBuffer());
    if (buf.length > MAX_BODY_SIZE) return res.status(413).json({ e: 'response too large' });

    const respHeaders = {};
    upstream.headers.forEach((v, k) => { respHeaders[k] = v; });

    return res.json({ s: upstream.status, h: respHeaders, b: buf.toString('base64') });

  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') return res.status(504).json({ e: 'upstream timeout' });
    return res.status(502).json({ e: 'fetch failed', details: err.message });
  }
});

app.listen(+PORT, '0.0.0.0', () => console.log(`🇫🇷 Relay Active on port ${PORT} (Long-Polling Enabled)`));
