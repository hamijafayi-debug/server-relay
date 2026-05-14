// ═══════════════════════════════════════════════════════════════════
// relay.js — France Relay Server for mhr-cfw (Streaming Optimized)
// سازگار ۱۰۰٪ با mhr-cfw Python client
// Node.js 18+ 
// ═══════════════════════════════════════════════════════════════════

import express from 'express';

const app = express();
const { API_KEY = 'changeme', PORT = '3000' } = process.env;

const BLOCKED_HEADERS = new Set([
  'host', 'connection', 'transfer-encoding', 'content-length', 
  'x-relay-hop', 'x-fwd-hop', 'proxy-authorization',
  'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
  'forwarded', 'via',
]);

const ALLOWED_METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
const MAX_BODY_SIZE = 50 * 1024 * 1024; // 50MB

app.set('trust proxy', false);
app.use(express.json({ limit: '20mb' }));

app.get('/health', (_req, res) => {
  res.json({ ok: true, server: 'france-relay-streaming', node: process.version });
});

app.post('/', async (req, res) => {
  if (req.headers['x-relay-hop'] === '1' || req.headers['x-fwd-hop'] === '1') {
    return res.status(508).json({ e: 'loop detected' });
  }

  const key = req.body?.k || req.headers['x-api-key'];
  if (!key || key !== API_KEY) {
    return res.status(401).json({ e: 'unauthorized' });
  }

  const { u, m, h, b, ct, r } = req.body;
  if (!u || typeof u !== 'string') return res.status(400).json({ e: 'missing url' });

  let targetUrl;
  try {
    targetUrl = new URL(u);
  } catch {
    return res.status(400).json({ e: 'invalid url' });
  }

  if (!['http:', 'https:'].includes(targetUrl.protocol)) {
    return res.status(400).json({ e: 'protocol not allowed' });
  }

  const selfHost = req.headers['host'] || '';
  if (selfHost && targetUrl.hostname === selfHost.split(':')[0]) {
    return res.status(400).json({ e: 'self-fetch blocked' });
  }

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

  ['x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto', 'forwarded', 'via'].forEach(hdr => delete headers[hdr]);

  let reqBody;
  if (b && typeof b === 'string') {
    try {
      reqBody = Buffer.from(b, 'base64');
    } catch {
      return res.status(400).json({ e: 'invalid base64 body' });
    }
  }

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

    const cl = parseInt(upstream.headers.get('content-length') || '0', 10);
    if (cl > MAX_BODY_SIZE) return res.status(413).json({ e: 'response too large' });

    const respHeaders = {};
    upstream.headers.forEach((v, k) => { respHeaders[k] = v; });

    // ─── JSON Streaming Logic ──────────────────────────────────────────
    res.status(200).setHeader('Content-Type', 'application/json');
    res.write(`{"s":${upstream.status},"h":${JSON.stringify(respHeaders)},"b":"`);

    if (upstream.body) {
      let leftover = Buffer.alloc(0);
      for await (const chunk of upstream.body) {
        const combined = Buffer.concat([leftover, chunk]);
        const remainder = combined.length % 3;
        const processable = combined.subarray(0, combined.length - remainder);
        leftover = combined.subarray(combined.length - remainder);
        
        if (processable.length > 0) {
          res.write(processable.toString('base64'));
        }
      }
      if (leftover.length > 0) {
        res.write(leftover.toString('base64'));
      }
    }
    
    res.write('"}');
    res.end();

  } catch (err) {
    clearTimeout(timer);
    
    if (res.headersSent) {
      // اگر دیتا در حال استریم شدن بود و قطع شد، JSON را میبندیم تا کرش نکند
      res.end('"}');
      return;
    }

    if (err.name === 'AbortError') return res.status(504).json({ e: 'upstream timeout' });

    const code = err.cause?.code;
    if (code === 'ECONNREFUSED') return res.status(502).json({ e: 'connection refused' });
    if (code === 'ENOTFOUND')    return res.status(502).json({ e: 'dns lookup failed' });
    if (code === 'ETIMEDOUT')    return res.status(504).json({ e: 'connection timeout' });

    console.error('[relay] fetch error:', err.message);
    return res.status(502).json({ e: 'fetch failed' });
  }
});

app.use((_req, res) => res.status(404).json({ e: 'not found' }));

const server = app.listen(+PORT, '0.0.0.0', () => {
  console.log(`🚀 France Relay Stream mode active on port ${PORT}`);
});

const shutdown = (sig) => {
  server.close(() => process.exit(0));
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
