// ============================================
// kaerez/speedtest/worker.js
// ============================================
// * Author: Erez Kalman - KSEC
// * Repo: kaerez/speedtest
// * License: PolyForm Noncommercial 1.0.0 (Requires CLA)

// Import frontend assets as raw text modules
import html from './index.html';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// Security Headers (New)
const SECURITY_HEADERS = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
  'X-XSS-Protection': '1; mode=block'
};

// Security Constants
// Removed AUTH_COOKIE_NAME and COOKIE_TTL_MS as we are now stateless

const CHUNK_SIZE = 10 * 1024 * 1024;
const BUFFER = new Uint8Array(CHUNK_SIZE);
for (let i = 0; i < CHUNK_SIZE; i++) BUFFER[i] = i % 256;

const textEncoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // --- HELPER: Validate Token per Request ---
    async function validateRequest(req) {
      const token = req.headers.get('X-Cap-Token');
      if (!token) return false;

      try {
        const capRes = await env.CFCAP.fetch(new Request('https://cfcap/api/validate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token,
            keepToken: true
          })
        }));
        const res = await capRes.json();
        return res.success === true;
      } catch (e) {
        return false;
      }
    }

    // --- CAPTCHA VALIDATION (UI Check only) ---
    // Kept for UI feedback "Verification Successful", though technically redundant if every call is checked.
    if (path === '/api/verify' && request.method === 'POST') {
      try {
        const { token } = await request.json();

        const capRes = await env.CFCAP.fetch(new Request('https://cfcap/api/validate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token,
            keepToken: true
          })
        }));

        if (capRes.ok) {
          return new Response('{"success": true}', {
            headers: { 'Content-Type': 'application/json' }
          });
        } else {
          const errorText = await capRes.text();
          return new Response(JSON.stringify({ success: false, error: 'Captcha validation failed', details: errorText }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          });
        }
      } catch (e) {
        return new Response('{"error": "Validation error"}', { status: 500 });
      }
    }

    // 2. Logout / Session Cleanup
    if (path === '/api/logout' && request.method === 'POST') {
      try {
        const body = await request.clone().json().catch(() => ({}));
        if (body.token) {
          await env.CFCAP.fetch(new Request('https://cfcap/api/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              token: body.token
            })
          }));
        }
      } catch (e) {
        // Ignore errors during logout
      }
      return new Response('{"success": true}', {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // --- APP LOGIC (Protected API) ---

    // 3. Serve Frontend Structure (Root) - PUBLIC
    if (path === '/' || path === '/index.html') {
      return new Response(html, {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'no-cache',
          ...CORS_HEADERS,
          ...SECURITY_HEADERS
        },
      });
    }

    // 4. API Preflight
    if (request.method === 'OPTIONS') {
      const headers = { ...CORS_HEADERS };
      if (request.headers.get('Access-Control-Request-Headers')) {
        headers['Access-Control-Allow-Headers'] = request.headers.get('Access-Control-Request-Headers');
      }
      return new Response(null, { headers });
    }

    // 5. API: Ping (Latency) - PROTECTED
    if (path === '/api/ping') {
      if (!await validateRequest(request)) return new Response('Unauthorized', { status: 401 });
      return new Response('pong', {
        headers: {
          ...CORS_HEADERS,
          'Cache-Control': 'no-store',
          'Content-Type': 'text/plain'
        }
      });
    }

    // 6. API: Download Stream - PROTECTED
    if (path === '/api/down') {
      if (!await validateRequest(request)) return new Response('Unauthorized', { status: 401 });

      const bytes = Math.min(parseInt(url.searchParams.get('bytes') || '50000000'), 100000000);
      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();

      (async () => {
        let sent = 0;
        try {
          while (sent < bytes) {
            const toSend = Math.min(bytes - sent, CHUNK_SIZE);
            await writer.write(BUFFER.slice(0, toSend));
            sent += toSend;
          }
        } catch (e) {
          // Client disconnected
        } finally {
          await writer.close();
        }
      })();

      return new Response(readable, {
        headers: {
          ...CORS_HEADERS,
          'Content-Type': 'application/octet-stream',
          'Content-Length': bytes,
        },
      });
    }

    // 7. API: Upload Stream - PROTECTED
    if (path === '/api/up' && request.method === 'POST') {
      if (!await validateRequest(request)) return new Response('Unauthorized', { status: 401 });

      const startTime = Date.now();
      const reader = request.body.getReader();
      let receivedLength = 0;

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          receivedLength += value.length;
        }
      } catch (e) {
        // Stream error 
      }

      const duration = Date.now() - startTime;
      return new Response(JSON.stringify({
        bytesReceived: receivedLength,
        durationMs: duration
      }), {
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
      });
    }

    // 8. API: Metadata - PROTECTED
    if (path === '/api/meta') {
      if (!await validateRequest(request)) return new Response('Unauthorized', { status: 401 });

      const cf = request.cf || {};

      return new Response(JSON.stringify({
        ip: request.headers.get('cf-connecting-ip') || 'Unknown',
        city: cf.city || 'Unknown City',
        region: cf.region || cf.regionCode || '',
        country: cf.country || 'XX',
        asn: cf.asn || 'AS---',
        isp: cf.asOrganization || 'Unknown ISP',
        colo: cf.colo || 'Edge'
      }), {
        headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
