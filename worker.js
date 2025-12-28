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
const AUTH_COOKIE_NAME = 'KSEC_AUTH';
// 90 seconds expiration
const COOKIE_TTL_MS = 90 * 1000;

// In-Memory Session Storage (UUID -> Expiration Timestamp)
// WARNING: This is ephemeral and local to the Worker isolate.
const SESSIONS = new Map();

const CHUNK_SIZE = 10 * 1024 * 1024;
const BUFFER = new Uint8Array(CHUNK_SIZE);
for (let i = 0; i < CHUNK_SIZE; i++) BUFFER[i] = i % 256;

const textEncoder = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cookieHeader = request.headers.get('Cookie') || '';

    // Normalize CAPTCHA_API_URL (Option B) - Strip trailing slashes
    const capApiBase = env.CAPTCHA_API_URL ? env.CAPTCHA_API_URL.replace(/\/+$/, '') : null;

    // --- CAPTCHA VALIDATION ---

    // 1. Validate CapJS Token
    if (path === '/api/verify' && request.method === 'POST') {
      try {
        const { token } = await request.json();

        // Validate with CapJS
        // 1. Check for custom API URL (e.g. external or simplified) (env.CAPTCHA_API_URL)
        // 2. Fallback to Service Binding (env.CFCAP)
        let capRes;
        if (capApiBase) {
          capRes = await fetch(`${capApiBase}/validate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, keepToken: true })
          });
        } else {
          capRes = await env.CFCAP.fetch(new Request('https://cfcap/api/validate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              token,
              keepToken: true
            })
          }));
        }

        if (capRes.ok) {
          // Success: Generate UUID and store in memory
          const sessionId = crypto.randomUUID();
          const expiration = Date.now() + COOKIE_TTL_MS;
          SESSIONS.set(sessionId, expiration);

          return new Response('{"success": true}', {
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie': `${AUTH_COOKIE_NAME}=${sessionId}; HttpOnly; Secure; SameSite=Strict; Max-Age=90; Path=/`
            }
          });
        } else {
          const errorText = await capRes.text();
          console.error('CapJS Validation Failed:', capRes.status, errorText);
          return new Response(JSON.stringify({ success: false, error: 'Captcha validation failed', details: errorText, status: capRes.status }), {
            status: 403,
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie': `${AUTH_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`
            }
          });
        }
      } catch (e) {
        return new Response('{"error": "Validation error"}', { status: 500 });
      }
    }

    // 2. Logout / Session Cleanup
    if (path === '/api/logout' && request.method === 'POST') {
      // 1. Cleanup In-Memory Session
      if (cookieHeader) {
        const cookie = cookieHeader.split(';').find(c => c.trim().startsWith(`${AUTH_COOKIE_NAME}=`));
        if (cookie) {
          const sessionId = cookie.split('=')[1];
          if (sessionId) SESSIONS.delete(sessionId);
        }
      }

      try {
        const body = await request.clone().json().catch(() => ({}));
        if (body.token) {
          // Fire and forget (or await if strict) delete call
          if (capApiBase) {
            // Option B: External Delete
            await fetch(`${capApiBase}/delete`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ token: body.token })
            });
          } else {
            // Option A: Service Binding
            await env.CFCAP.fetch(new Request('https://cfcap/api/delete', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                token: body.token
              })
            }));
          }
        }
      } catch (e) {
        // Ignore errors during logout
      }

      return new Response('{"success": true}', {
        headers: {
          'Content-Type': 'application/json',
          'Set-Cookie': `${AUTH_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/`
        }
      });
    }

    // --- APP LOGIC (Protected API) ---

    // Auth Check Helper
    let isAuthorized = false;
    const cookie = cookieHeader.split(';').find(c => c.trim().startsWith(`${AUTH_COOKIE_NAME}=`));

    if (cookie) {
      const sessionId = cookie.split('=')[1];
      // Check In-Memory Map
      if (sessionId && SESSIONS.has(sessionId)) {
        const exp = SESSIONS.get(sessionId);
        // Check Expiration
        if (Date.now() < exp) {
          isAuthorized = true;
        } else {
          // Cleanup expired
          SESSIONS.delete(sessionId);
        }
      }
    }

    // Optional Auth Bypass
    if (env.SPEEDTEST_REQUIRE_AUTH === 'false') {
      isAuthorized = true;
    }

    // 3. Serve Frontend Structure (Root)
    if (path === '/' || path === '/index.html') {
      // Inject Configuration
      const config = {
        requireAuth: env.SPEEDTEST_REQUIRE_AUTH !== 'false',
        captchaApiUrl: capApiBase // Option B: External API URL (Normalized)
      };

      const modifiedHtml = html.replace(
        '<!-- CONFIG_PLACEHOLDER -->',
        `<script>window.SPEEDTEST_CONFIG = ${JSON.stringify(config)};</script>`
      );

      return new Response(modifiedHtml, {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'no-cache',
          ...CORS_HEADERS,
          ...SECURITY_HEADERS,
          ...frameHeaders // Apply computed Frame Options / CSP
        },
      });
    }

    // 4. API Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // 5. API: Ping (Latency) - PROTECTED
    if (path === '/api/ping') {
      if (!isAuthorized) {
        return new Response('Unauthorized', {
          status: 401,
          headers: { 'Set-Cookie': `${AUTH_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/` }
        });
      }
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
      if (!isAuthorized) {
        return new Response('Unauthorized', {
          status: 401,
          headers: { 'Set-Cookie': `${AUTH_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/` }
        });
      }
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
      if (!isAuthorized) {
        return new Response('Unauthorized', {
          status: 401,
          headers: { 'Set-Cookie': `${AUTH_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/` }
        });
      }
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

    // --- IFRAME PROTECTION ---
    // Dynamic CSP/Frame-Options based on ALLOWED_IFRAMES

    let frameHeaders = {
      'X-Frame-Options': 'DENY',
      'Content-Security-Policy': "frame-ancestors 'none'"
    };

    if (env.ALLOWED_IFRAMES) {
      const referer = request.headers.get('Referer');
      if (referer) {
        try {
          const refUrl = new URL(referer);
          const refString = refUrl.host + refUrl.pathname; // host/path

          const allowedList = env.ALLOWED_IFRAMES.split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));

          let matched = false;
          for (const rule of allowedList) {
            // Convert rule to regex
            // Escape special chars except *
            // *.a.com -> .*\.a\.com
            const regexBody = rule.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
            const regex = new RegExp(`^${regexBody}$`); // Match entire string? Or part?
            // User examples:
            // "a.com" -> host must be a.com (exact?) 
            // "*.a.com" -> host ends with .a.com
            // "*.a.com/c/*" -> host+path match

            // To handle both simple host match and path match:
            // If rule has no '/', match against host only? 
            // Or always match against host+path?
            // "a.com" matches "a.com" and "a.com/"

            if (regex.test(refUrl.host) || regex.test(refString)) {
              matched = true;
              break;
            }
          }

          if (matched) {
            frameHeaders = {
              'X-Frame-Options': `ALLOW-FROM ${refUrl.origin}`,
              'Content-Security-Policy': `frame-ancestors ${refUrl.origin}`
            };
          }
        } catch (e) {
          // Invalid referer URL, block
        }
      }
    }

    // --- PROXY ENDPOINTS (Option B) ---
    // Only if CAPTCHA_API_URL is set

    if (env.CAPTCHA_API_URL) {
      // Prepare base URL (strip trailing slash)
      const baseUrl = env.CAPTCHA_API_URL.replace(/\/$/, '');
      const proxyHeaders = { ...CORS_HEADERS, 'Content-Type': 'application/json' };

      // Proxy /api/challenge
      if (path === '/api/challenge') {
        const upstream = `${baseUrl}/challenge${url.search}`;
        const proxied = await fetch(upstream, {
          method: request.method,
          headers: request.headers
        });
        // Rewrite headers if needed? usually fine.
        return proxied;
      }

      // Proxy /api/redeem (or validate)
      if (path === '/api/redeem') {
        const upstream = `${baseUrl}/redeem`;
        const proxied = await fetch(upstream, {
          method: request.method,
          headers: request.headers,
          body: request.body
        });
        return proxied;
      }

      // Proxy /api/delete
      if (path === '/api/delete') {
        const upstream = `${baseUrl}/delete`;
        // Fire and forget? Or wait? 
        // Ideally wait since client might expect 200
        const proxied = await fetch(upstream, {
          method: request.method,
          headers: request.headers,
          body: request.body
        });
        return proxied;
      }
    }

    // 8. API: Metadata
    if (path === '/api/meta') {
      if (!isAuthorized) {
        return new Response('Unauthorized', {
          status: 401,
          headers: { 'Set-Cookie': `${AUTH_COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/` }
        });
      }
      const cf = request.cf || {};

      return new Response(JSON.stringify({
        ip: request.headers.get('cf-connecting-ip') || 'Unknown',
        // Fallback chain: CF City -> CF Region -> Unknown
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
