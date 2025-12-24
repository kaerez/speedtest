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

// Security Constants
const AUTH_COOKIE_NAME = 'KSEC_AUTH';
const CHUNK_SIZE = 10 * 1024 * 1024;
const BUFFER = new Uint8Array(CHUNK_SIZE);
for (let i = 0; i < CHUNK_SIZE; i++) BUFFER[i] = i % 256;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const cookieHeader = request.headers.get('Cookie') || '';

    // --- TURNSTILE INTERCEPTION LOGIC ---
    
    // Helper to check for auth cookie
    const isVerified = cookieHeader.includes(`${AUTH_COOKIE_NAME}=verified`);
    
    // 1. Serve Challenge Page for Unverified Root/API requests
    // We allow /challenge endpoint and /favicon.ico without auth
    if (!isVerified && path !== '/challenge' && path !== '/favicon.ico') {
        const challengeHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Check | KSEC</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        body { font-family: 'Courier New', sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; background: #f8fafc; color: #1f2937; margin: 0; }
        .box { background: white; padding: 2rem; border-radius: 4px; box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1); border: 1px solid #e2e8f0; text-align: center; }
        h1 { margin-bottom: 1.5rem; font-size: 1.2rem; font-weight: bold; }
        .footer { margin-top: 1rem; font-size: 0.8rem; color: #94a3b8; }
    </style>
</head>
<body>
    <div class="box">
        <h1>KSEC Security Check</h1>
        <div class="cf-turnstile" data-sitekey="${env.turnstile_sitekey}" data-callback="onVerify"></div>
        <div class="footer">Please verify to continue</div>
    </div>
    <script>
        function onVerify(token) {
            fetch('/challenge', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token })
            }).then(res => {
                if (res.ok) window.location.reload();
                else alert('Verification failed. Please refresh.');
            });
        }
    </script>
</body>
</html>`;
        
        return new Response(challengeHtml, {
            headers: { 'Content-Type': 'text/html;charset=UTF-8' }
        });
    }

    // 2. Handle Turnstile Verification
    if (path === '/challenge' && request.method === 'POST') {
        try {
            const { token } = await request.json();
            const ip = request.headers.get('CF-Connecting-IP');
            
            // Validate with Cloudflare
            const formData = new FormData();
            formData.append('secret', env.turnstile_secretkey);
            formData.append('response', token);
            formData.append('remoteip', ip);
            
            const result = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
                body: formData,
                method: 'POST',
            });
            const outcome = await result.json();
            
            if (outcome.success) {
                // Success: Set Auth Cookie
                return new Response('{"success": true}', {
                    headers: {
                        'Content-Type': 'application/json',
                        'Set-Cookie': `${AUTH_COOKIE_NAME}=verified; HttpOnly; Secure; SameSite=Strict; Max-Age=3600; Path=/`
                    }
                });
            } else {
                return new Response('{"success": false}', { status: 403 });
            }
        } catch (e) {
            return new Response('{"error": "Validation error"}', { status: 500 });
        }
    }

    // --- APP LOGIC (Protected) ---

    // 3. Serve Frontend Structure (Root)
    if (path === '/' || path === '/index.html') {
      return new Response(html, {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'no-cache', 
          ...CORS_HEADERS
        },
      });
    }

    // 4. API Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // 5. API: Ping (Latency)
    if (path === '/api/ping') {
      return new Response('pong', {
        headers: { 
          ...CORS_HEADERS, 
          'Cache-Control': 'no-store', 
          'Content-Type': 'text/plain' 
        }
      });
    }

    // 6. API: Download Stream
    if (path === '/api/down') {
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

    // 7. API: Upload Stream
    if (path === '/api/up' && request.method === 'POST') {
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

    // 8. API: Metadata
    if (path === '/api/meta') {
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
