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

// Pre-allocate 10MB buffer for download tests to save CPU cycles
const CHUNK_SIZE = 10 * 1024 * 1024;
const BUFFER = new Uint8Array(CHUNK_SIZE);
for (let i = 0; i < CHUNK_SIZE; i++) BUFFER[i] = i % 256;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 1. Serve Frontend Structure (Root)
    if (path === '/' || path === '/index.html') {
      return new Response(html, {
        headers: {
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'no-cache', // Ensure latest UI is always loaded
          ...CORS_HEADERS
        },
      });
    }

    // 2. API Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // 3. API: Ping (Latency)
    if (path === '/api/ping') {
      return new Response('pong', {
        headers: { 
          ...CORS_HEADERS, 
          'Cache-Control': 'no-store', 
          'Content-Type': 'text/plain' 
        }
      });
    }

    // 4. API: Download Stream
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

    // 5. API: Upload Stream
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

    // 6. API: Metadata
    if (path === '/api/meta') {
      return new Response(JSON.stringify({
        ip: request.headers.get('cf-connecting-ip') || 'Unknown',
        city: request.headers.get('cf-ipcity') || 'Unknown',
        country: request.headers.get('cf-ipcountry') || 'Unknown',
        asn: request.headers.get('cf-ipasn') || '',
        isp: request.headers.get('cf-ipasn-org') || 'Unknown ISP',
        colo: request.cf?.colo || 'Edge'
      }), {
         headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
