# KSEC Speed Test

A high-performance, privacy-focused network speed test application built on **Cloudflare Workers**.

## Features

-   **Serverless Architecture**: Runs entirely on Cloudflare's global edge network.
-   **No Client-Side Bloat**: Single file React application served directly from the Worker.
-   **Accurate Metrics**: Measures Download, Upload, Latency (Ping), Jitter, and Packet Loss.
-   **Privacy Focused**: No third-party tracking. Metadata (IP, ISP) is only fetched after verification.
-   **Bot Protection (Optional)**: Integrated [CapJS](https://cap.js.org/) to prevent automated abuse of bandwidth.

## Architecture

-   **Frontend**: `index.html` (React + Tailwind CSS + Lucide Icons). Served by the Worker.
-   **Backend**: `worker.js`. Handles API routes (`/api/ping`, `/api/down`, `/api/up`, `/api/verify`).
-   **Session Management**: Ephemeral in-memory UUID sessions (per-isolate) to authorize tests.

## Configuration

The application is configured via `wrangler.toml` and Environment Variables.

### Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `SPEEDTEST_REQUIRE_AUTH` | Set to `"false"` to disable CapJS verification and allow immediate testing. | `"true"` |
| `CAPTCHA_API_URL` | Optional full URL to a custom CapJS validation API. If set, Workers proxies challenge/redeem endpoints here. | `undefined` |
| `ALLOWED_IFRAMES` | Comma-separated list of allowed parent origins or paths (e.g., `a.com,*.b.com,*.c.com/app/*`). | `undefined` (Deny All) |

### Service Bindings

-   **`CFCAP`**: Points to a `cfcap` worker (e.g., [kaerez/CFCap](https://github.com/kaerez/CFCap)) for internal validation.

## Deployment

### Prerequisites

-   [Node.js](https://nodejs.org/)
-   [Wrangler](https://developers.cloudflare.com/workers/wrangler/install-and-update/)

### 1. Setup CapJS (Optional)

If `SPEEDTEST_REQUIRE_AUTH` is enabled (default), you need a CapJS backend.

**Option A: Internal Service Binding (Recommended)**
1.  Deploy [kaerez/CFCap](https://github.com/kaerez/CFCap) to your Cloudflare account.
2.  Bind it in `wrangler.toml`:
    ```toml
    [[services]]
    binding = "CFCAP"
    service = "cfcap"
    ```

**Option B: External API**
1.  Set `CAPTCHA_API_URL` in `wrangler.toml` or via dashboard to your CapJS endpoint (e.g., `https://my-cap.example.com/api/validate`).

### 2. Deploy Speed Test

```bash
npm run deploy
```

### 3. Disable Authentication (Open Mode)

To run the speed test without any captcha verification:

1.  Set the variable:
    ```bash
    npx wrangler secret put SPEEDTEST_REQUIRE_AUTH
    # Enter value: false
    ```
    Or add to `wrangler.toml`:
    ```toml
    [vars]
    SPEEDTEST_REQUIRE_AUTH = "false"
    ```
2.  Redeploy. The "Start Test" button will work immediately.

## Development

**Local Development**:
```bash
npm run dev
```

**Note on Local Testing**: Service bindings and some security headers might behave differently in `wrangler dev` compared to production.

### External CapJS API (Option B)

If you configure `CAPTCHA_API_URL`, the Speed Test client connects directly to your external CapJS instance.
-   **Client**: Browser sends `/challenge` and `/redeem` requests directly to `CAPTCHA_API_URL`.
-   **Server**: Worker sends `/delete` requests to `CAPTCHA_API_URL/delete` during logout.
-   **Structure**: Set the base URL (e.g., `https://my-cap.example.com/api`).
    -   The system automatically appends `/challenge`, `/validate`, etc.

**Note**: Ensure your external CapJS instance allows CORS for your Speed Test domain.

### Iframe Protection

To allow embedding this Speed Test in an iframe, set `ALLOWED_IFRAMES`:

```bash
# Example: Allow specific domain and a wildcard path
npx wrangler secret put ALLOWED_IFRAMES
# Value: "my-portal.com,*.partners.com/dashboard/*"
```

The Worker checks the `Referer` header of the request:
-   **Match**: Sets `X-Frame-Options: ALLOW-FROM ...` and `Content-Security-Policy: frame-ancestors ...`.
-   **No Match**: Sets `DENY` and `frame-ancestors 'none'`.
-   **Rules**: 
    -   `a.com` matches exact host.
    -   `*.a.com` matches usage as wildcard prefix.
    -   `*/path/*` matches against host+path.

## License

License to use this software under the PolyForm Noncommercial License 1.0.0
is expressly conditioned upon the user having a valid, signed Contributor
License Agreement (CLA) on file with KSEC - Erez Kalman.
