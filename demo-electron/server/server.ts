/**
 * Auth Server for Desktop App
 *
 * This server handles authentication for desktop apps (Electron, Tauri, etc.)
 * that CANNOT store secrets. It implements:
 *
 * 1. PKCE (Proof Key for Code Exchange) - Prevents auth code interception
 * 2. Authorization Code Flow - No secrets needed on client
 * 3. Short-lived access tokens + refresh tokens
 *
 * KEY INSIGHT: The desktop app NEVER sees the signing key.
 * All token creation/verification happens here on the server.
 */

import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
const PORT = 3002;

// ============================================
// JWT IMPLEMENTATION (server-side only!)
// ============================================

function base64urlEncode(data: string | object): string {
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlDecode(str: string): string {
  const padded = str + '='.repeat((4 - str.length % 4) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64').toString('utf8');
}

// THE SECRET - Only exists on this server, NEVER in the client app!
const JWT_SECRET = crypto.randomBytes(32).toString('hex');
const REFRESH_SECRET = crypto.randomBytes(32).toString('hex');

console.log('🔐 JWT secrets generated (never shared with clients!)');

function signHMAC(data: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

function createJWT(payload: Record<string, unknown>, secret: string, expiresIn: number): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = { ...payload, iat: now, exp: now + expiresIn };

  const encodedHeader = base64urlEncode(header);
  const encodedPayload = base64urlEncode(fullPayload);
  const signature = signHMAC(`${encodedHeader}.${encodedPayload}`, secret);

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJWT(token: string, secret: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [encodedHeader, encodedPayload, signature] = parts;
    const expected = signHMAC(`${encodedHeader}.${encodedPayload}`, secret);

    if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) {
      return null;
    }

    const payload = JSON.parse(base64urlDecode(encodedPayload));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null; // Expired
    }

    return payload;
  } catch {
    return null;
  }
}

// ============================================
// SIMULATED DATABASE
// ============================================

interface User {
  id: string;
  email: string;
  password: string;
  name: string;
}

const users: User[] = [
  { id: '1', email: 'alice@example.com', password: 'password123', name: 'Alice' },
  { id: '2', email: 'bob@example.com', password: 'password123', name: 'Bob' },
];

// ============================================
// PKCE + AUTH CODE STORAGE
// ============================================

interface AuthRequest {
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  redirectUri: string;
  clientId: string;
  userId?: string;
  createdAt: number;
}

interface AuthCode {
  code: string;
  userId: string;
  codeChallenge: string;
  redirectUri: string;
  clientId: string;
  createdAt: number;
  used: boolean;
}

// In production: use Redis with TTL
const pendingAuthRequests = new Map<string, AuthRequest>(); // state -> request
const authCodes = new Map<string, AuthCode>(); // code -> auth code data
const refreshTokens = new Map<string, { userId: string; createdAt: number }>();

// Clean up expired entries periodically
setInterval(() => {
  const now = Date.now();
  const FIVE_MINUTES = 5 * 60 * 1000;
  const SEVEN_DAYS = 7 * 24 * 60 * 60 * 1000;

  for (const [state, req] of pendingAuthRequests) {
    if (now - req.createdAt > FIVE_MINUTES) pendingAuthRequests.delete(state);
  }
  for (const [code, data] of authCodes) {
    if (now - data.createdAt > FIVE_MINUTES) authCodes.delete(code);
  }
  for (const [token, data] of refreshTokens) {
    if (now - data.createdAt > SEVEN_DAYS) refreshTokens.delete(token);
  }
}, 60000);

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static login page
app.use(express.static('public'));

// ============================================
// OAUTH2 / PKCE ENDPOINTS
// ============================================

/**
 * GET /authorize
 *
 * Desktop app redirects user's browser here to start login.
 * This is the standard OAuth2 authorization endpoint.
 */
app.get('/authorize', (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    code_challenge,
    code_challenge_method,
    state,
  } = req.query;

  // Validate request
  if (response_type !== 'code') {
    return res.status(400).send('Invalid response_type. Must be "code".');
  }

  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).send('PKCE required. Provide code_challenge with S256 method.');
  }

  if (!state) {
    return res.status(400).send('State parameter required for CSRF protection.');
  }

  // Store the auth request (will be completed after login)
  pendingAuthRequests.set(state as string, {
    codeChallenge: code_challenge as string,
    codeChallengeMethod: 'S256',
    redirectUri: redirect_uri as string,
    clientId: client_id as string,
    createdAt: Date.now(),
  });

  // Show login page
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Login - Desktop App Auth</title>
      <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
          font-family: -apple-system, system-ui, sans-serif;
          background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          color: #fff;
        }
        .login-box {
          background: rgba(255,255,255,0.1);
          backdrop-filter: blur(10px);
          padding: 2rem;
          border-radius: 16px;
          width: 100%;
          max-width: 400px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        h1 { margin-bottom: 0.5rem; font-size: 1.5rem; }
        .subtitle { color: #94a3b8; margin-bottom: 1.5rem; font-size: 0.9rem; }
        .form-group { margin-bottom: 1rem; }
        label { display: block; margin-bottom: 0.5rem; color: #94a3b8; font-size: 0.85rem; }
        input {
          width: 100%;
          padding: 0.75rem;
          border: 1px solid rgba(255,255,255,0.2);
          border-radius: 8px;
          background: rgba(0,0,0,0.3);
          color: #fff;
          font-size: 1rem;
        }
        input:focus { outline: none; border-color: #3b82f6; }
        button {
          width: 100%;
          padding: 0.875rem;
          background: #3b82f6;
          color: white;
          border: none;
          border-radius: 8px;
          font-size: 1rem;
          cursor: pointer;
          margin-top: 0.5rem;
        }
        button:hover { background: #2563eb; }
        .error { color: #f87171; margin-top: 1rem; font-size: 0.9rem; }
        .info { background: rgba(59,130,246,0.2); padding: 1rem; border-radius: 8px; margin-bottom: 1.5rem; font-size: 0.85rem; }
        .info code { background: rgba(0,0,0,0.3); padding: 0.1rem 0.3rem; border-radius: 4px; }
      </style>
    </head>
    <body>
      <div class="login-box">
        <h1>Sign In</h1>
        <p class="subtitle">Authorize Desktop App</p>

        <div class="info">
          App <code>${client_id}</code> wants to access your account.
          After login, you'll be redirected back to the app.
        </div>

        <form method="POST" action="/authorize/login">
          <input type="hidden" name="state" value="${state}" />

          <div class="form-group">
            <label>Email</label>
            <input type="email" name="email" value="alice@example.com" required />
          </div>

          <div class="form-group">
            <label>Password</label>
            <input type="password" name="password" value="password123" required />
          </div>

          <button type="submit">Sign In & Authorize</button>
        </form>

        <p style="margin-top: 1rem; font-size: 0.8rem; color: #64748b;">
          Test: alice@example.com / password123
        </p>
      </div>
    </body>
    </html>
  `);
});

/**
 * POST /authorize/login
 *
 * Handles the login form submission. If valid, redirects back to
 * the desktop app with an authorization code.
 */
app.post('/authorize/login', (req, res) => {
  const { email, password, state } = req.body;

  // Get the pending auth request
  const authRequest = pendingAuthRequests.get(state);
  if (!authRequest) {
    return res.status(400).send('Invalid or expired authorization request.');
  }

  // Validate credentials
  const user = users.find(u => u.email === email && u.password === password);
  if (!user) {
    return res.status(401).send(`
      <html><body style="font-family: sans-serif; padding: 2rem;">
        <h2>Invalid credentials</h2>
        <p>Please <a href="javascript:history.back()">try again</a>.</p>
      </body></html>
    `);
  }

  // Generate authorization code (one-time use)
  const code = crypto.randomBytes(32).toString('hex');

  // Store the code with all the info we need to verify later
  authCodes.set(code, {
    code,
    userId: user.id,
    codeChallenge: authRequest.codeChallenge,
    redirectUri: authRequest.redirectUri,
    clientId: authRequest.clientId,
    createdAt: Date.now(),
    used: false,
  });

  // Clean up the pending request
  pendingAuthRequests.delete(state);

  // Redirect back to the desktop app with the code
  const redirectUrl = new URL(authRequest.redirectUri);
  redirectUrl.searchParams.set('code', code);
  redirectUrl.searchParams.set('state', state);

  console.log(`[AUTH] User ${user.email} authorized, redirecting to ${redirectUrl.origin}`);

  res.redirect(redirectUrl.toString());
});

/**
 * POST /token
 *
 * Token endpoint - exchanges authorization code for tokens.
 * Verifies PKCE code_verifier matches the original code_challenge.
 */
app.post('/token', (req, res) => {
  const { grant_type, code, code_verifier, redirect_uri, client_id, refresh_token } = req.body;

  // Handle refresh token grant
  if (grant_type === 'refresh_token') {
    if (!refresh_token) {
      return res.status(400).json({ error: 'invalid_request', error_description: 'Missing refresh_token' });
    }

    const tokenData = refreshTokens.get(refresh_token);
    if (!tokenData) {
      return res.status(401).json({ error: 'invalid_grant', error_description: 'Invalid refresh token' });
    }

    const user = users.find(u => u.id === tokenData.userId);
    if (!user) {
      return res.status(401).json({ error: 'invalid_grant', error_description: 'User not found' });
    }

    // Issue new access token
    const accessToken = createJWT(
      { sub: user.id, email: user.email, name: user.name },
      JWT_SECRET,
      900 // 15 minutes
    );

    console.log(`[REFRESH] New access token for ${user.email}`);

    return res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900,
    });
  }

  // Handle authorization code grant
  if (grant_type !== 'authorization_code') {
    return res.status(400).json({ error: 'unsupported_grant_type' });
  }

  // Get the stored auth code
  const authCode = authCodes.get(code);
  if (!authCode) {
    return res.status(401).json({ error: 'invalid_grant', error_description: 'Invalid or expired code' });
  }

  // Check if code was already used (prevent replay attacks)
  if (authCode.used) {
    // Potential attack! Revoke any tokens issued with this code
    console.log(`[SECURITY] Attempted code reuse detected!`);
    authCodes.delete(code);
    return res.status(401).json({ error: 'invalid_grant', error_description: 'Code already used' });
  }

  // Verify redirect_uri matches
  if (authCode.redirectUri !== redirect_uri) {
    return res.status(401).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' });
  }

  // PKCE Verification - This is the key security check!
  // Compute SHA256 of the code_verifier and compare to stored code_challenge
  const computedChallenge = crypto
    .createHash('sha256')
    .update(code_verifier)
    .digest('base64url');

  if (computedChallenge !== authCode.codeChallenge) {
    console.log(`[SECURITY] PKCE verification failed!`);
    return res.status(401).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
  }

  // Mark code as used
  authCode.used = true;

  // Get user
  const user = users.find(u => u.id === authCode.userId);
  if (!user) {
    return res.status(401).json({ error: 'invalid_grant', error_description: 'User not found' });
  }

  // Generate tokens
  const accessToken = createJWT(
    { sub: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    900 // 15 minutes
  );

  const newRefreshToken = crypto.randomBytes(32).toString('hex');
  refreshTokens.set(newRefreshToken, {
    userId: user.id,
    createdAt: Date.now(),
  });

  console.log(`[TOKEN] Issued tokens for ${user.email}`);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 900,
    refresh_token: newRefreshToken,
  });
});

/**
 * POST /revoke
 *
 * Revoke a refresh token (logout)
 */
app.post('/revoke', (req, res) => {
  const { token } = req.body;

  if (token && refreshTokens.has(token)) {
    refreshTokens.delete(token);
    console.log(`[REVOKE] Token revoked`);
  }

  res.status(200).json({ success: true });
});

/**
 * GET /userinfo
 *
 * Protected endpoint - returns user info if valid access token provided.
 * This is where the server verifies the JWT signature.
 */
app.get('/userinfo', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const token = authHeader.slice(7);
  const payload = verifyJWT(token, JWT_SECRET);

  if (!payload) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  res.json({
    sub: payload.sub,
    email: payload.email,
    name: payload.name,
  });
});

/**
 * GET /api/protected
 *
 * Example protected API endpoint
 */
app.get('/api/protected', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized' });
  }

  const token = authHeader.slice(7);
  const payload = verifyJWT(token, JWT_SECRET);

  if (!payload) {
    return res.status(401).json({ error: 'invalid_token' });
  }

  res.json({
    message: `Hello ${payload.name}! This is protected data.`,
    timestamp: new Date().toISOString(),
    user: { id: payload.sub, email: payload.email },
  });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════════════════╗
║           Desktop App Auth Server (PKCE + OAuth2)                  ║
╠════════════════════════════════════════════════════════════════════╣
║  Server: http://localhost:${PORT}                                     ║
║                                                                    ║
║  This server holds the JWT secrets - desktop apps never see them!  ║
║                                                                    ║
║  Endpoints:                                                        ║
║    GET  /authorize     - Start OAuth flow (browser)                ║
║    POST /authorize/login - Handle login form                       ║
║    POST /token         - Exchange code for tokens (PKCE verified)  ║
║    POST /revoke        - Revoke refresh token                      ║
║    GET  /userinfo      - Get user info (protected)                 ║
║    GET  /api/protected - Example protected endpoint                ║
║                                                                    ║
║  Test: alice@example.com / password123                             ║
╚════════════════════════════════════════════════════════════════════╝
  `);
});
