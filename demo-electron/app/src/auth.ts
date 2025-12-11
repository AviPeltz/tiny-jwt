/**
 * PKCE Authentication Module for Electron
 *
 * This module handles the OAuth2 + PKCE flow for desktop apps.
 *
 * Key Security Points:
 * 1. NO secrets are stored in this app - all signing happens on the server
 * 2. PKCE prevents authorization code interception attacks
 * 3. Tokens are stored in the OS keychain via Electron's safeStorage
 */

import * as crypto from 'crypto';

const AUTH_SERVER = 'http://localhost:3002';

// PKCE state - kept in memory only
let codeVerifier: string | null = null;
let authState: string | null = null;

/**
 * Generate a cryptographically random string for PKCE
 */
function generateRandomString(length: number): string {
  const bytes = crypto.randomBytes(length);
  return bytes.toString('base64url').slice(0, length);
}

/**
 * Create the code_challenge from code_verifier using SHA256
 *
 * code_challenge = BASE64URL(SHA256(code_verifier))
 */
function generateCodeChallenge(verifier: string): string {
  return crypto
    .createHash('sha256')
    .update(verifier)
    .digest('base64url');
}

/**
 * Start the OAuth2 + PKCE authorization flow
 * Returns the URL to open in the system browser
 */
export function startAuthFlow(): string {
  // Generate PKCE values
  // code_verifier: Random 43-128 character string
  codeVerifier = generateRandomString(64);

  // code_challenge: SHA256 hash of verifier
  const codeChallenge = generateCodeChallenge(codeVerifier);

  // state: Random string to prevent CSRF
  authState = generateRandomString(32);

  console.log('[Auth] Starting PKCE flow');
  console.log('[Auth] code_verifier length:', codeVerifier.length);
  console.log('[Auth] code_challenge:', codeChallenge.slice(0, 20) + '...');

  // Build authorization URL
  const params = new URLSearchParams({
    response_type: 'code',
    client_id: 'electron-app',
    redirect_uri: 'myapp://auth/callback',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state: authState,
    scope: 'openid profile'
  });

  return `${AUTH_SERVER}/authorize?${params.toString()}`;
}

/**
 * Exchange authorization code for tokens
 * This is where PKCE proves we're the same app that started the flow
 */
export async function exchangeCodeForTokens(
  code: string,
  returnedState: string
): Promise<{ accessToken: string; refreshToken: string; expiresIn: number }> {
  // Verify state to prevent CSRF
  if (returnedState !== authState) {
    throw new Error('State mismatch - possible CSRF attack!');
  }

  if (!codeVerifier) {
    throw new Error('No code verifier - auth flow not started properly');
  }

  console.log('[Auth] Exchanging code for tokens');
  console.log('[Auth] Sending code_verifier to prove we started this flow');

  const response = await fetch(`${AUTH_SERVER}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'myapp://auth/callback',
      client_id: 'electron-app',
      code_verifier: codeVerifier  // This is the PKCE proof!
    }).toString()
  });

  // Clear PKCE state
  codeVerifier = null;
  authState = null;

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error_description || 'Token exchange failed');
  }

  const data = await response.json();

  console.log('[Auth] Token exchange successful!');

  return {
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    expiresIn: data.expires_in
  };
}

/**
 * Refresh the access token using the refresh token
 */
export async function refreshAccessToken(
  refreshToken: string
): Promise<{ accessToken: string; expiresIn: number }> {
  console.log('[Auth] Refreshing access token');

  const response = await fetch(`${AUTH_SERVER}/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: 'electron-app'
    }).toString()
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error_description || 'Token refresh failed');
  }

  const data = await response.json();

  return {
    accessToken: data.access_token,
    expiresIn: data.expires_in
  };
}

/**
 * Call a protected API endpoint with the access token
 */
export async function callProtectedAPI(
  accessToken: string
): Promise<{ message: string; user: any }> {
  const response = await fetch(`${AUTH_SERVER}/api/protected`, {
    headers: {
      'Authorization': `Bearer ${accessToken}`
    }
  });

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error('Token expired or invalid');
    }
    throw new Error('API call failed');
  }

  return response.json();
}

/**
 * Revoke tokens on logout
 */
export async function revokeToken(refreshToken: string): Promise<void> {
  console.log('[Auth] Revoking refresh token');

  await fetch(`${AUTH_SERVER}/revoke`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: new URLSearchParams({
      token: refreshToken,
      token_type_hint: 'refresh_token'
    }).toString()
  });
}

/**
 * Parse the callback URL from the custom protocol
 */
export function parseCallbackURL(url: string): { code: string; state: string } | null {
  try {
    const parsed = new URL(url);
    const code = parsed.searchParams.get('code');
    const state = parsed.searchParams.get('state');

    if (code && state) {
      return { code, state };
    }

    // Check for error
    const error = parsed.searchParams.get('error');
    if (error) {
      console.error('[Auth] Authorization error:', error);
    }

    return null;
  } catch {
    return null;
  }
}
