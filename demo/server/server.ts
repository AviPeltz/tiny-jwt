/**
 * JWT Auth Demo - Express Server
 *
 * This demonstrates a real-world JWT authentication flow:
 * - Login returns access token (in body) + refresh token (in httpOnly cookie)
 * - Protected routes require valid access token
 * - Refresh endpoint issues new access tokens
 * - Logout clears cookies
 */

import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';

const app = express();
const PORT = 3001;

// ============================================
// JWT IMPLEMENTATION (simplified from tiny-jwt)
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

function signHMAC(data: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

function verifyHMAC(data: string, signature: string, secret: string): boolean {
  const expected = signHMAC(data, secret);
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch {
    return false;
  }
}

interface JWTPayload {
  [key: string]: unknown;
  iat?: number;
  exp?: number;
}

function createJWT(payload: JWTPayload, secret: string, expiresIn: number): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);

  const fullPayload = {
    ...payload,
    iat: now,
    exp: now + expiresIn,
  };

  const encodedHeader = base64urlEncode(header);
  const encodedPayload = base64urlEncode(fullPayload);
  const signature = signHMAC(`${encodedHeader}.${encodedPayload}`, secret);

  return `${encodedHeader}.${encodedPayload}.${signature}`;
}

function verifyJWT(token: string, secret: string): JWTPayload {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');

  const [encodedHeader, encodedPayload, signature] = parts;

  if (!verifyHMAC(`${encodedHeader}.${encodedPayload}`, signature, secret)) {
    throw new Error('Invalid signature');
  }

  const payload = JSON.parse(base64urlDecode(encodedPayload));
  const now = Math.floor(Date.now() / 1000);

  if (payload.exp && payload.exp < now) {
    throw new Error('Token expired');
  }

  return payload;
}

// ============================================
// CONFIGURATION
// ============================================

// In production, use long random strings stored in environment variables!
const ACCESS_TOKEN_SECRET = 'access-secret-min-32-chars-long!!';
const REFRESH_TOKEN_SECRET = 'refresh-secret-different-32chars!';
const ACCESS_TOKEN_EXPIRY = 15 * 60;      // 15 minutes
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days

// ============================================
// "DATABASE" (in-memory for demo)
// ============================================

interface User {
  id: number;
  email: string;
  password: string; // In production: ALWAYS hash with bcrypt/argon2!
  name: string;
  role: 'admin' | 'user';
}

const users: User[] = [
  { id: 1, email: 'alice@example.com', password: 'password123', name: 'Alice', role: 'admin' },
  { id: 2, email: 'bob@example.com', password: 'password123', name: 'Bob', role: 'user' },
];

// Track revoked refresh tokens (in production: use Redis)
const revokedTokens = new Set<string>();

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors({
  origin: 'http://localhost:5173', // Vite dev server
  credentials: true, // Allow cookies
}));
app.use(express.json());
app.use(cookieParser());

// Auth middleware - extracts user from token
interface AuthRequest extends express.Request {
  user?: { userId: number; email: string; role: string };
}

function authMiddleware(req: AuthRequest, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }

  const token = authHeader.slice(7);

  try {
    const payload = verifyJWT(token, ACCESS_TOKEN_SECRET);
    req.user = {
      userId: payload.userId as number,
      email: payload.email as string,
      role: payload.role as string,
    };
    next();
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid token';
    return res.status(401).json({ error: message });
  }
}

// ============================================
// AUTH ROUTES
// ============================================

// POST /auth/login
app.post('/auth/login', (req, res) => {
  const { email, password } = req.body;

  // Find user
  const user = users.find(u => u.email === email);
  if (!user || user.password !== password) {
    // Don't reveal which one was wrong!
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Create access token (returned in body)
  const accessToken = createJWT(
    { userId: user.id, email: user.email, role: user.role },
    ACCESS_TOKEN_SECRET,
    ACCESS_TOKEN_EXPIRY
  );

  // Create refresh token (stored in httpOnly cookie)
  const refreshToken = createJWT(
    { userId: user.id, tokenId: crypto.randomUUID() },
    REFRESH_TOKEN_SECRET,
    REFRESH_TOKEN_EXPIRY
  );

  // Set refresh token as httpOnly cookie
  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,      // JavaScript can't access this!
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    sameSite: 'lax',     // CSRF protection
    maxAge: REFRESH_TOKEN_EXPIRY * 1000,
    path: '/auth',       // Only sent to /auth/* routes
  });

  console.log(`[LOGIN] User ${user.email} logged in`);

  res.json({
    accessToken,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

// POST /auth/refresh
app.post('/auth/refresh', (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: 'No refresh token' });
  }

  try {
    const payload = verifyJWT(refreshToken, REFRESH_TOKEN_SECRET);

    // Check if token has been revoked
    if (revokedTokens.has(payload.tokenId as string)) {
      return res.status(401).json({ error: 'Token has been revoked' });
    }

    // Find user
    const user = users.find(u => u.id === payload.userId);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    // Issue new access token
    const accessToken = createJWT(
      { userId: user.id, email: user.email, role: user.role },
      ACCESS_TOKEN_SECRET,
      ACCESS_TOKEN_EXPIRY
    );

    console.log(`[REFRESH] New access token for ${user.email}`);

    res.json({ accessToken });
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Invalid refresh token';
    return res.status(401).json({ error: message });
  }
});

// POST /auth/logout
app.post('/auth/logout', (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (refreshToken) {
    try {
      const payload = verifyJWT(refreshToken, REFRESH_TOKEN_SECRET);
      // Revoke the refresh token
      revokedTokens.add(payload.tokenId as string);
      console.log(`[LOGOUT] Revoked token ${payload.tokenId}`);
    } catch {
      // Token invalid anyway, just clear the cookie
    }
  }

  // Clear the cookie
  res.clearCookie('refreshToken', { path: '/auth' });
  res.json({ message: 'Logged out' });
});

// GET /auth/me - Get current user (requires auth)
app.get('/auth/me', authMiddleware, (req: AuthRequest, res) => {
  const user = users.find(u => u.id === req.user!.userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({
    id: user.id,
    email: user.email,
    name: user.name,
    role: user.role,
  });
});

// ============================================
// PROTECTED API ROUTES
// ============================================

// GET /api/profile
app.get('/api/profile', authMiddleware, (req: AuthRequest, res) => {
  const user = users.find(u => u.id === req.user!.userId);
  res.json({
    message: `Hello, ${user?.name}!`,
    profile: {
      id: user?.id,
      email: user?.email,
      name: user?.name,
      role: user?.role,
      lastLogin: new Date().toISOString(),
    },
  });
});

// GET /api/admin - Admin only
app.get('/api/admin', authMiddleware, (req: AuthRequest, res) => {
  if (req.user!.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }

  res.json({
    message: 'Welcome to the admin panel!',
    secrets: {
      totalUsers: users.length,
      serverUptime: process.uptime(),
    },
  });
});

// GET /api/public - No auth required
app.get('/api/public', (_req, res) => {
  res.json({
    message: 'This is public data',
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// START SERVER
// ============================================

app.listen(PORT, () => {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║             JWT Auth Demo Server                          ║
╠═══════════════════════════════════════════════════════════╣
║  Server running at: http://localhost:${PORT}                 ║
║                                                           ║
║  Test users:                                              ║
║    - alice@example.com / password123 (admin)              ║
║    - bob@example.com / password123 (user)                 ║
║                                                           ║
║  Endpoints:                                               ║
║    POST /auth/login    - Get tokens                       ║
║    POST /auth/refresh  - Refresh access token             ║
║    POST /auth/logout   - Revoke refresh token             ║
║    GET  /auth/me       - Get current user (protected)     ║
║    GET  /api/profile   - User profile (protected)         ║
║    GET  /api/admin     - Admin only (protected)           ║
║    GET  /api/public    - Public data                      ║
╚═══════════════════════════════════════════════════════════╝
  `);
});
