/**
 * Auth System Starter
 *
 * Build a complete authentication system using your JWT library.
 * Fill in the implementations below.
 *
 * Run tests with: npx tsx starter/auth.ts
 */

// TODO: Import from your jwt.ts once it's working
// import { createJWT, verifyJWT } from './jwt.js';

// For now, use the reference implementation:
import { createJWT, verifyJWT, JWTPayload } from '../src/index.js';

// ============================================
// CONFIGURATION
// ============================================

const ACCESS_TOKEN_SECRET = 'access-secret-change-in-production';
const REFRESH_TOKEN_SECRET = 'refresh-secret-different-from-access';
const ACCESS_TOKEN_EXPIRY = 900;      // 15 minutes
const REFRESH_TOKEN_EXPIRY = 604800;  // 7 days

// ============================================
// TYPES
// ============================================

interface User {
  id: number;
  username: string;
  password: string;  // In real apps, ALWAYS hash passwords!
  role: 'admin' | 'user';
}

interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

interface UserInfo {
  userId: number;
  username: string;
  role: string;
}

// ============================================
// "DATABASE"
// ============================================

const users: User[] = [
  { id: 1, username: 'alice', password: 'password123', role: 'admin' },
  { id: 2, username: 'bob', password: 'bobsecret', role: 'user' },
  { id: 3, username: 'charlie', password: 'charlie456', role: 'user' },
];

// Token blacklist for logout
const blacklist = new Set<string>();

// ============================================
// IMPLEMENT THESE FUNCTIONS
// ============================================

/**
 * Authenticate user and return tokens
 *
 * Steps:
 * 1. Find user by username in users array
 * 2. Check if password matches
 * 3. If invalid, return null
 * 4. Create access token containing { userId, username, role }
 * 5. Create refresh token containing { userId, type: 'refresh' }
 * 6. Return both tokens
 */
export function login(username: string, password: string): TokenPair | null {
  // TODO: Implement this
  throw new Error('Not implemented');
}

/**
 * Verify access token and return user info
 *
 * Steps:
 * 1. Check if token is in blacklist -> throw 'Token revoked'
 * 2. Verify token with ACCESS_TOKEN_SECRET
 * 3. Return { userId, username, role } from payload
 */
export function authenticate(token: string): UserInfo {
  // TODO: Implement this
  throw new Error('Not implemented');
}

/**
 * Get new access token using refresh token
 *
 * Steps:
 * 1. Verify refresh token with REFRESH_TOKEN_SECRET
 * 2. Check payload.type === 'refresh' -> throw 'Invalid token type'
 * 3. Find user by payload.userId
 * 4. If user not found -> throw 'User not found'
 * 5. Create and return new access token
 */
export function refresh(refreshToken: string): string {
  // TODO: Implement this
  throw new Error('Not implemented');
}

/**
 * Invalidate a token (logout)
 *
 * Add token to blacklist set
 */
export function logout(token: string): void {
  // TODO: Implement this
  throw new Error('Not implemented');
}

/**
 * Check if user has required role
 *
 * Steps:
 * 1. Call authenticate(token) to verify and get user
 * 2. If requiredRole is specified and user.role !== requiredRole
 *    -> throw 'Insufficient permissions'
 * 3. Return user info
 */
export function authorize(token: string, requiredRole?: string): UserInfo {
  // TODO: Implement this
  throw new Error('Not implemented');
}

// ============================================
// TESTS
// ============================================

function runTests() {
  console.log('Running auth tests...\n');
  let passed = 0;
  let failed = 0;

  function test(name: string, fn: () => void) {
    try {
      fn();
      console.log(`✓ ${name}`);
      passed++;
    } catch (e) {
      console.log(`✗ ${name}`);
      console.log(`  Error: ${(e as Error).message}\n`);
      failed++;
    }
  }

  // Login tests
  test('login returns tokens for valid credentials', () => {
    const result = login('alice', 'password123');
    if (!result) throw new Error('Should return tokens');
    if (!result.accessToken) throw new Error('Missing access token');
    if (!result.refreshToken) throw new Error('Missing refresh token');
  });

  test('login returns null for invalid password', () => {
    const result = login('alice', 'wrongpassword');
    if (result !== null) throw new Error('Should return null');
  });

  test('login returns null for unknown user', () => {
    const result = login('unknown', 'password');
    if (result !== null) throw new Error('Should return null');
  });

  // Authenticate tests
  test('authenticate returns user info for valid token', () => {
    const tokens = login('alice', 'password123')!;
    const user = authenticate(tokens.accessToken);
    if (user.username !== 'alice') throw new Error('Wrong username');
    if (user.role !== 'admin') throw new Error('Wrong role');
  });

  test('authenticate throws for invalid token', () => {
    try {
      authenticate('invalid.token.here');
      throw new Error('Should have thrown');
    } catch (e) {
      if ((e as Error).message === 'Should have thrown') throw e;
    }
  });

  // Refresh tests
  test('refresh returns new access token', () => {
    const tokens = login('bob', 'bobsecret')!;
    const newToken = refresh(tokens.refreshToken);
    if (!newToken) throw new Error('Should return token');

    // New token should work
    const user = authenticate(newToken);
    if (user.username !== 'bob') throw new Error('Wrong user');
  });

  test('refresh rejects access token (wrong type)', () => {
    const tokens = login('bob', 'bobsecret')!;
    try {
      // Try using access token as refresh token
      refresh(tokens.accessToken);
      throw new Error('Should have thrown');
    } catch (e) {
      if ((e as Error).message === 'Should have thrown') throw e;
    }
  });

  // Logout tests
  test('logout invalidates token', () => {
    const tokens = login('charlie', 'charlie456')!;

    // Token works before logout
    authenticate(tokens.accessToken);

    // Logout
    logout(tokens.accessToken);

    // Token should be rejected after logout
    try {
      authenticate(tokens.accessToken);
      throw new Error('Should have thrown');
    } catch (e) {
      if ((e as Error).message === 'Should have thrown') throw e;
    }
  });

  // Authorization tests
  test('authorize passes for matching role', () => {
    const tokens = login('alice', 'password123')!;
    const user = authorize(tokens.accessToken, 'admin');
    if (user.role !== 'admin') throw new Error('Should be admin');
  });

  test('authorize throws for non-matching role', () => {
    const tokens = login('bob', 'bobsecret')!;
    try {
      authorize(tokens.accessToken, 'admin');
      throw new Error('Should have thrown');
    } catch (e) {
      if ((e as Error).message === 'Should have thrown') throw e;
    }
  });

  test('authorize passes without role requirement', () => {
    const tokens = login('bob', 'bobsecret')!;
    const user = authorize(tokens.accessToken);
    if (user.username !== 'bob') throw new Error('Wrong user');
  });

  console.log(`\n${passed} passed, ${failed} failed`);

  if (failed > 0) {
    console.log('\nKeep going! Check PROJECT.md for implementation hints.');
  } else {
    console.log('\n🎉 All auth tests passed! You built a complete auth system!');
  }
}

runTests();
