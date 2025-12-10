/**
 * Example 4: Complete Authentication Flow
 *
 * This example simulates a real authentication system with:
 *   - User login
 *   - JWT token generation
 *   - Protected route access
 *   - Token refresh
 *   - Common security pitfalls
 *
 * Run: npm run example:auth
 */

import { createJWT, verifyJWT, decodeJWT, type JWTPayload } from '../src/index.js';

console.log('='.repeat(60));
console.log('COMPLETE AUTHENTICATION FLOW');
console.log('='.repeat(60));

// ============================================
// SETUP: Simulated Database & Config
// ============================================

const SECRET_KEY = 'your-256-bit-secret-key-here-keep-safe';
const REFRESH_SECRET = 'different-secret-for-refresh-tokens';

// User type
interface User {
  id: number;
  password: string;
  role: 'admin' | 'user';
}

// Simulated user database
const users: Record<string, User> = {
  'alice': { id: 1, password: 'password123', role: 'admin' },
  'bob': { id: 2, password: 'bobsecret', role: 'user' },
};

// Token response type
interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

// Simulated token blacklist (for logout)
const tokenBlacklist = new Set<string>();

// ============================================
// AUTH FUNCTIONS
// ============================================

function login(username: string, password: string): TokenPair | null {
  console.log(`\n📥 Login attempt: ${username}`);

  const user = users[username];
  if (!user || user.password !== password) {
    console.log('   ✗ Invalid credentials');
    return null;
  }

  // Create access token (short-lived)
  const accessToken = createJWT(
    { userId: user.id, username, role: user.role },
    SECRET_KEY,
    { expiresIn: 900 } // 15 minutes
  );

  // Create refresh token (long-lived)
  const refreshToken = createJWT(
    { userId: user.id, type: 'refresh' },
    REFRESH_SECRET,
    { expiresIn: 604800 } // 7 days
  );

  console.log('   ✓ Login successful');
  console.log('   ✓ Access token created (15 min expiry)');
  console.log('   ✓ Refresh token created (7 day expiry)');

  return { accessToken, refreshToken };
}

function authenticateRequest(token: string): JWTPayload {
  // Check if token is blacklisted
  if (tokenBlacklist.has(token)) {
    throw new Error('Token has been revoked');
  }

  // Verify token
  const payload = verifyJWT(token, SECRET_KEY, { algorithms: ['HS256'] });
  return payload;
}

function refreshAccessToken(refreshToken: string): string {
  console.log('\n🔄 Refreshing access token...');

  // Verify refresh token
  const payload = verifyJWT(refreshToken, REFRESH_SECRET, { algorithms: ['HS256'] });

  if (payload.type !== 'refresh') {
    throw new Error('Invalid refresh token');
  }

  // Get user from "database"
  const user = Object.values(users).find(u => u.id === payload.userId);
  if (!user) {
    throw new Error('User not found');
  }

  // Create new access token
  const username = Object.keys(users).find(k => users[k].id === user.id)!;
  const newAccessToken = createJWT(
    { userId: user.id, username, role: user.role },
    SECRET_KEY,
    { expiresIn: 900 }
  );

  console.log('   ✓ New access token issued');
  return newAccessToken;
}

function logout(token: string): void {
  console.log('\n🚪 Logging out...');
  tokenBlacklist.add(token);
  console.log('   ✓ Token added to blacklist');
}

// ============================================
// PROTECTED ROUTES (Simulated)
// ============================================

interface Profile {
  id: unknown;
  username: unknown;
  role: unknown;
}

function getProfile(token: string): Profile {
  const user = authenticateRequest(token);
  return { id: user.userId, username: user.username, role: user.role };
}

interface AdminData {
  message: string;
  secretData: string;
}

function adminOnly(token: string): AdminData {
  const user = authenticateRequest(token);
  if (user.role !== 'admin') {
    throw new Error('Admin access required');
  }
  return { message: 'Welcome, admin!', secretData: '💎' };
}

// ============================================
// DEMO: Complete Flow
// ============================================

console.log('\n' + '='.repeat(60));
console.log('📋 SCENARIO 1: Successful Login & API Access');
console.log('='.repeat(60));

// Step 1: Login
const aliceTokens = login('alice', 'password123')!;

// Step 2: Access protected route
console.log('\n📡 Accessing /api/profile...');
try {
  const profile = getProfile(aliceTokens.accessToken);
  console.log('   ✓ Access granted');
  console.log('   Profile:', profile);
} catch (error) {
  console.log('   ✗ Access denied:', (error as Error).message);
}

// Step 3: Access admin route
console.log('\n📡 Accessing /api/admin...');
try {
  const admin = adminOnly(aliceTokens.accessToken);
  console.log('   ✓ Access granted');
  console.log('   Data:', admin);
} catch (error) {
  console.log('   ✗ Access denied:', (error as Error).message);
}

// ============================================
// SCENARIO 2: Non-Admin User
// ============================================

console.log('\n' + '='.repeat(60));
console.log('📋 SCENARIO 2: Non-Admin Tries Admin Route');
console.log('='.repeat(60));

const bobTokens = login('bob', 'bobsecret')!;

console.log('\n📡 Bob accessing /api/admin...');
try {
  const admin = adminOnly(bobTokens.accessToken);
  console.log('   ✓ Access granted:', admin);
} catch (error) {
  console.log('   ✗ Access denied:', (error as Error).message);
}

// ============================================
// SCENARIO 3: Invalid Token
// ============================================

console.log('\n' + '='.repeat(60));
console.log('📋 SCENARIO 3: Using Invalid/Tampered Token');
console.log('='.repeat(60));

console.log('\n📡 Accessing with tampered token...');
const tamperedToken = aliceTokens.accessToken.slice(0, -5) + 'XXXXX';
try {
  getProfile(tamperedToken);
  console.log('   ✓ Access granted (SECURITY ISSUE!)');
} catch (error) {
  console.log('   ✗ Access denied:', (error as Error).message);
}

// ============================================
// SCENARIO 4: Token Refresh
// ============================================

console.log('\n' + '='.repeat(60));
console.log('📋 SCENARIO 4: Token Refresh Flow');
console.log('='.repeat(60));

console.log('\n💡 When access token expires, use refresh token to get a new one');

try {
  const newAccessToken = refreshAccessToken(aliceTokens.refreshToken);
  console.log('\n📡 Using new access token...');
  const profile = getProfile(newAccessToken);
  console.log('   ✓ Access granted with new token');
  console.log('   Profile:', profile);
} catch (error) {
  console.log('   ✗ Refresh failed:', (error as Error).message);
}

// ============================================
// SCENARIO 5: Logout (Token Revocation)
// ============================================

console.log('\n' + '='.repeat(60));
console.log('📋 SCENARIO 5: Logout & Token Revocation');
console.log('='.repeat(60));

logout(aliceTokens.accessToken);

console.log('\n📡 Trying to use revoked token...');
try {
  getProfile(aliceTokens.accessToken);
  console.log('   ✓ Access granted (SECURITY ISSUE!)');
} catch (error) {
  console.log('   ✗ Access denied:', (error as Error).message);
}

// ============================================
// SECURITY LESSONS
// ============================================

console.log('\n' + '='.repeat(60));
console.log('🔒 SECURITY BEST PRACTICES');
console.log('='.repeat(60));

console.log(`
1. ACCESS vs REFRESH TOKENS
   ┌─────────────────┬────────────────────────────────┐
   │ Access Token    │ Refresh Token                  │
   ├─────────────────┼────────────────────────────────┤
   │ Short-lived     │ Long-lived                     │
   │ (15 min - 1 hr) │ (days - weeks)                 │
   ├─────────────────┼────────────────────────────────┤
   │ Sent with every │ Only sent to refresh endpoint  │
   │ API request     │                                │
   ├─────────────────┼────────────────────────────────┤
   │ If stolen, less │ Store securely (httpOnly       │
   │ damage (expires)│ cookie, not localStorage)      │
   └─────────────────┴────────────────────────────────┘

2. TOKEN STORAGE (Browser)
   ✗ localStorage    - Vulnerable to XSS attacks
   ✗ sessionStorage  - Vulnerable to XSS attacks
   ✓ httpOnly cookie - Safe from JavaScript access
   ✓ Memory only     - Lost on refresh, but safest

3. LOGOUT STRATEGIES
   - Token blacklist (we used this)
   - Short expiry + no refresh
   - Store token version in DB, increment on logout

4. COMMON ATTACKS TO PREVENT
   - XSS: Sanitize all user input
   - CSRF: Use CSRF tokens with cookies
   - Token theft: Use HTTPS, secure cookies
   - Algorithm confusion: Always specify allowed algorithms

5. WHAT TO PUT IN JWT PAYLOAD
   ✓ User ID
   ✓ Roles/permissions
   ✓ Token ID (for revocation)
   ✗ Sensitive data (passwords, SSN, etc.)
   ✗ Large data (JWTs are sent with every request!)
`);

// ============================================
// BONUS: See What's in the Tokens
// ============================================

console.log('='.repeat(60));
console.log('🔍 BONUS: Inspecting Our Tokens');
console.log('='.repeat(60));

console.log('\nAccess Token Contents:');
console.log(JSON.stringify(decodeJWT(aliceTokens.accessToken), null, 2));

console.log('\nRefresh Token Contents:');
console.log(JSON.stringify(decodeJWT(aliceTokens.refreshToken), null, 2));

console.log('\n' + '='.repeat(60));
console.log('✅ End of Authentication Flow Example');
console.log('='.repeat(60));
