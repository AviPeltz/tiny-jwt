# Build Your Own JWT Library

A hands-on project to understand JSON Web Tokens, cryptographic signing, and authentication by building it yourself.

**Time:** 2-4 hours
**Difficulty:** Intermediate
**Prerequisites:** Basic TypeScript/JavaScript, familiarity with Node.js

> **⚠️ Important:** This is an educational project. **Never use your own cryptographic implementations in production.** Use battle-tested libraries like [jose](https://github.com/panva/jose) instead. The goal here is to understand *how* JWTs work, not to create production-ready code.

---

## Part 0: The Big Picture - How Web Authentication Works

Before diving into code, let's understand what problem we're solving and how all the pieces fit together.

### The Problem: HTTP is Stateless

HTTP doesn't remember anything between requests. When you send a request to a server, it has no idea who you are or if you've logged in before. Every request starts fresh.

```
Browser                           Server
   │                                │
   │──── GET /dashboard ──────────▶│  "Who are you? I don't know you."
   │                                │
   │◀─── 401 Unauthorized ─────────│
```

We need a way to prove our identity on every request without logging in every time.

### Solution 1: Session-Based Auth (The Old Way)

Traditionally, servers stored login state in memory or a database:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SESSION-BASED AUTH                               │
└─────────────────────────────────────────────────────────────────────────┘

1. LOGIN
   Browser                              Server                    Database
      │                                    │                          │
      │── POST /login {user, pass} ──────▶│                          │
      │                                    │── Verify credentials ───▶│
      │                                    │◀── User valid ───────────│
      │                                    │                          │
      │                                    │── Store session ────────▶│
      │                                    │   {sid: "abc", oderId: 1}      │
      │                                    │                          │
      │◀── Set-Cookie: sid=abc ───────────│                          │

2. SUBSEQUENT REQUESTS
   Browser                              Server                    Database
      │                                    │                          │
      │── GET /dashboard ────────────────▶│                          │
      │   Cookie: sid=abc                  │                          │
      │                                    │── Lookup session ───────▶│
      │                                    │◀── {userId: 1} ──────────│
      │                                    │                          │
      │◀── 200 OK (dashboard data) ───────│                          │
```

**Problems with sessions:**
- Server must store every active session (memory/database)
- Hard to scale: if you have 10 servers, they all need access to sessions
- Every request requires a database lookup

### Solution 2: Token-Based Auth with JWTs (The Modern Way)

JWTs flip the model: instead of storing state on the server, we give the client a **signed token** containing their identity.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         TOKEN-BASED AUTH (JWT)                          │
└─────────────────────────────────────────────────────────────────────────┘

1. LOGIN
   Browser                              Server
      │                                    │
      │── POST /login {user, pass} ──────▶│
      │                                    │── Verify credentials (DB)
      │                                    │
      │                                    │── Create JWT:
      │                                    │   {userId: 1, role: "admin"}
      │                                    │   + signature
      │                                    │
      │◀── {token: "eyJhbG..."} ──────────│  (no session stored!)

2. SUBSEQUENT REQUESTS
   Browser                              Server
      │                                    │
      │── GET /dashboard ────────────────▶│
      │   Authorization: Bearer eyJhbG...  │
      │                                    │── Verify signature (no DB!)
      │                                    │── Read userId from token
      │                                    │
      │◀── 200 OK (dashboard data) ───────│
```

**Why this is better:**
- **Stateless:** Server stores nothing. Any server can verify the token.
- **Scalable:** Add more servers without sharing session state.
- **Fast:** No database lookup needed to verify identity.
- **Flexible:** Token works across different services/domains.

### What's Inside a JWT?

A JWT is just a JSON object that's been signed. Here's what a decoded one looks like:

```javascript
// HEADER (metadata)
{
  "alg": "HS256",    // Algorithm used to sign
  "typ": "JWT"       // Type of token
}

// PAYLOAD (your data)
{
  "userId": 123,
  "username": "alice",
  "role": "admin",
  "iat": 1699900000,  // Issued at (Unix timestamp)
  "exp": 1699903600   // Expires at (Unix timestamp)
}

// SIGNATURE
// Created by: HMAC-SHA256(header + "." + payload, secret)
// This proves the token wasn't tampered with
```

These three parts are Base64URL-encoded and joined with dots:

```
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjEyM30.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
```

### The Key Insight: Signatures Prevent Tampering

Why can't a user just change `"role": "user"` to `"role": "admin"` in their token?

Because the signature is created using:
1. The header and payload content
2. A secret key only the server knows

If you change *anything* in the payload, the signature won't match, and the server rejects it.

```
Original token:
  Payload: {"userId": 123, "role": "user"}
  Signature: abc123 (created with secret key)

Attacker modifies:
  Payload: {"userId": 123, "role": "admin"}  ← Changed!
  Signature: abc123 (still the old signature)

Server verifies:
  Expected signature for new payload: xyz789
  Actual signature in token: abc123
  MISMATCH → Rejected!
```

### Access Tokens vs Refresh Tokens

In practice, we use two tokens:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    TWO-TOKEN AUTHENTICATION                             │
└─────────────────────────────────────────────────────────────────────────┘

┌──────────────────────┐         ┌──────────────────────┐
│    ACCESS TOKEN      │         │   REFRESH TOKEN      │
├──────────────────────┤         ├──────────────────────┤
│ Short-lived (15 min) │         │ Long-lived (7 days)  │
│ Sent with every      │         │ Only sent to get     │
│ API request          │         │ new access tokens    │
│ Contains user info   │         │ Contains minimal info│
│ Store in memory      │         │ Store in httpOnly    │
│ (JavaScript variable)│         │ cookie               │
└──────────────────────┘         └──────────────────────┘

WHY TWO TOKENS?

If access token is stolen:
  → Attacker has 15 minutes before it expires
  → Limited damage

If refresh token is stolen:
  → It's in an httpOnly cookie (JavaScript can't read it!)
  → Only works with your domain
  → Can be revoked server-side
```

### The Complete Flow

Here's how a real application uses JWTs:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    COMPLETE AUTH FLOW                                   │
└─────────────────────────────────────────────────────────────────────────┘

    React App                    API Server                    Database
        │                            │                             │
   ┌────┴────┐                       │                             │
   │  LOGIN  │                       │                             │
   └────┬────┘                       │                             │
        │                            │                             │
        │── POST /auth/login ───────▶│                             │
        │   {email, password}        │── Verify password ─────────▶│
        │                            │◀── User found ──────────────│
        │                            │                             │
        │                            │── Generate tokens:          │
        │                            │   • Access (15 min)         │
        │                            │   • Refresh (7 days)        │
        │                            │                             │
        │◀── {accessToken} ─────────│                             │
        │    Set-Cookie: refresh=... │   (httpOnly, secure)        │
        │                            │                             │
   ┌────┴────┐                       │                             │
   │  STORE  │ accessToken           │                             │
   │   IN    │ in memory             │                             │
   │ MEMORY  │ (React state)         │                             │
   └────┬────┘                       │                             │
        │                            │                             │
   ┌────┴────┐                       │                             │
   │  USE    │                       │                             │
   │  API    │                       │                             │
   └────┬────┘                       │                             │
        │                            │                             │
        │── GET /api/profile ───────▶│                             │
        │   Authorization: Bearer xxx │── Verify signature         │
        │                            │── Check not expired         │
        │                            │── Extract userId            │
        │                            │                             │
        │                            │── Fetch user data ─────────▶│
        │◀── {user data} ───────────│◀────────────────────────────│
        │                            │                             │
   ┌────┴────┐                       │                             │
   │ TOKEN   │ (15 min later...)     │                             │
   │ EXPIRED │                       │                             │
   └────┬────┘                       │                             │
        │                            │                             │
        │── GET /api/profile ───────▶│                             │
        │   Authorization: Bearer xxx │── Token expired!           │
        │◀── 401 Unauthorized ───────│                             │
        │                            │                             │
   ┌────┴────┐                       │                             │
   │ REFRESH │                       │                             │
   └────┬────┘                       │                             │
        │                            │                             │
        │── POST /auth/refresh ─────▶│                             │
        │   Cookie: refresh=...      │── Verify refresh token      │
        │                            │── Generate new access token │
        │◀── {accessToken} ─────────│                             │
        │                            │                             │
        │   (retry original request) │                             │
        │── GET /api/profile ───────▶│                             │
        │   Authorization: Bearer new │                            │
        │◀── {user data} ───────────│                             │
```

### What You'll Build in This Project

1. **The JWT Library (Parts 1-5):** Encode, sign, verify, decode tokens
2. **Auth Functions (Part 6):** Login, logout, refresh, authorization
3. **Security Challenges (Part 7):** Try to break your own implementation

Once you understand how JWTs work internally, you'll be able to:
- Debug authentication issues confidently
- Understand security vulnerabilities
- Make informed decisions about token storage and expiration
- Use production JWT libraries effectively

Let's start building!

---

## Part 1: Understanding the JWT Structure

### Background

A JWT (JSON Web Token) is just three Base64URL-encoded strings separated by dots:

```
eyJhbGciOiJIUzI1NiJ9.eyJ1c2VySWQiOjEyM30.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ
|______________________|_______________________|___________________________________________|
       HEADER                  PAYLOAD                         SIGNATURE
```

**Header:** Metadata about the token (what algorithm was used)
**Payload:** The actual data (claims) you want to transmit
**Signature:** Proof that the token hasn't been tampered with

> **Critical:** JWTs are **signed**, not **encrypted**. Anyone can decode and read the payload! The signature only proves the token wasn't modified—it doesn't hide the contents. Never put passwords, credit card numbers, or sensitive data in a JWT.

### Why Base64URL?

Regular Base64 uses `+`, `/`, and `=` characters. These cause problems in URLs and HTTP headers. Base64URL replaces them:
- `+` → `-`
- `/` → `_`
- `=` → (removed)

### Exercise 1.1: Implement Base64URL Encoding

Create a new file `src/jwt.ts` and implement these functions:

```typescript
/**
 * Encode data to Base64URL format
 *
 * @param data - String or object to encode
 * @returns Base64URL encoded string
 *
 * Hints:
 * - If data is an object, JSON.stringify it first
 * - Use Buffer.from(str).toString('base64') to get Base64
 * - Replace + with -, / with _, and remove trailing =
 */
export function base64urlEncode(data: string | object): string {
  // Your implementation here
}

/**
 * Decode a Base64URL string back to UTF-8
 *
 * @param str - Base64URL encoded string
 * @returns Decoded UTF-8 string
 *
 * Hints:
 * - Add back padding: str + '='.repeat((4 - str.length % 4) % 4)
 * - Replace - with +, _ with /
 * - Use Buffer.from(base64, 'base64').toString('utf8')
 */
export function base64urlDecode(str: string): string {
  // Your implementation here
}
```

### Test Your Implementation

```typescript
// Test it:
const original = { hello: 'world', number: 42 };
const encoded = base64urlEncode(original);
console.log('Encoded:', encoded);
// Expected: eyJoZWxsbyI6IndvcmxkIiwibnVtYmVyIjo0Mn0

const decoded = base64urlDecode(encoded);
console.log('Decoded:', decoded);
// Expected: {"hello":"world","number":42}
```

### 🤔 Think About It

1. Why can't we just use JSON directly instead of Base64URL encoding?
2. What would happen if we used regular Base64 in a URL query parameter?

<details>
<summary>Answers</summary>

1. JSON contains characters like `{`, `}`, `"`, and spaces that aren't safe in HTTP headers or URLs without escaping. Base64URL gives us a clean alphanumeric string.

2. The `+` would be interpreted as a space, and `=` has special meaning in query strings (key=value). The token would be corrupted.

</details>

---

## Part 2: HMAC Signing (Symmetric Cryptography)

### Background

HMAC (Hash-based Message Authentication Code) uses a **single secret key** for both signing and verifying. Think of it like a password that both the sender and receiver know.

```
         Same Secret Key
              │
    ┌─────────┴─────────┐
    ▼                   ▼
  SIGN               VERIFY
(creator)          (verifier)
```

**How it works:**
1. HMAC uses the secret key in a specific way with the hash function (not just concatenation)
2. It runs: `hash(key XOR opad || hash(key XOR ipad || message))` (simplified)
3. The output is a unique "fingerprint" that depends on both message and key
4. Same inputs always produce the same fingerprint (deterministic)
5. Any change to message OR key = completely different fingerprint (avalanche effect)
6. Without the key, you cannot forge a valid signature even if you know the algorithm

### Exercise 2.1: Implement HMAC Signing

```typescript
import crypto from 'crypto';

/**
 * Create an HMAC signature for data
 *
 * @param data - The string to sign
 * @param secret - The secret key
 * @param algorithm - Hash algorithm ('sha256', 'sha384', 'sha512')
 * @returns Base64URL encoded signature
 *
 * Hints:
 * - Use crypto.createHmac(algorithm, secret)
 * - Call .update(data) to add the data
 * - Call .digest('base64url') to get the signature
 */
export function signHMAC(data: string, secret: string, algorithm = 'sha256'): string {
  // Your implementation here
}

/**
 * Verify an HMAC signature
 *
 * @param data - The original data
 * @param signature - The signature to verify
 * @param secret - The secret key
 * @param algorithm - Hash algorithm
 * @returns true if signature is valid
 *
 * Hints:
 * - Generate a new signature for the data
 * - Compare it to the provided signature
 * - Use crypto.timingSafeEqual() to prevent timing attacks!
 */
export function verifyHMAC(
  data: string,
  signature: string,
  secret: string,
  algorithm = 'sha256'
): boolean {
  // Your implementation here
}
```

### Test Your Implementation

```typescript
const message = 'Hello, World!';
const secret = 'my-secret-key';

const sig = signHMAC(message, secret);
console.log('Signature:', sig);

console.log('Valid:', verifyHMAC(message, sig, secret));           // true
console.log('Wrong secret:', verifyHMAC(message, sig, 'wrong'));   // false
console.log('Wrong message:', verifyHMAC('Tampered!', sig, secret)); // false
```

### 🤔 Think About It

1. Why do we use `crypto.timingSafeEqual()` instead of `===`?
2. If an attacker gets your HMAC secret, what can they do?

<details>
<summary>Answers</summary>

1. Regular string comparison (`===`) returns faster when the first characters don't match. An attacker could measure response times to guess the signature character by character (timing attack). `timingSafeEqual` always takes the same time regardless of where strings differ.

2. They can create valid tokens for any user! This is why HMAC secrets must be kept absolutely secure, and why RSA (asymmetric) signing is better for distributed systems.

</details>

---

## Part 3: Create Your First JWT

### Exercise 3.1: Implement JWT Creation

Now combine what you've built to create actual JWTs:

```typescript
export type Algorithm = 'HS256' | 'HS384' | 'HS512';

export interface JWTHeader {
  alg: Algorithm;
  typ: 'JWT';
}

export interface JWTPayload {
  [key: string]: unknown;
  iat?: number;  // Issued At (seconds since epoch)
  exp?: number;  // Expiration Time
}

export interface CreateJWTOptions {
  algorithm?: Algorithm;
  expiresIn?: number;  // Seconds until expiration
}

/**
 * Create a signed JWT
 *
 * @param payload - Data to include in the token
 * @param secret - Secret key for signing
 * @param options - Algorithm and expiration options
 * @returns The complete JWT string
 *
 * Steps:
 * 1. Create header object with alg and typ
 * 2. Add iat (current time) and exp (current time + expiresIn) to payload
 * 3. Base64URL encode the header
 * 4. Base64URL encode the payload
 * 5. Create signature: signHMAC(encodedHeader + '.' + encodedPayload, secret)
 * 6. Return: encodedHeader + '.' + encodedPayload + '.' + signature
 */
export function createJWT(
  payload: Record<string, unknown>,
  secret: string,
  options: CreateJWTOptions = {}
): string {
  const { algorithm = 'HS256', expiresIn = 3600 } = options;

  // Your implementation here
}
```

### Test Your Implementation

```typescript
const token = createJWT(
  { userId: 123, role: 'admin' },
  'my-secret-key',
  { expiresIn: 3600 }
);

console.log('Token:', token);
// Should look like: xxxxx.yyyyy.zzzzz

// Decode and inspect (don't verify yet, just look at it)
const [header, payload, sig] = token.split('.');
console.log('Header:', JSON.parse(base64urlDecode(header)));
console.log('Payload:', JSON.parse(base64urlDecode(payload)));
```

### 🤔 Think About It

1. The header and payload are just Base64URL encoded, not encrypted. What does this mean for what you should put in a JWT?
2. Why do we include `iat` (issued at) in every token?

<details>
<summary>Answers</summary>

1. **Anyone can read the payload!** Never put sensitive data like passwords, credit cards, or secrets in a JWT. The signature only proves it wasn't tampered with - it doesn't hide the contents.

2. `iat` helps with:
   - Debugging (when was this token created?)
   - Token rotation policies (reject tokens older than X)
   - Audit trails

</details>

---

## Part 4: Verify JWTs

### Background: Why Verification Matters

Without verification, an attacker could:
1. Take any JWT
2. Decode the payload
3. Change `{ userId: 123 }` to `{ userId: 1 }` (admin!)
4. Re-encode it
5. Send it to your server

The signature prevents this - when the payload changes, the signature no longer matches.

### Exercise 4.1: Implement JWT Verification

```typescript
export interface VerifyJWTOptions {
  algorithms?: Algorithm[];  // Which algorithms to allow
}

/**
 * Verify a JWT and return its payload
 *
 * @param token - The JWT string to verify
 * @param secret - The secret key
 * @param options - Verification options
 * @returns The verified payload
 * @throws Error if verification fails
 *
 * Steps:
 * 1. Split token into [header, payload, signature] by '.'
 * 2. If not exactly 3 parts, throw 'Invalid JWT format'
 * 3. Decode and parse the header
 * 4. Check if header.alg is in allowed algorithms (prevent algorithm confusion!)
 * 5. Verify signature: verifyHMAC(header + '.' + payload, signature, secret)
 * 6. If signature invalid, throw 'Invalid signature'
 * 7. Decode and parse the payload
 * 8. Check expiration: if payload.exp < current time, throw 'Token expired'
 * 9. Return the payload
 */
export function verifyJWT(
  token: string,
  secret: string,
  options: VerifyJWTOptions = {}
): JWTPayload {
  const { algorithms = ['HS256'] } = options;

  // Your implementation here
}
```

### Test Your Implementation

```typescript
const secret = 'my-secret-key';
const token = createJWT({ userId: 123 }, secret, { expiresIn: 3600 });

// Should work
try {
  const payload = verifyJWT(token, secret);
  console.log('✓ Verified:', payload);
} catch (e) {
  console.log('✗ Failed:', e.message);
}

// Wrong secret should fail
try {
  verifyJWT(token, 'wrong-secret');
  console.log('✗ Should have failed!');
} catch (e) {
  console.log('✓ Correctly rejected:', e.message);
}

// Tampered token should fail
const parts = token.split('.');
const tamperedPayload = base64urlEncode({ userId: 1, admin: true });
const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
try {
  verifyJWT(tamperedToken, secret);
  console.log('✗ Should have failed!');
} catch (e) {
  console.log('✓ Detected tampering:', e.message);
}
```

### 🤔 Think About It

1. Why do we check if the algorithm is in an allowed list?
2. What's the "algorithm confusion" attack?

<details>
<summary>Answers</summary>

1. To prevent **algorithm confusion attacks**. Without this check, an attacker could:
   - Take an RS256 token (signed with private key)
   - Change the header to say "HS256"
   - Use the PUBLIC key (which everyone has) as the HMAC secret
   - Your server would verify it with the public key and accept it!

2. See above. This is why you should always specify which algorithms you accept, and never trust the algorithm in the token header alone.

</details>

---

## Part 5: RSA Signing (Asymmetric Cryptography)

### Background

RSA uses **two different keys**:
- **Private key:** Used to SIGN tokens (keep this SECRET!)
- **Public key:** Used to VERIFY tokens (can share with anyone)

```
Private Key              Public Key
(keep secret!)           (share freely)
     │                        │
     ▼                        ▼
   SIGN                    VERIFY
```

This is powerful because:
- Services that verify tokens don't need the private key
- If a verification-only service is hacked, attacker still can't create tokens
- You can publish your public key for anyone to verify your tokens

### Exercise 5.1: Generate RSA Key Pair

```typescript
import crypto from 'crypto';

export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}

/**
 * Generate an RSA key pair for signing JWTs
 *
 * @returns Object with publicKey and privateKey as PEM strings
 *
 * Hints:
 * - Use crypto.generateKeyPairSync('rsa', options)
 * - modulusLength: 2048 (minimum secure size)
 * - publicKeyEncoding: { type: 'spki', format: 'pem' }
 * - privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
 */
export function generateRSAKeyPair(): RSAKeyPair {
  // Your implementation here
}
```

### Exercise 5.2: Implement RSA Signing

```typescript
/**
 * Sign data with an RSA private key
 *
 * @param data - String to sign
 * @param privateKey - PEM-encoded private key
 * @returns Base64URL encoded signature
 *
 * Hints:
 * - Use crypto.createSign('RSA-SHA256')
 * - Call .update(data)
 * - Call .sign(privateKey, 'base64url')
 */
export function signRSA(data: string, privateKey: string): string {
  // Your implementation here
}

/**
 * Verify an RSA signature with a public key
 *
 * @param data - Original data
 * @param signature - Signature to verify
 * @param publicKey - PEM-encoded public key
 * @returns true if valid
 *
 * Hints:
 * - Use crypto.createVerify('RSA-SHA256')
 * - Call .update(data)
 * - Call .verify(publicKey, signature, 'base64url')
 * - Wrap in try/catch, return false on error
 */
export function verifyRSA(data: string, signature: string, publicKey: string): boolean {
  // Your implementation here
}
```

### Exercise 5.3: Extend createJWT and verifyJWT for RSA

Update your `createJWT` and `verifyJWT` functions to support RSA:

```typescript
export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256';

export interface CreateJWTOptions {
  algorithm?: Algorithm;
  expiresIn?: number;
  privateKey?: string;  // For RSA
}

export interface VerifyJWTOptions {
  algorithms?: Algorithm[];
  publicKey?: string;  // For RSA
}

// In createJWT:
// - If algorithm starts with 'RS', use signRSA with privateKey
// - If algorithm starts with 'HS', use signHMAC with secret

// In verifyJWT:
// - If header.alg starts with 'RS', use verifyRSA with publicKey
// - If header.alg starts with 'HS', use verifyHMAC with secret
```

### Test Your Implementation

```typescript
const { publicKey, privateKey } = generateRSAKeyPair();

// Create with private key
const token = createJWT(
  { userId: 123 },
  null,
  { algorithm: 'RS256', privateKey }
);

// Verify with public key
const payload = verifyJWT(token, null, {
  algorithms: ['RS256'],
  publicKey
});

console.log('Verified with public key:', payload);

// Try with wrong public key
const { publicKey: wrongKey } = generateRSAKeyPair();
try {
  verifyJWT(token, null, { algorithms: ['RS256'], publicKey: wrongKey });
  console.log('✗ Should have failed!');
} catch (e) {
  console.log('✓ Correctly rejected wrong key');
}
```

### 🤔 Think About It

1. In a microservices architecture, which services need the private key? Which need the public key?
2. Why is RSA slower than HMAC?
3. When would you choose HMAC over RSA?

<details>
<summary>Answers</summary>

1. **Private key:** Only the authentication service that creates tokens
   **Public key:** All services that need to verify tokens (APIs, etc.)

2. RSA involves complex mathematical operations (modular exponentiation with very large numbers). HMAC is just hashing, which is much simpler computationally.

3. Choose HMAC when:
   - You have a single application (same server signs and verifies)
   - Simplicity is more important than separation of concerns
   - Performance is critical (HMAC is ~100x faster)
   - You can securely share the secret between all parties

</details>

---

## Part 6: Build an Auth System

Now let's use your JWT library to build a realistic authentication system.

### Exercise 6.1: Implement a Complete Auth Flow

Create a new file `src/auth.ts`:

```typescript
import { createJWT, verifyJWT } from './jwt.js';

// Configuration
const ACCESS_TOKEN_SECRET = 'access-secret-keep-safe';
const REFRESH_TOKEN_SECRET = 'refresh-secret-different';
const ACCESS_TOKEN_EXPIRY = 900;      // 15 minutes
const REFRESH_TOKEN_EXPIRY = 604800;  // 7 days

// Simulated user database
interface User {
  id: number;
  username: string;
  password: string;  // In real app, this would be hashed!
  role: 'admin' | 'user';
}

const users: User[] = [
  { id: 1, username: 'alice', password: 'password123', role: 'admin' },
  { id: 2, username: 'bob', password: 'bobsecret', role: 'user' },
];

// Token blacklist (for logout)
const blacklist = new Set<string>();

/**
 * Authenticate user and return tokens
 *
 * @param username
 * @param password
 * @returns Access and refresh tokens, or null if invalid credentials
 *
 * Implementation:
 * 1. Find user by username
 * 2. Check password matches
 * 3. Create access token with { userId, username, role }
 * 4. Create refresh token with { userId, type: 'refresh' }
 * 5. Return both tokens
 */
export function login(username: string, password: string): {
  accessToken: string;
  refreshToken: string
} | null {
  // Your implementation here
}

/**
 * Verify an access token and return the user info
 *
 * @param token - The access token
 * @returns User info from the token
 * @throws If token is invalid, expired, or blacklisted
 *
 * Implementation:
 * 1. Check if token is in blacklist
 * 2. Verify token with ACCESS_TOKEN_SECRET
 * 3. Return the payload
 */
export function authenticate(token: string): {
  userId: number;
  username: string;
  role: string
} {
  // Your implementation here
}

/**
 * Get a new access token using a refresh token
 *
 * @param refreshToken
 * @returns New access token
 * @throws If refresh token is invalid
 *
 * Implementation:
 * 1. Verify refresh token with REFRESH_TOKEN_SECRET
 * 2. Check payload.type === 'refresh'
 * 3. Look up user by userId
 * 4. Create and return new access token
 */
export function refresh(refreshToken: string): string {
  // Your implementation here
}

/**
 * Invalidate a token (logout)
 *
 * @param token - Token to invalidate
 *
 * Implementation:
 * Add token to blacklist
 */
export function logout(token: string): void {
  // Your implementation here
}

/**
 * Middleware-style function for protected routes
 *
 * @param token - Access token
 * @param requiredRole - Optional required role
 * @returns User info if authorized
 * @throws If not authenticated or not authorized
 */
export function authorize(token: string, requiredRole?: string): {
  userId: number;
  username: string;
  role: string;
} {
  // Your implementation here
}
```

### Test Your Auth System

```typescript
import { login, authenticate, refresh, logout, authorize } from './auth.js';

// Scenario 1: Successful login
console.log('=== Login ===');
const tokens = login('alice', 'password123');
console.log('Got tokens:', tokens ? 'Yes' : 'No');

// Scenario 2: Access protected resource
console.log('\n=== Access Resource ===');
try {
  const user = authenticate(tokens!.accessToken);
  console.log('Authenticated as:', user);
} catch (e) {
  console.log('Failed:', e.message);
}

// Scenario 3: Admin-only resource
console.log('\n=== Admin Access ===');
try {
  const user = authorize(tokens!.accessToken, 'admin');
  console.log('Admin access granted to:', user.username);
} catch (e) {
  console.log('Failed:', e.message);
}

// Scenario 4: Non-admin tries admin resource
console.log('\n=== Non-Admin Tries Admin ===');
const bobTokens = login('bob', 'bobsecret');
try {
  authorize(bobTokens!.accessToken, 'admin');
  console.log('Should have failed!');
} catch (e) {
  console.log('Correctly denied:', e.message);
}

// Scenario 5: Refresh token
console.log('\n=== Token Refresh ===');
const newAccessToken = refresh(tokens!.refreshToken);
console.log('Got new access token:', newAccessToken ? 'Yes' : 'No');

// Scenario 6: Logout
console.log('\n=== Logout ===');
logout(tokens!.accessToken);
try {
  authenticate(tokens!.accessToken);
  console.log('Should have failed!');
} catch (e) {
  console.log('Correctly rejected after logout:', e.message);
}
```

---

## Part 7: Security Challenges

Now that you have a working system, try to break it! These exercises will teach you about common vulnerabilities.

### Challenge 7.1: Tamper with a Token

Try to modify a token's payload without knowing the secret:

```typescript
const tokens = login('bob', 'bobsecret')!;

// Bob is a regular user, but wants to be admin
// Can you modify the token to make bob an admin?

const parts = tokens.accessToken.split('.');
// Decode payload, change role to 'admin', re-encode
// Does it work? Why or why not?
```

### Challenge 7.2: Algorithm Confusion (if you implemented RS256)

What happens if:
1. You create a token with RS256 (signed with private key)
2. You change the header to say "HS256"
3. You use the PUBLIC key as the HMAC secret

Does your implementation prevent this? If not, fix it!

### Challenge 7.3: Token Expiration Bypass

What happens if you:
1. Create a token with `expiresIn: 1` (1 second)
2. Wait 2 seconds
3. Try to verify it

Does your implementation check expiration? What about tokens with no `exp` claim?

### Challenge 7.4: Timing Attack

Look at your `verifyHMAC` function. If you used `===` to compare signatures:

```typescript
// Vulnerable!
return generatedSignature === providedSignature;
```

An attacker can measure how long verification takes. If the first character matches, it takes slightly longer than if no characters match. By trying many signatures and measuring times, they can guess the correct signature one character at a time.

**Fix:** Use `crypto.timingSafeEqual()` which always takes the same amount of time.

### Challenge 7.5: The "none" Algorithm

Some JWT libraries historically accepted `alg: "none"`, meaning "trust this token without any signature." An attacker could:

1. Take any valid token
2. Change the payload to anything they want
3. Set the header to `{ "alg": "none", "typ": "JWT" }`
4. Remove the signature entirely
5. Send: `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOjEsImFkbWluIjp0cnVlfQ.`

Does your implementation reject this? It should! Never allow `"none"` as an algorithm.

---

## Bonus Challenges

### Bonus 1: Add `nbf` (Not Before) Support

Some tokens shouldn't be valid until a future time. Add support for the `nbf` claim:

```typescript
const token = createJWT(
  { userId: 123 },
  secret,
  { notBefore: 3600 }  // Valid 1 hour from now
);
```

### Bonus 2: Add `jti` (JWT ID) for Revocation

Instead of blacklisting entire tokens, add a unique ID to each token and blacklist just the ID:

```typescript
const token = createJWT({ userId: 123 }, secret);
// Token includes jti: 'unique-id-123'

revokeTokenById('unique-id-123');
// Now any token with that jti is invalid
```

### Bonus 3: Implement Token Refresh Rotation

When a refresh token is used:
1. Invalidate the old refresh token
2. Issue a new refresh token along with the new access token

This limits the damage if a refresh token is stolen.

### Bonus 4: Add Support for ES256 (ECDSA)

ECDSA is another asymmetric algorithm that's faster than RSA and produces smaller signatures. Implement:
- `generateECKeyPair()`
- `signEC(data, privateKey)`
- `verifyEC(data, signature, publicKey)`

---

## Wrapping Up

### What You've Learned

- **JWT Structure:** Header, payload, signature - and why Base64URL
- **HMAC Signing:** Symmetric cryptography with shared secrets
- **RSA Signing:** Asymmetric cryptography with key pairs
- **Security:** Algorithm confusion, timing attacks, token expiration
- **Auth Patterns:** Access tokens, refresh tokens, token revocation

### Real-World Considerations

Things we simplified that you'd need in production:

1. **Password Hashing:** Never store plain passwords! Use bcrypt or Argon2.

2. **HMAC Key Length:** Your secret key should be at least as long as the hash output:
   - HS256: minimum 32 bytes (256 bits)
   - HS384: minimum 48 bytes (384 bits)
   - HS512: minimum 64 bytes (512 bits)
   Using a short secret like `"secret"` is insecure!

3. **Key Rotation:** Secrets should be rotated periodically. Use a `kid` (Key ID) header to identify which key signed a token.

4. **HTTPS Only:** JWTs should only ever be sent over HTTPS. Over HTTP, anyone can read and steal tokens.

5. **Secure Storage:**
   - Access tokens: Memory only (never localStorage!)
   - Refresh tokens: httpOnly, Secure, SameSite cookies

6. **Token Blacklist Scalability:** Our in-memory Set doesn't scale. In production:
   - Use Redis with TTL matching token expiration
   - Or store a "token version" per user in the database
   - Or use short-lived tokens without blacklisting

7. **Clock Skew:** Servers' clocks can differ. Add a small tolerance (e.g., 30 seconds) when checking `exp` and `nbf`.

8. **Rate Limiting:** Prevent brute force attacks on login endpoints.

9. **Proper Error Messages:** Don't reveal whether username or password was wrong—say "Invalid credentials" for both.

10. **The "none" Algorithm Attack:** Some JWT libraries accept `alg: "none"` which means "no signature required." Our implementation doesn't support this, but always be explicit about which algorithms you allow.

### Libraries to Use in Production

Don't use your own JWT implementation in production! Use battle-tested libraries:

- **Node.js:** [jose](https://github.com/panva/jose) or [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
- **Python:** [PyJWT](https://github.com/jpadilla/pyjwt) or [python-jose](https://github.com/mpdavis/python-jose)
- **Go:** [golang-jwt](https://github.com/golang-jwt/jwt)

### Further Reading

- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [JWT.io](https://jwt.io) - Debugger and library list
- [Auth0 JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)

---

## Solution

The complete implementation is available in `src/index.ts`. Try to implement everything yourself first, then compare with the solution to see different approaches!
