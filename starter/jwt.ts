/**
 * tiny-jwt: Build Your Own JWT Library
 *
 * Fill in the implementations below. Each function has hints in the comments.
 * Run tests with: npx tsx starter/jwt.ts
 */

import crypto from 'crypto';

// ============================================
// TYPES
// ============================================

export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256';

export interface JWTHeader {
  alg: Algorithm;
  typ: 'JWT';
}

export interface JWTPayload {
  iat?: number;
  exp?: number;
  [key: string]: unknown;
}

export interface CreateJWTOptions {
  algorithm?: Algorithm;
  expiresIn?: number;
  privateKey?: string;
}

export interface VerifyJWTOptions {
  algorithms?: Algorithm[];
  publicKey?: string;
}

export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}

// ============================================
// PART 1: BASE64URL ENCODING
// ============================================

/**
 * Encode data to Base64URL format
 *
 * Steps:
 * 1. If data is an object, JSON.stringify it
 * 2. Convert to Base64: Buffer.from(str).toString('base64')
 * 3. Replace + with -
 * 4. Replace / with _
 * 5. Remove trailing = signs
 */
export function base64urlEncode(data: string | object): string {
  // TODO: Implement this
  throw new Error('Not implemented');
}

/**
 * Decode a Base64URL string
 *
 * Steps:
 * 1. Add padding: str + '='.repeat((4 - str.length % 4) % 4)
 * 2. Replace - with +
 * 3. Replace _ with /
 * 4. Decode: Buffer.from(base64, 'base64').toString('utf8')
 */
export function base64urlDecode(str: string): string {
  // TODO: Implement this
  throw new Error('Not implemented');
}

// ============================================
// PART 2: HMAC SIGNING
// ============================================

/**
 * Create an HMAC signature
 *
 * Use:
 * - crypto.createHmac(algorithm, secret)
 * - .update(data)
 * - .digest('base64url')
 */
export function signHMAC(data: string, secret: string, algorithm = 'sha256'): string {
  // TODO: Implement this
  throw new Error('Not implemented');
}

/**
 * Verify an HMAC signature
 *
 * Steps:
 * 1. Generate expected signature using signHMAC
 * 2. Compare using crypto.timingSafeEqual (prevents timing attacks!)
 *
 * Note: timingSafeEqual needs Buffers of equal length, so wrap in try/catch
 */
export function verifyHMAC(
  data: string,
  signature: string,
  secret: string,
  algorithm = 'sha256'
): boolean {
  // TODO: Implement this
  throw new Error('Not implemented');
}

// ============================================
// PART 3: RSA SIGNING
// ============================================

/**
 * Generate an RSA key pair
 *
 * Use crypto.generateKeyPairSync('rsa', {
 *   modulusLength: 2048,
 *   publicKeyEncoding: { type: 'spki', format: 'pem' },
 *   privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
 * })
 */
export function generateRSAKeyPair(): RSAKeyPair {
  // TODO: Implement this
  throw new Error('Not implemented');
}

/**
 * Sign data with RSA private key
 *
 * Use:
 * - crypto.createSign('RSA-SHA256') for sha256
 * - crypto.createSign('RSA-SHA384') for sha384
 * - crypto.createSign('RSA-SHA512') for sha512
 * - .update(data)
 * - .sign(privateKey, 'base64url')
 */
export function signRSA(data: string, privateKey: string, algorithm: string = 'sha256'): string {
  // TODO: Implement this
  // Hint: Map algorithm to OpenSSL names: sha256 -> 'RSA-SHA256', etc.
  throw new Error('Not implemented');
}

/**
 * Verify RSA signature with public key
 *
 * Use:
 * - crypto.createVerify('RSA-SHA256') for sha256 (etc.)
 * - .update(data)
 * - .verify(publicKey, signature, 'base64url')
 *
 * Wrap in try/catch, return false on error
 */
export function verifyRSA(data: string, signature: string, publicKey: string, algorithm: string = 'sha256'): boolean {
  // TODO: Implement this
  throw new Error('Not implemented');
}

// ============================================
// PART 4: JWT CREATION
// ============================================

/**
 * Create a signed JWT
 *
 * Steps:
 * 1. Create header: { alg: algorithm, typ: 'JWT' }
 * 2. Add iat and exp to payload
 * 3. Encode header and payload with base64urlEncode
 * 4. Create data to sign: encodedHeader + '.' + encodedPayload
 * 5. Sign based on algorithm:
 *    - HS* -> signHMAC(dataToSign, secret, 'sha' + alg.slice(2))
 *    - RS* -> signRSA(dataToSign, privateKey)
 * 6. Return: dataToSign + '.' + signature
 */
export function createJWT(
  payload: Record<string, unknown>,
  secret: string | null,
  options: CreateJWTOptions = {}
): string {
  const { algorithm = 'HS256', expiresIn = 3600, privateKey = null } = options;

  // TODO: Implement this
  throw new Error('Not implemented');
}

// ============================================
// PART 5: JWT VERIFICATION
// ============================================

/**
 * Verify a JWT and return its payload
 *
 * Steps:
 * 1. Split token by '.' - must have exactly 3 parts
 * 2. Decode header, check algorithm is allowed
 * 3. Verify signature based on algorithm
 * 4. Decode payload
 * 5. Check exp > current time (if exp exists)
 * 6. Return payload
 *
 * Throw descriptive errors for each failure case!
 */
export function verifyJWT(
  token: string,
  secret: string | null,
  options: VerifyJWTOptions = {}
): JWTPayload {
  const { algorithms = ['HS256'], publicKey = null } = options;

  // TODO: Implement this
  throw new Error('Not implemented');
}

// ============================================
// PART 6: DECODE (WITHOUT VERIFICATION)
// ============================================

/**
 * Decode a JWT without verifying (for debugging only!)
 *
 * WARNING: Never trust data from an unverified token!
 */
export function decodeJWT(token: string): {
  header: JWTHeader;
  payload: JWTPayload;
  signature: string;
} {
  // TODO: Implement this
  throw new Error('Not implemented');
}

// ============================================
// TESTS - Run with: npx tsx starter/jwt.ts
// ============================================

function runTests() {
  console.log('Running tests...\n');
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

  // Part 1: Base64URL
  test('base64urlEncode encodes object', () => {
    const result = base64urlEncode({ hello: 'world' });
    if (result !== 'eyJoZWxsbyI6IndvcmxkIn0') throw new Error(`Got: ${result}`);
  });

  test('base64urlDecode decodes string', () => {
    const result = base64urlDecode('eyJoZWxsbyI6IndvcmxkIn0');
    if (result !== '{"hello":"world"}') throw new Error(`Got: ${result}`);
  });

  // Part 2: HMAC
  test('signHMAC produces signature', () => {
    const sig = signHMAC('test', 'secret');
    if (!sig || sig.length < 10) throw new Error('Signature too short');
  });

  test('verifyHMAC validates correct signature', () => {
    const sig = signHMAC('test', 'secret');
    if (!verifyHMAC('test', sig, 'secret')) throw new Error('Should be valid');
  });

  test('verifyHMAC rejects wrong secret', () => {
    const sig = signHMAC('test', 'secret');
    if (verifyHMAC('test', sig, 'wrong')) throw new Error('Should be invalid');
  });

  // Part 3: RSA
  test('generateRSAKeyPair produces keys', () => {
    const { publicKey, privateKey } = generateRSAKeyPair();
    if (!publicKey.includes('PUBLIC KEY')) throw new Error('Invalid public key');
    if (!privateKey.includes('PRIVATE KEY')) throw new Error('Invalid private key');
  });

  test('signRSA and verifyRSA work together', () => {
    const { publicKey, privateKey } = generateRSAKeyPair();
    const sig = signRSA('test', privateKey);
    if (!verifyRSA('test', sig, publicKey)) throw new Error('Should be valid');
  });

  // Part 4 & 5: JWT
  test('createJWT produces valid token', () => {
    const token = createJWT({ userId: 123 }, 'secret');
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Should have 3 parts');
  });

  test('verifyJWT validates and returns payload', () => {
    const token = createJWT({ userId: 123 }, 'secret');
    const payload = verifyJWT(token, 'secret');
    if (payload.userId !== 123) throw new Error('userId should be 123');
  });

  test('verifyJWT rejects wrong secret', () => {
    const token = createJWT({ userId: 123 }, 'secret');
    try {
      verifyJWT(token, 'wrong');
      throw new Error('Should have thrown');
    } catch (e) {
      if ((e as Error).message === 'Should have thrown') throw e;
    }
  });

  test('verifyJWT rejects tampered token', () => {
    const token = createJWT({ userId: 123 }, 'secret');
    const parts = token.split('.');
    const tamperedPayload = base64urlEncode({ userId: 1, admin: true });
    const tampered = `${parts[0]}.${tamperedPayload}.${parts[2]}`;
    try {
      verifyJWT(tampered, 'secret');
      throw new Error('Should have thrown');
    } catch (e) {
      if ((e as Error).message === 'Should have thrown') throw e;
    }
  });

  test('RSA JWT creation and verification', () => {
    const { publicKey, privateKey } = generateRSAKeyPair();
    const token = createJWT({ userId: 456 }, null, {
      algorithm: 'RS256',
      privateKey
    });
    const payload = verifyJWT(token, null, {
      algorithms: ['RS256'],
      publicKey
    });
    if (payload.userId !== 456) throw new Error('userId should be 456');
  });

  // Part 6: Decode
  test('decodeJWT extracts parts', () => {
    const token = createJWT({ userId: 789 }, 'secret');
    const decoded = decodeJWT(token);
    if (decoded.header.alg !== 'HS256') throw new Error('Wrong algorithm');
    if (decoded.payload.userId !== 789) throw new Error('Wrong userId');
  });

  console.log(`\n${passed} passed, ${failed} failed`);

  if (failed > 0) {
    console.log('\nKeep going! Check PROJECT.md for hints.');
  } else {
    console.log('\n🎉 All tests passed! Great job!');
  }
}

// Run tests if this file is executed directly
runTests();
