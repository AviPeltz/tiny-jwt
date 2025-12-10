/**
 * tiny-jwt: A minimal JWT implementation for learning purposes
 *
 * JWT Structure:
 * A JWT has 3 parts separated by dots: HEADER.PAYLOAD.SIGNATURE
 *
 * 1. HEADER: Contains metadata (algorithm used, token type)
 * 2. PAYLOAD: Contains the claims (data you want to transmit)
 * 3. SIGNATURE: Proves the token wasn't tampered with
 */

import crypto from 'crypto';

// ============================================
// TYPES
// ============================================

export type Algorithm = 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512';

export interface JWTHeader {
  alg: Algorithm;
  typ: 'JWT';
}

export interface JWTPayload {
  iat?: number;      // Issued At
  exp?: number;      // Expiration Time
  nbf?: number;      // Not Before
  sub?: string;      // Subject
  iss?: string;      // Issuer
  aud?: string;      // Audience
  jti?: string;      // JWT ID
  [key: string]: unknown;
}

export interface DecodedJWT {
  header: JWTHeader;
  payload: JWTPayload;
  signature: string;
}

export interface CreateJWTOptions {
  algorithm?: Algorithm;
  expiresIn?: number;
  privateKey?: string | null;
}

export interface VerifyJWTOptions {
  publicKey?: string | null;
  algorithms?: Algorithm[];
}

export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}

// ============================================
// BASE64URL ENCODING
// ============================================
// JWT uses base64url (not regular base64) because:
// - It's URL-safe (no +, /, or = characters)
// - Can be safely used in URLs and HTTP headers

export function base64urlEncode(data: string | object): string {
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')   // Replace + with -
    .replace(/\//g, '_')   // Replace / with _
    .replace(/=+$/, '');   // Remove trailing =
}

export function base64urlDecode(str: string): string {
  // Add back padding if needed
  const padded = str + '='.repeat((4 - str.length % 4) % 4);
  // Convert back to regular base64
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64').toString('utf8');
}

// ============================================
// HMAC SIGNING (Symmetric - same key for sign & verify)
// ============================================
// HMAC = Hash-based Message Authentication Code
// Uses a shared secret key - both parties must know it

export function signHMAC(data: string, secret: string, algorithm: string = 'sha256'): string {
  return crypto
    .createHmac(algorithm, secret)
    .update(data)
    .digest('base64url');
}

export function verifyHMAC(data: string, signature: string, secret: string, algorithm: string = 'sha256'): boolean {
  const expectedSignature = signHMAC(data, secret, algorithm);
  // Use timing-safe comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expectedSignature)
    );
  } catch {
    return false;
  }
}

// ============================================
// RSA SIGNING (Asymmetric - public/private key pair)
// ============================================
// RSA uses two keys:
// - Private key: Used to SIGN tokens (keep secret!)
// - Public key: Used to VERIFY tokens (can be shared)
// This is useful when the verifier shouldn't be able to create tokens

export function signRSA(data: string, privateKey: string, algorithm: string = 'sha256'): string {
  // Map to OpenSSL algorithm names
  const alg = algorithm === 'sha256' ? 'RSA-SHA256' :
              algorithm === 'sha384' ? 'RSA-SHA384' :
              algorithm === 'sha512' ? 'RSA-SHA512' : 'RSA-SHA256';
  const sign = crypto.createSign(alg);
  sign.update(data);
  return sign.sign(privateKey, 'base64url');
}

export function verifyRSA(data: string, signature: string, publicKey: string, algorithm: string = 'sha256'): boolean {
  const alg = algorithm === 'sha256' ? 'RSA-SHA256' :
              algorithm === 'sha384' ? 'RSA-SHA384' :
              algorithm === 'sha512' ? 'RSA-SHA512' : 'RSA-SHA256';
  const verify = crypto.createVerify(alg);
  verify.update(data);
  try {
    return verify.verify(publicKey, signature, 'base64url');
  } catch {
    return false;
  }
}

// ============================================
// RSA KEY GENERATION
// ============================================

export function generateRSAKeyPair(): RSAKeyPair {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,  // Key size in bits (2048 is standard minimum)
    publicKeyEncoding: {
      type: 'spki',       // Standard format for public keys
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',      // Standard format for private keys
      format: 'pem'
    }
  });
}

// ============================================
// JWT CREATION
// ============================================

export function createJWT(
  payload: Record<string, unknown>,
  secret: string | null,
  options: CreateJWTOptions = {}
): string {
  const {
    algorithm = 'HS256',  // HMAC with SHA-256 (default)
    expiresIn = 3600,     // 1 hour default
    privateKey = null     // For RSA algorithms
  } = options;

  // Create the header
  const header: JWTHeader = {
    alg: algorithm,
    typ: 'JWT'
  };

  // Add standard claims to payload
  const now = Math.floor(Date.now() / 1000);
  const fullPayload: JWTPayload = {
    ...payload,
    iat: now,                    // Issued At
    exp: now + expiresIn,        // Expiration Time
  };

  // Encode header and payload
  const encodedHeader = base64urlEncode(header);
  const encodedPayload = base64urlEncode(fullPayload);
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  // Sign based on algorithm
  let signature: string;
  if (algorithm.startsWith('HS')) {
    // HMAC algorithms (HS256, HS384, HS512)
    if (!secret) throw new Error('Secret required for HMAC signing');
    const hashAlg = 'sha' + algorithm.slice(2);
    signature = signHMAC(dataToSign, secret, hashAlg);
  } else if (algorithm.startsWith('RS')) {
    // RSA algorithms (RS256, RS384, RS512)
    if (!privateKey) throw new Error('Private key required for RSA signing');
    const hashAlg = 'sha' + algorithm.slice(2);
    signature = signRSA(dataToSign, privateKey, hashAlg);
  } else {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  return `${dataToSign}.${signature}`;
}

// ============================================
// JWT VERIFICATION
// ============================================

export function verifyJWT(
  token: string,
  secret: string | null,
  options: VerifyJWTOptions = {}
): JWTPayload {
  const { publicKey = null, algorithms = ['HS256', 'RS256'] } = options;

  // Split the token
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format: must have 3 parts');
  }

  const [encodedHeader, encodedPayload, signature] = parts;
  const dataToVerify = `${encodedHeader}.${encodedPayload}`;

  // Decode and parse header
  let header: JWTHeader;
  try {
    header = JSON.parse(base64urlDecode(encodedHeader));
  } catch {
    throw new Error('Invalid JWT: malformed header');
  }

  // Check algorithm is allowed (prevents algorithm confusion attacks)
  if (!algorithms.includes(header.alg)) {
    throw new Error(`Algorithm ${header.alg} not allowed`);
  }

  // Verify signature based on algorithm
  let isValid = false;
  if (header.alg.startsWith('HS')) {
    if (!secret) throw new Error('Secret required for HMAC verification');
    const hashAlg = 'sha' + header.alg.slice(2);
    isValid = verifyHMAC(dataToVerify, signature, secret, hashAlg);
  } else if (header.alg.startsWith('RS')) {
    if (!publicKey) throw new Error('Public key required for RSA verification');
    const hashAlg = 'sha' + header.alg.slice(2);
    isValid = verifyRSA(dataToVerify, signature, publicKey, hashAlg);
  }

  if (!isValid) {
    throw new Error('Invalid signature');
  }

  // Decode payload
  let payload: JWTPayload;
  try {
    payload = JSON.parse(base64urlDecode(encodedPayload));
  } catch {
    throw new Error('Invalid JWT: malformed payload');
  }

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new Error('Token has expired');
  }

  // Check "not before" claim
  if (payload.nbf && payload.nbf > now) {
    throw new Error('Token not yet valid');
  }

  return payload;
}

// ============================================
// JWT DECODING (without verification)
// ============================================
// WARNING: Only use this for debugging!
// Never trust data from an unverified token!

export function decodeJWT(token: string): DecodedJWT {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid JWT format');
  }

  return {
    header: JSON.parse(base64urlDecode(parts[0])),
    payload: JSON.parse(base64urlDecode(parts[1])),
    signature: parts[2]
  };
}
