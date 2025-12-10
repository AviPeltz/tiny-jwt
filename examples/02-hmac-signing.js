/**
 * Example 2: HMAC Signing (Symmetric Cryptography)
 *
 * HMAC = Hash-based Message Authentication Code
 *
 * Key concept: ONE secret key is used for both signing AND verifying.
 * Both the token creator and verifier must share the same secret.
 *
 * Run: npm run example:hmac
 */

import { createJWT, verifyJWT, signHMAC, verifyHMAC } from '../src/index.js';

console.log('='.repeat(60));
console.log('HMAC SIGNING - Symmetric Key Cryptography');
console.log('='.repeat(60));

// ============================================
// PART 1: How HMAC Works
// ============================================
console.log('\n🔑 PART 1: How HMAC Works\n');

const message = 'Hello, this is my message';
const secret = 'my-secret-key';

console.log('Message:', message);
console.log('Secret:', secret);

const signature = signHMAC(message, secret);
console.log('HMAC Signature:', signature);

console.log('\n--- Verification ---');
const isValid = verifyHMAC(message, signature, secret);
console.log('Valid signature?', isValid);

const wrongSecret = 'wrong-secret';
const isValidWrong = verifyHMAC(message, signature, wrongSecret);
console.log('Valid with wrong secret?', isValidWrong);

console.log('\n💡 How it works:');
console.log('   1. Combine the message with the secret key');
console.log('   2. Run through a hash function (SHA-256)');
console.log('   3. The result is a unique "fingerprint"');
console.log('   4. Same message + same key = same fingerprint');
console.log('   5. Any change = completely different fingerprint');

// ============================================
// PART 2: Creating HMAC-Signed JWTs
// ============================================
console.log('\n' + '='.repeat(60));
console.log('🎫 PART 2: Creating HMAC-Signed JWTs\n');

const jwtSecret = 'super-secret-jwt-key-keep-this-safe';
const payload = {
  userId: 42,
  email: 'user@example.com',
  permissions: ['read', 'write']
};

console.log('Payload:', JSON.stringify(payload, null, 2));
console.log('Secret:', jwtSecret);

// Create tokens with different HMAC algorithms
const tokenHS256 = createJWT(payload, jwtSecret, { algorithm: 'HS256' });
const tokenHS384 = createJWT(payload, jwtSecret, { algorithm: 'HS384' });
const tokenHS512 = createJWT(payload, jwtSecret, { algorithm: 'HS512' });

console.log('\nHS256 Token (SHA-256):');
console.log(tokenHS256);
console.log('\nHS384 Token (SHA-384):');
console.log(tokenHS384);
console.log('\nHS512 Token (SHA-512):');
console.log(tokenHS512);

console.log('\n💡 Algorithm differences:');
console.log('   HS256 - 256-bit hash, fastest, most common');
console.log('   HS384 - 384-bit hash, more secure');
console.log('   HS512 - 512-bit hash, most secure, longer signature');

// ============================================
// PART 3: Verifying JWTs
// ============================================
console.log('\n' + '='.repeat(60));
console.log('✅ PART 3: Verifying JWTs\n');

try {
  const verified = verifyJWT(tokenHS256, jwtSecret, { algorithms: ['HS256'] });
  console.log('✓ Token verified successfully!');
  console.log('Payload:', JSON.stringify(verified, null, 2));
} catch (error) {
  console.log('✗ Verification failed:', error.message);
}

// ============================================
// PART 4: What Happens with Wrong Secret?
// ============================================
console.log('\n' + '='.repeat(60));
console.log('🚫 PART 4: Wrong Secret = Verification Fails\n');

try {
  verifyJWT(tokenHS256, 'wrong-secret', { algorithms: ['HS256'] });
  console.log('✓ Token verified (this should not happen!)');
} catch (error) {
  console.log('✗ Verification failed:', error.message);
  console.log('\n💡 This is expected! The signature doesn\'t match.');
}

// ============================================
// PART 5: Tampered Token Detection
// ============================================
console.log('\n' + '='.repeat(60));
console.log('🔍 PART 5: Detecting Tampered Tokens\n');

// Let's try to modify a token and see what happens
const parts = tokenHS256.split('.');
const payloadBase64 = parts[1];

// Decode, modify, re-encode the payload
const decodedPayload = JSON.parse(
  Buffer.from(payloadBase64.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()
);
console.log('Original payload:', decodedPayload);

// Attacker tries to change userId
decodedPayload.userId = 1; // Trying to become admin!
decodedPayload.permissions = ['read', 'write', 'delete', 'admin'];
console.log('Tampered payload:', decodedPayload);

const tamperedPayloadBase64 = Buffer.from(JSON.stringify(decodedPayload))
  .toString('base64')
  .replace(/\+/g, '-')
  .replace(/\//g, '_')
  .replace(/=+$/, '');

const tamperedToken = `${parts[0]}.${tamperedPayloadBase64}.${parts[2]}`;
console.log('\nTampered token created (with original signature)');

try {
  verifyJWT(tamperedToken, jwtSecret, { algorithms: ['HS256'] });
  console.log('✓ Tampered token accepted (SECURITY BREACH!)');
} catch (error) {
  console.log('✗ Tampered token rejected:', error.message);
  console.log('\n💡 The signature was created for the ORIGINAL payload.');
  console.log('   When the payload changes, the signature no longer matches!');
}

// ============================================
// PART 6: When to Use HMAC
// ============================================
console.log('\n' + '='.repeat(60));
console.log('📖 PART 6: When to Use HMAC (Symmetric) Signing\n');

console.log('✅ Good use cases:');
console.log('   - Single application (same server signs & verifies)');
console.log('   - Microservices that can share a secret securely');
console.log('   - Internal APIs where you control both ends');
console.log('   - When simplicity is preferred over key management');

console.log('\n❌ Not ideal when:');
console.log('   - Third parties need to verify tokens');
console.log('   - You can\'t securely share the secret');
console.log('   - Different trust levels (some can verify, some can sign)');
console.log('   → Use RSA (asymmetric) instead! See example 3.');

console.log('\n' + '='.repeat(60));
console.log('✅ End of HMAC Signing Example');
console.log('='.repeat(60));
