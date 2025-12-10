/**
 * Example 3: RSA Signing (Asymmetric Cryptography)
 *
 * RSA uses a KEY PAIR:
 *   - Private Key: Used to SIGN tokens (keep this SECRET!)
 *   - Public Key: Used to VERIFY tokens (can share freely!)
 *
 * This is also called "Public Key Cryptography" or
 * "Asymmetric Cryptography" (the keys are different/asymmetric)
 *
 * Run: npm run example:rsa
 */

import { createJWT, verifyJWT, generateRSAKeyPair, signRSA, verifyRSA } from '../src/index.js';

console.log('='.repeat(60));
console.log('RSA SIGNING - Asymmetric (Public Key) Cryptography');
console.log('='.repeat(60));

// ============================================
// PART 1: Generate RSA Key Pair
// ============================================
console.log('\n🔐 PART 1: Generating RSA Key Pair\n');

const { publicKey, privateKey } = generateRSAKeyPair();

console.log('Private Key (KEEP SECRET!):');
console.log(privateKey.substring(0, 100) + '...');
console.log(`[${privateKey.length} characters total]\n`);

console.log('Public Key (can share freely):');
console.log(publicKey.substring(0, 100) + '...');
console.log(`[${publicKey.length} characters total]`);

console.log('\n💡 Key facts about these keys:');
console.log('   - Generated together as a mathematical pair');
console.log('   - Private key can create signatures only it can make');
console.log('   - Public key can verify those signatures');
console.log('   - You CANNOT derive the private key from the public key');
console.log('   - 2048 bits is the minimum secure size today');

// ============================================
// PART 2: How RSA Signing Works
// ============================================
console.log('\n' + '='.repeat(60));
console.log('✍️  PART 2: How RSA Signing Works\n');

const message = 'This message was signed by the private key holder';
console.log('Message:', message);

const signature = signRSA(message, privateKey);
console.log('\nSignature (created with private key):');
console.log(signature.substring(0, 60) + '...');

console.log('\n--- Verification with Public Key ---');
const isValid = verifyRSA(message, signature, publicKey);
console.log('Signature valid?', isValid);

console.log('\n--- Trying with wrong public key ---');
const { publicKey: wrongPublicKey } = generateRSAKeyPair();
const isValidWrong = verifyRSA(message, signature, wrongPublicKey);
console.log('Valid with different public key?', isValidWrong);

// ============================================
// PART 3: RSA-Signed JWTs
// ============================================
console.log('\n' + '='.repeat(60));
console.log('🎫 PART 3: Creating RSA-Signed JWTs\n');

const payload = {
  userId: 'user-123',
  name: 'Alice',
  role: 'admin',
  department: 'engineering'
};

console.log('Payload:', JSON.stringify(payload, null, 2));

const token = createJWT(payload, null, {
  algorithm: 'RS256',
  privateKey: privateKey,
  expiresIn: 3600
});

console.log('\nRS256 Token:');
console.log(token);

// ============================================
// PART 4: Verifying RSA JWTs
// ============================================
console.log('\n' + '='.repeat(60));
console.log('✅ PART 4: Verifying RSA JWTs\n');

console.log('Verifying with PUBLIC key (this works!):');
try {
  const verified = verifyJWT(token, null, {
    publicKey: publicKey,
    algorithms: ['RS256']
  });
  console.log('✓ Token verified!');
  console.log('Payload:', JSON.stringify(verified, null, 2));
} catch (error) {
  console.log('✗ Verification failed:', (error as Error).message);
}

console.log('\n--- Trying with wrong public key ---');
try {
  verifyJWT(token, null, {
    publicKey: wrongPublicKey,
    algorithms: ['RS256']
  });
  console.log('✓ Token verified (should not happen!)');
} catch (error) {
  console.log('✗ Verification failed:', (error as Error).message);
}

// ============================================
// PART 5: The "Magic" of Public Key Crypto
// ============================================
console.log('\n' + '='.repeat(60));
console.log('✨ PART 5: The "Magic" of Public Key Cryptography\n');

console.log('The key insight:');
console.log('');
console.log('  ┌─────────────────────────────────────────────────┐');
console.log('  │  Private Key → Can SIGN (create signatures)    │');
console.log('  │  Public Key  → Can VERIFY (check signatures)   │');
console.log('  │                                                 │');
console.log('  │  But you CANNOT:                               │');
console.log('  │  - Create valid signatures with public key     │');
console.log('  │  - Derive private key from public key          │');
console.log('  └─────────────────────────────────────────────────┘');
console.log('');
console.log('This allows:');
console.log('  1. Auth server keeps private key secret');
console.log('  2. Auth server signs tokens for users');
console.log('  3. Other services get the public key');
console.log('  4. Other services can verify tokens');
console.log('  5. Other services CANNOT create fake tokens!');

// ============================================
// PART 6: Real-World Scenario
// ============================================
console.log('\n' + '='.repeat(60));
console.log('🌍 PART 6: Real-World Scenario\n');

console.log('Imagine a microservices architecture:');
console.log('');
console.log('  ┌──────────────────┐');
console.log('  │   Auth Service   │  ← Has PRIVATE key');
console.log('  │  (login server)  │  ← Creates & signs JWTs');
console.log('  └────────┬─────────┘');
console.log('           │ JWT');
console.log('           ▼');
console.log('  ┌──────────────────┐');
console.log('  │      User        │  ← Receives JWT');
console.log('  │    (browser)     │  ← Sends JWT with requests');
console.log('  └────────┬─────────┘');
console.log('           │ JWT');
console.log('           ▼');
console.log('  ┌──────────────────┐');
console.log('  │   API Service    │  ← Has PUBLIC key');
console.log('  │   Orders API     │  ← Can VERIFY JWTs');
console.log('  │   Users API      │  ← Cannot CREATE JWTs');
console.log('  │   Products API   │');
console.log('  └──────────────────┘');
console.log('');
console.log('Benefits:');
console.log('  - If an API service is compromised, attacker cannot');
console.log('    create fake tokens (no private key!)');
console.log('  - Public key can be distributed freely');
console.log('  - Each service doesn\'t need to call auth service');
console.log('    to verify tokens (decentralized verification)');

// ============================================
// PART 7: HMAC vs RSA Comparison
// ============================================
console.log('\n' + '='.repeat(60));
console.log('⚖️  PART 7: HMAC vs RSA - When to Use Which?\n');

console.log('┌─────────────────┬─────────────────────────────────┐');
console.log('│     HMAC        │           RSA                   │');
console.log('├─────────────────┼─────────────────────────────────┤');
console.log('│ Same key for    │ Different keys for              │');
console.log('│ sign & verify   │ sign (private) & verify (public)│');
console.log('├─────────────────┼─────────────────────────────────┤');
console.log('│ Faster          │ Slower (math is complex)        │');
console.log('├─────────────────┼─────────────────────────────────┤');
console.log('│ Simpler         │ More complex key management     │');
console.log('├─────────────────┼─────────────────────────────────┤');
console.log('│ Secret must be  │ Only private key is secret      │');
console.log('│ shared securely │ Public key can be shared openly │');
console.log('├─────────────────┼─────────────────────────────────┤');
console.log('│ Good for single │ Good for distributed systems    │');
console.log('│ application     │ (microservices, third parties)  │');
console.log('└─────────────────┴─────────────────────────────────┘');

console.log('\n' + '='.repeat(60));
console.log('✅ End of RSA Signing Example');
console.log('='.repeat(60));
