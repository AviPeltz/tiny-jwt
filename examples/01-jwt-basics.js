/**
 * Example 1: JWT Basics
 *
 * This example shows the fundamental structure of a JWT
 * and how encoding/decoding works.
 *
 * Run: npm run example:basics
 */

import { base64urlEncode, base64urlDecode, decodeJWT, createJWT } from '../src/index.js';

console.log('='.repeat(60));
console.log('JWT BASICS - Understanding the Structure');
console.log('='.repeat(60));

// ============================================
// PART 1: Base64URL Encoding
// ============================================
console.log('\n📦 PART 1: Base64URL Encoding\n');

const originalData = { hello: 'world', number: 42 };
console.log('Original data:', originalData);

const encoded = base64urlEncode(originalData);
console.log('Base64URL encoded:', encoded);

const decoded = base64urlDecode(encoded);
console.log('Decoded back:', decoded);

console.log('\n💡 Why Base64URL?');
console.log('   - URL-safe (no special characters like + / =)');
console.log('   - Can be sent in HTTP headers and URLs');
console.log('   - Compact representation of JSON data');

// ============================================
// PART 2: JWT Structure
// ============================================
console.log('\n' + '='.repeat(60));
console.log('📋 PART 2: JWT Structure\n');

// Create a simple JWT
const secret = 'my-super-secret-key';
const payload = {
  userId: 123,
  username: 'alice',
  role: 'admin'
};

const token = createJWT(payload, secret);
console.log('Created JWT:\n');
console.log(token);

// Split and explain each part
const parts = token.split('.');
console.log('\n--- Breaking it down ---\n');

console.log('HEADER (Part 1):');
console.log('  Encoded:', parts[0]);
console.log('  Decoded:', base64urlDecode(parts[0]));

console.log('\nPAYLOAD (Part 2):');
console.log('  Encoded:', parts[1]);
console.log('  Decoded:', base64urlDecode(parts[1]));

console.log('\nSIGNATURE (Part 3):');
console.log('  Encoded:', parts[2]);
console.log('  (Cannot decode - this is a cryptographic hash)');

// ============================================
// PART 3: Decoding vs Verifying
// ============================================
console.log('\n' + '='.repeat(60));
console.log('⚠️  PART 3: Decoding vs Verifying\n');

const decodedToken = decodeJWT(token);
console.log('Decoded (without verification):');
console.log(JSON.stringify(decodedToken, null, 2));

console.log('\n🚨 IMPORTANT SECURITY NOTE:');
console.log('   decodeJWT() only READS the data - it does NOT verify!');
console.log('   Anyone can create a JWT with fake data.');
console.log('   ALWAYS use verifyJWT() before trusting the contents!');

// ============================================
// PART 4: Standard Claims
// ============================================
console.log('\n' + '='.repeat(60));
console.log('📝 PART 4: Standard JWT Claims\n');

console.log('Our payload automatically got these claims added:');
console.log(`  iat (Issued At): ${decodedToken.payload.iat}`);
console.log(`      = ${new Date(decodedToken.payload.iat * 1000).toISOString()}`);
console.log(`  exp (Expires At): ${decodedToken.payload.exp}`);
console.log(`      = ${new Date(decodedToken.payload.exp * 1000).toISOString()}`);

console.log('\nOther common claims (not used here):');
console.log('  sub (Subject)   - Who the token is about');
console.log('  iss (Issuer)    - Who created the token');
console.log('  aud (Audience)  - Who the token is for');
console.log('  nbf (Not Before)- Token not valid before this time');
console.log('  jti (JWT ID)    - Unique identifier for the token');

console.log('\n' + '='.repeat(60));
console.log('✅ End of JWT Basics Example');
console.log('='.repeat(60));
