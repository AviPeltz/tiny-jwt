# tiny-jwt

A minimal JWT implementation for learning purposes. No dependencies - just Node.js crypto.

## What You'll Learn

1. **JWT Structure** - What are the 3 parts of a JWT?
2. **Base64URL Encoding** - Why JWTs look the way they do
3. **HMAC Signing** - Symmetric cryptography (one shared secret)
4. **RSA Signing** - Asymmetric cryptography (public/private key pairs)
5. **Authentication Flows** - Access tokens, refresh tokens, logout

## Quick Start

```bash
# Run the examples in order:
npm run example:basics   # JWT structure & encoding
npm run example:hmac     # Symmetric signing
npm run example:rsa      # Asymmetric signing (public key crypto)
npm run example:auth     # Complete auth flow
```

## JWT Basics

A JWT (JSON Web Token) has 3 parts separated by dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEyM30.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
|_______________________________| |___________________| |__________________________________|
            HEADER                       PAYLOAD                    SIGNATURE
```

- **Header**: Metadata (algorithm, token type)
- **Payload**: Your data (user ID, roles, expiration)
- **Signature**: Cryptographic proof it wasn't tampered with

## Signing Algorithms

### HMAC (Symmetric) - HS256, HS384, HS512

```
     Same Key
        │
   ┌────┴────┐
   ▼         ▼
 SIGN     VERIFY
```

- One secret key for both signing and verifying
- Both parties must share the same secret
- Simpler, faster
- Good for: single applications, internal APIs

### RSA (Asymmetric) - RS256, RS384, RS512

```
Private Key          Public Key
    │                    │
    ▼                    ▼
  SIGN               VERIFY
(secret)           (shareable)
```

- Private key signs, public key verifies
- Only the signer needs the private key
- Verifiers only need the public key (can't create tokens)
- Good for: microservices, third-party verification

## Authentication Flow

```
┌────────┐          ┌────────────┐          ┌────────────┐
│ Client │          │ Auth Server│          │ API Server │
└───┬────┘          └─────┬──────┘          └─────┬──────┘
    │                     │                       │
    │ 1. Login (user/pass)│                       │
    │────────────────────>│                       │
    │                     │                       │
    │ 2. JWT (access +    │                       │
    │    refresh tokens)  │                       │
    │<────────────────────│                       │
    │                     │                       │
    │ 3. API Request + JWT│                       │
    │─────────────────────────────────────────────>
    │                     │                       │
    │                     │    4. Verify JWT      │
    │                     │    (no auth server    │
    │                     │     call needed!)     │
    │                     │                       │
    │ 5. Response         │                       │
    │<─────────────────────────────────────────────
```

## Security Best Practices

### Token Types

| Access Token | Refresh Token |
|-------------|---------------|
| Short-lived (15 min) | Long-lived (days) |
| Sent with every request | Only to /refresh endpoint |
| If stolen, expires quickly | Store very securely |

### What to Store in JWTs

```
Good:                     Bad:
- User ID                 - Passwords
- Username                - Credit card numbers
- Roles/permissions       - Large data blobs
- Token ID (for revoke)   - Sensitive PII
```

### Token Storage (Browser)

```
localStorage      ✗ Vulnerable to XSS
sessionStorage    ✗ Vulnerable to XSS
httpOnly cookie   ✓ Safe from JS access
Memory variable   ✓ Safest, but lost on refresh
```

## Project Structure

```
tiny-jwt/
├── src/
│   └── index.js         # JWT implementation
├── examples/
│   ├── 01-jwt-basics.js # Structure & encoding
│   ├── 02-hmac-signing.js # Symmetric crypto
│   ├── 03-rsa-signing.js  # Asymmetric crypto
│   └── 04-auth-flow.js    # Complete auth system
└── README.md
```

## API Reference

### Creating Tokens

```javascript
import { createJWT } from './src/index.js';

// HMAC (symmetric)
const token = createJWT(
  { userId: 123, role: 'admin' },
  'your-secret-key',
  { algorithm: 'HS256', expiresIn: 3600 }
);

// RSA (asymmetric)
const token = createJWT(
  { userId: 123 },
  null,
  { algorithm: 'RS256', privateKey: yourPrivateKey }
);
```

### Verifying Tokens

```javascript
import { verifyJWT } from './src/index.js';

// HMAC
const payload = verifyJWT(token, 'your-secret-key', {
  algorithms: ['HS256']
});

// RSA
const payload = verifyJWT(token, null, {
  publicKey: yourPublicKey,
  algorithms: ['RS256']
});
```

### Decoding (without verification)

```javascript
import { decodeJWT } from './src/index.js';

// WARNING: Don't trust unverified data!
const { header, payload, signature } = decodeJWT(token);
```

### Key Generation

```javascript
import { generateRSAKeyPair } from './src/index.js';

const { publicKey, privateKey } = generateRSAKeyPair();
```

## Common JWT Attacks

1. **Algorithm Confusion** - Attacker changes RS256 to HS256, uses public key as HMAC secret
   - Prevention: Always specify allowed algorithms in verify()

2. **Token Theft (XSS)** - Attacker steals token from localStorage via JavaScript
   - Prevention: Use httpOnly cookies

3. **Expired Token Reuse** - Using tokens after they should be invalid
   - Prevention: Always check exp claim, use token blacklists

4. **Signature Stripping** - Setting alg: "none" to skip verification
   - Prevention: Never allow "none" algorithm

## Resources

- [JWT.io](https://jwt.io) - Debugger & library list
- [RFC 7519](https://tools.ietf.org/html/rfc7519) - JWT specification
- [Auth0 JWT Handbook](https://auth0.com/resources/ebooks/jwt-handbook) - Free ebook
