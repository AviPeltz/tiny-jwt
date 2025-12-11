# JWT Auth for Desktop Apps (Electron)

## The Problem: Desktop Apps Can't Keep Secrets

Unlike web servers, desktop/mobile apps **cannot securely store secrets**:

```
Web Server (CAN keep secrets):
┌─────────────────────────────────────┐
│  Your Server (you control this)     │
│  ┌─────────────────────────────┐    │
│  │ SECRET_KEY = "abc123..."    │    │  ← Only you can see this
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘

Desktop App (CANNOT keep secrets):
┌─────────────────────────────────────┐
│  User's Computer (they control it!) │
│  ┌─────────────────────────────┐    │
│  │ Your Electron App           │    │
│  │ SECRET_KEY = "abc123..."    │    │  ← User can extract this!
│  └─────────────────────────────┘    │
└─────────────────────────────────────┘
```

An attacker can:
- Decompile your app
- Read your source code (Electron apps are JavaScript!)
- Use a debugger to inspect memory
- Extract any "secrets" you embed

**This means you CANNOT use HMAC (symmetric) signing in a desktop app!**

## The Solution: Asymmetric Cryptography + PKCE

### Architecture Overview

```
┌────────────────────────────────────────────────────────────────────────────┐
│                     DESKTOP APP AUTH ARCHITECTURE                          │
└────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────┐         ┌─────────────────────┐
│   ELECTRON APP      │         │   YOUR AUTH SERVER  │
│   (Public Client)   │         │   (Confidential)    │
├─────────────────────┤         ├─────────────────────┤
│                     │         │                     │
│ • No secrets!       │         │ • Has SECRET_KEY    │
│ • Stores tokens     │         │ • Signs tokens      │
│   securely          │         │ • Validates logins  │
│ • Uses PKCE for     │         │ • Issues tokens     │
│   auth flow         │         │                     │
│                     │         │                     │
└──────────┬──────────┘         └──────────┬──────────┘
           │                               │
           │  1. Auth request + PKCE       │
           │─────────────────────────────▶│
           │                               │
           │  2. Redirect to login page    │
           │◀─────────────────────────────│
           │                               │
           │  3. User logs in (in browser) │
           │─────────────────────────────▶│
           │                               │
           │  4. Auth code (one-time use)  │
           │◀─────────────────────────────│
           │                               │
           │  5. Exchange code + verifier  │
           │─────────────────────────────▶│
           │                               │
           │  6. Access + Refresh tokens   │
           │◀─────────────────────────────│
```

### Why PKCE (Proof Key for Code Exchange)?

Without PKCE, an attacker could intercept the auth code and exchange it for tokens.

PKCE prevents this:

```
1. App generates random "code_verifier" (kept secret in memory)
2. App creates "code_challenge" = SHA256(code_verifier)
3. App sends code_challenge with auth request
4. Server stores code_challenge
5. User logs in, server returns auth_code
6. App sends auth_code + original code_verifier
7. Server verifies: SHA256(code_verifier) == stored code_challenge
8. Only then does server return tokens

Even if attacker intercepts auth_code, they don't have code_verifier!
```

### Token Storage in Desktop Apps

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SECURE TOKEN STORAGE                             │
└─────────────────────────────────────────────────────────────────────┘

Platform          │ Recommended Storage
──────────────────┼────────────────────────────────────
Windows           │ Windows Credential Manager (DPAPI)
macOS             │ Keychain
Linux             │ libsecret / GNOME Keyring
                  │
Electron          │ safeStorage API (uses OS keychain)
                  │ or keytar package

NEVER store tokens in:
  ✗ Plain text files
  ✗ localStorage (Electron has this but it's not secure)
  ✗ Environment variables
  ✗ Embedded in code
```

## Quick Start

### Terminal 1: Start the Auth Server
```bash
cd server
npm install
npm run dev
```

### Terminal 2: Start the Electron App
```bash
cd app
npm install
npm run dev
```

## How This Demo Works

1. **Click "Login"** → Opens system browser to auth server
2. **Enter credentials** → Server validates, generates auth code
3. **Redirect back** → Custom protocol (`myapp://`) sends code to Electron
4. **Code exchange** → App exchanges code + PKCE verifier for tokens
5. **Secure storage** → Tokens stored in OS keychain via `safeStorage`
6. **API calls** → Access token sent with requests
7. **Token refresh** → Refresh token used when access token expires

## Files

```
demo-electron/
├── server/
│   └── server.ts        # Auth server (has the secrets)
├── app/
│   ├── main.ts          # Electron main process
│   ├── preload.ts       # Secure bridge to renderer
│   ├── renderer/
│   │   ├── index.html
│   │   └── app.ts       # UI logic
│   └── auth.ts          # PKCE + token management
└── README.md
```

## Security Considerations

### What This Demo Does Right:
- ✅ No secrets in the Electron app
- ✅ PKCE for secure auth code flow
- ✅ Tokens stored in OS keychain
- ✅ Auth happens in system browser (not embedded webview)
- ✅ Custom protocol for redirect

### What You'd Add for Production:
- Certificate pinning for API calls
- Token binding (proof of possession)
- Biometric unlock for keychain access
- Refresh token rotation
- Device registration/trust
