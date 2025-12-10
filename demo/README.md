# JWT Auth Demo

A complete working example of JWT authentication with a React frontend and Express backend.

## Quick Start

You'll need two terminals:

### Terminal 1: Start the API server

```bash
cd demo/server
npm install
npm run dev
```

Server runs at http://localhost:3001

### Terminal 2: Start the React app

```bash
cd demo/client
npm install
npm run dev
```

App runs at http://localhost:5173

## Test Accounts

| Email | Password | Role |
|-------|----------|------|
| alice@example.com | password123 | admin |
| bob@example.com | password123 | user |

## What This Demo Shows

### 1. Token Storage Best Practices

- **Access Token**: Stored in React state (memory), NOT localStorage
- **Refresh Token**: Stored in httpOnly cookie (JavaScript can't access it)

### 2. The Complete Auth Flow

1. User logs in with email/password
2. Server returns access token (in response body) + sets refresh token (httpOnly cookie)
3. React stores access token in state
4. Every API call includes `Authorization: Bearer <token>`
5. When token expires, app uses refresh cookie to get new access token
6. On logout, server revokes refresh token and clears cookie

### 3. Token Expiration & Refresh

- Access tokens expire in 15 minutes
- The UI shows a countdown timer
- Auto-refresh happens when <1 minute remaining
- Manual refresh button available

### 4. Protected Routes

- `/api/public` - No auth required
- `/api/profile` - Requires valid access token
- `/api/admin` - Requires valid access token + admin role

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         REACT APP                               │
│                    (http://localhost:5173)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────┐                                          │
│   │  React State    │  ← Access token stored here              │
│   │  (in memory)    │    (cleared on page refresh)             │
│   └────────┬────────┘                                          │
│            │                                                    │
│            │  Authorization: Bearer <token>                     │
│            ▼                                                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │  HTTP requests
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       EXPRESS SERVER                            │
│                    (http://localhost:3001)                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   /auth/login     → Verify credentials, return tokens          │
│   /auth/refresh   → Verify refresh cookie, return new access   │
│   /auth/logout    → Revoke refresh token, clear cookie         │
│   /api/*          → Verify access token, return data           │
│                                                                 │
│   ┌─────────────────┐    ┌─────────────────┐                   │
│   │ Access Token    │    │ Refresh Token   │                   │
│   │ Secret Key      │    │ Secret Key      │                   │
│   │ (for signing)   │    │ (different!)    │                   │
│   └─────────────────┘    └─────────────────┘                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Security Notes

This demo implements several security best practices:

1. **Separate secrets** for access and refresh tokens
2. **httpOnly cookies** for refresh tokens (no XSS access)
3. **Short-lived access tokens** (15 minutes)
4. **Token revocation** on logout
5. **CORS configuration** with credentials
6. **In-memory storage** for access tokens (not localStorage)

### What's NOT production-ready:

- Passwords stored in plain text (use bcrypt!)
- In-memory token blacklist (use Redis)
- Single server (no key rotation)
- No HTTPS (required in production)
- No rate limiting on login

## Files

```
demo/
├── server/
│   ├── server.ts      # Express API with JWT auth
│   └── package.json
├── client/
│   ├── src/
│   │   ├── App.tsx    # React app with auth
│   │   ├── main.tsx
│   │   └── index.css
│   ├── index.html
│   └── package.json
└── README.md
```
