import { useState, useEffect, useCallback } from 'react';

const API_URL = 'http://localhost:3001';

// ============================================
// TYPES
// ============================================

interface User {
  id: number;
  email: string;
  name: string;
  role: 'admin' | 'user';
}

interface DecodedToken {
  header: { alg: string; typ: string };
  payload: Record<string, unknown>;
}

interface ApiResponse {
  success: boolean;
  data?: unknown;
  error?: string;
}

// ============================================
// JWT UTILITIES (client-side decode only!)
// ============================================

function base64urlDecode(str: string): string {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  return atob(base64);
}

function decodeToken(token: string): DecodedToken | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    return {
      header: JSON.parse(base64urlDecode(parts[0])),
      payload: JSON.parse(base64urlDecode(parts[1])),
    };
  } catch {
    return null;
  }
}

function getTokenExpiry(token: string): number | null {
  const decoded = decodeToken(token);
  if (!decoded?.payload?.exp) return null;
  return (decoded.payload.exp as number) * 1000; // Convert to ms
}

// ============================================
// AUTH CONTEXT (in-memory storage)
// ============================================

// IMPORTANT: Access token is stored in memory (React state)
// This is more secure than localStorage - it's cleared on page refresh
// and not accessible via XSS attacks (assuming no DOM vulnerabilities)

// ============================================
// MAIN APP COMPONENT
// ============================================

export default function App() {
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [apiResponse, setApiResponse] = useState<ApiResponse | null>(null);
  const [tokenExpiry, setTokenExpiry] = useState<number | null>(null);
  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);

  // ============================================
  // API HELPER
  // ============================================

  const fetchWithAuth = useCallback(
    async (url: string, options: RequestInit = {}): Promise<Response> => {
      const headers: HeadersInit = {
        'Content-Type': 'application/json',
        ...options.headers,
      };

      if (accessToken) {
        (headers as Record<string, string>)['Authorization'] = `Bearer ${accessToken}`;
      }

      return fetch(`${API_URL}${url}`, {
        ...options,
        headers,
        credentials: 'include', // Include cookies for refresh token
      });
    },
    [accessToken]
  );

  // ============================================
  // TOKEN REFRESH
  // ============================================

  const refreshAccessToken = useCallback(async (): Promise<string | null> => {
    try {
      const res = await fetch(`${API_URL}/auth/refresh`, {
        method: 'POST',
        credentials: 'include',
      });

      if (!res.ok) {
        throw new Error('Refresh failed');
      }

      const data = await res.json();
      setAccessToken(data.accessToken);
      setTokenExpiry(getTokenExpiry(data.accessToken));
      return data.accessToken;
    } catch {
      // Refresh token invalid/expired - user needs to login again
      setAccessToken(null);
      setUser(null);
      setTokenExpiry(null);
      return null;
    }
  }, []);

  // ============================================
  // CHECK AUTH ON MOUNT
  // ============================================

  useEffect(() => {
    // Try to refresh token on page load (in case user has valid refresh cookie)
    const checkAuth = async () => {
      setLoading(true);
      const token = await refreshAccessToken();

      if (token) {
        // Get user info
        const res = await fetch(`${API_URL}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (res.ok) {
          const userData = await res.json();
          setUser(userData);
        }
      }

      setLoading(false);
    };

    checkAuth();
  }, [refreshAccessToken]);

  // ============================================
  // TOKEN EXPIRY TIMER
  // ============================================

  useEffect(() => {
    if (!tokenExpiry) {
      setTimeRemaining(null);
      return;
    }

    const updateTimer = () => {
      const remaining = Math.max(0, tokenExpiry - Date.now());
      setTimeRemaining(remaining);

      // Auto-refresh when less than 1 minute remaining
      if (remaining < 60000 && remaining > 0) {
        refreshAccessToken();
      }
    };

    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [tokenExpiry, refreshAccessToken]);

  // ============================================
  // AUTH HANDLERS
  // ============================================

  const handleLogin = async (email: string, password: string) => {
    setApiResponse(null);

    try {
      const res = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (!res.ok) {
        setApiResponse({ success: false, error: data.error });
        return;
      }

      setAccessToken(data.accessToken);
      setTokenExpiry(getTokenExpiry(data.accessToken));
      setUser(data.user);
      setApiResponse({ success: true, data: { message: 'Login successful!' } });
    } catch (err) {
      setApiResponse({ success: false, error: 'Network error' });
    }
  };

  const handleLogout = async () => {
    await fetch(`${API_URL}/auth/logout`, {
      method: 'POST',
      credentials: 'include',
    });

    setAccessToken(null);
    setUser(null);
    setTokenExpiry(null);
    setApiResponse({ success: true, data: { message: 'Logged out' } });
  };

  // ============================================
  // API CALLS
  // ============================================

  const callApi = async (endpoint: string) => {
    setApiResponse(null);

    try {
      const res = await fetchWithAuth(endpoint);
      const data = await res.json();

      if (!res.ok) {
        // If token expired, try to refresh and retry
        if (res.status === 401) {
          const newToken = await refreshAccessToken();
          if (newToken) {
            // Retry with new token
            const retryRes = await fetch(`${API_URL}${endpoint}`, {
              headers: { Authorization: `Bearer ${newToken}` },
            });
            const retryData = await retryRes.json();
            setApiResponse({
              success: retryRes.ok,
              data: retryRes.ok ? retryData : undefined,
              error: retryRes.ok ? undefined : retryData.error,
            });
            return;
          }
        }

        setApiResponse({ success: false, error: data.error });
        return;
      }

      setApiResponse({ success: true, data });
    } catch (err) {
      setApiResponse({ success: false, error: 'Network error' });
    }
  };

  // ============================================
  // RENDER
  // ============================================

  if (loading) {
    return (
      <div className="app">
        <div className="loading">Loading...</div>
      </div>
    );
  }

  return (
    <div className="app">
      <h1>JWT Auth Demo</h1>
      <p className="subtitle">See how JWT authentication works in a real React app</p>

      {user ? (
        <LoggedInView
          user={user}
          accessToken={accessToken}
          timeRemaining={timeRemaining}
          apiResponse={apiResponse}
          onLogout={handleLogout}
          onCallApi={callApi}
          onRefresh={refreshAccessToken}
        />
      ) : (
        <LoginForm onLogin={handleLogin} apiResponse={apiResponse} />
      )}
    </div>
  );
}

// ============================================
// LOGIN FORM
// ============================================

function LoginForm({
  onLogin,
  apiResponse,
}: {
  onLogin: (email: string, password: string) => Promise<void>;
  apiResponse: ApiResponse | null;
}) {
  const [email, setEmail] = useState('alice@example.com');
  const [password, setPassword] = useState('password123');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    await onLogin(email, password);
    setLoading(false);
  };

  return (
    <div className="card">
      <h2>Login</h2>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="alice@example.com"
          />
        </div>
        <div className="form-group">
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="password123"
          />
        </div>
        <button type="submit" className="btn-primary" disabled={loading}>
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>

      <div style={{ marginTop: '1rem', color: '#94a3b8', fontSize: '0.875rem' }}>
        <strong>Test accounts:</strong>
        <br />
        alice@example.com / password123 (admin)
        <br />
        bob@example.com / password123 (user)
      </div>

      {apiResponse && (
        <div className={`response ${apiResponse.success ? 'success' : 'error'}`}>
          <pre>{JSON.stringify(apiResponse.error || apiResponse.data, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}

// ============================================
// LOGGED IN VIEW
// ============================================

function LoggedInView({
  user,
  accessToken,
  timeRemaining,
  apiResponse,
  onLogout,
  onCallApi,
  onRefresh,
}: {
  user: User;
  accessToken: string | null;
  timeRemaining: number | null;
  apiResponse: ApiResponse | null;
  onLogout: () => void;
  onCallApi: (endpoint: string) => Promise<void>;
  onRefresh: () => Promise<string | null>;
}) {
  const [showToken, setShowToken] = useState(false);

  const formatTime = (ms: number) => {
    const seconds = Math.floor(ms / 1000);
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  const getTimerClass = () => {
    if (!timeRemaining) return '';
    if (timeRemaining < 60000) return 'danger';
    if (timeRemaining < 300000) return 'warning';
    return '';
  };

  return (
    <>
      {/* User Header */}
      <div className="user-header">
        <div className="user-info">
          <div className="avatar">{user.name[0]}</div>
          <div>
            <div className="user-name">{user.name}</div>
            <div className="user-role">
              {user.email} ·{' '}
              <span className={`badge badge-${user.role}`}>{user.role}</span>
            </div>
          </div>
        </div>
        <button onClick={onLogout} className="btn-danger btn-small">
          Logout
        </button>
      </div>

      {/* Token Info */}
      <div className="card">
        <h2>Access Token</h2>

        <div className="flex gap-4" style={{ alignItems: 'center', marginBottom: '1rem' }}>
          <div className="status">
            <span className={`status-dot ${timeRemaining && timeRemaining > 0 ? 'active' : 'expired'}`} />
            {timeRemaining && timeRemaining > 0 ? 'Active' : 'Expired'}
          </div>

          {timeRemaining !== null && (
            <div className={`timer ${getTimerClass()}`}>
              Expires in: {formatTime(timeRemaining)}
            </div>
          )}

          <button onClick={() => onRefresh()} className="btn-secondary btn-small">
            Refresh Token
          </button>
        </div>

        <button
          onClick={() => setShowToken(!showToken)}
          className="btn-secondary btn-small"
          style={{ marginBottom: '1rem' }}
        >
          {showToken ? 'Hide' : 'Show'} Token Details
        </button>

        {showToken && accessToken && <TokenDisplay token={accessToken} />}
      </div>

      {/* API Calls */}
      <div className="card">
        <h2>Test API Endpoints</h2>
        <p style={{ color: '#94a3b8', marginBottom: '1rem', fontSize: '0.875rem' }}>
          These buttons call protected API endpoints using your access token.
        </p>

        <div className="flex gap-2 flex-wrap mb-4">
          <button onClick={() => onCallApi('/api/public')} className="btn-secondary">
            GET /api/public (no auth)
          </button>
          <button onClick={() => onCallApi('/api/profile')} className="btn-primary">
            GET /api/profile
          </button>
          <button onClick={() => onCallApi('/api/admin')} className="btn-primary">
            GET /api/admin
          </button>
        </div>

        {apiResponse && (
          <div className={`response ${apiResponse.success ? 'success' : 'error'}`}>
            <pre>{JSON.stringify(apiResponse.data || apiResponse.error, null, 2)}</pre>
          </div>
        )}
      </div>

      {/* How It Works */}
      <div className="card">
        <h2>How It Works</h2>
        <div style={{ color: '#94a3b8', fontSize: '0.875rem', lineHeight: 1.6 }}>
          <p style={{ marginBottom: '0.5rem' }}>
            <strong>Access Token:</strong> Stored in React state (memory). Sent with every API
            request in the <code>Authorization: Bearer</code> header. Short-lived (15 minutes).
          </p>
          <p style={{ marginBottom: '0.5rem' }}>
            <strong>Refresh Token:</strong> Stored in an httpOnly cookie (JavaScript can't read
            it!). Only sent to <code>/auth/refresh</code>. Long-lived (7 days).
          </p>
          <p>
            <strong>Auto-refresh:</strong> When the access token has less than 1 minute remaining,
            the app automatically refreshes it using the refresh token cookie.
          </p>
        </div>
      </div>
    </>
  );
}

// ============================================
// TOKEN DISPLAY
// ============================================

function TokenDisplay({ token }: { token: string }) {
  const decoded = decodeToken(token);
  const parts = token.split('.');

  return (
    <div>
      <div className="token-section">
        <h3>Raw Token (what gets sent to server)</h3>
        <div className="token-display">{token}</div>
      </div>

      {decoded && (
        <div className="decoded-token">
          <div className="token-part token-part-header">
            <div className="token-part-label">Header (algorithm info)</div>
            <pre>{JSON.stringify(decoded.header, null, 2)}</pre>
          </div>

          <div className="token-part token-part-payload">
            <div className="token-part-label">Payload (your data - anyone can read this!)</div>
            <pre>{JSON.stringify(decoded.payload, null, 2)}</pre>
          </div>

          <div className="token-part">
            <div className="token-part-label">Signature (proves it wasn't tampered)</div>
            <div className="token-part-signature">{parts[2]}</div>
          </div>
        </div>
      )}
    </div>
  );
}
