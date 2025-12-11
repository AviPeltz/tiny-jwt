/**
 * Electron Main Process
 *
 * This is the "backend" of the Electron app. It has access to:
 * - Node.js APIs
 * - Electron APIs (including safeStorage for secure token storage)
 * - System resources
 *
 * Security Architecture:
 * - Main process handles all sensitive operations
 * - Renderer process (web page) communicates via IPC
 * - preload.ts provides a secure bridge between them
 */

import { app, BrowserWindow, ipcMain, shell, safeStorage } from 'electron';
import * as path from 'path';
import { fileURLToPath } from 'url';
import {
  startAuthFlow,
  exchangeCodeForTokens,
  refreshAccessToken,
  callProtectedAPI,
  revokeToken,
  parseCallbackURL
} from './auth.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

let mainWindow: BrowserWindow | null = null;

// Token storage keys
const ACCESS_TOKEN_KEY = 'electron-auth-demo:access-token';
const REFRESH_TOKEN_KEY = 'electron-auth-demo:refresh-token';

/**
 * Securely store a token using the OS keychain
 */
function storeToken(key: string, token: string): void {
  if (!safeStorage.isEncryptionAvailable()) {
    console.warn('[Security] safeStorage not available - tokens stored insecurely!');
    // In production, you'd want to handle this better
  }

  const encrypted = safeStorage.encryptString(token);
  // Store in a simple file (in production, use electron-store or similar)
  const fs = require('fs');
  const storePath = path.join(app.getPath('userData'), `${key}.enc`);
  fs.writeFileSync(storePath, encrypted);
  console.log(`[Storage] Token stored securely: ${key}`);
}

/**
 * Retrieve a token from secure storage
 */
function getToken(key: string): string | null {
  try {
    const fs = require('fs');
    const storePath = path.join(app.getPath('userData'), `${key}.enc`);
    const encrypted = fs.readFileSync(storePath);
    return safeStorage.decryptString(encrypted);
  } catch {
    return null;
  }
}

/**
 * Delete a token from secure storage
 */
function deleteToken(key: string): void {
  try {
    const fs = require('fs');
    const storePath = path.join(app.getPath('userData'), `${key}.enc`);
    fs.unlinkSync(storePath);
    console.log(`[Storage] Token deleted: ${key}`);
  } catch {
    // Token didn't exist
  }
}

/**
 * Create the main application window
 */
function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 900,
    height: 700,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,  // Security: isolate renderer from main
      nodeIntegration: false,  // Security: no Node.js in renderer
      sandbox: true            // Security: sandbox renderer process
    }
  });

  // Load the renderer HTML
  mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));

  // Open DevTools in development
  mainWindow.webContents.openDevTools();
}

/**
 * Handle custom protocol (myapp://) for OAuth callback
 */
function setupProtocolHandler(): void {
  // Register the custom protocol
  if (process.defaultApp) {
    if (process.argv.length >= 2) {
      app.setAsDefaultProtocolClient('myapp', process.execPath, [path.resolve(process.argv[1])]);
    }
  } else {
    app.setAsDefaultProtocolClient('myapp');
  }

  // Handle the protocol on macOS
  app.on('open-url', async (event, url) => {
    event.preventDefault();
    console.log('[Protocol] Received callback URL:', url);
    await handleAuthCallback(url);
  });

  // Handle the protocol on Windows/Linux (second instance)
  const gotTheLock = app.requestSingleInstanceLock();
  if (!gotTheLock) {
    app.quit();
  } else {
    app.on('second-instance', async (event, commandLine) => {
      // Find the URL in command line args
      const url = commandLine.find(arg => arg.startsWith('myapp://'));
      if (url) {
        console.log('[Protocol] Received callback URL:', url);
        await handleAuthCallback(url);
      }

      // Focus the window
      if (mainWindow) {
        if (mainWindow.isMinimized()) mainWindow.restore();
        mainWindow.focus();
      }
    });
  }
}

/**
 * Handle the OAuth callback
 */
async function handleAuthCallback(url: string): Promise<void> {
  const params = parseCallbackURL(url);

  if (!params) {
    console.error('[Auth] Invalid callback URL');
    mainWindow?.webContents.send('auth:error', 'Invalid callback');
    return;
  }

  try {
    // Exchange the authorization code for tokens
    const tokens = await exchangeCodeForTokens(params.code, params.state);

    // Store tokens securely
    storeToken(ACCESS_TOKEN_KEY, tokens.accessToken);
    storeToken(REFRESH_TOKEN_KEY, tokens.refreshToken);

    // Notify the renderer
    mainWindow?.webContents.send('auth:success', {
      expiresIn: tokens.expiresIn
    });

    console.log('[Auth] Login successful!');
  } catch (error) {
    console.error('[Auth] Token exchange failed:', error);
    mainWindow?.webContents.send('auth:error', (error as Error).message);
  }
}

// ============================================
// IPC Handlers - Communication with Renderer
// ============================================

/**
 * Start the login flow
 */
ipcMain.handle('auth:login', async () => {
  console.log('[IPC] Starting login flow');

  // Get the authorization URL
  const authURL = startAuthFlow();

  // Open in the system browser (NOT an embedded webview!)
  // This is important for security - users can verify they're on the real login page
  await shell.openExternal(authURL);

  return { status: 'opened' };
});

/**
 * Check if user is logged in
 */
ipcMain.handle('auth:check', async () => {
  const accessToken = getToken(ACCESS_TOKEN_KEY);
  const refreshToken = getToken(REFRESH_TOKEN_KEY);

  return {
    isLoggedIn: !!accessToken && !!refreshToken,
    hasAccessToken: !!accessToken,
    hasRefreshToken: !!refreshToken
  };
});

/**
 * Get the current access token (decoded for display)
 */
ipcMain.handle('auth:getTokenInfo', async () => {
  const accessToken = getToken(ACCESS_TOKEN_KEY);

  if (!accessToken) {
    return null;
  }

  try {
    // Decode the JWT payload (not verifying - just for display)
    const parts = accessToken.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    return {
      payload,
      expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
      isExpired: payload.exp ? Date.now() > payload.exp * 1000 : false
    };
  } catch {
    return null;
  }
});

/**
 * Call a protected API
 */
ipcMain.handle('api:protected', async () => {
  let accessToken = getToken(ACCESS_TOKEN_KEY);

  if (!accessToken) {
    throw new Error('Not logged in');
  }

  try {
    return await callProtectedAPI(accessToken);
  } catch (error) {
    // If token expired, try to refresh
    if ((error as Error).message.includes('expired')) {
      console.log('[API] Access token expired, attempting refresh...');

      const refreshToken = getToken(REFRESH_TOKEN_KEY);
      if (!refreshToken) {
        throw new Error('No refresh token available');
      }

      try {
        const newTokens = await refreshAccessToken(refreshToken);
        storeToken(ACCESS_TOKEN_KEY, newTokens.accessToken);

        // Retry the API call
        return await callProtectedAPI(newTokens.accessToken);
      } catch (refreshError) {
        // Refresh failed - user needs to login again
        deleteToken(ACCESS_TOKEN_KEY);
        deleteToken(REFRESH_TOKEN_KEY);
        throw new Error('Session expired - please login again');
      }
    }
    throw error;
  }
});

/**
 * Manually refresh the access token
 */
ipcMain.handle('auth:refresh', async () => {
  const refreshToken = getToken(REFRESH_TOKEN_KEY);

  if (!refreshToken) {
    throw new Error('No refresh token available');
  }

  const newTokens = await refreshAccessToken(refreshToken);
  storeToken(ACCESS_TOKEN_KEY, newTokens.accessToken);

  return { expiresIn: newTokens.expiresIn };
});

/**
 * Logout - revoke tokens and clear storage
 */
ipcMain.handle('auth:logout', async () => {
  console.log('[IPC] Logging out');

  const refreshToken = getToken(REFRESH_TOKEN_KEY);

  // Revoke the refresh token on the server
  if (refreshToken) {
    try {
      await revokeToken(refreshToken);
    } catch (error) {
      console.error('[Auth] Failed to revoke token:', error);
    }
  }

  // Clear local storage
  deleteToken(ACCESS_TOKEN_KEY);
  deleteToken(REFRESH_TOKEN_KEY);

  return { status: 'logged_out' };
});

// ============================================
// App Lifecycle
// ============================================

app.whenReady().then(() => {
  setupProtocolHandler();
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
