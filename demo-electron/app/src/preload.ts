/**
 * Preload Script - Secure Bridge Between Main and Renderer
 *
 * This script runs in a special context:
 * - Has access to some Electron APIs
 * - Can expose safe functions to the renderer (web page)
 * - Acts as a security boundary
 *
 * The renderer (web page) CANNOT:
 * - Access Node.js directly
 * - Access Electron APIs directly
 * - Access the file system
 * - Access the network directly for auth
 *
 * It can ONLY use the functions we expose here via contextBridge.
 */

import { contextBridge, ipcRenderer } from 'electron';

// Expose a safe API to the renderer process
contextBridge.exposeInMainWorld('electronAuth', {
  /**
   * Start the login flow (opens browser)
   */
  login: (): Promise<{ status: string }> => {
    return ipcRenderer.invoke('auth:login');
  },

  /**
   * Check if user is logged in
   */
  checkAuth: (): Promise<{
    isLoggedIn: boolean;
    hasAccessToken: boolean;
    hasRefreshToken: boolean;
  }> => {
    return ipcRenderer.invoke('auth:check');
  },

  /**
   * Get information about the current access token
   */
  getTokenInfo: (): Promise<{
    payload: any;
    expiresAt: string | null;
    isExpired: boolean;
  } | null> => {
    return ipcRenderer.invoke('auth:getTokenInfo');
  },

  /**
   * Manually refresh the access token
   */
  refresh: (): Promise<{ expiresIn: number }> => {
    return ipcRenderer.invoke('auth:refresh');
  },

  /**
   * Logout and clear tokens
   */
  logout: (): Promise<{ status: string }> => {
    return ipcRenderer.invoke('auth:logout');
  },

  /**
   * Call the protected API endpoint
   */
  callProtectedAPI: (): Promise<{ message: string; user: any }> => {
    return ipcRenderer.invoke('api:protected');
  },

  /**
   * Listen for auth events from the main process
   */
  onAuthSuccess: (callback: (data: { expiresIn: number }) => void): void => {
    ipcRenderer.on('auth:success', (_event, data) => callback(data));
  },

  onAuthError: (callback: (error: string) => void): void => {
    ipcRenderer.on('auth:error', (_event, error) => callback(error));
  }
});

// Type declaration for the renderer
declare global {
  interface Window {
    electronAuth: {
      login: () => Promise<{ status: string }>;
      checkAuth: () => Promise<{
        isLoggedIn: boolean;
        hasAccessToken: boolean;
        hasRefreshToken: boolean;
      }>;
      getTokenInfo: () => Promise<{
        payload: any;
        expiresAt: string | null;
        isExpired: boolean;
      } | null>;
      refresh: () => Promise<{ expiresIn: number }>;
      logout: () => Promise<{ status: string }>;
      callProtectedAPI: () => Promise<{ message: string; user: any }>;
      onAuthSuccess: (callback: (data: { expiresIn: number }) => void) => void;
      onAuthError: (callback: (error: string) => void) => void;
    };
  }
}
