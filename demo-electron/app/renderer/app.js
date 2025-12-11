/**
 * Renderer Process - UI Logic
 *
 * This runs in the web page context and can ONLY access:
 * - DOM APIs
 * - The safe API exposed by preload.ts (window.electronAuth)
 *
 * It CANNOT access:
 * - Node.js
 * - Electron APIs
 * - File system
 * - Secure token storage directly
 */

// DOM Elements
const authStatus = document.getElementById('auth-status');
const statusText = document.getElementById('status-text');
const loggedOutActions = document.getElementById('logged-out-actions');
const loggedInActions = document.getElementById('logged-in-actions');
const loginBtn = document.getElementById('login-btn');
const refreshBtn = document.getElementById('refresh-btn');
const apiBtn = document.getElementById('api-btn');
const logoutBtn = document.getElementById('logout-btn');
const tokenCard = document.getElementById('token-card');
const tokenInfo = document.getElementById('token-info');
const expiryInfo = document.getElementById('expiry-info');
const expiryTime = document.getElementById('expiry-time');
const expiryCountdown = document.getElementById('expiry-countdown');
const apiCard = document.getElementById('api-card');
const apiResponse = document.getElementById('api-response');

let countdownInterval = null;

/**
 * Update the UI based on auth state
 */
async function updateAuthState() {
  try {
    const state = await window.electronAuth.checkAuth();

    if (state.isLoggedIn) {
      setLoggedIn();
      await updateTokenInfo();
    } else {
      setLoggedOut();
    }
  } catch (error) {
    console.error('Failed to check auth state:', error);
    setLoggedOut();
  }
}

/**
 * Set UI to logged-in state
 */
function setLoggedIn() {
  authStatus.classList.remove('logged-out');
  authStatus.classList.add('logged-in');
  statusText.textContent = 'Logged in';
  loggedOutActions.classList.add('hidden');
  loggedInActions.classList.remove('hidden');
  tokenCard.classList.remove('hidden');
}

/**
 * Set UI to logged-out state
 */
function setLoggedOut() {
  authStatus.classList.remove('logged-in');
  authStatus.classList.add('logged-out');
  statusText.textContent = 'Not logged in';
  loggedOutActions.classList.remove('hidden');
  loggedInActions.classList.add('hidden');
  tokenCard.classList.add('hidden');
  apiCard.classList.add('hidden');

  if (countdownInterval) {
    clearInterval(countdownInterval);
    countdownInterval = null;
  }
}

/**
 * Update token information display
 */
async function updateTokenInfo() {
  try {
    const info = await window.electronAuth.getTokenInfo();

    if (!info) {
      tokenInfo.innerHTML = '<p>No token information available</p>';
      return;
    }

    // Display token payload
    tokenInfo.innerHTML = `
      <div class="token-display">
        <div class="token-label">Token Payload (decoded):</div>
        <pre>${JSON.stringify(info.payload, null, 2)}</pre>
      </div>
    `;

    // Update expiry info
    if (info.expiresAt) {
      const expiryDate = new Date(info.expiresAt);
      expiryTime.textContent = expiryDate.toLocaleTimeString();

      // Update expiry class
      if (info.isExpired) {
        expiryInfo.classList.add('expired');
      } else {
        expiryInfo.classList.remove('expired');
      }

      // Start countdown
      startExpiryCountdown(expiryDate);
    } else {
      expiryTime.textContent = 'No expiry';
      expiryCountdown.textContent = '--';
    }
  } catch (error) {
    console.error('Failed to get token info:', error);
    tokenInfo.innerHTML = '<p>Error loading token info</p>';
  }
}

/**
 * Start the expiry countdown timer
 */
function startExpiryCountdown(expiryDate) {
  if (countdownInterval) {
    clearInterval(countdownInterval);
  }

  function update() {
    const now = new Date();
    const diff = expiryDate - now;

    if (diff <= 0) {
      expiryCountdown.textContent = 'EXPIRED';
      expiryInfo.classList.add('expired');
      clearInterval(countdownInterval);
      return;
    }

    const minutes = Math.floor(diff / 60000);
    const seconds = Math.floor((diff % 60000) / 1000);
    expiryCountdown.textContent = `${minutes}m ${seconds}s remaining`;
  }

  update();
  countdownInterval = setInterval(update, 1000);
}

/**
 * Show API response
 */
function showApiResponse(data, isError = false) {
  apiCard.classList.remove('hidden');
  apiResponse.classList.toggle('error', isError);

  if (isError) {
    apiResponse.innerHTML = `<pre>Error: ${data}</pre>`;
  } else {
    apiResponse.innerHTML = `<pre>${JSON.stringify(data, null, 2)}</pre>`;
  }
}

// ============================================
// Event Handlers
// ============================================

loginBtn.addEventListener('click', async () => {
  loginBtn.disabled = true;
  loginBtn.textContent = 'Opening browser...';

  try {
    await window.electronAuth.login();
    // The browser will open - user logs in there
    // We'll get notified via onAuthSuccess when done
    loginBtn.textContent = 'Waiting for login...';
  } catch (error) {
    console.error('Login failed:', error);
    loginBtn.disabled = false;
    loginBtn.textContent = 'Login with Browser';
  }
});

refreshBtn.addEventListener('click', async () => {
  refreshBtn.disabled = true;

  try {
    await window.electronAuth.refresh();
    await updateTokenInfo();
    showApiResponse({ message: 'Token refreshed successfully!' });
  } catch (error) {
    console.error('Refresh failed:', error);
    showApiResponse(error.message, true);
  } finally {
    refreshBtn.disabled = false;
  }
});

apiBtn.addEventListener('click', async () => {
  apiBtn.disabled = true;

  try {
    const response = await window.electronAuth.callProtectedAPI();
    showApiResponse(response);
    // Update token info in case it was refreshed automatically
    await updateTokenInfo();
  } catch (error) {
    console.error('API call failed:', error);
    showApiResponse(error.message, true);

    // If session expired, update UI
    if (error.message.includes('login again')) {
      setLoggedOut();
    }
  } finally {
    apiBtn.disabled = false;
  }
});

logoutBtn.addEventListener('click', async () => {
  logoutBtn.disabled = true;

  try {
    await window.electronAuth.logout();
    setLoggedOut();
    apiCard.classList.add('hidden');
  } catch (error) {
    console.error('Logout failed:', error);
  } finally {
    logoutBtn.disabled = false;
  }
});

// ============================================
// Auth Event Listeners
// ============================================

// Called when OAuth callback is received and tokens are obtained
window.electronAuth.onAuthSuccess((data) => {
  console.log('Auth success!', data);
  loginBtn.disabled = false;
  loginBtn.textContent = 'Login with Browser';
  setLoggedIn();
  updateTokenInfo();
});

// Called when OAuth callback has an error
window.electronAuth.onAuthError((error) => {
  console.error('Auth error:', error);
  loginBtn.disabled = false;
  loginBtn.textContent = 'Login with Browser';
  showApiResponse(error, true);
});

// ============================================
// Initialize
// ============================================

updateAuthState();
