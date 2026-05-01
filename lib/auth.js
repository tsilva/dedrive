export const DRIVE_READONLY_SCOPE = 'https://www.googleapis.com/auth/drive.readonly';
export const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive';

let tokenClient = null;
let accessToken = null;
let grantedScopes = new Set();
let pendingRequest = null;
let silentRefreshPromise = null;
let onAuthChange = null;

function clearAuthState() {
  accessToken = null;
  grantedScopes = new Set();
}

function normalizeScopes(scopeString) {
  return (scopeString || '').split(' ').filter(Boolean);
}

function resolveGrantedScopes(response) {
  const scopes = new Set(grantedScopes);

  normalizeScopes(response?.scope).forEach((scope) => scopes.add(scope));

  return scopes;
}

function toAuthError(response) {
  if (!response) return new Error('Google sign-in failed.');

  if (response.type === 'popup_closed' || response.error === 'popup_closed_by_user') {
    return new Error('Google sign-in was cancelled.');
  }
  if (response.type === 'popup_failed_to_open') {
    return new Error('Google sign-in popup could not be opened.');
  }
  if (response.error === 'access_denied') {
    return new Error('Google did not grant the requested access.');
  }
  if (response.error === 'interaction_required') {
    return new Error('Google requires another sign-in prompt to continue.');
  }

  return new Error(response.error || response.message || 'Google sign-in failed.');
}

function finishPendingRequest(error, response) {
  if (!pendingRequest) return;

  const current = pendingRequest;
  pendingRequest = null;

  if (error) {
    current.reject(error);
    return;
  }

  current.resolve(response);
}

function handleTokenResponse(response) {
  if (response.error) {
    finishPendingRequest(toAuthError(response));
    return;
  }

  accessToken = response.access_token;
  grantedScopes = resolveGrantedScopes(response);
  finishPendingRequest(null, response);
}

function handleTokenError(error) {
  finishPendingRequest(toAuthError(error));
}

function requireClient() {
  if (!tokenClient) throw new Error('Auth not initialized');
}

function requestScope(scope, prompt) {
  requireClient();

  if (pendingRequest) {
    return Promise.reject(new Error('Another Google auth request is already in progress.'));
  }

  return new Promise((resolve, reject) => {
    pendingRequest = { resolve, reject, scope };
    tokenClient.requestAccessToken({
      scope,
      prompt,
      include_granted_scopes: true,
    });
  });
}

export function setAuthCallback(cb) {
  onAuthChange = cb;
}

export function getToken() {
  return accessToken;
}

export function isSignedIn() {
  return !!accessToken;
}

export function hasWriteAccess() {
  return grantedScopes.has(DRIVE_SCOPE);
}

export function initAuth(clientId) {
  if (tokenClient) return;
  if (!window.google?.accounts?.oauth2) {
    throw new Error('Google Identity Services not loaded');
  }
  tokenClient = google.accounts.oauth2.initTokenClient({
    client_id: clientId,
    scope: DRIVE_READONLY_SCOPE,
    callback: handleTokenResponse,
    error_callback: handleTokenError,
  });
}

export async function requestReadAccess() {
  if (accessToken) return accessToken;

  await requestScope(DRIVE_READONLY_SCOPE, 'consent');
  return accessToken;
}

export async function requestWriteAccess() {
  if (hasWriteAccess()) return accessToken;

  await requestScope(DRIVE_SCOPE, 'consent');
  return accessToken;
}

export async function silentRefresh() {
  requireClient();

  if (!silentRefreshPromise) {
    silentRefreshPromise = (async () => {
      const scope = hasWriteAccess() ? DRIVE_SCOPE : DRIVE_READONLY_SCOPE;
      await requestScope(scope, '');
      return accessToken;
    })()
      .catch((error) => {
        clearAuthState();
        onAuthChange?.(false);
        throw error;
      })
      .finally(() => {
        silentRefreshPromise = null;
      });
  }

  return silentRefreshPromise;
}

export function releaseWriteAccess() {
  if (!hasWriteAccess()) return false;

  const tokenToRevoke = accessToken;
  clearAuthState();

  if (tokenToRevoke && window.google?.accounts?.oauth2) {
    google.accounts.oauth2.revoke(tokenToRevoke);
  }

  return true;
}

export function signOut() {
  if (accessToken && window.google?.accounts?.oauth2) {
    google.accounts.oauth2.revoke(accessToken);
  }
  clearAuthState();
}
