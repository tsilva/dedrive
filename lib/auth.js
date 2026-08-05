export const DRIVE_READONLY_SCOPE = 'https://www.googleapis.com/auth/drive.readonly';
export const DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive';

let tokenClient = null;
let accessToken = null;
let accessTokenExpiresAt = 0;
let grantedScopes = new Set();
let pendingRequest = null;

export class AuthExpiredError extends Error {
  constructor(message = 'Your Google session expired. Sign in again.') {
    super(message);
    this.name = 'AuthExpiredError';
    this.code = 'AUTH_EXPIRED';
  }
}

export function isAuthExpiredError(error) {
  return error instanceof AuthExpiredError || error?.code === 'AUTH_EXPIRED';
}

function clearAuthState() {
  accessToken = null;
  accessTokenExpiresAt = 0;
  grantedScopes = new Set();
}

function hasUsableToken(minValidityMs = 0) {
  if (!accessToken) return false;
  if (!accessTokenExpiresAt) return true;
  return accessTokenExpiresAt - Date.now() > minValidityMs;
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
  const expiresInSeconds = Number(response.expires_in);
  accessTokenExpiresAt = Number.isFinite(expiresInSeconds) && expiresInSeconds > 0
    ? Date.now() + expiresInSeconds * 1000
    : 0;
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

export function getToken() {
  return accessToken;
}

export function invalidateAuth() {
  clearAuthState();
}

export function isSignedIn() {
  return hasUsableToken();
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
  if (hasUsableToken()) return accessToken;

  await requestScope(DRIVE_READONLY_SCOPE, 'consent');
  return accessToken;
}

export async function requestWriteAccess() {
  if (hasWriteAccess() && hasUsableToken()) return accessToken;

  await requestScope(DRIVE_SCOPE, 'consent');
  return accessToken;
}

export async function ensureReadAccess(minValidityMs = 60_000) {
  if (hasUsableToken(minValidityMs)) return accessToken;

  await requestScope(DRIVE_READONLY_SCOPE, '');
  return accessToken;
}

export async function ensureWriteAccess(minValidityMs = 60_000) {
  if (hasWriteAccess() && hasUsableToken(minValidityMs)) return accessToken;

  await requestScope(DRIVE_SCOPE, hasWriteAccess() ? '' : 'consent');
  return accessToken;
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
