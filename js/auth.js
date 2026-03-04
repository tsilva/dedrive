let tokenClient = null;
let accessToken = null;
let onAuthChange = null;

export function setAuthCallback(cb) {
  onAuthChange = cb;
}

export function getToken() {
  return accessToken;
}

export function isSignedIn() {
  return !!accessToken;
}

export function initAuth(clientId) {
  return new Promise((resolve) => {
    if (tokenClient) {
      resolve();
      return;
    }
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.onload = () => {
      tokenClient = google.accounts.oauth2.initTokenClient({
        client_id: clientId,
        scope: 'https://www.googleapis.com/auth/drive',
        callback: (response) => {
          if (response.error) {
            console.error('Auth error:', response);
            return;
          }
          accessToken = response.access_token;
          onAuthChange?.(true);
        },
      });
      resolve();
    };
    document.head.appendChild(script);
  });
}

export function signIn() {
  if (!tokenClient) throw new Error('Auth not initialized');
  tokenClient.requestAccessToken({ prompt: 'consent' });
}

export function silentRefresh() {
  if (!tokenClient) return;
  tokenClient.requestAccessToken({ prompt: '' });
}

export function signOut() {
  if (accessToken) {
    google.accounts.oauth2.revoke(accessToken);
  }
  accessToken = null;
  tokenClient = null;
  onAuthChange?.(false);
}
