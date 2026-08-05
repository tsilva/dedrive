import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AuthExpiredError,
  DRIVE_READONLY_SCOPE,
  initAuth,
  invalidateAuth,
  requestReadAccess,
} from '@/lib/auth';
import {
  DriveApiError,
  clearFolderCache,
  findOrCreateFolder,
  getUserInfo,
  moveFile,
} from '@/lib/drive';

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
}

function driveError(status, reason, message = 'Drive rejected the request', headers = {}) {
  return jsonResponse({
    error: {
      code: status,
      message,
      errors: reason ? [{ reason }] : [],
    },
  }, status, headers);
}

describe('Drive request safety', () => {
  let tokenConfig;

  beforeAll(() => {
    const oauth2 = {
      initTokenClient: vi.fn((config) => {
        tokenConfig = config;
        return {
          requestAccessToken: ({ scope }) => {
            config.callback({
              access_token: 'test-token',
              expires_in: 3600,
              scope: scope || DRIVE_READONLY_SCOPE,
            });
          },
        };
      }),
      revoke: vi.fn(),
    };
    globalThis.google = { accounts: { oauth2 } };
    initAuth('test-client-id');
  });

  beforeEach(async () => {
    vi.clearAllMocks();
    clearFolderCache();
    invalidateAuth();
    await requestReadAccess();
    vi.stubGlobal('fetch', vi.fn());
  });

  afterAll(() => {
    delete globalThis.google;
    vi.unstubAllGlobals();
  });

  it('retries a classified 403 rate limit response', async () => {
    fetch
      .mockResolvedValueOnce(driveError(403, 'userRateLimitExceeded', 'Slow down', { 'Retry-After': '0' }))
      .mockResolvedValueOnce(jsonResponse({ user: { displayName: 'Recovered' } }));

    await expect(getUserInfo()).resolves.toEqual({ displayName: 'Recovered' });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('does not retry a permanent 403 response', async () => {
    fetch.mockResolvedValue(driveError(403, 'insufficientPermissions', 'Not allowed'));

    await expect(getUserInfo()).rejects.toMatchObject({
      name: 'DriveApiError',
      status: 403,
      reasons: ['insufficientPermissions'],
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('retries a safe GET after a transient server response', async () => {
    fetch
      .mockResolvedValueOnce(driveError(503, 'backendError', 'Unavailable', { 'Retry-After': '0' }))
      .mockResolvedValueOnce(jsonResponse({ user: { displayName: 'Recovered' } }));

    await expect(getUserInfo()).resolves.toEqual({ displayName: 'Recovered' });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('invalidates authentication on 401 without silently refreshing', async () => {
    fetch.mockResolvedValueOnce(driveError(401, 'authError', 'Expired'));

    await expect(getUserInfo()).rejects.toBeInstanceOf(AuthExpiredError);
    expect(fetch).toHaveBeenCalledTimes(1);

    fetch.mockResolvedValueOnce(jsonResponse({ user: { displayName: 'Should not run' } }));
    await expect(getUserInfo()).rejects.toBeInstanceOf(AuthExpiredError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('uses source folder IDs to create distinct exact-name mirrors', async () => {
    const generatedIds = ['mirror-a', 'mirror-b'];
    fetch.mockImplementation(async (url, options = {}) => {
      if (String(url).includes('/generateIds')) {
        return jsonResponse({ ids: [generatedIds.shift()] });
      }
      if (options.method === 'POST') {
        return jsonResponse(JSON.parse(options.body));
      }
      return jsonResponse({ files: [] });
    });

    const exactName = '  Reports / Final  ';
    const first = await findOrCreateFolder({ id: 'source-a', name: exactName }, 'dupes-root');
    const second = await findOrCreateFolder({ id: 'source-b', name: exactName }, 'dupes-root');

    expect(first).toBe('mirror-a');
    expect(second).toBe('mirror-b');
    const creates = fetch.mock.calls
      .filter(([, options]) => options?.method === 'POST')
      .map(([, options]) => JSON.parse(options.body));
    expect(creates).toEqual([
      expect.objectContaining({
        id: 'mirror-a',
        name: exactName,
        appProperties: { dedriveSourceFolderId: 'source-a' },
      }),
      expect.objectContaining({
        id: 'mirror-b',
        name: exactName,
        appProperties: { dedriveSourceFolderId: 'source-b' },
      }),
    ]);
  });

  it('reconciles an ambiguous move before deciding whether to retry', async () => {
    fetch
      .mockResolvedValueOnce(driveError(503, 'backendError', 'Unknown outcome', { 'Retry-After': '0' }))
      .mockResolvedValueOnce(jsonResponse({
        id: 'file-id',
        name: 'copy.txt',
        parents: ['destination'],
      }));

    await expect(moveFile('file-id', ['source'], 'destination')).resolves.toMatchObject({
      id: 'file-id',
      parents: ['destination'],
    });
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(fetch.mock.calls[0][1]).toMatchObject({ method: 'PATCH' });
    expect(fetch.mock.calls[1][0]).toContain('/files/file-id?fields=');
  });

  it('preserves structured Drive error details for callers', async () => {
    fetch.mockResolvedValueOnce(driveError(404, 'notFound', 'Missing'));

    try {
      await getUserInfo();
      throw new Error('Expected getUserInfo to fail');
    } catch (error) {
      expect(error).toBeInstanceOf(DriveApiError);
      expect(error).toMatchObject({ status: 404, reasons: ['notFound'] });
    }
  });
});
