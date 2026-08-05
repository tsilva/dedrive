import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  AuthExpiredError,
  DRIVE_READONLY_SCOPE,
  initAuth,
  invalidateAuth,
  requestReadAccess,
} from '@/lib/auth';
import {
  DownloadTooLargeError,
  DriveApiError,
  UnsafeDestinationError,
  assertPrivateFolder,
  clearFolderCache,
  downloadFile,
  ensureDedupeRootFolder,
  ensureFolderPath,
  fetchAllFiles,
  findOrCreateFolder,
  getDriveRootId,
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
      const requestUrl = String(url);
      if (requestUrl.includes('/generateIds')) {
        return jsonResponse({ ids: [generatedIds.shift()] });
      }
      if (options.method === 'POST') {
        return jsonResponse(JSON.parse(options.body));
      }
      if (requestUrl.includes('/files/mirror-')) {
        return jsonResponse({
          id: requestUrl.includes('mirror-a') ? 'mirror-a' : 'mirror-b',
          mimeType: 'application/vnd.google-apps.folder',
          ownedByMe: true,
          shared: false,
          trashed: false,
        });
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

  it('replaces a shared marked cleanup root without modifying the unsafe folder', async () => {
    fetch.mockImplementation(async (url, options = {}) => {
      const requestUrl = String(url);
      if (requestUrl.includes('/generateIds')) return jsonResponse({ ids: ['private-root'] });
      if (options.method === 'POST') return jsonResponse(JSON.parse(options.body));
      if (requestUrl.includes('/files/shared-root?')) {
        return jsonResponse({
          id: 'shared-root',
          mimeType: 'application/vnd.google-apps.folder',
          ownedByMe: true,
          shared: true,
          trashed: false,
        });
      }
      if (requestUrl.includes('/files/private-root?')) {
        return jsonResponse({
          id: 'private-root',
          mimeType: 'application/vnd.google-apps.folder',
          ownedByMe: true,
          shared: false,
          trashed: false,
        });
      }
      if (requestUrl.includes('dedriveRole')) {
        return jsonResponse({ files: [{ id: 'shared-root', createdTime: '2025-01-01' }] });
      }
      return jsonResponse({ files: [] });
    });

    await expect(ensureDedupeRootFolder('_dupes')).resolves.toEqual({
      id: 'private-root',
      privacyReplacementCreated: true,
    });
    expect(fetch.mock.calls.some(([, options]) => options?.method === 'PATCH')).toBe(false);
  });

  it('reports that a replacement was created if its post-create privacy check fails', async () => {
    fetch.mockImplementation(async (url, options = {}) => {
      const requestUrl = String(url);
      if (requestUrl.includes('/generateIds')) return jsonResponse({ ids: ['unverified-root'] });
      if (options.method === 'POST') return jsonResponse(JSON.parse(options.body));
      if (requestUrl.includes('/files/shared-root?')) {
        return jsonResponse({
          id: 'shared-root',
          mimeType: 'application/vnd.google-apps.folder',
          ownedByMe: true,
          shared: true,
          trashed: false,
        });
      }
      if (requestUrl.includes('/files/unverified-root?')) {
        return jsonResponse({
          id: 'unverified-root',
          mimeType: 'application/vnd.google-apps.folder',
          ownedByMe: true,
          shared: true,
          trashed: false,
        });
      }
      if (requestUrl.includes('dedriveRole')) {
        return jsonResponse({ files: [{ id: 'shared-root', createdTime: '2025-01-01' }] });
      }
      return jsonResponse({ files: [] });
    });

    await expect(ensureDedupeRootFolder('_dupes')).rejects.toMatchObject({
      code: 'UNSAFE_DESTINATION',
      privacyReplacementCreated: true,
    });
  });

  it('paginates cleanup-root candidates and selects a freshly verified private folder', async () => {
    fetch.mockImplementation(async (url) => {
      const requestUrl = new URL(String(url));
      if (requestUrl.pathname.endsWith('/files/private-root')) {
        return jsonResponse({
          id: 'private-root',
          mimeType: 'application/vnd.google-apps.folder',
          ownedByMe: true,
          shared: false,
          trashed: false,
        });
      }
      if (requestUrl.searchParams.get('pageToken') === 'next-page') {
        return jsonResponse({ files: [{ id: 'private-root', createdTime: '2025-01-02' }] });
      }
      return jsonResponse({
        files: [{ id: 'missing-privacy-fields', createdTime: '2025-01-01' }],
        nextPageToken: 'next-page',
      });
    });

    await expect(ensureDedupeRootFolder('_dupes')).resolves.toEqual({
      id: 'private-root',
      privacyReplacementCreated: false,
    });
    expect(fetch.mock.calls.some(([url]) => String(url).includes('pageToken=next-page'))).toBe(true);
  });

  it('creates a private mirrored descendant when the marked candidate is shared', async () => {
    fetch.mockImplementation(async (url, options = {}) => {
      const requestUrl = String(url);
      if (requestUrl.includes('/generateIds')) return jsonResponse({ ids: ['private-child'] });
      if (options.method === 'POST') return jsonResponse(JSON.parse(options.body));
      if (requestUrl.includes('/files/shared-child?')) {
        return jsonResponse({
          id: 'shared-child',
          mimeType: 'application/vnd.google-apps.folder',
          ownedByMe: true,
          shared: true,
          trashed: false,
        });
      }
      if (requestUrl.includes('/files/private-child?')) {
        return jsonResponse({
          id: 'private-child',
          mimeType: 'application/vnd.google-apps.folder',
          ownedByMe: true,
          shared: false,
          trashed: false,
        });
      }
      return jsonResponse({ files: [{ id: 'shared-child', createdTime: '2025-01-01' }] });
    });

    await expect(ensureFolderPath(
      [{ id: 'source-child', name: 'Shared-looking child' }],
      'private-root'
    )).resolves.toEqual({ id: 'private-child', privacyReplacementCreated: true });
  });

  it('rejects a destination that became shared immediately before a move', async () => {
    fetch.mockResolvedValueOnce(jsonResponse({
      id: 'destination',
      mimeType: 'application/vnd.google-apps.folder',
      ownedByMe: true,
      shared: true,
      trashed: false,
    }));

    await expect(assertPrivateFolder('destination')).rejects.toBeInstanceOf(UnsafeDestinationError);
  });

  it('fails closed when destination privacy metadata is incomplete', async () => {
    fetch.mockResolvedValueOnce(jsonResponse({
      id: 'destination',
      mimeType: 'application/vnd.google-apps.folder',
      ownedByMe: true,
      trashed: false,
    }));

    await expect(assertPrivateFolder('destination')).rejects.toMatchObject({
      code: 'UNSAFE_DESTINATION',
    });
  });

  it('stops a bounded download before returning an oversized body', async () => {
    fetch.mockResolvedValueOnce(new Response(new Uint8Array(11), {
      headers: { 'Content-Length': '11', 'Content-Type': 'application/pdf' },
    }));

    await expect(downloadFile('large-pdf', { maxBytes: 10 })).rejects.toBeInstanceOf(
      DownloadTooLargeError
    );
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('enforces the byte cap when Drive omits response length metadata', async () => {
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(6));
        controller.enqueue(new Uint8Array(6));
        controller.close();
      },
    });
    fetch.mockResolvedValueOnce(new Response(body, {
      headers: { 'Content-Type': 'application/pdf' },
    }));

    await expect(downloadFile('streamed-pdf', { maxBytes: 10 })).rejects.toMatchObject({
      code: 'DOWNLOAD_TOO_LARGE',
    });
  });

  it('does not wrap or retry an aborted Drive download', async () => {
    const abortError = new DOMException('Aborted', 'AbortError');
    fetch.mockRejectedValue(abortError);

    await expect(downloadFile('cancelled', { signal: AbortSignal.abort() })).rejects.toBe(abortError);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('resolves the canonical My Drive root ID', async () => {
    fetch.mockResolvedValueOnce(jsonResponse({ id: 'canonical-root' }));

    await expect(getDriveRootId()).resolves.toBe('canonical-root');
    expect(fetch.mock.calls[0][0]).toContain('/files/root?fields=id');
  });

  it('retains shared folders for ancestry without retaining shared files', async () => {
    const onProgress = vi.fn();
    fetch.mockResolvedValueOnce(jsonResponse({
      files: [
        { id: 'owned-file', name: 'owned.txt', ownedByMe: true, mimeType: 'text/plain' },
        { id: 'shared-folder', name: 'Shared', ownedByMe: false, mimeType: 'application/vnd.google-apps.folder' },
        { id: 'shared-file', name: 'shared.txt', ownedByMe: false, mimeType: 'text/plain' },
      ],
    }));

    await expect(fetchAllFiles(onProgress)).resolves.toEqual([
      expect.objectContaining({ id: 'owned-file' }),
      expect.objectContaining({ id: 'shared-folder' }),
    ]);
    expect(onProgress).toHaveBeenCalledWith({ page: 1, fileCount: 1 });
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
