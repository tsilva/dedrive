import { AuthExpiredError, getToken, invalidateAuth } from './auth';

const API = 'https://www.googleapis.com/drive/v3';
const DEDUPE_ROOT_APP_PROPERTY_KEY = 'dedriveRole';
const DEDUPE_ROOT_APP_PROPERTY_VALUE = 'dupesRoot';
const SOURCE_FOLDER_APP_PROPERTY_KEY = 'dedriveSourceFolderId';
const FOLDER_MIME_TYPE = 'application/vnd.google-apps.folder';
const MAX_RETRIES = 5;
const MAX_RETRY_DELAY_MS = 64_000;
const RETRYABLE_403_REASONS = new Set(['rateLimitExceeded', 'userRateLimitExceeded']);
const RETRYABLE_SERVER_STATUSES = new Set([500, 502, 503, 504]);
const folderPromiseCache = new Map();
const dedupeRootPromiseCache = new Map();

export class DriveApiError extends Error {
  constructor(message, {
    status = 0,
    reasons = [],
    body = null,
    retryAfterMs = null,
    cause,
  } = {}) {
    super(message, cause ? { cause } : undefined);
    this.name = 'DriveApiError';
    this.code = 'DRIVE_API_ERROR';
    this.status = status;
    this.reasons = reasons;
    this.body = body;
    this.retryAfterMs = retryAfterMs;
  }
}

function escapeDriveQueryValue(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseRetryAfter(value) {
  if (!value) return null;

  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, MAX_RETRY_DELAY_MS);
  }

  const retryDate = Date.parse(value);
  if (!Number.isNaN(retryDate)) {
    return Math.min(Math.max(0, retryDate - Date.now()), MAX_RETRY_DELAY_MS);
  }

  return null;
}

function getRetryDelay(error, attempt) {
  if (Number.isFinite(error?.retryAfterMs)) return error.retryAfterMs;
  const exponential = Math.pow(2, attempt) * 1000;
  const jitter = Math.floor(Math.random() * 250);
  return Math.min(exponential + jitter, MAX_RETRY_DELAY_MS);
}

async function parseErrorResponse(res) {
  const text = await res.text();
  let body = null;

  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }

  const reasons = Array.isArray(body?.error?.errors)
    ? body.error.errors.map((entry) => entry?.reason).filter(Boolean)
    : [];
  const message = body?.error?.message || text || res.statusText || 'Unknown Drive API error';

  return new DriveApiError(`Drive API ${res.status}: ${message}`, {
    status: res.status,
    reasons,
    body,
    retryAfterMs: parseRetryAfter(res.headers.get('Retry-After')),
  });
}

function isRateLimitError(error) {
  return error.status === 429
    || (error.status === 403 && error.reasons.some((reason) => RETRYABLE_403_REASONS.has(reason)));
}

function isRetryableServerError(error) {
  return RETRYABLE_SERVER_STATUSES.has(error.status);
}

function isAmbiguousMutationError(error) {
  return error instanceof DriveApiError && (error.status === 0 || isRetryableServerError(error));
}

async function request(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const {
    safeToRetry = method === 'GET' || method === 'HEAD',
    ...fetchOptions
  } = options;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const token = getToken();
    if (!token) throw new AuthExpiredError();

    let res;
    try {
      res = await fetch(`${API}${path}`, {
        ...fetchOptions,
        headers: {
          Authorization: `Bearer ${token}`,
          ...fetchOptions.headers,
        },
      });
    } catch (cause) {
      const error = new DriveApiError(`Drive API network error: ${cause.message || 'Request failed'}`, {
        cause,
      });
      if (safeToRetry && attempt < MAX_RETRIES) {
        await sleep(getRetryDelay(error, attempt));
        continue;
      }
      throw error;
    }

    if (res.ok) return res;

    const error = await parseErrorResponse(res);
    if (res.status === 401) {
      invalidateAuth();
      throw new AuthExpiredError();
    }

    const retryable = isRateLimitError(error) || (safeToRetry && isRetryableServerError(error));
    if (retryable && attempt < MAX_RETRIES) {
      await sleep(getRetryDelay(error, attempt));
      continue;
    }

    throw error;
  }

  throw new DriveApiError('Drive API retry limit exhausted');
}

async function getFileMetadata(fileId, fields = 'id,name,mimeType,parents,appProperties') {
  const res = await request(`/files/${encodeURIComponent(fileId)}?fields=${encodeURIComponent(fields)}`);
  return res.json();
}

async function generateFolderId() {
  const res = await request('/files/generateIds?count=1&space=drive&type=files');
  const data = await res.json();
  const id = data.ids?.[0];
  if (!id) throw new Error('Drive did not return a folder ID');
  return id;
}

function validateCreatedFolder(folder, { id, parentId, appProperties }) {
  if (folder?.id !== id || folder.mimeType !== FOLDER_MIME_TYPE) return false;
  if (parentId && !folder.parents?.includes(parentId)) return false;

  return Object.entries(appProperties || {}).every(([key, value]) => {
    return folder.appProperties?.[key] === value;
  });
}

async function createFolder({ id, name, parentId = null, appProperties = {} }) {
  const body = {
    id,
    name,
    mimeType: FOLDER_MIME_TYPE,
    appProperties,
  };
  if (parentId) body.parents = [parentId];

  try {
    const res = await request('/files?fields=id,name,mimeType,parents,appProperties', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      // A pre-generated ID makes replay safe: a prior success returns 409.
      safeToRetry: true,
    });
    return (await res.json()).id;
  } catch (error) {
    if (!(error instanceof DriveApiError) || error.status !== 409) throw error;

    const folder = await getFileMetadata(id);
    if (!validateCreatedFolder(folder, { id, parentId, appProperties })) {
      throw new DriveApiError('Drive returned a conflicting folder for a pre-generated ID', {
        status: 409,
        body: folder,
      });
    }
    return id;
  }
}

export async function getUserInfo() {
  const res = await request('/about?fields=user(displayName,emailAddress,photoLink)');
  const data = await res.json();
  return data.user;
}

export async function fetchAllFiles(onProgress) {
  const fields = 'nextPageToken,files(id,name,mimeType,size,md5Checksum,modifiedTime,createdTime,parents,thumbnailLink,owners,ownedByMe,appProperties)';
  const q = 'trashed = false';
  let files = [];
  let pageToken = null;
  let page = 0;

  do {
    const params = new URLSearchParams({
      q,
      fields,
      pageSize: '1000',
      corpora: 'user',
      includeItemsFromAllDrives: 'false',
      supportsAllDrives: 'false',
    });
    if (pageToken) params.set('pageToken', pageToken);

    const res = await request(`/files?${params}`);
    const data = await res.json();
    const ownedFiles = (data.files || []).filter((file) => file.ownedByMe);
    files = files.concat(ownedFiles);
    pageToken = data.nextPageToken;
    page++;
    onProgress?.({ page, fileCount: files.length });
  } while (pageToken);

  return files;
}

export async function downloadFile(fileId, rangeHeader) {
  const options = rangeHeader ? { headers: { Range: rangeHeader } } : {};
  const res = await request(`/files/${encodeURIComponent(fileId)}?alt=media`, options);
  return res.blob();
}

export async function findOrCreateFolder(segment, parentId) {
  const sourceId = String(segment?.id || '');
  const name = String(segment?.name ?? '');
  if (!sourceId) throw new Error('Source folder ID is required');
  if (!name) throw new Error('Source folder name is required');
  if (!parentId) throw new Error('Destination parent folder ID is required');

  const cacheKey = `${parentId}:${sourceId}`;
  if (folderPromiseCache.has(cacheKey)) {
    return folderPromiseCache.get(cacheKey);
  }

  const folderPromise = (async () => {
    const markerQuery =
      `appProperties has { key='${SOURCE_FOLDER_APP_PROPERTY_KEY}' and value='${escapeDriveQueryValue(sourceId)}' } and ` +
      `mimeType='${FOLDER_MIME_TYPE}' and trashed=false and '${escapeDriveQueryValue(parentId)}' in parents`;
    const markerRes = await request(
      `/files?q=${encodeURIComponent(markerQuery)}&fields=files(id,name,createdTime,parents,appProperties)&orderBy=createdTime`
    );
    const markerData = await markerRes.json();
    if (markerData.files?.length > 0) return markerData.files[0].id;

    const id = await generateFolderId();
    return createFolder({
      id,
      name,
      parentId,
      appProperties: { [SOURCE_FOLDER_APP_PROPERTY_KEY]: sourceId },
    });
  })();

  folderPromiseCache.set(cacheKey, folderPromise);
  try {
    return await folderPromise;
  } catch (error) {
    folderPromiseCache.delete(cacheKey);
    throw error;
  }
}

export async function ensureDedupeRootFolder(name) {
  const normalizedName = String(name).trim().replace(/^\/+|\/+$/g, '');
  if (!normalizedName) throw new Error('Folder name is required');

  if (dedupeRootPromiseCache.has(normalizedName)) {
    return dedupeRootPromiseCache.get(normalizedName);
  }

  const rootPromise = (async () => {
    const markerQuery =
      `appProperties has { key='${DEDUPE_ROOT_APP_PROPERTY_KEY}' and value='${DEDUPE_ROOT_APP_PROPERTY_VALUE}' } and ` +
      `mimeType='${FOLDER_MIME_TYPE}' and trashed=false and 'root' in parents`;
    const markerRes = await request(
      `/files?q=${encodeURIComponent(markerQuery)}&fields=files(id,name,createdTime,appProperties)&orderBy=createdTime`
    );
    const markerData = await markerRes.json();

    if (markerData.files?.length > 0) return markerData.files[0].id;

    const nameQuery =
      `name='${escapeDriveQueryValue(normalizedName)}' and ` +
      `mimeType='${FOLDER_MIME_TYPE}' and trashed=false and 'root' in parents`;
    const nameRes = await request(
      `/files?q=${encodeURIComponent(nameQuery)}&fields=files(id,name,createdTime,appProperties)&orderBy=createdTime`
    );
    const nameData = await nameRes.json();
    const existingFolder = nameData.files?.[0];

    if (existingFolder) {
      await request(`/files/${encodeURIComponent(existingFolder.id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          appProperties: {
            ...(existingFolder.appProperties || {}),
            [DEDUPE_ROOT_APP_PROPERTY_KEY]: DEDUPE_ROOT_APP_PROPERTY_VALUE,
          },
        }),
        safeToRetry: true,
      });
      return existingFolder.id;
    }

    const id = await generateFolderId();
    return createFolder({
      id,
      name: normalizedName,
      appProperties: {
        [DEDUPE_ROOT_APP_PROPERTY_KEY]: DEDUPE_ROOT_APP_PROPERTY_VALUE,
      },
    });
  })();

  dedupeRootPromiseCache.set(normalizedName, rootPromise);
  try {
    return await rootPromise;
  } catch (error) {
    dedupeRootPromiseCache.delete(normalizedName);
    throw error;
  }
}

function sameParentSet(first, second) {
  if (first.length !== second.length) return false;
  const secondSet = new Set(second);
  return first.every((parentId) => secondSet.has(parentId));
}

export async function moveFile(fileId, currentParents, newParentId) {
  let expectedParents = [...currentParents];

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const params = new URLSearchParams({ addParents: newParentId });
    if (expectedParents.length > 0) {
      params.set('removeParents', expectedParents.join(','));
    }

    try {
      const res = await request(`/files/${encodeURIComponent(fileId)}?${params}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
        safeToRetry: false,
      });
      return res.json();
    } catch (error) {
      if (!isAmbiguousMutationError(error) || attempt >= MAX_RETRIES) throw error;

      await sleep(getRetryDelay(error, attempt));
      const metadata = await getFileMetadata(fileId, 'id,name,parents');
      const actualParents = metadata.parents || [];
      if (actualParents.includes(newParentId)) return metadata;

      if (!sameParentSet(expectedParents, actualParents)) {
        throw new DriveApiError(`File ${fileId} moved to an unexpected folder during execution`, {
          body: metadata,
        });
      }
      expectedParents = actualParents;
    }
  }

  throw new DriveApiError(`Move retry limit exhausted for file ${fileId}`);
}

export async function ensureFolderPath(parentChain, initialParentId) {
  if (!initialParentId) throw new Error('Initial destination folder ID is required');
  if (!Array.isArray(parentChain)) throw new Error('Parent chain must be an array');

  let parentId = initialParentId;
  for (const segment of parentChain) {
    parentId = await findOrCreateFolder(segment, parentId);
  }
  return parentId;
}

export function clearFolderCache() {
  folderPromiseCache.clear();
  dedupeRootPromiseCache.clear();
}
