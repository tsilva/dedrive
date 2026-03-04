import { getToken, silentRefresh } from './auth.js';

const API = 'https://www.googleapis.com/drive/v3';

async function request(path, options = {}) {
  const maxRetries = 5;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const token = getToken();
    if (!token) throw new Error('Not authenticated');

    const res = await fetch(`${API}${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        ...options.headers,
      },
    });

    if (res.status === 401 && attempt < maxRetries) {
      silentRefresh();
      await new Promise((r) => setTimeout(r, 1000));
      continue;
    }

    if ((res.status === 429 || res.status === 403) && attempt < maxRetries) {
      await new Promise((r) => setTimeout(r, Math.pow(2, attempt) * 1000));
      continue;
    }

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`Drive API ${res.status}: ${body}`);
    }

    return res;
  }
}

export async function getUserInfo() {
  const res = await request('/about?fields=user(displayName,emailAddress,photoLink)');
  const data = await res.json();
  return data.user;
}

export async function fetchAllFiles(onProgress) {
  const fields = 'nextPageToken,files(id,name,mimeType,size,md5Checksum,modifiedTime,createdTime,parents,thumbnailLink,owners)';
  const q = "trashed=false and 'me' in owners";
  let files = [];
  let pageToken = null;
  let page = 0;

  do {
    const params = new URLSearchParams({ q, fields, pageSize: '1000' });
    if (pageToken) params.set('pageToken', pageToken);

    const res = await request(`/files?${params}`);
    const data = await res.json();
    files = files.concat(data.files || []);
    pageToken = data.nextPageToken;
    page++;
    onProgress?.({ page, fileCount: files.length });
  } while (pageToken);

  return files;
}

export async function downloadFile(fileId, rangeHeader) {
  const options = rangeHeader ? { headers: { Range: rangeHeader } } : {};
  const res = await request(`/files/${fileId}?alt=media`, options);
  return res.blob();
}

export async function findOrCreateFolder(name, parentId) {
  const q = `name='${name}' and mimeType='application/vnd.google-apps.folder' and trashed=false` +
    (parentId ? ` and '${parentId}' in parents` : '');
  const res = await request(`/files?q=${encodeURIComponent(q)}&fields=files(id,name)`);
  const data = await res.json();

  if (data.files?.length > 0) return data.files[0].id;

  const body = {
    name,
    mimeType: 'application/vnd.google-apps.folder',
  };
  if (parentId) body.parents = [parentId];

  const createRes = await request('/files', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const folder = await createRes.json();
  return folder.id;
}

export async function moveFile(fileId, currentParents, newParentId) {
  const removeParents = currentParents.join(',');
  const res = await request(
    `/files/${fileId}?addParents=${newParentId}&removeParents=${removeParents}`,
    { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: '{}' }
  );
  return res.json();
}

export async function ensureFolderPath(pathParts) {
  let parentId = null;
  for (const part of pathParts) {
    parentId = await findOrCreateFolder(part, parentId);
  }
  return parentId;
}
