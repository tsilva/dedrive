import { beforeEach, describe, expect, it, vi } from 'vitest';

const driveMocks = vi.hoisted(() => ({
  downloadFile: vi.fn(),
}));

vi.mock('@/lib/drive', () => driveMocks);
vi.mock('@/lib/state', () => ({
  getSettings: () => ({ maxPreviewMb: 25 }),
}));

import { clearPreviewCache, getPreview } from '@/lib/preview';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe('bounded preview loading', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    clearPreviewCache();
  });

  it('runs no more than two preview downloads concurrently', async () => {
    const first = deferred();
    const second = deferred();
    const third = deferred();
    driveMocks.downloadFile
      .mockReturnValueOnce(first.promise)
      .mockReturnValueOnce(second.promise)
      .mockReturnValueOnce(third.promise);

    const previews = [1, 2, 3].map((id) => getPreview({
      id: `pdf-${id}`,
      name: `pdf-${id}.pdf`,
      mimeType: 'application/pdf',
      size: '100',
    }));

    await Promise.resolve();
    expect(driveMocks.downloadFile).toHaveBeenCalledTimes(2);
    first.resolve(new Blob(['first'], { type: 'application/pdf' }));
    await first.promise;
    await vi.waitFor(() => expect(driveMocks.downloadFile).toHaveBeenCalledTimes(3));
    second.resolve(new Blob(['second'], { type: 'application/pdf' }));
    third.resolve(new Blob(['third'], { type: 'application/pdf' }));
    await Promise.all(previews);
  });

  it('turns an oversized response into a normal no-preview result', async () => {
    driveMocks.downloadFile.mockRejectedValueOnce(
      Object.assign(new Error('Too large'), { code: 'DOWNLOAD_TOO_LARGE' })
    );

    await expect(getPreview({
      id: 'oversized',
      name: 'oversized.pdf',
      mimeType: 'application/pdf',
      size: '100',
    })).resolves.toEqual({ type: 'none', reason: 'too_large', maxPreviewMb: 10 });
  });

  it('aborts queued and active work when the workflow is cleared', async () => {
    driveMocks.downloadFile.mockImplementation((_id, { signal }) => {
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(signal.reason), { once: true });
      });
    });

    const pending = getPreview({
      id: 'cancel-me',
      name: 'cancel-me.pdf',
      mimeType: 'application/pdf',
      size: '100',
    });
    await Promise.resolve();
    clearPreviewCache();

    await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
  });
});
