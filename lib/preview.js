import { downloadFile } from './drive';
import { getSettings } from './state';

const MAX_CONCURRENT_PREVIEWS = 2;
const MAX_PREVIEW_MB = 10;
const MIN_PREVIEW_MB = 1;
const TEXT_PREVIEW_BYTES = 5 * 1024;
const queuedTasks = [];
const activeTasks = new Set();

function createAbortError() {
  return new DOMException('Preview cancelled.', 'AbortError');
}

function abortReason(signal) {
  return signal.reason instanceof Error ? signal.reason : createAbortError();
}

function removeQueuedTask(task) {
  const index = queuedTasks.indexOf(task);
  if (index >= 0) queuedTasks.splice(index, 1);
}

function finishQueuedAbort(task) {
  if (task.status !== 'queued') return;
  task.status = 'settled';
  removeQueuedTask(task);
  task.detachExternalAbort();
  task.reject(abortReason(task.controller.signal));
  pumpQueue();
}

function pumpQueue() {
  while (activeTasks.size < MAX_CONCURRENT_PREVIEWS && queuedTasks.length > 0) {
    const task = queuedTasks.shift();
    if (task.controller.signal.aborted) {
      finishQueuedAbort(task);
      continue;
    }

    task.status = 'active';
    activeTasks.add(task);
    const abortPromise = new Promise((_, reject) => {
      task.controller.signal.addEventListener(
        'abort',
        () => reject(abortReason(task.controller.signal)),
        { once: true }
      );
    });

    Promise.race([
      Promise.resolve().then(() => task.operation(task.controller.signal)),
      abortPromise,
    ])
      .then(task.resolve, task.reject)
      .finally(() => {
        task.status = 'settled';
        activeTasks.delete(task);
        task.detachExternalAbort();
        pumpQueue();
      });
  }
}

function enqueuePreview(operation, externalSignal) {
  return new Promise((resolve, reject) => {
    const controller = new AbortController();
    const task = {
      controller,
      operation,
      resolve,
      reject,
      status: 'queued',
      detachExternalAbort: () => {},
    };

    const handleInternalAbort = () => finishQueuedAbort(task);
    controller.signal.addEventListener('abort', handleInternalAbort, { once: true });
    queuedTasks.push(task);

    if (externalSignal) {
      const handleExternalAbort = () => controller.abort(abortReason(externalSignal));
      if (externalSignal.aborted) {
        controller.abort(abortReason(externalSignal));
      } else {
        externalSignal.addEventListener('abort', handleExternalAbort, { once: true });
        task.detachExternalAbort = () => {
          externalSignal.removeEventListener('abort', handleExternalAbort);
        };
      }
    }

    if (controller.signal.aborted) {
      finishQueuedAbort(task);
    } else {
      pumpQueue();
    }
  });
}

function getPreviewLimit() {
  const configured = Number(getSettings().maxPreviewMb);
  const clampedMb = Number.isFinite(configured)
    ? Math.min(MAX_PREVIEW_MB, Math.max(MIN_PREVIEW_MB, configured))
    : MAX_PREVIEW_MB;
  return { maxPreviewMb: clampedMb, maxBytes: clampedMb * 1024 * 1024 };
}

function tooLargeResult() {
  return { type: 'none', reason: 'too_large', maxPreviewMb: MAX_PREVIEW_MB };
}

function throwIfAborted(signal) {
  if (signal.aborted) throw abortReason(signal);
}

async function loadPreview(file, signal) {
  const mime = file.mimeType || '';
  const sizeBytes = Number.parseInt(file.size, 10) || 0;
  const { maxBytes } = getPreviewLimit();

  if (mime.startsWith('image/')) {
    if (file.thumbnailLink) {
      return { type: 'image', url: file.thumbnailLink.replace('=s220', '=s400') };
    }
    if (sizeBytes > maxBytes) return tooLargeResult();
    const blob = await downloadFile(file.id, { signal, maxBytes });
    throwIfAborted(signal);
    return { type: 'image', url: URL.createObjectURL(blob), isBlob: true };
  }

  if (mime === 'application/pdf') {
    if (sizeBytes > maxBytes) return tooLargeResult();
    const blob = await downloadFile(file.id, { signal, maxBytes });
    throwIfAborted(signal);
    return { type: 'pdf', blob };
  }

  if (isTextMime(mime) && sizeBytes > 0) {
    const downloadSize = Math.min(sizeBytes, TEXT_PREVIEW_BYTES);
    const blob = await downloadFile(file.id, {
      rangeHeader: `bytes=0-${downloadSize - 1}`,
      signal,
      maxBytes: TEXT_PREVIEW_BYTES,
    });
    throwIfAborted(signal);
    const text = await blob.text();
    throwIfAborted(signal);
    return { type: 'text', content: text, truncated: sizeBytes > downloadSize };
  }

  if (file.thumbnailLink) {
    return { type: 'image', url: file.thumbnailLink.replace('=s220', '=s400') };
  }

  return { type: 'none' };
}

export function getPreview(file, { signal } = {}) {
  return enqueuePreview(async (taskSignal) => {
    try {
      return await loadPreview(file, taskSignal);
    } catch (error) {
      if (error?.code === 'DOWNLOAD_TOO_LARGE') return tooLargeResult();
      throw error;
    }
  }, signal);
}

function isTextMime(mime) {
  if (mime.startsWith('text/')) return true;
  const textTypes = [
    'application/json', 'application/xml', 'application/javascript',
    'application/x-yaml', 'application/x-sh', 'application/sql',
    'application/x-python', 'application/x-ruby',
  ];
  return textTypes.includes(mime);
}

export function getMimeIcon(mime) {
  if (!mime) return '\u{1F4C4}';
  if (mime.startsWith('video/')) return '\u{1F3AC}';
  if (mime.startsWith('audio/')) return '\u{1F3B5}';
  if (mime.startsWith('image/')) return '\u{1F5BC}';
  if (mime === 'application/pdf') return '\u{1F4D1}';
  if (mime.includes('spreadsheet') || mime.includes('excel')) return '\u{1F4CA}';
  if (mime.includes('presentation') || mime.includes('powerpoint')) return '\u{1F4CA}';
  if (mime.includes('document') || mime.includes('word')) return '\u{1F4DD}';
  if (mime.includes('zip') || mime.includes('archive') || mime.includes('compressed')) return '\u{1F4E6}';
  return '\u{1F4C4}';
}

export function disposePreview(preview) {
  if (preview?.isBlob && preview.url) URL.revokeObjectURL(preview.url);
}

export function clearPreviewCache() {
  const cancellation = createAbortError();
  for (const task of [...queuedTasks, ...activeTasks]) {
    task.controller.abort(cancellation);
  }
}
