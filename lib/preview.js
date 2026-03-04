import { downloadFile } from './drive';
import { getSettings } from './state';

const cache = new Map();

export async function getPreview(file) {
  if (cache.has(file.id)) return cache.get(file.id);

  const mime = file.mimeType || '';
  const settings = getSettings();
  const sizeBytes = parseInt(file.size) || 0;
  const maxBytes = settings.maxPreviewMb * 1024 * 1024;

  // Images: use thumbnailLink first
  if (mime.startsWith('image/')) {
    if (file.thumbnailLink) {
      const result = { type: 'image', url: file.thumbnailLink.replace('=s220', '=s400') };
      cache.set(file.id, result);
      return result;
    }
    if (sizeBytes <= maxBytes) {
      const blob = await downloadFile(file.id);
      const url = URL.createObjectURL(blob);
      const result = { type: 'image', url, isBlob: true };
      cache.set(file.id, result);
      return result;
    }
  }

  // PDF: download and render with PDF.js
  if (mime === 'application/pdf' && sizeBytes <= maxBytes) {
    const blob = await downloadFile(file.id);
    const result = { type: 'pdf', blob };
    cache.set(file.id, result);
    return result;
  }

  // Text/code
  if (isTextMime(mime) && sizeBytes > 0) {
    const downloadSize = Math.min(sizeBytes, 5 * 1024);
    const blob = await downloadFile(file.id, `bytes=0-${downloadSize - 1}`);
    const text = await blob.text();
    const result = { type: 'text', content: text, truncated: sizeBytes > downloadSize };
    cache.set(file.id, result);
    return result;
  }

  // Thumbnail fallback for anything else
  if (file.thumbnailLink) {
    const result = { type: 'image', url: file.thumbnailLink.replace('=s220', '=s400') };
    cache.set(file.id, result);
    return result;
  }

  return { type: 'none' };
}

export async function prefetchPreview(file) {
  // Already cached, no need to fetch
  if (cache.has(file.id)) return;

  const mime = file.mimeType || '';
  const settings = getSettings();
  const sizeBytes = parseInt(file.size) || 0;
  const maxBytes = settings.maxPreviewMb * 1024 * 1024;

  // Images: use thumbnailLink first (fast, no download needed)
  if (mime.startsWith('image/')) {
    if (file.thumbnailLink) {
      const result = { type: 'image', url: file.thumbnailLink.replace('=s220', '=s400') };
      cache.set(file.id, result);
      return;
    }
    if (sizeBytes <= maxBytes) {
      try {
        const blob = await downloadFile(file.id);
        const url = URL.createObjectURL(blob);
        const result = { type: 'image', url, isBlob: true };
        cache.set(file.id, result);
      } catch {
        // Silently fail prefetch
      }
      return;
    }
  }

  // PDF: download and store blob
  if (mime === 'application/pdf' && sizeBytes <= maxBytes) {
    try {
      const blob = await downloadFile(file.id);
      const result = { type: 'pdf', blob };
      cache.set(file.id, result);
    } catch {
      // Silently fail prefetch
    }
    return;
  }

  // Text/code
  if (isTextMime(mime) && sizeBytes > 0) {
    const downloadSize = Math.min(sizeBytes, 5 * 1024);
    try {
      const blob = await downloadFile(file.id, `bytes=0-${downloadSize - 1}`);
      const text = await blob.text();
      const result = { type: 'text', content: text, truncated: sizeBytes > downloadSize };
      cache.set(file.id, result);
    } catch {
      // Silently fail prefetch
    }
    return;
  }

  // Thumbnail fallback for anything else
  if (file.thumbnailLink) {
    const result = { type: 'image', url: file.thumbnailLink.replace('=s220', '=s400') };
    cache.set(file.id, result);
  }
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

export function clearPreviewCache() {
  for (const [, val] of cache) {
    if (val.isBlob && val.url) URL.revokeObjectURL(val.url);
  }
  cache.clear();
}
