import { downloadFile } from './drive.js';
import { getSettings } from './state.js';

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
      const result = { type: 'image', url, blob: true };
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

function isTextMime(mime) {
  if (mime.startsWith('text/')) return true;
  const textTypes = [
    'application/json', 'application/xml', 'application/javascript',
    'application/x-yaml', 'application/x-sh', 'application/sql',
    'application/x-python', 'application/x-ruby',
  ];
  return textTypes.includes(mime);
}

export async function renderPreview(container, file) {
  container.innerHTML = '<div class="preview-loading">Loading preview...</div>';

  try {
    const preview = await getPreview(file);

    switch (preview.type) {
      case 'image':
        container.innerHTML = `<img src="${preview.url}" alt="${file.name}" class="preview-image" />`;
        break;

      case 'pdf':
        await renderPdf(container, preview.blob);
        break;

      case 'text':
        container.innerHTML = `<pre class="preview-text"><code>${escapeHtml(preview.content)}${preview.truncated ? '\n\n... (truncated)' : ''}</code></pre>`;
        break;

      default:
        container.innerHTML = `<div class="preview-none">
          <div class="preview-icon">${getMimeIcon(file.mimeType)}</div>
          <div class="preview-label">No preview available</div>
          <a href="https://drive.google.com/file/d/${file.id}/view" target="_blank" rel="noopener" class="preview-open">Open in Drive</a>
        </div>`;
    }
  } catch (e) {
    container.innerHTML = `<div class="preview-error">Preview failed: ${escapeHtml(e.message)}</div>`;
  }
}

async function renderPdf(container, blob) {
  if (!window.pdfjsLib) {
    const script = document.createElement('script');
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.0.379/pdf.min.mjs';
    script.type = 'module';
    await new Promise((resolve, reject) => {
      script.onload = resolve;
      script.onerror = reject;
      document.head.appendChild(script);
    });
    const pdfjsLib = await import('https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.0.379/pdf.min.mjs');
    window.pdfjsLib = pdfjsLib;
    pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.0.379/pdf.worker.min.mjs';
  }

  const arrayBuffer = await blob.arrayBuffer();
  const pdf = await window.pdfjsLib.getDocument({ data: arrayBuffer }).promise;
  const page = await pdf.getPage(1);
  const viewport = page.getViewport({ scale: 1 });
  const scale = Math.min(400 / viewport.width, 300 / viewport.height);
  const scaledViewport = page.getViewport({ scale });

  const canvas = document.createElement('canvas');
  canvas.width = scaledViewport.width;
  canvas.height = scaledViewport.height;
  canvas.className = 'preview-pdf';

  await page.render({ canvasContext: canvas.getContext('2d'), viewport: scaledViewport }).promise;

  container.innerHTML = '';
  container.appendChild(canvas);
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function getMimeIcon(mime) {
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
    if (val.blob && val.url) URL.revokeObjectURL(val.url);
  }
  cache.clear();
}
