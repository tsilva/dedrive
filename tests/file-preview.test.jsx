import { render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const previewMocks = vi.hoisted(() => ({
  disposePreview: vi.fn(),
  getMimeIcon: vi.fn(() => 'file'),
  getPreview: vi.fn(),
}));

vi.mock('@/lib/preview', () => previewMocks);
vi.mock('@/components/PdfPreview', () => ({
  default: () => <div>PDF canvas</div>,
}));

import FilePreview from '@/components/FilePreview';

const file = {
  id: 'preview-file',
  name: 'preview.png',
  mimeType: 'image/png',
};

describe('preview lifecycle', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('aborts loading and disposes a blob URL when its card unmounts', async () => {
    const result = { type: 'image', url: 'blob:preview', isBlob: true };
    previewMocks.getPreview.mockResolvedValueOnce(result);

    const { unmount } = render(<FilePreview file={file} onAuthExpired={vi.fn()} />);
    expect(await screen.findByAltText('preview.png')).toHaveAttribute('src', 'blob:preview');
    const signal = previewMocks.getPreview.mock.calls[0][1].signal;

    unmount();

    expect(signal.aborted).toBe(true);
    expect(previewMocks.disposePreview).toHaveBeenCalledWith(result);
  });

  it('shows oversized files as a normal Open in Drive fallback', async () => {
    previewMocks.getPreview.mockResolvedValueOnce({
      type: 'none',
      reason: 'too_large',
      maxPreviewMb: 10,
    });

    render(<FilePreview file={file} onAuthExpired={vi.fn()} />);

    expect(await screen.findByText('Preview exceeds the 10 MB limit. Open in Drive.')).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByRole('link', { name: 'Open in Drive' })).toHaveAttribute(
        'href',
        'https://drive.google.com/file/d/preview-file/view'
      );
    });
  });
});
