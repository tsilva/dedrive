'use client';

import { useState, useEffect, useCallback } from 'react';
import { getPreview, getMimeIcon } from '@/lib/preview';
import PdfPreview from './PdfPreview';

export default function FilePreview({ file }) {
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [zoom, setZoom] = useState(1);
  const [pdfPage, setPdfPage] = useState(1);
  const [pdfPageCount, setPdfPageCount] = useState(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    setZoom(1); // Reset zoom when file changes
    setPdfPage(1);
    setPdfPageCount(null);

    getPreview(file)
      .then((result) => {
        if (!cancelled) {
          setPreview(result);
          setLoading(false);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setError(e.message);
          setLoading(false);
        }
      });

    return () => { cancelled = true; };
  }, [file.id]);

  const closeFullscreen = useCallback(() => {
    setIsFullscreen(false);
    setZoom(1);
    setPdfPage(1);
  }, []);

  const isPdfPreview = preview?.type === 'pdf';
  const canGoToPreviousPdfPage = isPdfPreview && pdfPage > 1;
  const canGoToNextPdfPage = isPdfPreview && (!pdfPageCount || pdfPage < pdfPageCount);
  const goToPreviousPdfPage = useCallback(() => {
    setPdfPage((page) => Math.max(1, page - 1));
  }, []);
  const goToNextPdfPage = useCallback(() => {
    setPdfPage((page) => (pdfPageCount ? Math.min(pdfPageCount, page + 1) : page + 1));
  }, [pdfPageCount]);
  const handlePdfPageCountChange = useCallback((count) => {
    setPdfPageCount(count);
    setPdfPage((page) => Math.min(page, count));
  }, []);

  // Close fullscreen on escape key and prevent body scroll
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isFullscreen) {
        closeFullscreen();
        return;
      }
      if (isFullscreen) {
        if (isPdfPreview && (e.key === 'ArrowLeft' || e.key === 'PageUp')) {
          e.preventDefault();
          goToPreviousPdfPage();
          return;
        }
        if (isPdfPreview && (e.key === 'ArrowRight' || e.key === 'PageDown')) {
          e.preventDefault();
          goToNextPdfPage();
          return;
        }
        if ((e.ctrlKey || e.metaKey) && e.key === '=') {
          e.preventDefault();
          setZoom(z => Math.min(4, z + 0.25));
        }
        if ((e.ctrlKey || e.metaKey) && e.key === '-') {
          e.preventDefault();
          setZoom(z => Math.max(0.25, z - 0.25));
        }
        if ((e.ctrlKey || e.metaKey) && e.key === '0') {
          e.preventDefault();
          setZoom(1);
        }
      }
    };
    
    if (isFullscreen) {
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
    }
    
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = '';
    };
  }, [
    closeFullscreen,
    goToNextPdfPage,
    goToPreviousPdfPage,
    isFullscreen,
    isPdfPreview,
    pdfPageCount,
  ]);

  if (loading) {
    return <div className="preview-loading">Loading preview...</div>;
  }

  if (error) {
    return <div className="preview-error">Preview failed: {error}</div>;
  }

  if (!preview || preview.type === 'none') {
    return (
      <div className="preview-none">
        <div className="preview-icon">{getMimeIcon(file.mimeType)}</div>
        <div className="preview-label">No preview available</div>
        <a
          href={`https://drive.google.com/file/d/${file.id}/view`}
          target="_blank"
          rel="noopener noreferrer"
          className="preview-open"
        >
          Open in Drive
        </a>
      </div>
    );
  }

  const renderPreviewContent = (fullscreen = false, zoomLevel = 1) => {
    if (preview.type === 'image') {
      return (
        <img 
          src={preview.url} 
          alt={file.name} 
          className="preview-image" 
          style={zoomLevel !== 1 ? { transform: `scale(${zoomLevel})` } : undefined}
        />
      );
    }

    if (preview.type === 'pdf') {
      return (
        <PdfPreview
          blob={preview.blob}
          fullscreen={fullscreen}
          zoom={zoomLevel}
          pageNumber={fullscreen ? pdfPage : 1}
          onPageCountChange={handlePdfPageCountChange}
        />
      );
    }

    if (preview.type === 'text') {
      return (
        <pre className="preview-text">
          <code>
            {preview.content}
            {preview.truncated && '\n\n... (truncated)'}
          </code>
        </pre>
      );
    }

    return null;
  };

  return (
    <>
      <div className="file-preview-container" style={{ width: '100%', height: '100%' }}>
        {renderPreviewContent(false)}
        <button
          className="preview-fullscreen-btn"
          onClick={() => setIsFullscreen(true)}
          title="View fullscreen"
        >
          ⛶ Fullscreen
        </button>
      </div>

      {isFullscreen && (
        <div className="fullscreen-modal-overlay" onClick={closeFullscreen}>
          <div className="fullscreen-modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="fullscreen-modal-header">
              <div className="fullscreen-modal-title">{file.path || file.name}</div>
              <div className="fullscreen-modal-controls">
                {isPdfPreview && (
                  <div className="fullscreen-modal-page-controls" aria-label="PDF page controls">
                    <button
                      className="fullscreen-modal-control-btn"
                      onClick={goToPreviousPdfPage}
                      disabled={!canGoToPreviousPdfPage}
                      aria-label="Previous PDF page"
                      title="Previous page (Left arrow)"
                    >
                      ‹
                    </button>
                    <span className="fullscreen-modal-page-status" aria-live="polite">
                      Page {pdfPage}{pdfPageCount ? ` of ${pdfPageCount}` : ''}
                    </span>
                    <button
                      className="fullscreen-modal-control-btn"
                      onClick={goToNextPdfPage}
                      disabled={!canGoToNextPdfPage}
                      aria-label="Next PDF page"
                      title="Next page (Right arrow)"
                    >
                      ›
                    </button>
                  </div>
                )}
                <button
                  className="fullscreen-modal-control-btn"
                  onClick={() => setZoom(z => Math.max(0.25, z - 0.25))}
                  title="Zoom out (-)"
                  aria-label="Zoom out"
                >
                  −
                </button>
                <span className="fullscreen-modal-zoom-level">{Math.round(zoom * 100)}%</span>
                <button
                  className="fullscreen-modal-control-btn"
                  onClick={() => setZoom(z => Math.min(4, z + 0.25))}
                  title="Zoom in (+)"
                  aria-label="Zoom in"
                >
                  +
                </button>
                <button
                  className="fullscreen-modal-control-btn"
                  onClick={() => setZoom(1)}
                  title="Reset zoom (0)"
                  aria-label="Reset zoom"
                >
                  ↺
                </button>
                <button
                  className="fullscreen-modal-close"
                  onClick={closeFullscreen}
                  title="Close (Esc)"
                  aria-label="Close fullscreen preview"
                >
                  ×
                </button>
              </div>
            </div>
            <div className="fullscreen-modal-body">
              {renderPreviewContent(true, zoom)}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
