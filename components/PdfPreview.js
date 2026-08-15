'use client';

import { useRef, useEffect, useState } from 'react';

export default function PdfPreview({
  blob,
  fullscreen = false,
  zoom = 1,
  pageNumber = 1,
  onPageCountChange,
}) {
  const canvasRef = useRef(null);
  const [error, setError] = useState(null);
  const [pdfDoc, setPdfDoc] = useState(null);
  const [renderBounds, setRenderBounds] = useState(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const container = canvas?.parentElement;
    if (!container) return undefined;

    const updateRenderBounds = () => {
      const width = Math.max(1, Math.floor(container.clientWidth));
      const height = Math.max(1, Math.floor(container.clientHeight));
      setRenderBounds((current) => {
        if (current?.width === width && current?.height === height) return current;
        return { width, height };
      });
    };

    updateRenderBounds();
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', updateRenderBounds);
      return () => window.removeEventListener('resize', updateRenderBounds);
    }

    const observer = new ResizeObserver(updateRenderBounds);
    observer.observe(container);
    return () => observer.disconnect();
  }, [fullscreen]);

  useEffect(() => {
    let cancelled = false;
    let loadedPdf = null;
    let loadingTask = null;

    async function loadPdf() {
      setError(null);
      setPdfDoc(null);
      const pdfjsLib = await import('pdfjs-dist');
      pdfjsLib.GlobalWorkerOptions.workerSrc = new URL(
        'pdfjs-dist/build/pdf.worker.min.mjs',
        import.meta.url
      ).toString();

      const arrayBuffer = await blob.arrayBuffer();
      loadingTask = pdfjsLib.getDocument({
        data: arrayBuffer,
        isEvalSupported: false,
      });
      const pdf = await loadingTask.promise;
      loadedPdf = pdf;

      if (cancelled) {
        await pdf.destroy?.();
        return;
      }

      if (!cancelled) onPageCountChange?.(pdf.numPages);
      setPdfDoc(pdf);
    }

    loadPdf().catch((e) => {
      if (!cancelled) {
        console.error(e);
        setError(e.message || 'Could not load PDF preview');
      }
    });

    return () => {
      cancelled = true;
      if (loadedPdf) {
        loadedPdf.destroy?.();
      } else {
        loadingTask?.destroy?.();
      }
    };
  }, [blob, onPageCountChange]);

  useEffect(() => {
    if (!pdfDoc) return undefined;

    let cancelled = false;
    let renderTask = null;

    async function renderPage() {
      setError(null);
      const safePageNumber = Math.min(Math.max(pageNumber, 1), pdfDoc.numPages);
      const page = await pdfDoc.getPage(safePageNumber);
      const viewport = page.getViewport({ scale: 1 });

      const baseMaxWidth = renderBounds?.width || (fullscreen ? 1200 : 600);
      const baseMaxHeight = renderBounds?.height || (fullscreen ? 800 : 400);
      const maxWidth = baseMaxWidth * zoom;
      const maxHeight = baseMaxHeight * zoom;
      const scale = Math.min(maxWidth / viewport.width, maxHeight / viewport.height);
      const cssViewport = page.getViewport({ scale });
      const outputScale = Math.min(window.devicePixelRatio || 1, 2);
      const renderedViewport = page.getViewport({ scale: scale * outputScale });

      if (cancelled || !canvasRef.current) return;

      // Render into a staging canvas so an already-prefetched page stays visible
      // while a promoted card adapts to its final on-screen dimensions.
      const stagingCanvas = document.createElement('canvas');
      stagingCanvas.width = Math.max(1, Math.floor(renderedViewport.width));
      stagingCanvas.height = Math.max(1, Math.floor(renderedViewport.height));

      renderTask = page.render({
        canvasContext: stagingCanvas.getContext('2d'),
        viewport: renderedViewport,
      });
      await renderTask.promise;

      if (cancelled || !canvasRef.current) return;

      const canvas = canvasRef.current;
      canvas.width = stagingCanvas.width;
      canvas.height = stagingCanvas.height;
      canvas.style.width = `${Math.floor(cssViewport.width)}px`;
      canvas.style.height = `${Math.floor(cssViewport.height)}px`;
      canvas.getContext('2d').drawImage(stagingCanvas, 0, 0);
    }

    renderPage().catch((e) => {
      if (!cancelled) {
        console.error(e);
        setError(e.message || 'Could not render PDF page');
      }
    });

    return () => {
      cancelled = true;
      renderTask?.cancel?.();
    };
  }, [pdfDoc, fullscreen, zoom, pageNumber, renderBounds]);

  if (error) {
    return <div className="preview-error">Preview failed: {error}</div>;
  }

  return <canvas ref={canvasRef} className="preview-pdf" />;
}
