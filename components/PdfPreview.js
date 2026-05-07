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

  useEffect(() => {
    let cancelled = false;
    let loadedPdf = null;

    async function loadPdf() {
      setError(null);
      setPdfDoc(null);
      const pdfjsLib = await import('pdfjs-dist');
      pdfjsLib.GlobalWorkerOptions.workerSrc = new URL(
        'pdfjs-dist/build/pdf.worker.min.mjs',
        import.meta.url
      ).toString();

      const arrayBuffer = await blob.arrayBuffer();
      const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
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
      loadedPdf?.destroy?.();
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
      
      // Use larger dimensions for fullscreen, apply zoom
      const baseMaxWidth = fullscreen ? 1200 : 600;
      const baseMaxHeight = fullscreen ? 800 : 400;
      const maxWidth = baseMaxWidth * zoom;
      const maxHeight = baseMaxHeight * zoom;
      const scale = Math.min(maxWidth / viewport.width, maxHeight / viewport.height);
      const scaledViewport = page.getViewport({ scale });

      if (cancelled || !canvasRef.current) return;

      const canvas = canvasRef.current;
      canvas.width = scaledViewport.width;
      canvas.height = scaledViewport.height;

      renderTask = page.render({
        canvasContext: canvas.getContext('2d'),
        viewport: scaledViewport,
      });
      await renderTask.promise;
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
  }, [pdfDoc, fullscreen, zoom, pageNumber]);

  if (error) {
    return <div className="preview-error">Preview failed: {error}</div>;
  }

  return <canvas ref={canvasRef} className="preview-pdf" />;
}
