const GA_MEASUREMENT_ID = process.env.NEXT_PUBLIC_GA_MEASUREMENT_ID;

function getGtag() {
  if (typeof window === 'undefined') return null;
  if (!GA_MEASUREMENT_ID) return null;
  if (typeof window.gtag !== 'function') return null;
  return window.gtag;
}

export function trackEvent(name, params = {}) {
  const gtag = getGtag();
  if (!gtag) return;
  gtag('event', name, params);
}

export function trackException(description, fatal = false) {
  const gtag = getGtag();
  if (!gtag) return;
  gtag('event', 'exception', {
    description,
    fatal,
  });
}
