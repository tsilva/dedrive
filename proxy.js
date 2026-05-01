import { NextResponse } from 'next/server';

function buildCsp(parts) {
  return parts.join(' ').replace(/\s{2,}/g, ' ').trim();
}

export function proxy(request) {
  const nonce = Buffer.from(crypto.randomUUID()).toString('base64');
  const isDev = process.env.NODE_ENV === 'development';
  const secureAppCsp = buildCsp([
    "default-src 'self';",
    "base-uri 'self';",
    "object-src 'none';",
    "frame-ancestors 'none';",
    "form-action 'self' https://accounts.google.com;",
    `script-src 'self' 'nonce-${nonce}' https://accounts.google.com https://accounts.gstatic.com${isDev ? " 'unsafe-eval'" : ''};`,
    "style-src 'self' 'unsafe-inline';",
    "img-src 'self' blob: data: https://*.googleusercontent.com https://*.gstatic.com https://*.google.com;",
    "font-src 'self' data:;",
    "connect-src 'self' https://www.googleapis.com https://accounts.google.com https://oauth2.googleapis.com;",
    "frame-src https://accounts.google.com;",
    "worker-src 'self' blob:;",
    'upgrade-insecure-requests;',
  ]);

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set('x-nonce', nonce);
  requestHeaders.set('Content-Security-Policy', secureAppCsp);

  const response = NextResponse.next({
    request: {
      headers: requestHeaders,
    },
  });
  response.headers.set('Content-Security-Policy', secureAppCsp);
  return response;
}

export const config = {
  matcher: ['/app', '/app/:path*'],
};
