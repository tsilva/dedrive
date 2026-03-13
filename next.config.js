/** @type {import('next').NextConfig} */
const { execSync } = require('child_process');

function buildCsp(parts) {
  return parts.join(' ').replace(/\s{2,}/g, ' ').trim();
}

const secureAppCsp = buildCsp([
  "default-src 'self';",
  "base-uri 'self';",
  "object-src 'none';",
  "frame-ancestors 'none';",
  "form-action 'self' https://accounts.google.com;",
  "script-src 'self' 'unsafe-inline' https://accounts.google.com https://accounts.gstatic.com;",
  "style-src 'self' 'unsafe-inline';",
  "img-src 'self' blob: data: https://*.googleusercontent.com https://*.gstatic.com https://*.google.com;",
  "font-src 'self' data:;",
  "connect-src 'self' https://www.googleapis.com https://accounts.google.com https://oauth2.googleapis.com;",
  "frame-src https://accounts.google.com;",
  "worker-src 'self' blob:;",
  'upgrade-insecure-requests;',
]);

const defaultSecurityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Referrer-Policy', value: 'same-origin' },
  {
    key: 'Permissions-Policy',
    value: 'accelerometer=(), autoplay=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()',
  },
];

function getGitVersion() {
  try {
    const hash = execSync('git rev-parse --short HEAD').toString().trim();
    const date = execSync('git log -1 --format=%cd --date=short').toString().trim();
    return { hash, date };
  } catch {
    return { hash: 'dev', date: '' };
  }
}

const gitVersion = getGitVersion();

const nextConfig = {
  env: {
    NEXT_PUBLIC_GIT_HASH: gitVersion.hash,
    NEXT_PUBLIC_GIT_DATE: gitVersion.date,
  },
  async headers() {
    return [
      {
        source: '/app',
        headers: [
          { key: 'Content-Security-Policy', value: secureAppCsp },
        ],
      },
      {
        source: '/app/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: secureAppCsp },
        ],
      },
      {
        source: '/:path*',
        headers: [
          ...defaultSecurityHeaders,
        ],
      },
    ];
  },
};

module.exports = nextConfig;
