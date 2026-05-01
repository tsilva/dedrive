/** @type {import('next').NextConfig} */
const { execSync } = require('child_process');

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
  turbopack: {
    root: __dirname,
  },
  async headers() {
    return [
      {
        source: '/brand/:path*',
        headers: [
          { key: 'Cache-Control', value: 'public, max-age=31536000, immutable' },
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
