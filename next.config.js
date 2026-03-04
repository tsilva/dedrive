/** @type {import('next').NextConfig} */
const { execSync } = require('child_process');

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
        source: '/(.*)',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'X-Frame-Options', value: 'DENY' },
        ],
      },
    ];
  },
};

module.exports = nextConfig;
