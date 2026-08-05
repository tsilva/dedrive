import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const projectRoot = path.dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  esbuild: {
    loader: 'jsx',
    jsx: 'automatic',
    include: /.*\.jsx?$/,
    exclude: [],
  },
  resolve: {
    alias: {
      '@': projectRoot,
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./tests/setup.js'],
    exclude: ['node_modules/**', '.next/**', '.pnpm-store/**'],
    clearMocks: true,
    restoreMocks: true,
  },
});
