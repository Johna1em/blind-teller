import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default defineConfig({
  // Relative paths: the site is plain files, and can be served from anywhere.
  base: './',
  // dcap-qvl expects Node's Buffer in the browser.
  plugins: [react(), nodePolyfills({ include: ['buffer'], globals: { Buffer: true } })],
  build: { target: 'es2022', sourcemap: false },
  test: { environment: 'node', include: ['src/**/*.test.ts'] },
} as never);
