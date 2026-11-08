import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

// Everything the page may talk to. The browser enforces this, so the site can't
// quietly call anything else, and it blocks the analytics script that the public
// FastFS gateway adds to the pages it serves.
const CONNECT = [
  "'self'",
  'https://test.fastfs.io',
  'https://test.rpc.fastnear.com',
  'https://rpc.testnet.fastnear.com',
  'https://rpc.testnet.near.org',
  'https://testnet-api.outlayer.ai',
  'https://cloud-api.near.ai',
  'https://cloud.near.ai',
  'https://nras.attestation.nvidia.com',
  'https://pccs.phala.network',
  'https://1click.chaindefuser.com',
];

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "img-src 'self' data:",
  `connect-src ${CONNECT.join(' ')}`,
  "base-uri 'none'",
  "form-action 'none'",
].join('; ');

export default defineConfig({
  // Relative paths: the site is plain files, and can be served from anywhere.
  base: './',
  plugins: [
    react(),
    // dcap-qvl expects Node's Buffer in the browser.
    nodePolyfills({ include: ['buffer'], globals: { Buffer: true } }),
    // Build only: the dev server needs inline scripts and a websocket.
    {
      name: 'content-security-policy',
      apply: 'build',
      transformIndexHtml: (html: string) => html.replace('<title>', `<meta http-equiv="Content-Security-Policy" content="${CSP}" />\n    <title>`),
    },
  ],
  build: { target: 'es2022', sourcemap: false },
  test: { environment: 'node', include: ['src/**/*.test.ts'] },
} as never);
