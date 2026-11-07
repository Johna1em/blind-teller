// Publishes the built site to FastFS, so the page lives on NEAR too: the
// contract, the enclave build and the website all sit on the same chain, and no
// server of ours exists to take down or subpoena.
//
//   npm run build && npx tsx scripts/host.ts

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { concat, utf8 } from '../src/lib/bytes';
import { send } from '../src/lib/near';
import { log, REPO, ROOT_ACCOUNT, signerFor } from './lib';

const DIST = join(REPO, 'web/dist');
const MIME: Record<string, string> = {
  html: 'text/html; charset=utf-8',
  js: 'text/javascript; charset=utf-8',
  css: 'text/css; charset=utf-8',
  json: 'application/json',
  wasm: 'application/wasm',
};

const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const str = (s: string) => concat(u32(utf8(s).length), utf8(s));

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

const signer = signerFor(ROOT_ACCOUNT);
for (const file of walk(DIST)) {
  const path = relative(DIST, file).split(sep).join('/');
  const bytes = new Uint8Array(readFileSync(file));
  const mime = MIME[path.split('.').pop() ?? ''] ?? 'application/octet-stream';
  const args = concat(Uint8Array.of(0), str(path), Uint8Array.of(1), str(mime), u32(bytes.length), bytes);
  await send(signer, ROOT_ACCOUNT, { method: '__fastdata_fastfs', args, gas: 1n }, { allowFailure: true });
  log('uploaded', path, `${Math.round(bytes.length / 1024)} KB`);
}
log(`site: https://test.fastfs.io/${ROOT_ACCOUNT}/${ROOT_ACCOUNT}/index.html`);
