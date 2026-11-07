// One-time setup: creates the sandbox bank's DKIM key.
//
// This is a published test key. Sandbox rails only accept `.example` domains,
// which no real bank can hold, and only move test tokens, so anyone may forge a
// sandbox email. That's by design: it lets judges try the attacks themselves.
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const publicPath = join(root, 'enclave', 'sandbox', 'sandbox-dkim-public.b64');
const privatePath = join(root, 'web', 'src', 'sandbox', 'sandbox-dkim-private.json');

if (existsSync(publicPath)) {
  console.log('sandbox key already exists');
  process.exit(0);
}
const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
mkdirSync(dirname(publicPath), { recursive: true });
mkdirSync(dirname(privatePath), { recursive: true });
writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'der' }).toString('base64') + '\n');
writeFileSync(
  privatePath,
  JSON.stringify(
    {
      note: 'Public sandbox test key. It can only sign for .example domains on sandbox rails.',
      pkcs8: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    },
    null,
    2,
  ) + '\n',
);
console.log('wrote', publicPath);
