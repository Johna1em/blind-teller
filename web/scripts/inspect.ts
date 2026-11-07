// Send real .eml files to the enclave and print what it says. Each email is
// sealed here, so only the enclave can read it.
//
//   npx tsx scripts/inspect.ts [files...]
//
// With no files, it only checks the enclave can reach what its manifest allows.

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { loadDemo } from '../src/config';
import { callEnclave, getConfig, inspectEmail } from '../src/lib/teller';

await loadDemo();

const { output: probe } = await callEnclave({ action: 'probe' });
console.log('reachability from inside the enclave:', JSON.stringify(probe));

const config = await getConfig();
for (const file of process.argv.slice(2)) {
  const out = await inspectEmail(config.seal_key, new Uint8Array(readFileSync(file)));
  console.log(basename(file), out.ok ? `GENUINE, signed headers: ${out.signed_headers?.join(',')}` : `refused: ${out.code}`);
}
