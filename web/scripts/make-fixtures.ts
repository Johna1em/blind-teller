// Writes the fictional sample emails. The browser's sandbox bank and these files
// come from one implementation, and `enclave/tests/fixtures.rs` verifies them
// with the Rust DKIM code against the published sandbox key.

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { BANKS, issueEmail } from '../src/sandbox/banks';

const out = join(dirname(fileURLToPath(import.meta.url)), '../../fixtures/sandbox');
mkdirSync(out, { recursive: true });

for (const bank of BANKS) {
  const mail = await issueEmail(bank, {
    amountMinor: 885_037,
    payee: 'asha.rao@meridian',
    note: 'order 3',
    payerEmail: 'buyer@mail.example',
    balanceMinor: 4_231_005,
    at: 1_794_045_660,
  });
  writeFileSync(join(out, `${bank.id}.eml`), mail, 'utf8');
  console.log('wrote', `${bank.id}.eml`);
}
