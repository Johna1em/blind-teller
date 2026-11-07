// Check a Blind Teller order yourself, from public data. No keys, no account, and
// nothing of ours in the path.
//
//   npx tsx scripts/verify.ts                    the latest settled order
//   npx tsx scripts/verify.ts 7                  a specific order
//   npx tsx scripts/verify.ts 7 <attestation>    also check the enclave run,
//                                                by attestation URL or call id
//
// Exit code 0 means every check passed.

import { accountInfo, view } from '../src/lib/near';
import { REGISTRY, TELLER } from '../src/config';
import { checkOrder, checkRun, activeWasm, type Check } from '../src/lib/runproof';
import { getConfig, getOrder, listModelKeys, listOrders } from '../src/lib/teller';

const print = (title: string, checks: Check[]) => {
  console.log(`\n${title}`);
  for (const c of checks) console.log(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.label}${c.detail ? `  (${c.detail})` : ''}`);
};

let [orderId, attestation] = process.argv.slice(2);
const config = await getConfig();
if (!orderId) {
  const from = Math.max(0, Number(config.orders) - 50);
  const recent = await listOrders(String(from));
  const settled = recent.filter(([, o]) => o.status === 'Settled').pop();
  if (!settled) throw new Error('no settled orders yet');
  orderId = settled[0];
}
const order = await getOrder(orderId);
if (!order) throw new Error(`no order ${orderId}`);

console.log(`Blind Teller order ${orderId} on ${TELLER}`);

const results: Check[] = [];
const orderChecks = await checkOrder(orderId, order, config);
print('The order', orderChecks);
results.push(...orderChecks);

if (attestation) {
  const runChecks = await checkRun(attestation);
  print('The enclave run', runChecks);
  results.push(...runChecks);
} else {
  console.log('\nThe enclave run\n  Skipped. Pass the attestation link the page shows after settling.');
}

const keys = await listModelKeys();
console.log(`\nProven model keys on ${REGISTRY}`);
for (const k of keys) console.log(`  ${k.model}  ${k.signing_key.slice(0, 16)}…  ${k.tcb_status}  until ${new Date(Number(k.expires_ms)).toISOString()}`);

const info = await accountInfo(TELLER);
console.log(`\nDeployment\n  Contract code hash  ${info?.code_hash}\n  Enclave build       ${await activeWasm()}\n  Dev reader allowed  ${config.allow_dev}`);
void view;

const failed = results.filter((c) => !c.ok);
console.log(failed.length ? `\n${failed.length} of ${results.length} checks failed.` : `\nAll ${results.length} checks passed.`);
process.exit(failed.length ? 1 : 0);
