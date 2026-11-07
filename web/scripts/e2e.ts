// The whole flow against live testnet and the real enclave, with the same code
// the browser runs. Every step is real: an order locks real test tokens, the
// enclave runs in hardware, and the contract pays.
//
//   npx tsx scripts/e2e.ts
//
// Set BT_MODELS=1 once the enclave has its NEAR AI key.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DEMO, TELLER } from '../src/config';
import { ATTACKS, randomOrderId } from '../src/lib/attack';
import { getConfig, getOrder, listOffers, newBuyerKey, prove, revealPayee, settle, takeOffer, termsOf, type Offer } from '../src/lib/teller';
import { BANKS, bankForRail, issueEmail } from '../src/sandbox/banks';
import { BUYER_ACCOUNT, log, REPO } from './lib';

const demo = JSON.parse(readFileSync(join(REPO, 'web/public/demo.json'), 'utf8'));
Object.assign(DEMO, demo);
const useDev = !process.env.BT_MODELS;

async function happyPath(offerId: string, offer: Offer) {
  const bank = bankForRail(offer.rail);
  const config = await getConfig();
  const signer = { accountId: BUYER_ACCOUNT, secretKey: DEMO.buyerKey };

  const key = newBuyerKey();
  const { orderId, hash } = await takeOffer(signer, offerId, '10000000', key.public);
  log(bank.name, 'order', orderId, 'locked', hash);

  const payee = await revealPayee(orderId, key.secret);
  log('payee revealed to the buyer only:', payee.name);

  const order = (await getOrder(orderId))!;
  const mail = await issueEmail(bank, {
    amountMinor: Number(order.fiat_minor),
    payee: payee.handle,
    note: `order ${orderId}`,
    payerEmail: 'you@mail.example',
    balanceMinor: 4_231_005,
    at: Math.floor(Date.now() / 1000),
  });
  const result = await prove(config.seal_key, termsOf(orderId, order), offer.sealed_payee, mail, useDev);
  log('enclave answered in', Math.round(result.ms ?? 0), 'ms:', (result.trace ?? []).map((t) => `${t.step}${t.ok ? '' : ` FAILED(${t.code})`}`).join(' '));
  if (!result.ok || !result.verdict) throw new Error(`refused: ${result.code}`);

  const tx = await settle(signer, orderId, result.verdict);
  const settled = (await getOrder(orderId))!;
  log('settled', tx.hash, settled.status, settled.extractor, result.attestationUrl ?? '');
  if (settled.status !== 'Settled') throw new Error(`order is ${settled.status}`);

  let replayed = false;
  try {
    await settle(signer, orderId, result.verdict);
    replayed = true;
  } catch (e) {
    log('replaying the verdict is refused:', (e as Error).message);
  }
  if (replayed) throw new Error('a replay was accepted');
}

async function attacks(offerId: string, offer: Offer) {
  const config = await getConfig();
  let refused = 0;
  for (const attack of ATTACKS) {
    const now = Date.now();
    const terms = {
      contract: TELLER, order_id: randomOrderId(), offer_id: Number(offerId), seller: offer.seller, buyer: BUYER_ACCOUNT,
      token: config.token, token_amount: '100000000', currency: offer.currency, fiat_minor: 885_037, rail: offer.rail,
      payee_commit: offer.payee_commit, created_ms: now - 60_000, deadline_ms: now + 1_800_000,
    };
    const mail = await attack.build(885_037, 'asha.rao@meridian', Math.floor(now / 1000));
    const result = await prove(config.seal_key, terms, offer.sealed_payee, mail, useDev);
    const pass = !result.ok && result.code === attack.expect;
    log(pass ? 'refused' : 'UNEXPECTED', attack.title, '->', result.code ?? 'accepted');
    if (pass) refused++;
  }
  log(`${refused} of ${ATTACKS.length} attacks refused for the expected reason`);
  if (refused !== ATTACKS.length) throw new Error('an attack was not refused as expected');
}

const offers = await listOffers();
for (const bank of BANKS) {
  const hit = offers.find(([, o]) => o.rail === bank.rail);
  if (!hit) throw new Error(`no offer for ${bank.rail}`);
  await happyPath(hit[0], hit[1]);
}
const meridian = offers.find(([, o]) => bankForRail(o.rail).id === 'meridian')!;
await attacks(meridian[0], meridian[1]);
log('end to end: all green');
