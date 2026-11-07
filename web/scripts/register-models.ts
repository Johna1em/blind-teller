// Proves each model's key on NEAR. Anyone can run this: it relays a fresh
// attestation to the registry, and `tee-verifier` checks Intel's signature chain.
//
//   npx tsx scripts/register-models.ts
//
// A key stays attested for 7 days. Run this again to refresh it.

import { getCollateral } from '@phala/dcap-qvl';
import { MODELS, NEAR_AI_API } from '../src/config';
import { concat, fromHex, toBase64, utf8 } from '../src/lib/bytes';
import { send, TGAS, view } from '../src/lib/near';
import { log, NEAR, REGISTRY_ACCOUNT, ROOT_ACCOUNT, signerFor } from './lib';

const PCCS = 'https://pccs.phala.network';

const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const vec = (b: Uint8Array) => concat(u32(b.length), b);
const str = (s: string) => vec(utf8(s));
const raw = (v: number[] | string): Uint8Array => (typeof v === 'string' ? fromHex(v.replace(/^0x/, '')) : Uint8Array.from(v));

async function attest(model: string, relayer: ReturnType<typeof signerFor>) {
  const { value: nonce } = await send(relayer, REGISTRY_ACCOUNT, { method: 'new_nonce', args: {}, gas: 30n * TGAS });
  const params = new URLSearchParams({ model, provider: 'near', signing_algo: 'ed25519', nonce: String(nonce) });
  const response = await fetch(`${NEAR_AI_API}/attestation/report?${params}`, { headers: { 'x-no-aliasing': 'true' } });
  if (!response.ok) throw new Error(`attestation for ${model}: ${response.status}`);
  const report = await response.json();
  const a = report.model_attestations[0];
  const quote = fromHex(a.intel_quote);

  const c = await getCollateral(`${PCCS}/sgx/certification/v4/`, Buffer.from(quote));
  // Borsh for `(QuoteBytes, Collateral)`, field order from near/mpc's
  // tee-verifier-interface. The PCK chain is inside the quote, so it's None.
  const args = concat(
    vec(quote),
    str(c.pck_crl_issuer_chain),
    vec(raw(c.root_ca_crl)),
    vec(raw(c.pck_crl)),
    str(c.tcb_info_issuer_chain),
    str(c.tcb_info),
    vec(raw(c.tcb_info_signature)),
    str(c.qe_identity_issuer_chain),
    str(c.qe_identity),
    vec(raw(c.qe_identity_signature)),
    Uint8Array.of(0),
  );

  const outcome = await send(relayer, REGISTRY_ACCOUNT, {
    method: 'submit',
    args: { model, signing_key: a.signing_public_key, nonce, verify_args: toBase64(args) },
    gas: 290n * TGAS,
    deposit: NEAR('0.01'),
  });
  const attested = await view<boolean>(REGISTRY_ACCOUNT, 'is_attested', { key: a.signing_public_key });
  log(model, attested ? 'attested on NEAR' : 'NOT attested', a.signing_public_key, outcome.hash);
  for (const line of outcome.logs) if (line.includes('not recorded')) log(line);
  return attested;
}

async function main() {
  const relayer = signerFor(process.env.BT_RELAYER ?? ROOT_ACCOUNT);
  const results = await Promise.all(MODELS.map(async (m, i) => {
    await new Promise((r) => setTimeout(r, i * 3000));
    return attest(m, relayer);
  }));
  if (!results.every(Boolean)) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
