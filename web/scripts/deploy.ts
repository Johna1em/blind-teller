// Deploys everything to NEAR testnet from a funded root account. Each step
// checks whether it's already done, so a run that stops can be run again.
//
//   npx tsx scripts/deploy.ts
//
// Needs: `blindteller.testnet` (or BT_ROOT) in the NEAR CLI's legacy keychain.

import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { accountInfo, base58Encode, send, TGAS, view } from '../src/lib/near';
import { concat, fromHex, hex, randomBytes, utf8 } from '../src/lib/bytes';
import { payeeAad } from '../src/lib/canonical';
import { seal } from '../src/lib/seal';
import { DEMO, OUTLAYER_API } from '../src/config';
import { callEnclave } from '../src/lib/teller';
import { BANKS } from '../src/sandbox/banks';
import { ed25519 } from '@noble/curves/ed25519.js';
import {
  BUYER_ACCOUNT, ENCLAVE_WASM, keystoreEncrypt, keystoreKey, log, NEAR, near, OUTLAYER, PROJECT, REGISTRY_ACCOUNT, REGISTRY_WASM, REPO,
  ROOT_ACCOUNT, SELLER_ACCOUNT, signerFor, TEE_VERIFIER, TELLER_ACCOUNT, TELLER_WASM, TOKEN,
} from './lib';

const STATE_PATH = join(REPO, '.deploy', 'state.json');
const state: Record<string, any> = existsSync(STATE_PATH) ? JSON.parse(readFileSync(STATE_PATH, 'utf8')) : {};
const save = () => {
  mkdirSync(join(REPO, '.deploy'), { recursive: true });
  writeFileSync(STATE_PATH, JSON.stringify(state, null, 2));
};

const root = () => signerFor(ROOT_ACCOUNT);

const exists = async (account: string) => (await accountInfo(account)) !== null;

async function subaccount(account: string, funding: string) {
  if (await exists(account)) return log('exists', account);
  near('account', 'create-account', 'fund-myself', account, `${funding} NEAR`, 'autogenerate-new-keypair', 'save-to-legacy-keychain', 'sign-as', ROOT_ACCOUNT, 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send');
  log('created', account);
}

/** True when the account has a contract on it. */
async function hasCode(account: string): Promise<boolean> {
  const info = await accountInfo(account);
  return !!info && info.code_hash !== '11111111111111111111111111111111';
}

function deploy(account: string, wasm: string, init: { method: string; args: object } | null) {
  const base = ['contract', 'deploy', account, 'use-file', wasm];
  const tail = ['network-config', 'testnet', 'sign-with-legacy-keychain', 'send'];
  if (init) near(...base, 'with-init-call', init.method, 'json-args', JSON.stringify(init.args), 'prepaid-gas', '100 Tgas', 'attached-deposit', '0 NEAR', ...tail);
  else near(...base, 'without-init-call', ...tail);
}

/** Upload a file to FastFS: the indexer reads it from the transaction's args. */
async function uploadWasm(bytes: Uint8Array, name: string): Promise<string> {
  const u32 = (n: number) => {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, true);
    return b;
  };
  const str = (s: string) => concat(u32(utf8(s).length), utf8(s));
  const args = concat(Uint8Array.of(0), str(name), Uint8Array.of(1), str('application/wasm'), u32(bytes.length), bytes);
  await send(root(), OUTLAYER, { method: '__fastdata_fastfs', args, gas: 1n }, { allowFailure: true });
  return `https://test.fastfs.io/${ROOT_ACCOUNT}/${OUTLAYER}/${name}`;
}

async function publishEnclave() {
  const wasm = new Uint8Array(readFileSync(ENCLAVE_WASM));
  const hash = createHash('sha256').update(wasm).digest('hex');
  const url = await uploadWasm(wasm, `${hash}.wasm`);
  log('uploaded enclave', hash, url);
  for (let i = 0; i < 40; i++) {
    const r = await fetch(url).catch(() => null);
    if (r?.ok) break;
    await new Promise((res) => setTimeout(res, 5000));
  }
  const source = { WasmUrl: { url, hash, build_target: 'wasm32-wasip2' } };
  const projectId = `${ROOT_ACCOUNT}/${PROJECT}`;
  const project = await view<any>(OUTLAYER, 'get_project', { project_id: projectId }).catch(() => null);
  if (!project) {
    await send(root(), OUTLAYER, { method: 'create_project', args: { name: PROJECT, source }, gas: 100n * TGAS, deposit: NEAR('0.5') });
    log('created project', projectId);
  } else if (state.enclaveHash !== hash) {
    await send(root(), OUTLAYER, { method: 'add_version', args: { project_name: PROJECT, source, set_active: true }, gas: 100n * TGAS, deposit: NEAR('0.1') });
    log('added version', hash);
  }
  state.enclaveHash = hash;
  state.enclaveUrl = url;
  save();
}

/** The row the enclave reads its NEAR AI key from. Starts empty. */
async function ensureSecretRow() {
  if (state.secretRow) return;
  const accessor = { Project: { project_id: `${ROOT_ACCOUNT}/${PROJECT}` } };
  const pub = await keystoreKey({ type: 'Project', project_id: `${ROOT_ACCOUNT}/${PROJECT}` }, ROOT_ACCOUNT, 'prod');
  const encrypted = keystoreEncrypt(pub, JSON.stringify({ NEAR_AI_API_KEY: '' }));
  await send(root(), OUTLAYER, { method: 'store_secrets', args: { accessor, profile: 'prod', encrypted_secrets_base64: encrypted, access: 'AllowAll', vault_id: null }, gas: 50n * TGAS, deposit: NEAR('0.1') });
  state.secretRow = true;
  save();
  log('stored the empty secret row');
}

async function ensurePaymentKey() {
  if (!state.paymentKey) {
    const nonce = await view<number>(OUTLAYER, 'get_next_payment_key_nonce', { account_id: ROOT_ACCOUNT });
    const key = hex(randomBytes(32));
    const blob = JSON.stringify({ key, initial_balance: '0', project_ids: [`${ROOT_ACCOUNT}/${PROJECT}`], max_per_call: '50000' });
    const pub = await keystoreKey({ type: 'System', PaymentKey: {} }, ROOT_ACCOUNT, String(nonce));
    await send(root(), OUTLAYER, {
      method: 'store_secrets',
      args: { accessor: { System: 'PaymentKey' }, profile: String(nonce), encrypted_secrets_base64: keystoreEncrypt(pub, blob), access: 'AllowAll', vault_id: null },
      gas: 50n * TGAS,
      deposit: NEAR('0.1'),
    });
    state.paymentKey = `${ROOT_ACCOUNT}:${nonce}:${key}`;
    state.paymentNonce = nonce;
    save();
    log('created payment key', nonce);
  }
  if (!state.paymentFunded) {
    await send(root(), TOKEN, { method: 'storage_deposit', args: { account_id: ROOT_ACCOUNT }, deposit: NEAR('0.0125'), gas: 30n * TGAS }, { allowFailure: true });
    await send(root(), TOKEN, { method: 'mint', args: { account_id: ROOT_ACCOUNT, amount: '100000000' }, gas: 30n * TGAS });
    await send(root(), TOKEN, {
      method: 'ft_transfer_call',
      args: { receiver_id: OUTLAYER, amount: '20000000', msg: JSON.stringify({ action: 'top_up_payment_key', nonce: state.paymentNonce }) },
      gas: 200n * TGAS,
      deposit: 1n,
    });
    state.paymentFunded = true;
    save();
    log('funded the payment key with test USDC');
  }
  DEMO.paymentKey = state.paymentKey;
}

async function deployTeller(keys: { seal_public: string; verdict_public: string }) {
  const init = {
    owner: ROOT_ACCOUNT,
    registry: REGISTRY_ACCOUNT,
    token: TOKEN,
    token_decimals: 6,
    verdict_key: keys.verdict_public,
    seal_key: keys.seal_public,
    allow_dev: process.env.BT_ALLOW_DEV !== 'false',
    fee_bps: 25,
  };
  if (await hasCode(TELLER_ACCOUNT)) {
    deploy(TELLER_ACCOUNT, TELLER_WASM, null);
    await send(root(), TELLER_ACCOUNT, { method: 'set_enclave_keys', args: { verdict_key: keys.verdict_public, seal_key: keys.seal_public }, gas: 30n * TGAS });
    log('updated teller');
  } else {
    deploy(TELLER_ACCOUNT, TELLER_WASM, { method: 'new', args: init });
    log('deployed teller');
  }
  await send(signerFor(TELLER_ACCOUNT), TOKEN, { method: 'storage_deposit', args: { account_id: TELLER_ACCOUNT }, deposit: NEAR('0.0125'), gas: 30n * TGAS }, { allowFailure: true });
}

const PAYEES: Record<string, { handle: string; name: string; account_tail: string }> = {
  meridian: { handle: 'asha.rao@meridian', name: 'Asha Rao', account_tail: '4021' },
  aurora: { handle: 'bruno.lima@aurora', name: 'Bruno Lima', account_tail: '7733' },
  rhein: { handle: 'DE89370400440532013000', name: 'Clara Vogt', account_tail: '3000' },
};
const RATES: Record<string, string> = { meridian: '8850', aurora: '540', rhein: '91' };

async function seedOffers(sealPublic: string) {
  const seller = signerFor(SELLER_ACCOUNT);
  await send(seller, TOKEN, { method: 'storage_deposit', args: { account_id: SELLER_ACCOUNT }, deposit: NEAR('0.0125'), gas: 30n * TGAS }, { allowFailure: true });
  await send(seller, TOKEN, { method: 'mint', args: { account_id: SELLER_ACCOUNT, amount: '30000000000' }, gas: 30n * TGAS });
  const existing = await view<[string, any][]>(TELLER_ACCOUNT, 'list_offers', { limit: 50 });
  for (const bank of BANKS) {
    if (existing.some(([, o]) => o.rail === bank.rail && o.sealed_payee)) continue;
    const sealed = seal(fromHex(sealPublic), utf8(JSON.stringify(PAYEES[bank.id])), payeeAad(TELLER_ACCOUNT, SELLER_ACCOUNT));
    const commit = createHash('sha256').update(sealed).digest('hex');
    const msg = JSON.stringify({
      rate_minor: RATES[bank.id],
      currency: bank.currency,
      rail: bank.rail,
      min_amount: '1000000',
      max_amount: '500000000',
      sealed_payee: sealed,
      payee_commit: commit,
      window_minutes: 30,
    });
    await send(seller, TOKEN, { method: 'ft_transfer_call', args: { receiver_id: TELLER_ACCOUNT, amount: '10000000000', msg }, gas: 100n * TGAS, deposit: 1n });
    log('offer listed for', bank.name);
  }
}

/** A key the page can use for the demo buyer: two methods, one contract, a capped gas allowance. */
async function demoBuyerKey() {
  await send(signerFor(BUYER_ACCOUNT), TOKEN, { method: 'storage_deposit', args: { account_id: BUYER_ACCOUNT }, deposit: NEAR('0.0125'), gas: 30n * TGAS }, { allowFailure: true });
  if (state.demoKey) return;
  const seed = randomBytes(32);
  const pub = ed25519.getPublicKey(seed);
  const secretKey = `ed25519:${base58Encode(concat(seed, pub))}`;
  const pk = `ed25519:${base58Encode(pub)}`;
  near('account', 'add-key', BUYER_ACCOUNT, 'grant-function-call-access', '--allowance', '0.3 NEAR', '--contract-account-id', TELLER_ACCOUNT, '--function-names', 'take_offer,settle', 'use-manually-provided-public-key', pk, 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send');
  state.demoKey = secretKey;
  save();
  log('added the demo key', pk);
}

function writeClientConfig() {
  const demo = { buyerAccount: BUYER_ACCOUNT, buyerKey: state.demoKey, paymentKey: state.paymentKey };
  mkdirSync(join(REPO, 'web/public'), { recursive: true });
  writeFileSync(join(REPO, 'web/public/demo.json'), JSON.stringify(demo, null, 2));
  const pub = {
    network: 'testnet',
    teller: TELLER_ACCOUNT,
    registry: REGISTRY_ACCOUNT,
    token: TOKEN,
    enclave: { project: `${ROOT_ACCOUNT}/${PROJECT}`, wasm_sha256: state.enclaveHash, url: state.enclaveUrl },
    keys: state.keys,
    tee_verifier: TEE_VERIFIER,
  };
  mkdirSync(join(REPO, 'deployments'), { recursive: true });
  writeFileSync(join(REPO, 'deployments/testnet.json'), JSON.stringify(pub, null, 2) + '\n');
}

async function main() {
  await subaccount(REGISTRY_ACCOUNT, '2.2');
  await subaccount(TELLER_ACCOUNT, '3');
  await subaccount(SELLER_ACCOUNT, '0.3');
  await subaccount(BUYER_ACCOUNT, '0.4');

  if (!(await hasCode(REGISTRY_ACCOUNT))) {
    deploy(REGISTRY_ACCOUNT, REGISTRY_WASM, { method: 'new', args: { verifier: TEE_VERIFIER } });
    log('deployed registry');
  }

  await publishEnclave();
  await ensureSecretRow();
  await ensurePaymentKey();

  let balance: unknown = null;
  for (let i = 0; i < 24; i++) {
    balance = await fetch(`${OUTLAYER_API}/public/payment-keys/${ROOT_ACCOUNT}/${state.paymentNonce}/balance`).then((r) => r.json()).catch(() => null);
    if ((balance as any)?.available ?? (balance as any)?.balance) break;
    await new Promise((res) => setTimeout(res, 5000));
  }
  log('payment key balance', JSON.stringify(balance));

  const { output: keys } = await callEnclave({ action: 'pubkey' });
  log('enclave keys', keys);
  state.keys = keys;
  save();

  await deployTeller(keys);
  await seedOffers(keys.seal_public);
  await demoBuyerKey();
  writeClientConfig();
  log('done. Next: npx tsx scripts/register-models.ts, then npx tsx scripts/e2e.ts');
}

main().catch((e) => {
  console.error('deploy failed:', e?.stderr?.toString?.() ?? e);
  process.exit(1);
});

