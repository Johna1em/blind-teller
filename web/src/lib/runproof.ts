// Independent checks of a settled order and the enclave run behind it. The page
// and `scripts/verify.ts` share this file, so both ask the same questions. All
// of it reads public data: nothing here needs a key, an account or our word.

import { ed25519 } from '@noble/curves/ed25519.js';
import { getCollateralAndVerify } from '@phala/dcap-qvl';
import { ENCLAVE_OWNER, ENCLAVE_PROJECT, OUTLAYER_API, REGISTRY, TELLER } from '../config';
import { concat, fromBase64, fromHex, hex, sha256, sha256Hex, utf8 } from './bytes';
import { termsLine, verdictMessage } from './canonical';
import { view } from './near';
import { termsOf, type Config, type Order } from './teller';

export const OUTLAYER_CONTRACT = 'outlayer.testnet';
export const WORKER_REGISTER = 'worker.outlayer.testnet';
const PCCS = 'https://pccs.phala.network';

export interface Check {
  id: string;
  label: string;
  ok: boolean;
  detail: string;
}

interface Attestation {
  task_id: number;
  task_type: string;
  tdx_quote: string;
  worker_measurement: string;
  caller_account_id?: string;
  call_id?: string;
  build_target?: string;
  wasm_hash: string;
  executed_wasm_sha256: string;
  input_hash: string;
  output_hash: string;
  project_id?: string;
  repo_url?: string;
  commit_hash?: string;
  block_height?: number;
  secrets_ref?: string;
  attached_usd?: string;
  timestamp: number;
}

/** OutLayer's task hash (worker/src/tdx_attestation.rs), bound into the quote. */
async function taskHash(a: Attestation): Promise<string> {
  const i64 = (v: number | bigint) => {
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigInt64(0, BigInt(v), true);
    return b;
  };
  const parts: Uint8Array[] = [utf8(a.task_type), i64(a.task_id)];
  for (const k of ['repo_url', 'commit_hash', 'build_target', 'wasm_hash', 'input_hash', 'output_hash'] as const) {
    if (a[k]) parts.push(utf8(a[k]!));
  }
  if (a.block_height != null) parts.push(i64(a.block_height));
  for (const k of ['caller_account_id', 'project_id', 'secrets_ref'] as const) {
    if (a[k]) parts.push(utf8(a[k]!));
  }
  parts.push(i64(a.timestamp));
  if (a.attached_usd != null) parts.push(utf8(a.attached_usd));
  return hex(await sha256(concat(...parts)));
}

/** The enclave build the project is running, from OutLayer's contract. */
export async function activeWasm(): Promise<string> {
  const project = await view<{ active_version?: string }>(OUTLAYER_CONTRACT, 'get_project', { project_id: `${ENCLAVE_OWNER}/${ENCLAVE_PROJECT}` });
  return project?.active_version ?? '';
}

/** Check one enclave run from its public attestation. */
export async function checkRun(attestationUrl: string): Promise<Check[]> {
  const checks: Check[] = [];
  const add = (id: string, label: string, ok: boolean, detail = '') => checks.push({ id, label, ok, detail });
  const url = attestationUrl.startsWith('http') ? attestationUrl : `${OUTLAYER_API}/attestations/by-call/${attestationUrl}`;
  const response = await fetch(url);
  if (!response.ok) {
    add('attestation', 'OutLayer published an attestation for this run', false, `HTTP ${response.status}`);
    return checks;
  }
  const a: Attestation = await response.json();
  add('attestation', 'OutLayer published an attestation for this run', true, `Task ${a.task_id}`);

  const active = await activeWasm().catch(() => '');
  add('code', "The code that ran is the project's published release", !!active && a.executed_wasm_sha256 === active, a.executed_wasm_sha256.slice(0, 16) + '…');
  add('project', 'It ran as the Blind Teller project', a.project_id === `${ENCLAVE_OWNER}/${ENCLAVE_PROJECT}`, a.project_id ?? 'none');

  try {
    const verified = await getCollateralAndVerify(fromBase64(a.tdx_quote), PCCS);
    add('intel', "Intel's signature on the worker's quote verifies", verified.status === 'UpToDate', `TCB ${verified.status}`);
    const td = verified.report.asTd10();
    if (!td) {
      add('tdx', 'The quote is a TDX report', false);
      return checks;
    }
    add('debug', 'Debug mode is off', (td.tdAttributes[0] & 1) === 0, 'A debug TD could be read by its host');
    const measurements = { mrtd: hex(td.mrTd), rtmr0: hex(td.rtMr0), rtmr1: hex(td.rtMr1), rtmr2: hex(td.rtMr2), rtmr3: hex(td.rtMr3) };
    const approved = await view<boolean>(WORKER_REGISTER, 'is_measurements_approved', { measurements });
    add('build', 'The worker is an approved OutLayer build', approved && measurements.rtmr3 === a.worker_measurement, measurements.rtmr3.slice(0, 16) + '…');
    add('binding', 'The quote signs this exact run: code, input and output', (await taskHash(a)) === hex(td.reportData.subarray(0, 32)), `Input ${a.input_hash.slice(0, 12)}…, output ${a.output_hash.slice(0, 12)}…`);
  } catch (e) {
    add('intel', "Intel's signature on the worker's quote verifies", false, String((e as Error).message ?? e).slice(0, 140));
  }
  return checks;
}

/** Check a settled order from chain state alone. */
export async function checkOrder(orderId: string, order: Order, config: Config): Promise<Check[]> {
  const checks: Check[] = [];
  const add = (id: string, label: string, ok: boolean, detail = '') => checks.push({ id, label, ok, detail });
  add('settled', 'The order is settled', order.status === 'Settled', order.status);

  const terms = termsOf(orderId, order);
  const line = termsLine(terms);
  const onChain = await view<string>(TELLER, 'get_terms_line', { order_id: orderId });
  add('terms', 'The canonical terms match the contract', line === onChain);

  if (order.verdict_signature && order.nullifier && order.verdict_issued_ms && order.extractor) {
    const message = verdictMessage(TELLER, Number(orderId), await sha256Hex(line), order.nullifier, order.model_keys, order.extractor, Number(order.verdict_issued_ms));
    const valid = ed25519.verify(fromHex(order.verdict_signature), utf8(message), fromHex(config.verdict_key));
    add('signature', "The verdict carries the enclave's signature over these terms", valid, order.verdict_signature.slice(0, 16) + '…');
  } else {
    add('signature', "The verdict carries the enclave's signature over these terms", false, 'No verdict on this order');
  }
  add('nullifier', 'The email behind it can never be reused', !!order.nullifier && (await view<boolean>(TELLER, 'is_nullifier_used', { nullifier: order.nullifier })), (order.nullifier ?? '').slice(0, 16) + '…');

  if (order.extractor === 'near-ai') {
    add('models', 'The model keys are proven on NEAR', await view<boolean>(REGISTRY, 'are_attested', { keys: order.model_keys }), `${order.model_keys.length} keys`);
  } else {
    add('models', 'Read by the two private models', false, `This order used the labelled ${order.extractor ?? 'unknown'} reader`);
  }
  return checks;
}
