// A small NEAR client: read views, and sign function calls with a local key.
// It holds no server state, and it's short enough to read.

import { ed25519 } from '@noble/curves/ed25519.js';
import { RPC_URLS } from '../config';
import { concat, fromBase64, sha256, toBase64, utf8 } from './bytes';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = ALPHABET.indexOf(c);
    if (i < 0) throw new Error('bad base58');
    n = n * 58n + BigInt(i);
  }
  const out: number[] = [];
  while (n > 0n) {
    out.unshift(Number(n % 256n));
    n /= 256n;
  }
  for (const c of s) {
    if (c !== '1') break;
    out.unshift(0);
  }
  return Uint8Array.from(out);
}

export function base58Encode(b: Uint8Array): string {
  let n = b.reduce((acc, x) => acc * 256n + BigInt(x), 0n);
  let out = '';
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const x of b) {
    if (x !== 0) break;
    out = `1${out}`;
  }
  return out;
}

async function rpc(method: string, params: unknown): Promise<any> {
  let last: unknown;
  for (let attempt = 0; attempt < RPC_URLS.length * 2; attempt++) {
    const url = RPC_URLS[attempt % RPC_URLS.length];
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 'blind-teller', method, params }),
      });
      if (!response.ok) throw new Error(`rpc ${response.status}`);
      const json = await response.json();
      if (json.error) throw Object.assign(new Error(json.error.data ?? json.error.message ?? 'rpc error'), { rpc: json.error });
      return json.result;
    } catch (e) {
      last = e;
      if ((e as { rpc?: unknown }).rpc) throw e;
      await new Promise((r) => setTimeout(r, 400));
    }
  }
  throw last;
}

export async function view<T>(account: string, method: string, args: object = {}): Promise<T> {
  const result = await rpc('query', {
    request_type: 'call_function',
    finality: 'optimistic',
    account_id: account,
    method_name: method,
    args_base64: toBase64(utf8(JSON.stringify(args))),
  });
  if (result.error) throw new Error(result.error);
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(result.result)));
}

// ---- borsh, for the one transaction shape this app sends ----

const u32 = (n: number) => {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
};
const u64 = (n: bigint) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
};
const u128 = (n: bigint) => concat(u64(n & 0xffff_ffff_ffff_ffffn), u64(n >> 64n));
const bytes = (b: Uint8Array) => concat(u32(b.length), b);
const str = (s: string) => bytes(utf8(s));
const publicKey = (k: Uint8Array) => concat(Uint8Array.of(0), k);

export interface Call {
  method: string;
  /** JSON args, or raw bytes for a method that takes Borsh. */
  args: object | Uint8Array;
  gas?: bigint;
  deposit?: bigint;
}

export interface Signer {
  accountId: string;
  /** `ed25519:` then base58 of seed + public key. */
  secretKey: string;
}

export interface Outcome {
  hash: string;
  value: unknown;
  logs: string[];
}

const TGAS = 1_000_000_000_000n;

/** Sign and send one function call, and wait for it to execute. */
export async function send(signer: Signer, receiver: string, call: Call, opts: { allowFailure?: boolean } = {}): Promise<Outcome> {
  const raw = base58Decode(signer.secretKey.replace(/^ed25519:/, ''));
  const seed = raw.subarray(0, 32);
  const pk = ed25519.getPublicKey(seed);
  const pkText = `ed25519:${base58Encode(pk)}`;
  const key = await rpc('query', { request_type: 'view_access_key', finality: 'optimistic', account_id: signer.accountId, public_key: pkText });
  const block = await rpc('block', { finality: 'final' });

  const action = concat(
    Uint8Array.of(2),
    str(call.method),
    bytes(call.args instanceof Uint8Array ? call.args : utf8(JSON.stringify(call.args))),
    u64(call.gas ?? 100n * TGAS),
    u128(call.deposit ?? 0n),
  );
  const tx = concat(
    str(signer.accountId),
    publicKey(pk),
    u64(BigInt(key.nonce) + 1n),
    str(receiver),
    base58Decode(block.header.hash),
    u32(1),
    action,
  );
  const hash = await sha256(tx);
  const signature = ed25519.sign(hash, seed);
  const signed = concat(tx, Uint8Array.of(0), signature);

  const result = await rpc('send_tx', { signed_tx_base64: toBase64(signed), wait_until: 'EXECUTED_OPTIMISTIC' });
  const failure = result.status?.Failure ?? result.receipts_outcome?.map((o: any) => o.outcome.status?.Failure).find(Boolean);
  if (failure && !opts.allowFailure) throw new Error(describeFailure(failure));
  const last = result.status?.SuccessValue;
  let value: unknown = null;
  if (typeof last === 'string' && last.length) {
    try {
      value = JSON.parse(new TextDecoder().decode(fromBase64(last)));
    } catch {
      value = last;
    }
  }
  const logs: string[] = (result.receipts_outcome ?? []).flatMap((o: any) => o.outcome.logs ?? []);
  return { hash: result.transaction?.hash ?? base58Encode(hash), value, logs };
}

/** Pull the contract's own words out of a failed receipt. */
function describeFailure(failure: any): string {
  const text = JSON.stringify(failure);
  const panic = text.match(/Smart contract panicked: ([^"\\]+)/);
  return panic ? panic[1] : text.slice(0, 200);
}

export { TGAS };
