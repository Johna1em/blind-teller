// Shared by the operator scripts. They run on the deployer's machine; nothing
// here ships to the browser.

import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { x25519 } from '@noble/curves/ed25519.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { OUTLAYER_API } from '../src/config';
import { concat, fromHex, randomBytes, toBase64, utf8 } from '../src/lib/bytes';
import type { Signer } from '../src/lib/near';

export const ROOT_ACCOUNT = process.env.BT_ROOT ?? 'blindteller.testnet';
export const TELLER_ACCOUNT = `teller.${ROOT_ACCOUNT}`;
export const REGISTRY_ACCOUNT = `models.${ROOT_ACCOUNT}`;
export const SELLER_ACCOUNT = `seller.${ROOT_ACCOUNT}`;
export const BUYER_ACCOUNT = `buyer.${ROOT_ACCOUNT}`;
export const OUTLAYER = 'outlayer.testnet';
export const PROJECT = 'teller';
export const TEE_VERIFIER = 'tee-verifier-2026-11-02.testnet';
export const TOKEN = 'usdc.fakes.testnet';

export const REPO = join(dirname(fileURLToPath(import.meta.url)), '../..');
const TARGET = process.env.CARGO_TARGET_DIR ?? join(REPO, 'target');
export const TELLER_WASM = join(TARGET, 'near/teller/teller.wasm');
export const REGISTRY_WASM = join(TARGET, 'near/model_registry/model_registry.wasm');
export const ENCLAVE_WASM = join(TARGET, 'wasm32-wasip2/release/blind-teller-enclave.wasm');

export const NEAR = (attached: string) => BigInt(Math.round(Number(attached) * 1e6)) * 10n ** 18n;

/** Read a key from the NEAR CLI's legacy keychain. */
export function signerFor(account: string): Signer {
  const path = join(homedir(), '.near-credentials', 'testnet', `${account}.json`);
  if (!existsSync(path)) throw new Error(`no key for ${account} in the NEAR CLI keychain`);
  const data = JSON.parse(readFileSync(path, 'utf8'));
  return { accountId: account, secretKey: data.private_key };
}

export function near(...args: string[]): string {
  return execFileSync(process.platform === 'win32' ? 'near.exe' : 'near', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 16 * 1024 * 1024 });
}

/**
 * ECIES for OutLayer's keystore, written from its documented format:
 * `0x01 | ephemeral(32) | nonce(12) | ciphertext+tag`, with X25519 and
 * HKDF-SHA256 (info `outlayer-keystore-v1`) into ChaCha20-Poly1305.
 */
export function keystoreEncrypt(pubkeyHex: string, plaintext: string): string {
  const recipient = fromHex(pubkeyHex);
  const ephemeral = randomBytes(32);
  const nonce = randomBytes(12);
  const shared = x25519.getSharedSecret(ephemeral, recipient);
  const key = hkdf(sha256, shared, undefined, utf8('outlayer-keystore-v1'), 32);
  const ct = chacha20poly1305(key, nonce).encrypt(utf8(plaintext));
  return toBase64(concat(Uint8Array.of(1), x25519.getPublicKey(ephemeral), nonce, ct));
}

/**
 * The keystore's key for one secret row. `secrets_json` stays `{}` on purpose:
 * the coordinator relays that field in the clear, and it plays no part in the
 * key, so the real secret never leaves this machine unencrypted.
 */
export async function keystoreKey(accessor: object, owner: string, profile: string): Promise<string> {
  const response = await fetch(`${OUTLAYER_API}/secrets/pubkey`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ accessor, owner, profile, secrets_json: '{}' }),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`keystore: ${text.slice(0, 200)}`);
  return JSON.parse(text).pubkey;
}

export const log = (...parts: unknown[]) => console.log('•', ...parts);

async function promptHidden(question: string): Promise<string> {
  process.stdout.write(question);
  const silent = new Writable({ write: (_chunk, _encoding, done) => done() });
  const rl = createInterface({ input: process.stdin, output: silent, terminal: true });
  const answer = await new Promise<string>((resolve) => rl.question('', resolve));
  rl.close();
  process.stdout.write('\n');
  return answer;
}

/** The NEAR AI key, from the environment, `web/.env` or a hidden prompt. Never logged. */
export async function readNearAiKey(): Promise<string> {
  try {
    process.loadEnvFile(join(REPO, 'web/.env'));
  } catch {
    // No .env file. That's fine: the prompt is the default.
  }
  const key = process.env.NEAR_AI_API_KEY;
  if (key) return key.trim();
  return process.stdin.isTTY ? (await promptHidden('Paste your NEAR AI key, then press Enter (nothing will show): ')).trim() : '';
}
