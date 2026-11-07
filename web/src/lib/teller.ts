// Everything the page does, with no server in the path: the browser talks to the
// NEAR contract and, over HTTPS, directly to the enclave.

import { DEMO, ENCLAVE_OWNER, ENCLAVE_PROJECT, MODELS, OUTLAYER_API, REGISTRY, TELLER, TOKEN } from '../config';
import { fromHex, hex, randomBytes, sha256Hex, utf8 } from './bytes';
import { emailAad, revealAad, type Terms } from './canonical';
import { send, TGAS, view, type Outcome, type Signer } from './near';
import { open, publicOf, seal } from './seal';

export type OrderStatus = 'Open' | 'Settling' | 'Settled' | 'PayoutFailed' | 'Cancelled' | 'Expired';

export interface Offer {
  seller: string;
  available: string;
  locked: string;
  rate_minor: string;
  currency: string;
  rail: string;
  min_amount: string;
  max_amount: string;
  sealed_payee: string;
  payee_commit: string;
  buyer_bond: string;
  window_minutes: number;
  open_ids: string[];
  created_ms: string;
}

export interface Order {
  offer_id: string;
  seller: string;
  buyer: string;
  buyer_pubkey: string;
  token_amount: string;
  currency: string;
  fiat_minor: string;
  rail: string;
  payee_commit: string;
  bond: string;
  created_ms: string;
  deadline_ms: string;
  status: OrderStatus;
  nullifier: string | null;
  extractor: string | null;
  model_keys: string[];
  verdict_signature: string | null;
  verdict_issued_ms: string | null;
  settled_ms: string | null;
}

export interface Config {
  owner: string;
  registry: string;
  token: string;
  token_decimals: number;
  verdict_key: string;
  seal_key: string;
  allow_dev: boolean;
  fee_bps: number;
  fees_accrued: string;
  offers: string;
  orders: string;
  settled: string;
  volume: string;
}

export interface Verdict {
  nullifier: string;
  model_keys: string[];
  extractor: string;
  issued_ms: string;
  signature: string;
}

export interface TraceStep {
  step: string;
  ok: boolean;
  code?: string;
}

export interface ProofResult {
  ok: boolean;
  code?: string;
  verdict?: Verdict;
  trace?: TraceStep[];
  attestationUrl?: string;
  callId?: string;
  ms?: number;
}

export interface ModelKey {
  model: string;
  signing_key: string;
  compose_hash: string;
  mr_td: string;
  rtmr3: string;
  tcb_status: string;
  relayer: string;
  verified_ms: string;
  expires_ms: string;
}

export const demoBuyer = (): Signer => ({ accountId: DEMO.buyerAccount, secretKey: DEMO.buyerKey });

export const getConfig = () => view<Config>(TELLER, 'get_config');
export const listOffers = () => view<[string, Offer][]>(TELLER, 'list_offers', { limit: 50 });
export const getOffer = (id: string) => view<Offer | null>(TELLER, 'get_offer', { offer_id: id });
export const getOrder = (id: string) => view<Order | null>(TELLER, 'get_order', { order_id: id });
export const listOrders = (from?: string) => view<[string, Order][]>(TELLER, 'list_orders', { from, limit: 50 });
export const listModelKeys = () => view<ModelKey[]>(REGISTRY, 'list_keys', { limit: 50 });

/** A key for this one order. The seller's details are sealed to it. */
export function newBuyerKey(): { secret: string; public: string } {
  const secret = randomBytes(32);
  return { secret: hex(secret), public: hex(publicOf(secret)) };
}

export async function takeOffer(signer: Signer, offerId: string, amount: string, buyerPublic: string): Promise<{ orderId: string; hash: string }> {
  const out = await send(signer, TELLER, {
    method: 'take_offer',
    args: { offer_id: offerId, amount, buyer_pubkey: buyerPublic },
    gas: 50n * TGAS,
  });
  return { orderId: String(out.value), hash: out.hash };
}

export interface EnclaveCall {
  output: any;
  callId?: string;
  attestationUrl?: string;
  ms: number;
}

/** Call the enclave directly. The request carries only ciphertext and terms. */
export async function callEnclave(input: object): Promise<EnclaveCall> {
  const started = performance.now();
  const response = await fetch(`${OUTLAYER_API}/call/${ENCLAVE_OWNER}/${ENCLAVE_PROJECT}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Payment-Key': DEMO.paymentKey },
    body: JSON.stringify({ input, resource_limits: { max_execution_seconds: 170 } }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error ?? body.message ?? `enclave call failed (${response.status})`);
  if (body.status === 'failed' || body.error) throw new Error(String(body.error ?? 'the enclave run failed'));
  const output = typeof body.output === 'string' ? JSON.parse(body.output) : body.output;
  const attestationUrl = body.attestation_url ? new URL(body.attestation_url, OUTLAYER_API).href : undefined;
  return { output, callId: body.call_id, attestationUrl, ms: performance.now() - started };
}

export interface EnclaveKeys {
  seal_public: string;
  verdict_public: string;
  policy_hash: string;
  signature: string;
  extractor: string;
  models: string[];
  version: string;
}

export async function enclaveKeys(): Promise<EnclaveKeys> {
  return (await callEnclave({ action: 'pubkey' })).output;
}

export interface Payee {
  handle: string;
  name: string;
  account_tail?: string;
}

/** Ask the enclave for the seller's details, sealed to this browser's key. */
export async function revealPayee(orderId: string, buyerSecret: string): Promise<Payee> {
  const { output } = await callEnclave({ action: 'reveal', contract: TELLER, order_id: Number(orderId) });
  if (!output.ok) throw new Error(output.code ?? 'reveal failed');
  const plain = open(fromHex(buyerSecret), output.sealed, revealAad(TELLER, Number(orderId)));
  return JSON.parse(new TextDecoder().decode(plain));
}

export function termsOf(orderId: string, o: Order): Terms {
  return {
    contract: TELLER,
    order_id: Number(orderId),
    offer_id: Number(o.offer_id),
    seller: o.seller,
    buyer: o.buyer,
    token: TOKEN,
    token_amount: o.token_amount,
    currency: o.currency,
    fiat_minor: Number(o.fiat_minor),
    rail: o.rail,
    payee_commit: o.payee_commit,
    created_ms: Number(o.created_ms),
    deadline_ms: Number(o.deadline_ms),
  };
}

/** The registered key for each model, read from the on-chain registry. */
export async function modelRefs(): Promise<{ id: string; key: string }[]> {
  const keys = await listModelKeys();
  return MODELS.map((id) => {
    const found = keys.find((k) => k.model === id && Number(k.expires_ms) > Date.now());
    if (!found) throw new Error(`${id} has no live key in the registry`);
    return { id, key: found.signing_key };
  });
}

/** Seal the email in this browser and hand it to the enclave. */
export async function prove(sealKey: string, terms: Terms, sealedPayee: string, email: string, dev: boolean): Promise<ProofResult> {
  const sealedEmail = seal(fromHex(sealKey), utf8(email), emailAad(terms.contract, terms.order_id));
  const models = dev ? [] : await modelRefs();
  const call = await callEnclave({ action: 'prove', terms, sealed_email: sealedEmail, sealed_payee: sealedPayee, models, dev });
  return { ...call.output, attestationUrl: call.attestationUrl, callId: call.callId, ms: call.ms };
}

export async function settle(signer: Signer, orderId: string, verdict: Verdict): Promise<Outcome> {
  return send(signer, TELLER, { method: 'settle', args: { order_id: orderId, verdict }, gas: 150n * TGAS });
}

export const commitOf = (sealed: string) => sha256Hex(sealed);

/** Human text for each reason the enclave can refuse. */
export const REFUSALS: Record<string, string> = {
  bad_ciphertext: "The email was sealed for a different order, so the enclave couldn't open it.",
  bad_terms: "The order terms didn't parse.",
  unknown_rail: "This enclave doesn't serve that payment rail.",
  payee_commit_mismatch: "The seller's details don't match the order's commitment.",
  payee_unreadable: "The seller's details couldn't be opened.",
  email_too_large: 'That file is too large to be a bank alert.',
  dkim_missing: 'This email has no DKIM signature, so nothing proves who sent it.',
  dkim_malformed: "The email's signature is malformed.",
  dkim_algorithm: 'The email uses a signature algorithm that is not accepted.',
  dkim_length_tag: 'The signature only covers part of the body, so extra text could be hiding below it.',
  dkim_from_unsigned: "The signature doesn't cover the From header.",
  dkim_duplicate_header: 'A header appears twice, which is how a forged sender gets shown to readers.',
  dkim_body_hash: "The body changed after the bank signed it. The bank's signature no longer matches.",
  dkim_key_missing: "The bank's public key couldn't be found.",
  dkim_key_revoked: 'The bank has revoked this signing key.',
  dkim_key_weak: "The bank's signing key is too short to trust.",
  dkim_signature: "The signature wasn't made by this bank's key.",
  dkim_alignment: "The email isn't signed by a bank this payment rail accepts.",
  issuer_not_allowed: "This bank isn't on this rail's list.",
  email_outside_order_window: 'The email is from before this order existed.',
  email_undated: 'The email carries no signed date.',
  model_key_not_configured: 'The enclave has no NEAR AI key yet.',
  model_set_invalid: "The request named models this enclave doesn't accept.",
  model_error: 'The model returned an error.',
  model_unreachable: "The model couldn't be reached.",
  model_reply_invalid: "The model's reply wasn't valid JSON.",
  model_signature_not_tee: 'The reply was signed by the gateway, not the model.',
  model_signature_mismatch: "The model's signature doesn't cover this exact exchange.",
  model_signature_invalid: "The model's signature is invalid.",
  injection_suspected: 'The email tries to instruct the AI. Refused, and no rule was bent.',
  models_disagree: "The two models didn't read the same facts.",
  status_not_success: "The bank says this payment didn't go through.",
  not_a_debit: "This email isn't a debit from the payer's account.",
  currency_mismatch: 'The payment is in the wrong currency.',
  amount_mismatch: "The amount paid isn't the exact amount this order asked for.",
  amount_not_in_source: "The amount isn't in the bank's own text, only in text the payer wrote.",
  unexplained_amount: 'The email shows a different amount that nothing explains.',
  recipient_mismatch: 'This payment went to someone other than the seller.',
  dev_rules_unknown_format: "The sandbox reader doesn't know this email format.",
  dev_extractor_not_in_this_build: 'The release enclave has no sandbox reader.',
};

export const refusal = (code?: string) => (code && REFUSALS[code]) ?? code ?? 'The enclave refused.';
