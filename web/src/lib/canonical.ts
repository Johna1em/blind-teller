// The canonical strings, matching crates/teller-core byte for byte.
// `canonical.test.ts` holds this file to the vectors Rust generates.

export const DOMAIN = 'blind-teller/v1';

export interface Terms {
  contract: string;
  order_id: number;
  offer_id: number;
  seller: string;
  buyer: string;
  token: string;
  token_amount: string;
  currency: string;
  fiat_minor: number;
  rail: string;
  payee_commit: string;
  created_ms: number;
  deadline_ms: number;
}

export function termsLine(t: Terms): string {
  return [
    DOMAIN,
    'terms',
    t.contract,
    t.order_id,
    t.offer_id,
    t.seller,
    t.buyer,
    t.token,
    t.token_amount,
    t.currency,
    t.fiat_minor,
    t.rail,
    t.payee_commit,
    t.created_ms,
    t.deadline_ms,
  ].join('|');
}

export function verdictMessage(
  contract: string,
  orderId: number,
  termsHash: string,
  nullifier: string,
  modelKeys: string[],
  extractor: string,
  issuedMs: number,
): string {
  return `${DOMAIN}|verdict|paid|${contract}|${orderId}|${termsHash}|${nullifier}|${modelKeys.join(',')}|${extractor}|${issuedMs}`;
}

export const emailAad = (contract: string, orderId: number) => `${DOMAIN}|email|${contract}|${orderId}`;
export const payeeAad = (contract: string, seller: string) => `${DOMAIN}|payee|${contract}|${seller}`;
export const revealAad = (contract: string, orderId: number) => `${DOMAIN}|reveal|${contract}|${orderId}`;
