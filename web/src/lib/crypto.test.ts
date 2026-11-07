import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { BANKS, issueEmail } from '../sandbox/banks';
import { fromHex, sha256Hex, utf8 } from './bytes';
import { emailAad, payeeAad, revealAad, termsLine, verdictMessage, type Terms } from './canonical';
import { open, publicOf, seal } from './seal';

const fixture = (name: string) => JSON.parse(readFileSync(join(__dirname, '../../../fixtures', name), 'utf8'));

describe('canonical strings match Rust', () => {
  const v = fixture('canonical-vectors.json');
  const terms = v.terms as Terms;

  it('terms line', () => expect(termsLine(terms)).toBe(v.terms_line));
  it('terms hash', async () => expect(await sha256Hex(termsLine(terms))).toBe(v.terms_hash));
  it('verdict message', () => {
    expect(verdictMessage(terms.contract, terms.order_id, v.terms_hash, v.nullifier, v.model_keys, 'near-ai', v.issued_ms)).toBe(v.verdict_message);
  });
  it('associated data', () => {
    expect(emailAad(terms.contract, terms.order_id)).toBe(v.email_aad);
    expect(payeeAad(terms.contract, terms.seller)).toBe(v.payee_aad);
    expect(revealAad(terms.contract, terms.order_id)).toBe(v.reveal_aad);
  });
});

describe('sealing matches Rust', () => {
  const v = fixture('seal-vector.json');

  it('produces the same bytes', () => {
    expect(seal(fromHex(v.recipient_public), utf8(v.plaintext), v.aad, fromHex(v.entropy))).toBe(v.sealed);
  });
  it('opens what Rust sealed', () => {
    expect(new TextDecoder().decode(open(fromHex(v.recipient_secret), v.sealed, v.aad))).toBe(v.plaintext);
  });
  it('derives the same public key', () => {
    expect(Buffer.from(publicOf(fromHex(v.recipient_secret))).toString('hex')).toBe(v.recipient_public);
  });
  it('refuses the wrong purpose', () => {
    expect(() => open(fromHex(v.recipient_secret), v.sealed, 'other')).toThrow();
  });
});

describe('sandbox banks', () => {
  it('issue signed mail in three formats', async () => {
    for (const bank of BANKS) {
      const mail = await issueEmail(bank, { amountMinor: 885_037, payee: 'asha.rao@meridian', note: 'order 1', payerEmail: 'b@mail.example', balanceMinor: 4_231_005, at: 1_794_045_660 });
      expect(mail.startsWith('DKIM-Signature: v=1;')).toBe(true);
      expect(mail).toContain(`d=${bank.domain}`);
      expect(mail).toContain(bank.format(885_037));
    }
  });
  it('formats each locale', () => {
    expect(BANKS[0].format(10_885_037)).toBe('Rs. 1,08,850.37');
    expect(BANKS[1].format(885_037)).toBe('R$ 8.850,37');
    expect(BANKS[2].format(885_037)).toBe('8.850,37 EUR');
  });
});
