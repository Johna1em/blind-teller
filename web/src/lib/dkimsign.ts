// DKIM signing for the sandbox bank only. The real path never signs anything:
// real emails come signed by real banks. This runs in the browser and in Node,
// so the fixtures and the live sandbox share one implementation, and
// `enclave/tests/fixtures.rs` holds it to the Rust verifier.

import { fromBase64, sha256, toBase64, utf8 } from './bytes';

export const SANDBOX_SELECTOR = 'sb1';
export const SANDBOX_COVERED = ['from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type'];

function compress(line: string): string {
  return line.replace(/[ \t]+/g, ' ').replace(/ $/, '');
}

function canonBody(body: string): string {
  const lines = body.replace(/\r\n$/, '').split('\r\n').map(compress);
  while (lines.length && lines[lines.length - 1] === '') lines.pop();
  return lines.length ? lines.join('\r\n') + '\r\n' : '';
}

function canonHeader(raw: string): string {
  const colon = raw.indexOf(':');
  const name = raw.slice(0, colon).replace(/[ \t]/g, '').toLowerCase();
  const value = compress(raw.slice(colon + 1).replace(/\r\n/g, '')).replace(/^ /, '');
  return `${name}:${value}\r\n`;
}

function headersOf(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split('\r\n')) {
    if (/^[ \t]/.test(line) && out.length) out[out.length - 1] += `\r\n${line}`;
    else if (line) out.push(line);
  }
  return out;
}

export interface SignOptions {
  domain: string;
  selector?: string;
  timestamp: number;
  pkcs8: string;
  covered?: string[];
}

/** Sign a CRLF message with relaxed/relaxed canonicalization. */
export async function dkimSign(message: string, opts: SignOptions): Promise<string> {
  const split = message.indexOf('\r\n\r\n');
  const head = message.slice(0, split);
  const body = message.slice(split + 4);
  const selector = opts.selector ?? SANDBOX_SELECTOR;
  const covered = opts.covered ?? SANDBOX_COVERED;
  const bh = toBase64(await sha256(utf8(canonBody(body))));
  const prefix = `DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=${opts.domain}; s=${selector}; t=${opts.timestamp}; h=${covered.join(':')}; bh=${bh}; b=`;

  const headers = headersOf(head);
  const taken = new Set<number>();
  let signed = '';
  for (const name of covered) {
    for (let i = headers.length - 1; i >= 0; i--) {
      if (!taken.has(i) && headers[i].slice(0, headers[i].indexOf(':')).trim().toLowerCase() === name) {
        taken.add(i);
        signed += canonHeader(headers[i]);
        break;
      }
    }
  }
  signed += canonHeader(prefix).replace(/\r\n$/, '');

  const key = await crypto.subtle.importKey('pkcs8', fromBase64(opts.pkcs8) as BufferSource, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
  const signature = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, utf8(signed) as BufferSource));
  return `${prefix}${toBase64(signature)}\r\n${message}`;
}
