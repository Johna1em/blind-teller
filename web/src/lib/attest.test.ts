import { beforeEach, describe, expect, it, vi } from 'vitest';
import { concat, fromHex, hex, sha256, utf8 } from './bytes';

// Intel's verifier needs a real quote, so it's replaced by one that reads back the
// fields of a report built below. Everything after it is the real panel logic.
const quote = vi.hoisted((): Record<string, Uint8Array> => ({}));
vi.mock('@phala/dcap-qvl', () => ({
  getCollateralAndVerify: async () => ({ status: 'UpToDate', report: { type: 'td10', data: quote } }),
}));
vi.mock('./near', () => ({ view: async () => ({ expires_ms: String(Date.now() + 60_000) }) }));

const { checkGateway, checkModel } = await import('./attest');

const MODEL = 'z-ai/glm-5.3-flash';
const KEY = 'ab'.repeat(32);
const COMPOSE = '{"name":"compose"}';
const EVENT = { imr: 3, event_type: 1, event: 'app-id', event_payload: 'aa', digest: '' };

async function sha384(b: Uint8Array) {
  return new Uint8Array(await crypto.subtle.digest('SHA-384', b as BufferSource));
}

async function eventDigest() {
  return sha384(concat(Uint8Array.of(1, 0, 0, 0), utf8(':app-id:'), fromHex('aa')));
}

/** Answers like NEAR AI and NVIDIA, for whichever nonce the panel sends. */
function serve(tamper: (report: any, nonce: string) => void = () => undefined) {
  vi.stubGlobal('fetch', async (url: string) => {
    if (url.includes('/model/')) return Response.json({ metadata: { providerType: 'vllm', attestationSupported: true, isReady: true } });
    if (url.includes('/attestation/report')) {
      const nonce = new URL(url).searchParams.get('nonce')!;
      quote.reportData = concat(fromHex(KEY), fromHex(nonce));
      quote.mrConfigId = concat(Uint8Array.of(1), await sha256(utf8(COMPOSE)), new Uint8Array(15));
      quote.rtMr3 = await sha384(concat(new Uint8Array(48), await eventDigest()));
      quote.tdAttributes = new Uint8Array(8);
      const report: any = {
        signing_address: KEY,
        signing_public_key: KEY,
        signing_algo: 'ed25519',
        request_nonce: nonce,
        intel_quote: 'aa',
        event_log: JSON.stringify([EVENT]),
        info: { tcb_info: { app_compose: COMPOSE } },
        nvidia_payload: JSON.stringify({ nonce, evidence_list: [{}] }),
      };
      tamper(report, nonce);
      return Response.json({ gateway_attestation: report, model_attestations: report.none ? [] : [report] });
    }
    if (url.includes('jwks')) return Response.json({ keys: [] });
    return new Response('not found', { status: 404 });
  });
}

const failed = (checks: { id: string; ok: boolean }[]) => checks.filter((c) => !c.ok).map((c) => c.id.replace(/^0-/, ''));

describe('the Verified panel', () => {
  beforeEach(() => vi.unstubAllGlobals());

  it('passes a clean gateway report', async () => {
    serve();
    const checks = await checkGateway();
    expect(checks.map((c) => c.id)).toEqual(['fetch', 'intel', 'key', 'nonce', 'debug', 'compose', 'rtmr3']);
    expect(failed(checks)).toEqual([]);
  });

  it('notices a nonce the server echoes wrongly', async () => {
    serve((r) => {
      r.request_nonce = '00'.repeat(32);
    });
    expect(failed(await checkGateway())).toEqual(['nonce']);
  });

  it('notices a report for another signer', async () => {
    serve((r) => {
      r.signing_address = 'cd'.repeat(32);
    });
    expect(failed(await checkGateway())).toContain('key');
  });

  it('refuses debug mode', async () => {
    serve(() => {
      quote.tdAttributes = Uint8Array.of(1, 0, 0, 0, 0, 0, 0, 0);
    });
    expect(failed(await checkGateway())).toEqual(['debug']);
  });

  it('recomputes event digests instead of trusting them', async () => {
    serve((r) => {
      r.event_log = JSON.stringify([{ ...EVENT, digest: 'ff'.repeat(48) }]);
    });
    expect(failed(await checkGateway())).toEqual(['rtmr3']);
  });

  it('accepts a supplied digest that matches', async () => {
    const digest = hex(await eventDigest());
    serve((r) => {
      r.event_log = JSON.stringify([{ ...EVENT, digest }]);
    });
    expect(failed(await checkGateway())).toEqual([]);
  });

  it('refuses GPU evidence for another nonce', async () => {
    serve((r) => {
      r.nvidia_payload = JSON.stringify({ nonce: '00'.repeat(32) });
    });
    const checks = await checkModel(MODEL);
    expect(failed(checks)).toEqual(['nvidia']);
    expect(checks.find((c) => c.id === '0-nvidia')?.detail).toContain('our nonce');
  });

  it('fails when GPU evidence is missing, rather than skipping the check', async () => {
    serve((r) => {
      delete r.nvidia_payload;
    });
    expect(failed(await checkModel(MODEL))).toEqual(['nvidia']);
  });

  it('fails when no model report comes back', async () => {
    serve((r) => {
      r.none = true;
    });
    expect(failed(await checkModel(MODEL))).toEqual(['fetch']);
  });

  it('refuses a model that NEAR AI does not attest', async () => {
    serve();
    const inner = fetch;
    vi.stubGlobal('fetch', async (url: string) => (url.includes('/model/') ? Response.json({ metadata: { providerType: 'external', attestationSupported: false } }) : inner(url)));
    expect(failed(await checkModel(MODEL))).toContain('listed');
  });

  it("counts a verdict as unverified without NVIDIA's signature", async () => {
    const claims = (nonce: string) => btoa(JSON.stringify({ 'x-nvidia-overall-att-result': true, eat_nonce: nonce }));
    serve();
    const inner = fetch;
    vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
      if (!url.includes('nras')) return inner(url);
      const { nonce } = JSON.parse(String(init?.body));
      return Response.json([['JWT', `${btoa('{"kid":"k"}')}.${claims(nonce)}.c2ln`]]);
    });
    const checks = await checkModel(MODEL);
    expect(failed(checks)).toEqual(['nvidia']);
    expect(checks.find((c) => c.id === '0-nvidia')?.detail).toContain('unverified');
  });
});
