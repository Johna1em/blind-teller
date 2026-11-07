// The "Verified" panel: live checks this browser runs itself, with a fresh nonce.
// None of this asks a server of ours, because there isn't one.

import { getCollateralAndVerify } from '@phala/dcap-qvl';
import { MODELS, NEAR_AI_API, NEAR_AI_NRAS, NEAR_AI_PCCS, REGISTRY } from '../config';
import { concat, fromHex, hex, randomBytes, sha256, utf8 } from './bytes';
import { view } from './near';
import type { ModelKey } from './teller';

const NVIDIA_JWKS = 'https://nras.attestation.nvidia.com/.well-known/jwks.json';

export interface Check {
  id: string;
  label: string;
  ok: boolean;
  detail: string;
}

interface Attestation {
  signing_public_key?: string;
  signing_address: string;
  intel_quote: string;
  event_log: string | object[];
  nvidia_payload?: string;
  info: string | { tcb_info: string | { app_compose: string; event_log?: object[] } };
}

// TDX quote v4 offsets (a 48-byte header, then the TD report).
const REPORT = 48;
const TD_ATTRIBUTES = REPORT + 120;
const MR_CONFIG_ID = REPORT + 184;
const RTMR3 = REPORT + 328 + 3 * 48;
const REPORT_DATA = REPORT + 520;

const parse = <T,>(v: string | T): T => (typeof v === 'string' ? (JSON.parse(v) as T) : v);
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

async function sha384(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-384', b as BufferSource));
}

async function replayRtmr3(events: { imr: number; digest?: string; event_type?: number; event?: string; event_payload?: string }[]): Promise<Uint8Array> {
  let rtmr: Uint8Array = new Uint8Array(48);
  for (const e of events.filter((x) => x.imr === 3)) {
    let digest = e.digest ? fromHex(e.digest) : new Uint8Array();
    if (digest.length !== 48 && e.event_type !== undefined) {
      const type = new Uint8Array(4);
      new DataView(type.buffer).setUint32(0, e.event_type, true);
      digest = await sha384(concat(type, utf8(':'), utf8(e.event ?? ''), utf8(':'), fromHex(e.event_payload ?? '')));
    }
    rtmr = await sha384(concat(rtmr, digest));
  }
  return rtmr;
}

const unb64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

/**
 * Ask NVIDIA's attestation service about the GPU evidence. Its verdict is a
 * signed JWT, read and verified here: a proxy can forward the answer, but it
 * can't change it. Browsers can't read the response headers, and don't need to.
 */
async function checkGpu(payload: string): Promise<{ ok: boolean; detail: string }> {
  const response = await fetch(NEAR_AI_NRAS, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload });
  if (!response.ok) return { ok: false, detail: `NRAS answered ${response.status}` };
  const body = await response.json();
  const jwt: string | undefined = Array.isArray(body) ? body[0]?.[1] : undefined;
  if (!jwt) return { ok: false, detail: 'NRAS returned no signed verdict' };
  const [head, claims, signature] = jwt.split('.');
  const parsedHead = JSON.parse(new TextDecoder().decode(unb64url(head)));
  const parsed = JSON.parse(new TextDecoder().decode(unb64url(claims)));
  const passed = parsed['x-nvidia-overall-att-result'] === true;
  const fresh = parsed.eat_nonce === JSON.parse(payload).nonce;
  const count: number = JSON.parse(payload).evidence_list?.length ?? 0;
  const gpus = `${count} GPU${count === 1 ? '' : 's'}`;
  if (!passed) return { ok: false, detail: 'NVIDIA reports a failed attestation' };
  if (!fresh) return { ok: false, detail: "NVIDIA's verdict doesn't cover this nonce" };

  // NVIDIA's public keys aren't always reachable from a browser, so say which
  // of the two this was instead of claiming more than happened.
  try {
    const jwks = await (await fetch(NVIDIA_JWKS)).json();
    const jwk = jwks.keys.find((k: { kid: string }) => k.kid === parsedHead.kid);
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-384', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
    const signed = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, unb64url(signature) as BufferSource, utf8(`${head}.${claims}`) as BufferSource);
    return { ok: signed, detail: signed ? `${gpus}, verdict signature verified` : "NVIDIA's signature doesn't verify" };
  } catch {
    return { ok: true, detail: `${gpus}. The verdict is read, but NVIDIA's keys aren't reachable from a browser; run the CLI to check its signature` };
  }
}

/** Run every check for one model. Nothing here decides anything on-chain. */
export async function checkModel(model: string): Promise<Check[]> {
  const nonce = hex(randomBytes(32));
  const params = new URLSearchParams({ model, provider: 'near', signing_algo: 'ed25519', nonce });
  const response = await fetch(`${NEAR_AI_API}/attestation/report?${params}`, { headers: { 'x-no-aliasing': 'true' } });
  const checks: Check[] = [];
  const add = (id: string, label: string, ok: boolean, detail: string) => checks.push({ id, label, ok, detail });
  if (!response.ok) {
    add('fetch', 'Fetched a fresh attestation', false, `NEAR AI answered ${response.status}`);
    return checks;
  }
  const report = await response.json();
  const a: Attestation | undefined = report.model_attestations?.[0];
  if (!a) {
    add('fetch', 'Fetched a fresh attestation', false, 'No attestation in the response');
    return checks;
  }
  const key = (a.signing_public_key ?? a.signing_address).replace(/^0x/, '');
  add('fetch', 'Fetched a fresh attestation', true, `Random nonce ${nonce.slice(0, 12)}…`);

  const quote = fromHex(a.intel_quote);
  const reportData = quote.subarray(REPORT_DATA, REPORT_DATA + 64);
  add('key', 'The hardware quote binds the signing key', same(reportData.subarray(0, 32), fromHex(key)), `Key ${key.slice(0, 16)}…`);
  add('nonce', 'The quote binds our nonce, so it is fresh', same(reportData.subarray(32), fromHex(nonce)), 'A replayed quote would fail here');
  add('debug', 'Debug mode is off', (quote[TD_ATTRIBUTES] & 1) === 0, 'A debug TD could be read by its host');

  const info = parse<any>(a.info);
  const tcb = parse<any>(info.tcb_info);
  const composeHash = await sha256(utf8(tcb.app_compose));
  const expected = concat(Uint8Array.of(1), composeHash, new Uint8Array(15));
  add('compose', 'The running config matches its measurement', same(quote.subarray(MR_CONFIG_ID, MR_CONFIG_ID + 48), expected), `Compose ${hex(composeHash).slice(0, 16)}…`);

  const events = parse<any[]>(tcb.event_log ?? a.event_log);
  add('rtmr3', 'The boot event log replays to RTMR3', same(await replayRtmr3(events), quote.subarray(RTMR3, RTMR3 + 48)), `${events.filter((e) => e.imr === 3).length} events`);

  try {
    const verified = await getCollateralAndVerify(quote, NEAR_AI_PCCS);
    add('intel', "Intel's signature chain verifies", verified.status === 'UpToDate', `TCB ${verified.status}`);
  } catch (e) {
    add('intel', "Intel's signature chain verifies", false, String((e as Error).message ?? e).slice(0, 120));
  }

  if (a.nvidia_payload) {
    try {
      const gpu = await checkGpu(a.nvidia_payload);
      add('nvidia', 'NVIDIA attests the GPUs', gpu.ok, gpu.detail);
    } catch (e) {
      add('nvidia', 'NVIDIA attests the GPUs', false, String((e as Error).message ?? e).slice(0, 120));
    }
  }

  try {
    const registered = await view<ModelKey | null>(REGISTRY, 'get_key', { key });
    const live = !!registered && Number(registered.expires_ms) > Date.now();
    add('registry', 'This key is proven on NEAR', live, live ? `Via tee-verifier, until ${new Date(Number(registered!.expires_ms)).toUTCString()}` : 'Not in the on-chain registry yet');
  } catch {
    add('registry', 'This key is proven on NEAR', false, "The registry couldn't be read");
  }
  return checks;
}

export { MODELS };
