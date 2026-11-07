// The "Verified" panel: live checks this browser runs itself, with a fresh nonce.
// They follow NEAR AI's verification docs: the gateway first, then every model
// report, with each value read from the verified quote and not the HTTP fields.
// See https://docs.near.ai/cloud/verification. A check that can't run counts as
// failed. None of this asks a server of ours, because there isn't one.

import { getCollateralAndVerify, type TDReport10 } from '@phala/dcap-qvl';
import { MODELS, NEAR_AI_API, NEAR_AI_NRAS, NEAR_AI_PCCS, REGISTRY } from '../config';
import { concat, fromHex, hex, randomBytes, sha256, utf8 } from './bytes';
import { view } from './near';
import type { ModelKey } from './teller';

const NVIDIA_JWKS = 'https://nras.attestation.nvidia.com/.well-known/jwks.json';
const SIGNING_ALGO = 'ed25519';
const ACCEPTED_TCB = 'UpToDate';
const RATE_LIMIT_ATTEMPTS = 4;
const RATE_LIMIT_WAIT_MS = 2_000;

export interface Check {
  id: string;
  label: string;
  ok: boolean;
  detail: string;
}

interface LogEvent {
  imr: number;
  digest?: string;
  event_type: number;
  event: string;
  event_payload?: string;
}

/** One NEAR report. The gateway's and each model's have the same shape. */
interface Report {
  signing_public_key?: string;
  signing_address: string;
  signing_algo?: string;
  request_nonce?: string;
  report_data?: string;
  intel_quote: string;
  event_log?: string | LogEvent[];
  nvidia_payload?: string;
  info: string | { tcb_info: string | { app_compose: string; event_log?: string | LogEvent[] } };
}

type Add = (id: string, label: string, ok: boolean, detail: string) => void;

const parse = <T,>(v: string | T): T => (typeof v === 'string' ? (JSON.parse(v) as T) : v);
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const message = (e: unknown) => String((e as Error).message ?? e).slice(0, 120);

function collector(): { checks: Check[]; add: Add } {
  const checks: Check[] = [];
  return { checks, add: (id, label, ok, detail) => checks.push({ id, label, ok, detail }) };
}

async function sha384(b: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-384', b as BufferSource));
}

/** Recomputing each digest is what authenticates the event payloads. */
async function replayRtmr3(events: LogEvent[]): Promise<Uint8Array | null> {
  let rtmr: Uint8Array = new Uint8Array(48);
  for (const e of events.filter((x) => x.imr === 3)) {
    const type = new Uint8Array(4);
    new DataView(type.buffer).setUint32(0, e.event_type, true);
    const digest = await sha384(concat(type, utf8(':'), utf8(e.event), utf8(':'), fromHex(e.event_payload ?? '')));
    if (e.digest && !same(fromHex(e.digest), digest)) return null;
    rtmr = await sha384(concat(rtmr, digest));
  }
  return rtmr;
}

/** Requests without a key share a small limit, so wait it out a few times. */
async function fetchReport(params: Record<string, string>): Promise<Response> {
  const query = new URLSearchParams({ signing_algo: SIGNING_ALGO, ...params });
  for (let attempt = 1; ; attempt++) {
    const response = await fetch(`${NEAR_AI_API}/attestation/report?${query}`, { headers: { 'x-no-aliasing': 'true' } });
    if (response.status !== 429 || attempt === RATE_LIMIT_ATTEMPTS) return response;
    await new Promise((resolve) => setTimeout(resolve, RATE_LIMIT_WAIT_MS));
  }
}

const unb64url = (s: string) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

/**
 * Ask NVIDIA's attestation service about the GPU evidence. Browsers reach it
 * through NEAR AI's proxy, so the verdict counts only if NVIDIA's own signature
 * on it verifies here: a proxy can forward the answer, but it can't change it.
 */
async function checkGpu(payload: string | undefined, nonce: string): Promise<{ ok: boolean; detail: string }> {
  if (!payload) return { ok: false, detail: 'This report has no GPU evidence' };
  const evidence = JSON.parse(payload);
  if (String(evidence.nonce).toLowerCase() !== nonce) return { ok: false, detail: "The GPU evidence doesn't carry our nonce" };

  const response = await fetch(NEAR_AI_NRAS, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload });
  if (!response.ok) return { ok: false, detail: `NRAS answered ${response.status}` };
  const body = await response.json();
  const jwt: string | undefined = Array.isArray(body) ? body[0]?.[1] : undefined;
  if (!jwt) return { ok: false, detail: 'NRAS returned no signed verdict' };
  const [head, claims, signature] = jwt.split('.');
  const parsedHead = JSON.parse(new TextDecoder().decode(unb64url(head)));
  const parsed = JSON.parse(new TextDecoder().decode(unb64url(claims)));
  const count: number = evidence.evidence_list?.length ?? 0;
  const gpus = `${count} GPU${count === 1 ? '' : 's'}`;
  if (parsed['x-nvidia-overall-att-result'] !== true) return { ok: false, detail: 'NVIDIA reports a failed attestation' };
  if (String(parsed.eat_nonce).toLowerCase() !== nonce) return { ok: false, detail: "NVIDIA's verdict doesn't cover our nonce" };

  try {
    const jwks = await (await fetch(NVIDIA_JWKS)).json();
    const jwk = jwks.keys.find((k: { kid: string }) => k.kid === parsedHead.kid);
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-384', x: jwk.x, y: jwk.y }, { name: 'ECDSA', namedCurve: 'P-384' }, false, ['verify']);
    const signed = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-384' }, key, unb64url(signature) as BufferSource, utf8(`${head}.${claims}`) as BufferSource);
    return { ok: signed, detail: signed ? `${gpus}, verdict signature verified` : "NVIDIA's signature doesn't verify" };
  } catch {
    return { ok: false, detail: "NVIDIA's public keys couldn't be reached, so this verdict stays unverified" };
  }
}

/** The checks every NEAR report gets. Stops early if the quote itself fails. */
async function checkReport(report: Report, nonce: string, add: Add): Promise<void> {
  const INTEL = "Intel's signature chain verifies";
  let verified: Awaited<ReturnType<typeof getCollateralAndVerify>>;
  try {
    verified = await getCollateralAndVerify(fromHex(report.intel_quote), NEAR_AI_PCCS);
  } catch (e) {
    add('intel', INTEL, false, message(e));
    return;
  }
  const isTdx = verified.report.type === 'td10';
  add('intel', INTEL, isTdx && verified.status === ACCEPTED_TCB, `TCB ${verified.status}`);
  if (!isTdx) return;
  const quote = verified.report.data as TDReport10;

  const address = report.signing_address.replace(/^0x/, '').toLowerCase();
  const signer = fromHex(address);
  const sameKey = (report.signing_public_key ?? address).replace(/^0x/, '').toLowerCase() === address;
  add('key', 'The hardware quote binds the signing key', report.signing_algo === SIGNING_ALGO && sameKey && signer.length === 32 && same(quote.reportData.subarray(0, 32), signer), `Key ${address.slice(0, 16)}…`);

  const echoed = report.request_nonce?.toLowerCase() === nonce;
  const copied = !report.report_data || same(fromHex(report.report_data), quote.reportData);
  add('nonce', 'The quote binds our nonce, so it is fresh', echoed && copied && same(quote.reportData.subarray(32), fromHex(nonce)), 'A replayed quote would fail here');
  add('debug', 'Debug mode is off', (quote.tdAttributes[0] & 1) === 0, 'A debug TD could be read by its host');

  const tcb = parse(parse(report.info).tcb_info);
  const composeHash = await sha256(utf8(tcb.app_compose));
  add('compose', 'The running config matches its measurement', same(quote.mrConfigId, concat(Uint8Array.of(1), composeHash, new Uint8Array(15))), `Compose ${hex(composeHash).slice(0, 16)}…`);

  const events = parse<LogEvent[]>(report.event_log || tcb.event_log || []);
  const replayed = await replayRtmr3(events);
  add('rtmr3', 'The boot event log replays to RTMR3', !!replayed && same(replayed, quote.rtMr3), `${events.filter((e) => e.imr === 3).length} events`);
}

/** NEAR AI's front door. The docs start here, before any key or completion. */
export async function checkGateway(): Promise<Check[]> {
  const { checks, add } = collector();
  const nonce = hex(randomBytes(32));
  try {
    const response = await fetchReport({ nonce });
    const report: Report | undefined = response.ok ? (await response.json()).gateway_attestation : undefined;
    add('fetch', 'Fetched a fresh attestation', !!report, report ? `Random nonce ${nonce.slice(0, 12)}…` : `NEAR AI answered ${response.status}`);
    if (report) await checkReport(report, nonce, add);
  } catch (e) {
    add('error', 'The checks finished', false, message(e));
  }
  return checks;
}

/** Run every check for one model, on every report NEAR AI returns for it. */
export async function checkModel(model: string): Promise<Check[]> {
  const { checks, add } = collector();
  const nonce = hex(randomBytes(32));
  try {
    const listing = await fetch(`${NEAR_AI_API}/model/${encodeURIComponent(model)}`);
    const meta = listing.ok ? (await listing.json()).metadata : undefined;
    const attested = meta?.providerType === 'vllm' && meta?.attestationSupported === true;
    add('listed', 'NEAR AI lists this as an attested TEE model', attested, meta ? `${meta.providerType}, ${meta.isReady ? 'ready' : 'not ready'}` : `NEAR AI answered ${listing.status}`);

    const response = await fetchReport({ model, provider: 'near', nonce });
    const reports: Report[] = response.ok ? ((await response.json()).model_attestations ?? []) : [];
    add('fetch', 'Fetched a fresh attestation', reports.length > 0, reports.length ? `Random nonce ${nonce.slice(0, 12)}…, ${reports.length} report${reports.length === 1 ? '' : 's'}` : `No reports, NEAR AI answered ${response.status}`);

    for (const [i, report] of reports.entries()) {
      const tag = reports.length > 1 ? `Report ${i + 1}: ` : '';
      const addTo: Add = (id, label, ok, detail) => add(`${i}-${id}`, `${tag}${label}`, ok, detail);
      await checkReport(report, nonce, addTo);
      const gpu = await checkGpu(report.nvidia_payload, nonce);
      addTo('nvidia', 'NVIDIA attests the GPUs', gpu.ok, gpu.detail);
    }

    for (const key of new Set(reports.map((r) => (r.signing_public_key ?? r.signing_address).replace(/^0x/, '').toLowerCase()))) {
      const registered = await view<ModelKey | null>(REGISTRY, 'get_key', { key });
      const live = !!registered && Number(registered.expires_ms) > Date.now();
      add(`registry-${key}`, 'This key is proven on NEAR', live, live ? `Via tee-verifier, until ${new Date(Number(registered!.expires_ms)).toUTCString()}` : 'Not in the on-chain registry yet');
    }
  } catch (e) {
    add('error', 'The checks finished', false, message(e));
  }
  return checks;
}

export { MODELS };
