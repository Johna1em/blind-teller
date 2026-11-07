// The track's checkpoint: verify attestation, send one completion, and verify its
// signature. NEAR's own SDK does the second half, so this is an independent check
// of what the repository does by hand. It also reports image provenance.
//
//   npx tsx scripts/smoke.ts
//
// With no key it stops before the completion. The key comes from NEAR_AI_API_KEY,
// web/.env or a hidden prompt, and it's never printed.

import {
  getSdkError,
  InferenceClient,
  verifyComposeManagerDeploymentImageProvenance,
  verifyDeploymentImageProvenance,
  type ImageProvenancePolicy,
} from '@nearai/inference-sdk/node';
import { NEAR_AI_API } from '../src/config';
import { checkGateway, checkModel, MODELS, type Check } from '../src/lib/attest';
import { readNearAiKey } from './lib';

// The images in NEAR AI's measured configs, with the builds that should produce
// them, as listed in the SDK's gateway example.
const GATEWAY_IMAGES: Record<string, ImageProvenancePolicy> = {
  'nearaidev/cloud-api': { repository: 'nearai/cloud-api', workflow: '.github/workflows/build.yml' },
  'nearaidev/cvm-ingress': { repository: 'nearai/cvm-ingress', workflow: '.github/workflows/build-push.yml' },
};
const MODEL_IMAGES: Record<string, ImageProvenancePolicy> = {
  'nearaidev/vllm-proxy-rs': { repository: 'nearai/inference-proxy', workflow: '.github/workflows/build.yml' },
};
const COMPOSE_MANAGER = { imageRepository: 'nearaidev/compose-manager', repository: 'nearai/compose-manager', workflow: '.github/workflows/build.yml' };

// Replicas of a model can differ, so one failed lookup doesn't settle it.
const PROVENANCE_ATTEMPTS = 3;

// The same request settings as `enclave/src/policy.rs`.
const REQUEST: Record<string, object> = {
  'z-ai/glm-5.3-flash': { thinking_token_budget: 512 },
  'Qwen/Qwen3.8-27B': { chat_template_kwargs: { enable_thinking: false } },
};
const MAX_TOKENS = 4_096;

/**
 * NVIDIA stamps its verdict with its own clock, and the SDK allows no difference,
 * so a PC running a few seconds slow fails a genuine verdict as "not yet valid".
 * This puts the script on NEAR AI's clock. Nothing outside this process changes.
 */
async function useServerClock(): Promise<void> {
  const MARGIN_MS = 2_000;
  const response = await fetch(`${NEAR_AI_API}/models`, { method: 'HEAD' });
  const slow = Date.parse(response.headers.get('date') ?? '') - Date.now() + MARGIN_MS;
  if (!(slow > 0)) return;
  const RealDate = Date;
  class ServerDate extends RealDate {
    constructor(...args: unknown[]) {
      super(...((args.length ? args : [RealDate.now() + slow]) as [number]));
    }
    static override now() {
      return RealDate.now() + slow;
    }
  }
  globalThis.Date = ServerDate as unknown as DateConstructor;
}

function report(name: string, checks: Check[]): boolean {
  const failed = checks.filter((c) => !c.ok);
  console.log(`  ${name}: ${checks.length - failed.length} of ${checks.length} passed`);
  for (const c of failed) console.log(`    FAILED ${c.label}: ${c.detail}`);
  return failed.length === 0;
}

function explain(error: unknown): { text: string; status?: number } {
  const sdk = getSdkError(error);
  const failure = sdk?.toJSON().failure as { details?: { status?: number } } | undefined;
  const status = failure?.details?.status ?? (error as { status?: number }).status;
  return { text: failure ? JSON.stringify(failure) : String((error as Error).message ?? error), status };
}

const baseOptions = (apiKey: string) => ({ apiKey: apiKey || undefined, e2ee: true, signingAlgo: 'ed25519', ohttp: false }) as const;

/** A client that also requires image provenance. Used only to report on it. */
const provenanceClient = () =>
  new InferenceClient({
    ...baseOptions(''),
    attestationCacheTimeToLiveMs: 0,
    gatewayVerification: {
      verifiers: { deployment: ({ appCompose }) => verifyDeploymentImageProvenance({ appCompose, imagePolicies: GATEWAY_IMAGES }) },
    },
    modelVerification: {
      verifiers: {
        deployment: (deployment) => verifyComposeManagerDeploymentImageProvenance({ deployment, imagePolicies: MODEL_IMAGES, composeManagerImagePolicy: COMPOSE_MANAGER }),
      },
    },
  });

async function provenance(model: string): Promise<string> {
  let last = '';
  for (let attempt = 1; attempt <= PROVENANCE_ATTEMPTS; attempt++) {
    try {
      await provenanceClient().verify(model);
      return `verified on attempt ${attempt}`;
    } catch (error) {
      last = explain(error).text;
    }
  }
  return `not verified: ${last}`;
}

/** Returns whether every required check passed, and whether NEAR AI refused the key. */
export async function smoke(apiKey: string): Promise<{ ok: boolean; keyRejected: boolean }> {
  let ok = true;
  let keyRejected = false;
  const refused = (status?: number) => status === 401 || status === 403;
  await useServerClock();

  console.log('Attestation, checked by this repository');
  ok = report('NEAR AI gateway', await checkGateway()) && ok;
  for (const model of MODELS) ok = report(model, await checkModel(model)) && ok;

  console.log("Attestation, checked by NEAR's SDK");
  const sdk = new InferenceClient(baseOptions(apiKey));
  for (const model of MODELS) {
    try {
      const result = await sdk.verify(model);
      console.log(`  ${model}: verified, ${result.models.length} model report(s)`);
    } catch (error) {
      const { text, status } = explain(error);
      ok = false;
      keyRejected ||= refused(status);
      console.log(`  ${model}: FAILED ${text}`);
    }
  }
  if (keyRejected) return { ok, keyRejected };

  console.log("Image provenance, checked by NEAR's SDK (reported, not required)");
  for (const model of MODELS) console.log(`  ${model}: ${await provenance(model)}`);

  if (!apiKey) {
    console.log('No NEAR AI key, so no completion was sent.');
    return { ok, keyRejected };
  }

  console.log('One encrypted completion, with its signature checked');
  for (const model of MODELS) {
    try {
      const request = { model, messages: [{ role: 'user' as const, content: 'Reply with the word ok.' }], temperature: 0, max_tokens: MAX_TOKENS, stream: false as const, ...REQUEST[model] };
      const completion = await sdk.chat.completions.create(request);
      const verified = await sdk.verifyResponse(completion.id);
      const choice = completion.choices[0];
      const usage = completion.usage as { completion_tokens?: number; completion_tokens_details?: { reasoning_tokens?: number } } | undefined;
      console.log(`  ${model}: replied ${JSON.stringify(choice?.message.content ?? '')}, finish ${choice?.finish_reason}, ${usage?.completion_tokens ?? '?'} tokens (${usage?.completion_tokens_details?.reasoning_tokens ?? 0} thinking), signature ${verified.signatureKind}`);
      if (verified.signatureKind !== 'provider_tee') ok = false;
    } catch (error) {
      const { text, status } = explain(error);
      ok = false;
      keyRejected ||= refused(status);
      console.log(`  ${model}: FAILED${status ? ` (HTTP ${status})` : ''} ${text}`);
    }
  }
  return { ok, keyRejected };
}

if (process.argv[1]?.endsWith('smoke.ts')) {
  const { ok } = await smoke(await readNearAiKey());
  process.exit(ok ? 0 : 1);
}
