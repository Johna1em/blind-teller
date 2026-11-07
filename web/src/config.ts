// Everything public about this deployment. There are no secrets here: the demo
// key can only call two methods on one contract, with a small gas allowance.

export const NETWORK = 'testnet';

export const RPC_URLS = ['https://rpc.testnet.near.org', 'https://test.rpc.fastnear.com'];
export const EXPLORER = 'https://testnet.nearblocks.io';

export const TELLER = 'teller.blindteller.testnet';
export const REGISTRY = 'models.blindteller.testnet';
export const TOKEN = 'usdc.fakes.testnet';
export const TOKEN_DECIMALS = 6;

export const OUTLAYER_API = 'https://testnet-api.outlayer.ai';
export const ENCLAVE_OWNER = 'blindteller.testnet';
export const ENCLAVE_PROJECT = 'teller';

export const NEAR_AI_API = 'https://cloud-api.near.ai/v1';
/** NEAR's proxies for Intel and NVIDIA, which don't allow browser calls. */
export const NEAR_AI_PCCS = 'https://cloud.near.ai/api/proxy/pccs';
export const NEAR_AI_NRAS = 'https://cloud.near.ai/api/proxy/nras';

/** The two TEE-hosted models that read every email. */
export const MODELS = ['z-ai/glm-5.3-flash', 'Qwen/Qwen3.8-27B'];

/**
 * Written by `scripts/deploy.mjs`. The demo buyer's key can call only
 * `take_offer` and `settle`, so judges can run the flow without a wallet. The
 * payment key pays for enclave runs and can spend only its small balance.
 */
export const DEMO = {
  buyerAccount: import.meta.env?.VITE_DEMO_BUYER ?? 'buyer.blindteller.testnet',
  buyerKey: import.meta.env?.VITE_DEMO_BUYER_KEY ?? '',
  paymentKey: import.meta.env?.VITE_DEMO_PAYMENT_KEY ?? '',
  /** True while the release enclave is waiting for its API key. */
  devExtractor: (import.meta.env?.VITE_DEV_EXTRACTOR ?? 'true') === 'true',
};
