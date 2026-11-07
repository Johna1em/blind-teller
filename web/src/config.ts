// Everything public about this deployment. There are no secrets here: the demo
// key can only call two methods on one contract, with a small gas allowance.

export const NETWORK = 'testnet';

export const RPC_URLS = ['https://test.rpc.fastnear.com', 'https://rpc.testnet.fastnear.com', 'https://rpc.testnet.near.org'];
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
export const NEAR_AI_NRAS = 'https://cloud.near.ai/api/proxy/nras/v3/attest/gpu';

/** The two TEE-hosted models that read every email. */
export const MODELS = ['z-ai/glm-5.3-flash', 'Qwen/Qwen3.8-27B'];

/**
 * Loaded at runtime from `demo.json`, which ships with the hosted site and isn't
 * in the repository. The demo buyer's key can call only `take_offer` and
 * `settle`, so judges can run the flow without a wallet. The payment key pays
 * for enclave runs and can spend only its small balance on this one project.
 */
export const DEMO = {
  buyerAccount: 'buyer.blindteller.testnet',
  buyerKey: '',
  paymentKey: '',
};

export async function loadDemo(): Promise<void> {
  try {
    const response = await fetch('./demo.json');
    if (response.ok) Object.assign(DEMO, await response.json());
  } catch {
    // The page still reads the chain without it.
  }
}
