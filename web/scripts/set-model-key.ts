// Gives the enclave its NEAR AI key, with no code change and no new wasm: the
// key is encrypted here, to the keystore, and only enclave runs can open it.
//
//   npx tsx scripts/set-model-key.ts
//
// The key comes from NEAR_AI_API_KEY, web/.env or a hidden prompt. It's never an
// argument, so it can't land in shell history, and this script never writes it to
// disk. It runs scripts/smoke.ts first, and stores nothing if NEAR AI refuses it.

import { send, TGAS } from '../src/lib/near';
import { keystoreEncrypt, keystoreKey, log, NEAR, OUTLAYER, PROJECT, readNearAiKey, ROOT_ACCOUNT, signerFor } from './lib';
import { smoke } from './smoke';

const key = await readNearAiKey();
if (!key) {
  console.error('No key given, so nothing was stored.');
  process.exit(1);
}

const { ok, keyRejected } = await smoke(key);
if (keyRejected) {
  console.error('NEAR AI refused this key, so nothing was stored.');
  process.exit(1);
}

const projectId = `${ROOT_ACCOUNT}/${PROJECT}`;
const pub = await keystoreKey({ type: 'Project', project_id: projectId }, ROOT_ACCOUNT, 'prod');
await send(signerFor(ROOT_ACCOUNT), OUTLAYER, {
  method: 'store_secrets',
  args: {
    accessor: { Project: { project_id: projectId } },
    profile: 'prod',
    encrypted_secrets_base64: keystoreEncrypt(pub, JSON.stringify({ NEAR_AI_API_KEY: key })),
    access: 'AllowAll',
    vault_id: null,
  },
  gas: 50n * TGAS,
  deposit: NEAR('0.01'),
});
log(ok ? 'Stored. Every check passed, so you can close this tab.' : 'Stored, but some checks above failed. Leave this tab open so they can be read.');
