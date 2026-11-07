// Gives the enclave its NEAR AI key, with no code change and no new wasm: the
// key is encrypted here, to the keystore, and only enclave runs can open it.
//
//   NEAR_AI_API_KEY=... npx tsx scripts/set-model-key.ts
//
// The key comes from the environment, so it never lands in shell history as an
// argument, and it's never written to disk by this script.

import { send, TGAS } from '../src/lib/near';
import { keystoreEncrypt, keystoreKey, log, NEAR, OUTLAYER, PROJECT, ROOT_ACCOUNT, signerFor } from './lib';

const key = process.env.NEAR_AI_API_KEY;
if (!key) {
  console.error('Set NEAR_AI_API_KEY in the environment first.');
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
log('stored. The enclave reads it on its next run.');
