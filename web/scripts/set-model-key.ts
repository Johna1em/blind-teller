// Gives the enclave its NEAR AI key, with no code change and no new wasm: the
// key is encrypted here, to the keystore, and only enclave runs can open it.
//
//   npx tsx scripts/set-model-key.ts
//
// It asks for the key and hides what you type. It also reads NEAR_AI_API_KEY from
// the environment, for automation. The key is never an argument, so it can't land
// in shell history, and this script never writes it to disk.

import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { send, TGAS } from '../src/lib/near';
import { keystoreEncrypt, keystoreKey, log, NEAR, OUTLAYER, PROJECT, ROOT_ACCOUNT, signerFor } from './lib';

async function promptHidden(question: string): Promise<string> {
  process.stdout.write(question);
  const silent = new Writable({ write: (_chunk, _encoding, done) => done() });
  const rl = createInterface({ input: process.stdin, output: silent, terminal: true });
  const answer = await new Promise<string>((resolve) => rl.question('', resolve));
  rl.close();
  process.stdout.write('\n');
  return answer.trim();
}

const key = process.env.NEAR_AI_API_KEY ?? (await promptHidden('Paste your NEAR AI key, then press Enter (nothing will show): '));
if (!key) {
  console.error('No key given, so nothing was stored.');
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
log('Stored. The enclave reads it on its next run. You can close this tab.');
