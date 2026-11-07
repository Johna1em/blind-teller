import { useState } from 'react';
import { MODELS, REGISTRY, TELLER } from '../config';
import { checkModel, type Check } from '../lib/attest';
import { enclaveKeys, type Config, type EnclaveKeys } from '../lib/teller';
import { Notice, short, Step } from './parts';

export function Proof({ config }: { config: Config | null }) {
  const [running, setRunning] = useState(false);
  const [models, setModels] = useState<Record<string, Check[]>>({});
  const [keys, setKeys] = useState<EnclaveKeys | null>(null);
  const [keyError, setKeyError] = useState('');

  async function run() {
    setRunning(true);
    setModels({});
    setKeys(null);
    setKeyError('');
    await Promise.all(
      MODELS.map(async (m) => {
        try {
          const checks = await checkModel(m);
          setModels((all) => ({ ...all, [m]: checks }));
        } catch (e) {
          setModels((all) => ({ ...all, [m]: [{ id: 'fetch', label: 'Fetched a fresh attestation', ok: false, detail: String((e as Error).message) }] }));
        }
      }),
    );
    try {
      setKeys(await enclaveKeys());
    } catch (e) {
      setKeyError((e as Error).message);
    }
    setRunning(false);
  }

  const matches = keys && config ? keys.verdict_public === config.verdict_key && keys.seal_public === config.seal_key : null;

  return (
    <>
      <section className="hero hero-small">
        <h1>Don&rsquo;t take our word for it</h1>
        <p>
          These checks run in this browser, against live hardware evidence, with a nonce made just now. A saved answer can&rsquo;t pass them,
          and no server of ours is involved, because there isn&rsquo;t one.
        </p>
        <button className="primary" disabled={running} onClick={run}>{running ? 'Checking…' : 'Run the checks'}</button>
      </section>

      {MODELS.map((m) => (
        <section className="panel" key={m}>
          <h2 className="mono">{m}</h2>
          {models[m] ? (
            <ol className="steps">
              {models[m].map((c) => <Step key={c.id} state={c.ok ? 'pass' : 'fail'} label={c.label} detail={c.detail} />)}
            </ol>
          ) : (
            <p className="fine">{running ? 'Fetching evidence…' : 'Not checked yet.'}</p>
          )}
        </section>
      ))}

      <section className="panel">
        <h2>The enclave and the contract</h2>
        {keyError ? <Notice tone="warn">The enclave couldn&rsquo;t be reached: {keyError}</Notice> : null}
        {keys ? (
          <ol className="steps">
            <Step state={matches ? 'pass' : 'fail'} label="The enclave's keys match the contract's" detail={`Verdict key ${short(keys.verdict_public, 12)}`} />
            <Step state="pass" label="Policy hash published" detail={short(keys.policy_hash, 14)} />
          </ol>
        ) : (
          <p className="fine">{running ? 'Asking the enclave…' : 'Not checked yet.'}</p>
        )}
        <dl className="pairs">
          <div><dt>Escrow</dt><dd className="mono">{TELLER}</dd></div>
          <div><dt>Model registry</dt><dd className="mono">{REGISTRY}</dd></div>
        </dl>
      </section>

      <section className="panel">
        <h2>What these checks don&rsquo;t prove</h2>
        <ul className="plain">
          <li>Hardware attestation means a genuine quote from a trusted operator. It isn&rsquo;t a mathematical proof of privacy, and physical attacks on TEEs exist.</li>
          <li>NEAR AI&rsquo;s measured config is a launcher. The model server changes at runtime, so the quote doesn&rsquo;t pin the model weights.</li>
          <li>OutLayer&rsquo;s keystore rests on a shared master secret that its key holder could reach.</li>
          <li>GPU evidence is checked here in the browser. It can&rsquo;t be checked on-chain, because NEAR has no P-384 host function.</li>
        </ul>
        <p className="fine">The full list is in the threat model in the repository.</p>
      </section>
    </>
  );
}
