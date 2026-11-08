import { useState } from 'react';
import { MODELS, REGISTRY, TELLER } from '../config';
import { checkGateway, checkModel, type Check } from '../lib/attest';
import { enclaveKeys, inspectEmail, refusal, type Config, type EnclaveKeys } from '../lib/teller';
import { Icon } from './Art';
import { Notice, short, Stamp, Step } from './parts';

/** One set of checks with its score. */
function Group({ title, checks, running, mono, note }: { title: string; checks?: Check[] | null; running: boolean; mono?: boolean; note?: string }) {
  const passed = checks?.filter((c) => c.ok).length ?? 0;
  return (
    <section className="panel group">
      <header className="group-head">
        <h2 className={mono ? 'mono' : undefined}>{title}</h2>
        {checks ? <span className={`pill ${passed === checks.length ? 'pill-ok' : 'pill-bad'}`}>{passed}/{checks.length}</span> : null}
      </header>
      {checks ? (
        <ol className="steps steps-compact">
          {checks.map((c) => <Step key={c.id} state={c.ok ? 'pass' : 'fail'} label={c.label} detail={c.detail} />)}
        </ol>
      ) : (
        <p className="fine spinline">{running ? <><span className="spin" aria-hidden="true" />Fetching evidence…</> : 'Not checked yet.'}</p>
      )}
      {note ? <p className="fine">{note}</p> : null}
    </section>
  );
}

export function Proof({ config }: { config: Config | null }) {
  const [running, setRunning] = useState(false);
  const [gateway, setGateway] = useState<Check[] | null>(null);
  const [models, setModels] = useState<Record<string, Check[]>>({});
  const [checkedAt, setCheckedAt] = useState<Date | null>(null);
  const [keys, setKeys] = useState<EnclaveKeys | null>(null);
  const [keyError, setKeyError] = useState('');
  const [inspecting, setInspecting] = useState(false);
  const [inspected, setInspected] = useState<{ ok: boolean; code?: string; headers?: string[]; domain?: string } | null>(null);

  async function inspect(file: File) {
    if (!config) return;
    setInspecting(true);
    setInspected(null);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      // Read here in the browser for display. It never leaves in plaintext.
      const domain = new TextDecoder('latin1').decode(bytes).match(/DKIM-Signature:[^]*?\bd=([a-z0-9.-]+)/i)?.[1];
      const out = await inspectEmail(config.seal_key, bytes);
      setInspected({ ok: out.ok, code: out.code, headers: out.signed_headers, domain });
    } catch (e) {
      setInspected({ ok: false, code: (e as Error).message });
    }
    setInspecting(false);
  }

  async function run() {
    setRunning(true);
    setCheckedAt(null);
    setGateway(null);
    setModels({});
    setKeys(null);
    setKeyError('');
    setGateway(await checkGateway());
    await Promise.all(
      MODELS.map(async (m) => {
        const checks = await checkModel(m);
        setModels((all) => ({ ...all, [m]: checks }));
      }),
    );
    try {
      setKeys(await enclaveKeys());
    } catch (e) {
      setKeyError((e as Error).message);
    }
    setCheckedAt(new Date());
    setRunning(false);
  }

  const matches = keys && config ? keys.verdict_public === config.verdict_key && keys.seal_public === config.seal_key : null;
  const results: Check[] = [
    ...(gateway ?? []),
    ...MODELS.flatMap((m) => models[m] ?? []),
    { id: 'keys', label: "The enclave's keys match the contract's", ok: !!matches, detail: '' },
  ];
  const failed = results.filter((c) => !c.ok);
  const verified = checkedAt !== null && failed.length === 0;

  return (
    <>
      <section className="hero hero-small hero-split">
        <div>
          <p className="eyebrow">Checked in your browser</p>
          <h1>Don&rsquo;t take our word for it</h1>
          <p className="hero-lede">
            These checks run in this browser, against live hardware evidence, with a nonce made just now. A saved answer can&rsquo;t pass them,
            and no server of ours is involved, because there isn&rsquo;t one.
          </p>
          <button className="primary" disabled={running} onClick={run}>{running ? 'Checking…' : 'Run the checks'}</button>
        </div>
        <ul className="covered" aria-label="What gets checked">
          <li><Icon name="chip" />Intel&rsquo;s signature on the secure hardware</li>
          <li><Icon name="shield" />NVIDIA&rsquo;s verdict on the GPUs</li>
          <li><Icon name="lock" />Each model&rsquo;s key, bound to fresh evidence</li>
          <li><Icon name="link" />The same keys, proven on NEAR</li>
        </ul>
      </section>

      {checkedAt ? (
        <section className={`verified ${verified ? 'verified-ok' : 'verified-bad'}`} aria-live="polite">
          <h2>{verified ? 'Verified' : 'Not verified'}</h2>
          <Stamp kind={verified ? 'paid' : 'refused'}>{verified ? 'Verified' : 'Not verified'}</Stamp>
          <div className="verified-body">
            {verified ? (
              <p>
                All {results.length} checks passed at {checkedAt.toUTCString()}, with nonces made in this browser. Each one is listed below. This proves the environment.
                Each settled order carries its own proof: the model&rsquo;s signature over that exact exchange.
              </p>
            ) : (
              <>
                <p className="reason">{failed.length} of {results.length} checks failed, so treat this environment as unverified:</p>
                <ul className="plain">{failed.map((c) => <li key={c.id}>{c.label}{c.detail ? `: ${c.detail}` : ''}</li>)}</ul>
              </>
            )}
          </div>
        </section>
      ) : null}

      <div className="proof-grid">
        <Group title="NEAR AI gateway" checks={gateway} running={running} note="The gateway routes requests to the models. It only sees encrypted text, so privacy doesn&rsquo;t depend on it, but NEAR AI&rsquo;s docs start here." />
        {MODELS.map((m) => <Group key={m} title={m} mono checks={models[m]} running={running} />)}
      </div>

      <div className="twin">
        <section className="panel">
          <h2>Try a real email from your inbox</h2>
          <p>
            The banks on this site are fictional, so here&rsquo;s the proof that the DKIM check is real. Save any email as a <span className="mono">.eml</span> file
            (in Gmail: the three dots, then &ldquo;Download message&rdquo;). This page encrypts it, and the enclave checks it against the sender&rsquo;s live DNS records.
          </p>
          <div className="upload">
            <label className="filebtn">
              <Icon name="upload" size={16} />
              {inspecting ? 'Checking inside the enclave…' : 'Choose a .eml file'}
              <input type="file" accept=".eml,message/rfc822" disabled={inspecting || !config} onChange={(e) => e.target.files?.[0] && inspect(e.target.files[0])} />
            </label>
            <p className="fine">The enclave answers only pass or fail, stores nothing, and never moves money. Recent mail you received often passes. Older mail can fail once the sender rotates its key, and an edited or forwarded email won&rsquo;t pass.</p>
          </div>
          {inspected ? (
            inspected.ok ? (
              <>
                <p><Stamp kind="paid">Genuine</Stamp></p>
                <p>
                  The enclave verified this email&rsquo;s signature against {inspected.domain ?? 'the sender'}&rsquo;s public key in DNS, using two independent resolvers.
                  {' '}It covers these headers: <span className="mono">{inspected.headers?.join(', ')}</span>.
                </p>
              </>
            ) : (
              <>
                <p><Stamp kind="refused">Refused</Stamp></p>
                <p className="reason">{refusal(inspected.code)}</p>
                <span className="code">{inspected.code}</span>
              </>
            )
          ) : null}
        </section>

        <section className="panel">
          <h2>The enclave and the contract</h2>
          {keyError ? <Notice tone="warn">The enclave couldn&rsquo;t be reached: {keyError}</Notice> : null}
          {keys ? (
            <ol className="steps steps-compact">
              <Step state={matches ? 'pass' : 'fail'} label="The enclave's keys match the contract's" detail={`Verdict key ${short(keys.verdict_public, 12)}`} />
              <Step state="pass" label="Policy hash published" detail={short(keys.policy_hash, 14)} />
            </ol>
          ) : (
            <p className="fine spinline">{running ? <><span className="spin" aria-hidden="true" />Asking the enclave…</> : 'Not checked yet.'}</p>
          )}
          <dl className="pairs">
            <div><dt>Escrow</dt><dd className="mono">{TELLER}</dd></div>
            <div><dt>Model registry</dt><dd className="mono">{REGISTRY}</dd></div>
          </dl>
        </section>
      </div>

      <section className="panel">
        <h2>What these checks don&rsquo;t prove</h2>
        <ul className="plain">
          <li>Hardware attestation means a genuine quote from a trusted operator. It isn&rsquo;t a mathematical proof of privacy, and physical attacks on TEEs exist.</li>
          <li>NEAR AI&rsquo;s measured config is a launcher. The model server changes at runtime, so the quote doesn&rsquo;t pin the model weights.</li>
          <li>OutLayer&rsquo;s keystore rests on a shared master secret that its key holder could reach.</li>
          <li>GPU evidence is checked here in the browser. It can&rsquo;t be checked on-chain, because NEAR has no P-384 host function.</li>
          <li>This page doesn&rsquo;t check image provenance, meaning which build produced the images in the measured config. The repository&rsquo;s <span className="mono">smoke.ts</span> script reports it, using NEAR&rsquo;s SDK.</li>
          <li>A browser can&rsquo;t see the TLS certificate, so this connection isn&rsquo;t bound to the gateway&rsquo;s quote. The email doesn&rsquo;t rely on that, because it&rsquo;s encrypted to the model&rsquo;s key.</li>
        </ul>
        <p className="fine">The verification policy is in the README, and the full list of limits is in the threat model.</p>
      </section>
    </>
  );
}
