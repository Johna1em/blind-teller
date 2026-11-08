import { useEffect, useState } from 'react';
import { DEMO, TELLER, TOKEN } from '../config';
import { ATTACKS, randomOrderId, type Attack } from '../lib/attack';
import { listOffers, prove, refusal, type Config, type Offer, type ProofResult } from '../lib/teller';
import { bankForRail } from '../sandbox/banks';
import { Icon } from './Art';
import { Notice, Stamp } from './parts';

type Outcome = { state: 'idle' } | { state: 'running' } | { state: 'done'; result: ProofResult } | { state: 'error'; message: string };

const FIAT = 885_037;

export function Cheat({ config }: { config: Config | null }) {
  const [offer, setOffer] = useState<Offer | null>(null);
  const [offerId, setOfferId] = useState('0');
  const [outcomes, setOutcomes] = useState<Record<string, Outcome>>({});
  const [payee] = useState('asha.rao@meridian');
  const [trying, setTrying] = useState(false);

  useEffect(() => {
    listOffers()
      .then((list) => {
        const hit = list.find(([, o]) => bankForRail(o.rail).id === 'meridian');
        if (hit) {
          setOfferId(hit[0]);
          setOffer(hit[1]);
        }
      })
      .catch(() => undefined);
  }, []);

  const ready = !!(offer && config && DEMO.paymentKey);

  async function run(attack: Attack) {
    if (!offer || !config) return;
    setOutcomes((o) => ({ ...o, [attack.id]: { state: 'running' } }));
    try {
      const now = Date.now();
      const terms = {
        contract: TELLER,
        order_id: randomOrderId(),
        offer_id: Number(offerId),
        seller: offer.seller,
        buyer: DEMO.buyerAccount,
        token: TOKEN,
        token_amount: '100000000',
        currency: offer.currency,
        fiat_minor: FIAT,
        rail: offer.rail,
        payee_commit: offer.payee_commit,
        created_ms: now - 60_000,
        deadline_ms: now + 1_800_000,
      };
      const mail = await attack.build(FIAT, payee, Math.floor(now / 1000));
      const result = await prove(config.seal_key, terms, offer.sealed_payee, mail, config.allow_dev);
      setOutcomes((o) => ({ ...o, [attack.id]: { state: 'done', result } }));
    } catch (e) {
      setOutcomes((o) => ({ ...o, [attack.id]: { state: 'error', message: (e as Error).message } }));
    }
  }

  async function runAll() {
    setTrying(true);
    for (const attack of ATTACKS) await run(attack);
    setTrying(false);
  }

  const results = ATTACKS.map((a) => outcomes[a.id]).filter((o): o is Extract<Outcome, { state: 'done' }> => o?.state === 'done');
  const refused = results.filter((o) => !o.result.ok).length;

  return (
    <>
      <section className="hero hero-small hero-split">
        <div>
          <p className="eyebrow">Live attacks on the real enclave</p>
          <h1>Try to cheat the teller</h1>
          <p className="hero-lede">
            Each button builds a real attack email in this browser, seals it, and sends it to the real enclave. Nothing is simulated. A refusal is
            the enclave&rsquo;s own answer, and the reason shown is the code it returned.
          </p>
          <button className="primary" disabled={!ready || trying} onClick={runAll}>{trying ? 'Trying them all…' : 'Try them all'}</button>
        </div>
        <div className="score" role="status">
          <p className="score-num"><strong>{refused}</strong> / {ATTACKS.length}</p>
          <p className="score-label">attacks refused so far</p>
          <div className="bar"><span style={{ width: `${(results.length / ATTACKS.length) * 100}%` }} /></div>
        </div>
      </section>

      {!ready ? <Notice tone="warn">The enclave isn&rsquo;t connected on this deployment yet, so these can&rsquo;t run.</Notice> : null}

      <div className="attacks">
        {ATTACKS.map((attack, i) => {
          const outcome = outcomes[attack.id] ?? { state: 'idle' };
          const wasRefused = outcome.state === 'done' && !outcome.result.ok;
          return (
            <article className={`attack${wasRefused ? ' attack-refused' : ''}`} key={attack.id}>
              <div className="attack-head">
                <span className="num">{i + 1}</span>
                <h2>{attack.title}</h2>
              </div>
              <p>{attack.move}</p>
              <span className="tag"><Icon name="shield" size={14} />Stopped by: {attack.defense}</span>
              {outcome.state === 'done' ? (
                outcome.result.ok ? (
                  <Stamp kind="paid">Passed</Stamp>
                ) : (
                  <>
                    <Stamp kind="refused">Refused</Stamp>
                    <p className="reason">{refusal(outcome.result.code)}</p>
                    <span className="code">{outcome.result.code}</span>
                  </>
                )
              ) : outcome.state === 'error' ? (
                <p className="reason">{outcome.message}</p>
              ) : (
                <button disabled={!ready || outcome.state === 'running'} onClick={() => run(attack)}>
                  {outcome.state === 'running' ? <><span className="spin" aria-hidden="true" />Reading…</> : 'Try it'}
                </button>
              )}
            </article>
          );
        })}
      </div>
    </>
  );
}
