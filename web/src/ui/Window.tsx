import { useCallback, useEffect, useRef, useState } from 'react';
import { DEMO } from '../config';
import {
  demoBuyer, getOrder, listOffers, newBuyerKey, prove, refusal, revealPayee, settle, takeOffer, termsOf,
  type Config, type Offer, type Order, type Payee, type ProofResult, type TraceStep,
} from '../lib/teller';
import { quoteRoute, ROUTES, type Quote } from '../lib/intents';
import { checkOrder, checkRun, type Check } from '../lib/runproof';
import { bankForRail, issueEmail } from '../sandbox/banks';
import { Icon, TellerArt } from './Art';
import { Notice, short, Stamp, Step, Ticket, tokenText, TxLink, type StepState } from './parts';

type Stage = 'browse' | 'locking' | 'pay' | 'receipt' | 'reading' | 'paid' | 'refused';

const AMOUNTS = ['10000000', '50000000', '100000000'];

const STEPS: { id: string; label: string; dev?: string }[] = [
  { id: 'terms', label: 'The order terms match' },
  { id: 'decrypt', label: 'Opened inside the enclave' },
  { id: 'dkim', label: "The bank's signature verifies" },
  { id: 'timing', label: 'Sent after this order opened' },
  { id: 'read', label: 'Read by two private AI models', dev: 'Read by the sandbox reader' },
  { id: 'rules', label: 'Fixed rules pass' },
  { id: 'sign', label: 'Verdict signed' },
];

/** The mainnet route from here: any chain, through NEAR Intents. */
function SendAnywhere({ amount }: { amount: string }) {
  const [quotes, setQuotes] = useState<Record<string, Quote | 'failed'>>({});

  useEffect(() => {
    for (const route of ROUTES) {
      quoteRoute(route, amount)
        .then((q) => setQuotes((all) => ({ ...all, [route.id]: q })))
        .catch(() => setQuotes((all) => ({ ...all, [route.id]: 'failed' })));
    }
  }, [amount]);

  return (
    <div className="routes">
      <h3>Send it to any chain</h3>
      <p className="fine">Live NEAR Intents quotes for this amount, from the mainnet 1Click API. Testnet tokens can&rsquo;t bridge, so nothing moves here.</p>
      <dl className="route-grid">
        {ROUTES.map((route) => {
          const q = quotes[route.id];
          return (
            <div key={route.id}>
              <dt>{route.name}</dt>
              <dd className="mono">{!q ? 'Quoting…' : q === 'failed' ? 'No quote right now' : `${Number(q.amountOut).toFixed(3)} USDC in about ${q.seconds}s`}</dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}

/** Lets a viewer check the order and the enclave run from public data. */
function RunChecks({ orderId, order, config, attestationUrl }: { orderId: string; order: Order; config: Config | null; attestationUrl?: string }) {
  const [checks, setChecks] = useState<Check[] | null>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    if (!config) return;
    setBusy(true);
    const results = await checkOrder(orderId, order, config);
    if (attestationUrl) results.push(...(await checkRun(attestationUrl)));
    setChecks(results);
    setBusy(false);
  }

  return (
    <div className="proofbox">
      {checks ? (
        <ol className="steps">{checks.map((c) => <Step key={c.id} state={c.ok ? 'pass' : 'fail'} label={c.label} detail={c.detail} />)}</ol>
      ) : (
        <button disabled={busy} onClick={run}>{busy ? 'Checking public data…' : 'Check this yourself'}</button>
      )}
      {attestationUrl ? <p className="fine"><a href={attestationUrl} target="_blank" rel="noreferrer">Raw hardware attestation for this run</a></p> : null}
    </div>
  );
}

const TRACK = ['Locked', 'Pay', 'Receipt', 'Teller', 'Paid'];
const TRACK_AT: Record<Stage, number> = { browse: -1, locking: 0, pay: 1, receipt: 2, reading: 3, refused: 3, paid: TRACK.length };

function Tracker({ stage }: { stage: Stage }) {
  const at = TRACK_AT[stage];
  return (
    <ol className="tracker" aria-label="Order progress">
      {TRACK.map((label, i) => {
        const state = i < at ? 'done' : i > at ? 'todo' : stage === 'refused' ? 'failed' : 'now';
        return (
          <li key={label} className={`tracker-${state}`} aria-current={i === at ? 'step' : undefined}>
            <span className="tracker-dot">{state === 'done' ? <Icon name="check" size={14} /> : state === 'failed' ? <Icon name="x" size={14} /> : i + 1}</span>
            <span>{label}</span>
          </li>
        );
      })}
    </ol>
  );
}

interface Live {
  offerId: string;
  orderId: string;
  order: Order;
  offer: Offer;
  secret: string;
  payee?: Payee;
  takeHash: string;
}

export function Window({ config, offline }: { config: Config | null; offline: boolean }) {
  const [offers, setOffers] = useState<[string, Offer][] | null>(null);
  const [stage, setStage] = useState<Stage>('browse');
  const [live, setLive] = useState<Live | null>(null);
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [trace, setTrace] = useState<TraceStep[]>([]);
  const [running, setRunning] = useState(false);
  const [settling, setSettling] = useState(false);
  const [result, setResult] = useState<ProofResult | null>(null);
  const [settleHash, setSettleHash] = useState('');
  const [settled, setSettled] = useState<Order | null>(null);
  const flow = useRef<HTMLDivElement>(null);

  const load = useCallback(() => {
    listOffers().then(setOffers).catch(() => setOffers([]));
  }, []);
  useEffect(load, [load]);
  useEffect(() => {
    if (stage !== 'browse') flow.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [stage]);

  const dev = config?.allow_dev ?? true;

  async function take(offerId: string, offer: Offer, amount: string) {
    setError('');
    setStage('locking');
    try {
      const key = newBuyerKey();
      const { orderId, hash } = await takeOffer(demoBuyer(), offerId, amount, key.public);
      const order = await getOrder(orderId);
      if (!order) throw new Error('The order did not appear');
      const next: Live = { offerId, orderId, order, offer, secret: key.secret, takeHash: hash };
      setLive(next);
      setStage('pay');
      const payee = await revealPayee(orderId, key.secret);
      setLive({ ...next, payee });
    } catch (e) {
      setError((e as Error).message);
      setStage('browse');
    }
  }

  async function pay() {
    if (!live?.payee) return;
    const bank = bankForRail(live.order.rail);
    const mail = await issueEmail(bank, {
      amountMinor: Number(live.order.fiat_minor),
      payee: live.payee.handle,
      note: `order ${live.orderId}`,
      payerEmail: 'you@mail.example',
      balanceMinor: 4_231_005,
      at: Math.floor(Date.now() / 1000),
    });
    setEmail(mail);
    setStage('receipt');
  }

  async function hand(mail: string | Uint8Array) {
    if (!live || !config) return;
    setStage('reading');
    setRunning(true);
    setTrace([]);
    setError('');
    try {
      const out = await prove(config.seal_key, termsOf(live.orderId, live.order), live.offer.sealed_payee, mail, dev);
      setResult(out);
      for (const step of out.trace ?? []) {
        setTrace((t) => [...t, step]);
        await new Promise((r) => setTimeout(r, 260));
      }
      if (!out.ok || !out.verdict) {
        setStage('refused');
        return;
      }
      setSettling(true);
      const tx = await settle(demoBuyer(), live.orderId, out.verdict);
      setSettleHash(tx.hash);
      setSettled(await getOrder(live.orderId));
      setStage('paid');
      load();
    } catch (e) {
      setError((e as Error).message);
      setStage('refused');
    } finally {
      setRunning(false);
      setSettling(false);
    }
  }

  function stateOf(id: string, index: number): StepState {
    const hit = trace.find((t) => t.step === id);
    if (hit) return hit.ok ? 'pass' : 'fail';
    if (stage === 'refused' && trace.length) return 'wait';
    return running && index === trace.length ? 'run' : 'wait';
  }

  function reset() {
    setStage('browse');
    setLive(null);
    setEmail('');
    setTrace([]);
    setResult(null);
    setSettled(null);
    setSettleHash('');
    setError('');
  }

  async function readFile(file: File) {
    await hand(new Uint8Array(await file.arrayBuffer()));
  }

  const bank = live ? bankForRail(live.order.rail) : null;

  return (
    <>
      <section className="hero hero-split">
        <div>
          <p className="eyebrow">Private bank-to-crypto on NEAR</p>
          <h1>A contract just read your bank&rsquo;s email. <em>Nobody else did.</em></h1>
          <p className="hero-lede">
            Buy crypto with an ordinary bank transfer. A private AI checks your bank&rsquo;s own receipt inside secure hardware, and a NEAR
            contract releases the funds. No custodian holds them, and no vendor stores your documents.
          </p>
          <div className="row">
            <button className="primary" onClick={() => document.getElementById('board')?.scrollIntoView({ block: 'start' })}>Buy test USDC <Icon name="arrow" size={16} /></button>
            <a className="btn" href="#/cheat">Try to cheat it</a>
          </div>
          {config ? (
            <dl className="tally">
              <div><dt>Orders settled</dt><dd>{config.settled}</dd></div>
              <div><dt>Volume</dt><dd>{tokenText(config.volume)} USDC</dd></div>
              <div><dt>Read by</dt><dd>{dev ? 'Sandbox rules' : '2 private AI models'}</dd></div>
            </dl>
          ) : null}
        </div>
        <TellerArt />
      </section>

      <ol className="threesteps" aria-label="How a trade works">
        <li><span className="num">1</span><div><h3>Lock</h3><p>The seller&rsquo;s USDC is locked in a NEAR contract, so it can&rsquo;t be taken back mid-trade.</p></div></li>
        <li><span className="num">2</span><div><h3>Pay</h3><p>You pay from your normal bank app, and your bank emails you a receipt as usual.</p></div></li>
        <li><span className="num">3</span><div><h3>Prove</h3><p>Sealed hardware checks that receipt privately, and the contract pays you.</p></div></li>
      </ol>

      {offline ? <Notice tone="warn">The contract isn&rsquo;t reachable right now, so offers can&rsquo;t load.</Notice> : null}
      {dev ? (
        <Notice tone="warn">
          Sandbox mode: this deployment reads emails with a labelled rule-based reader, and its verdicts are marked <span className="mono">dev-rules</span>.
          Everything else here is the real path.
        </Notice>
      ) : null}
      {error ? <Notice tone="bad">{error}</Notice> : null}

      <section aria-labelledby="board">
        <div className="board-title" id="board-anchor">
          <h2 id="board">Offers at this window</h2>
          <span>Live from the contract · test USDC</span>
        </div>
        <div className="ledger" role="table" aria-label="Open offers">
          <div className="ledger-row ledger-head" role="row">
            <span role="columnheader">Bank</span>
            <span role="columnheader">Rate per USDC</span>
            <span role="columnheader">Available</span>
            <span role="columnheader" style={{ textAlign: 'right' }}>Buy USDC</span>
          </div>
          {offers === null ? <p className="ledger-empty">Reading the contract…</p> : null}
          {offers?.length === 0 ? <p className="ledger-empty">No offers yet.</p> : null}
          {offers?.map(([id, offer]) => {
            const b = bankForRail(offer.rail);
            return (
              <div className="ledger-row" role="row" key={id}>
                <span role="cell" className="ledger-bank">
                  <span className={`monogram monogram-${b.id}`} aria-hidden="true">{b.name[0]}</span>
                  <span><strong>{b.name}</strong><small>{b.locale}</small></span>
                </span>
                <span role="cell" className="ledger-num" data-label="Rate per USDC">{b.format(Number(offer.rate_minor))}</span>
                <span role="cell" className="ledger-num" data-label="Available">{tokenText(offer.available)}</span>
                <span role="cell" className="ledger-actions">
                  {AMOUNTS.filter((a) => BigInt(a) <= BigInt(offer.available) && BigInt(a) >= BigInt(offer.min_amount)).map((a) => (
                    <button key={a} disabled={stage !== 'browse' || !DEMO.buyerKey} onClick={() => take(id, offer, a)}>{tokenText(a)}</button>
                  ))}
                </span>
              </div>
            );
          })}
        </div>
        <p className="fine"><Icon name="lock" size={15} /><span>The seller&rsquo;s payment details aren&rsquo;t on this board. They&rsquo;re sealed to the enclave, which opens them only for the buyer of a live order.</span></p>
      </section>

      <div ref={flow} className="flow-anchor">
        {stage === 'locking' ? (
          <Ticket label="Locking the order">
            <Tracker stage={stage} />
            <p className="lede spinline"><span className="spin" aria-hidden="true" />Locking the seller&rsquo;s funds on NEAR…</p>
          </Ticket>
        ) : null}

        {live && bank && stage !== 'browse' && stage !== 'locking' ? (
          <Ticket label={`Order ${live.orderId}`}>
            <Tracker stage={stage} />
            <header className="ticket-head">
              <span>Order {live.orderId}</span>
              <span>{tokenText(live.order.token_amount)} USDC</span>
            </header>
            <p className="amount">{bank.format(Number(live.order.fiat_minor))}</p>
            <p className="fine">
              Pay exactly this amount. The last digits tag your order, because many banks rewrite a transfer note and the amount always survives.
              {' '}<TxLink hash={live.takeHash}>Locked on NEAR</TxLink>
            </p>

            {stage === 'pay' ? (
              <div className="bankapp">
                <header className="bankapp-head">
                  <span className={`monogram monogram-${bank.id}`} aria-hidden="true">{bank.name[0]}</span>
                  <div>
                    <h3>{bank.name}</h3>
                    <small>A fictional bank, standing in for your banking app.</small>
                  </div>
                </header>
                {live.payee ? (
                  <>
                    <dl className="pairs">
                      <div><dt>Pay to</dt><dd className="mono">{live.payee.handle}</dd></div>
                      <div><dt>Name</dt><dd>{live.payee.name}</dd></div>
                    </dl>
                    <p className="fine">These details were sealed to this browser. Nobody else watching this order can read them.</p>
                    <button className="primary" onClick={pay}>Send {bank.format(Number(live.order.fiat_minor))}</button>
                  </>
                ) : (
                  <p className="spinline"><span className="spin" aria-hidden="true" />Asking the enclave for the seller&rsquo;s details…</p>
                )}
              </div>
            ) : null}

            {stage === 'receipt' ? (
              <div className="receipt">
                <h3>Your bank emailed a receipt</h3>
                <p className="fine">It&rsquo;s still only in this browser. It gets encrypted here, and only the enclave can open it.</p>
                <div className="paper">
                  <div className="paper-head">
                    <span>Email from {bank.name}</span>
                    <span className="paper-seal"><Icon name="shield" size={14} />Signed by the bank</span>
                  </div>
                  <pre className="mail" tabIndex={0}>{email.slice(email.indexOf('From:'))}</pre>
                </div>
                <div className="row">
                  <button className="primary" onClick={() => hand(email)}><Icon name="lock" size={16} />Hand it to the teller</button>
                  <label className="filebtn">
                    Use a .eml file instead
                    <input type="file" accept=".eml,message/rfc822" onChange={(e) => e.target.files?.[0] && readFile(e.target.files[0])} />
                  </label>
                </div>
              </div>
            ) : null}

            {stage === 'refused' ? (
              <div className="verdict verdict-head">
                <Stamp kind="refused">Refused</Stamp>
                <p>{result?.code ? refusal(result.code) : error}</p>
              </div>
            ) : null}

            {stage === 'paid' && settled ? (
              <div className="verdict verdict-head">
                <Stamp kind="paid">Paid</Stamp>
                <p><TxLink hash={settleHash}>The contract released {tokenText(settled.token_amount)} USDC</TxLink> to {short(settled.buyer, 14)}.</p>
              </div>
            ) : null}

            {stage === 'reading' || stage === 'paid' || stage === 'refused' ? (
              <ol className="steps steps-pair">
                <Step state="pass" label="Encrypted in this browser" />
                {STEPS.map((s, i) => <Step key={s.id} state={stateOf(s.id, i)} label={dev && s.dev ? s.dev : s.label} />)}
                {settling || stage === 'paid' ? <Step state={settling ? 'run' : 'pass'} label="The contract checks the signature and pays" /> : null}
              </ol>
            ) : null}

            {stage === 'refused' ? <div className="row"><button onClick={reset}>Back to the window</button></div> : null}

            {stage === 'paid' && settled ? (
              <div className="verdict">
                <div className="columns">
                  <div className="mini">
                    <h3><Icon name="link" />On the chain</h3>
                    <ul className="plain">
                      <li>The order and the token amount</li>
                      <li>The enclave&rsquo;s signature</li>
                      <li>A nullifier: <span className="mono">{short(settled.nullifier ?? '', 8)}</span></li>
                    </ul>
                  </div>
                  <div className="mini mini-private">
                    <h3><Icon name="eyeoff" />Never on the chain</h3>
                    <ul className="plain">
                      <li>The email, even encrypted</li>
                      <li>Your bank and your name</li>
                      <li>The seller&rsquo;s payment details</li>
                    </ul>
                  </div>
                </div>
                <SendAnywhere amount={settled.token_amount} />
                <RunChecks orderId={live.orderId} order={settled} config={config} attestationUrl={result?.attestationUrl} />
                <button onClick={reset}>Back to the window</button>
              </div>
            ) : null}
          </Ticket>
        ) : null}
      </div>
    </>
  );
}
