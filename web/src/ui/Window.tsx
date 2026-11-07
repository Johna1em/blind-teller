import { useCallback, useEffect, useRef, useState } from 'react';
import { DEMO, TELLER } from '../config';
import {
  demoBuyer, getOffer, getOrder, listOffers, newBuyerKey, prove, refusal, revealPayee, settle, takeOffer, termsOf,
  type Config, type Offer, type Order, type Payee, type ProofResult, type TraceStep,
} from '../lib/teller';
import { bankForRail, issueEmail } from '../sandbox/banks';
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

  async function hand(mail: string) {
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
    await hand(await file.text());
  }

  const bank = live ? bankForRail(live.order.rail) : null;

  return (
    <>
      <section className="hero">
        <h1>A contract just read your bank&rsquo;s email. Nobody else did.</h1>
        <p>
          Buy crypto with an ordinary bank transfer. A private AI checks your bank&rsquo;s own receipt inside secure hardware, and a NEAR
          contract releases the funds. No custodian holds them, and no vendor stores your documents.
        </p>
        {config ? (
          <dl className="tally">
            <div><dt>Orders settled</dt><dd>{config.settled}</dd></div>
            <div><dt>Volume</dt><dd>{tokenText(config.volume)} USDC</dd></div>
            <div><dt>Reader</dt><dd>{dev ? 'Sandbox rules' : 'Two TEE models'}</dd></div>
          </dl>
        ) : null}
      </section>

      {offline ? <Notice tone="warn">The contract isn&rsquo;t reachable right now, so offers can&rsquo;t load.</Notice> : null}
      {dev ? (
        <Notice tone="warn">
          Sandbox mode: this deployment reads emails with a labelled rule-based reader, and its verdicts are marked <span className="mono">dev-rules</span>.
          Everything else here is the real path.
        </Notice>
      ) : null}
      {error ? <Notice tone="bad">{error}</Notice> : null}

      <section aria-labelledby="board">
        <h2 id="board">Offers at this window</h2>
        <div className="ledger" role="table" aria-label="Open offers">
          <div className="ledger-row ledger-head" role="row">
            <span role="columnheader">Bank</span>
            <span role="columnheader">Rate per USDC</span>
            <span role="columnheader">Available</span>
            <span role="columnheader">Buy</span>
          </div>
          {offers === null ? <p className="ledger-empty">Reading the contract…</p> : null}
          {offers?.length === 0 ? <p className="ledger-empty">No offers yet.</p> : null}
          {offers?.map(([id, offer]) => {
            const b = bankForRail(offer.rail);
            return (
              <div className="ledger-row" role="row" key={id}>
                <span role="cell"><strong>{b.name}</strong><small>{b.locale}</small></span>
                <span role="cell" className="mono">{b.format(Number(offer.rate_minor))}</span>
                <span role="cell" className="mono">{tokenText(offer.available)}</span>
                <span role="cell" className="ledger-actions">
                  {AMOUNTS.filter((a) => BigInt(a) <= BigInt(offer.available) && BigInt(a) >= BigInt(offer.min_amount)).map((a) => (
                    <button key={a} disabled={stage !== 'browse' || !DEMO.buyerKey} onClick={() => take(id, offer, a)}>{tokenText(a)}</button>
                  ))}
                </span>
              </div>
            );
          })}
        </div>
        <p className="fine">The seller&rsquo;s payment details aren&rsquo;t on this board. They&rsquo;re sealed to the enclave, which opens them only for the buyer of a live order.</p>
      </section>

      <div ref={flow}>
        {stage === 'locking' ? <Ticket label="Locking the order"><p className="lede">Locking the seller&rsquo;s funds on NEAR…</p></Ticket> : null}

        {live && bank && stage !== 'browse' && stage !== 'locking' ? (
          <Ticket label={`Order ${live.orderId}`}>
            <header className="ticket-head">
              <span>Order {live.orderId}</span>
              <span className="mono">{tokenText(live.order.token_amount)} USDC</span>
            </header>
            <p className="amount">{bank.format(Number(live.order.fiat_minor))}</p>
            <p className="fine">
              Pay exactly this amount. The last digits tag your order, because many banks rewrite a transfer note and the amount always survives.
              {' '}<TxLink hash={live.takeHash}>Locked on NEAR</TxLink>
            </p>

            {stage === 'pay' ? (
              <div className="bank">
                <h3>{bank.name}</h3>
                <p className="fine">A fictional bank, standing in for your banking app.</p>
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
                  <p>Asking the enclave for the seller&rsquo;s details…</p>
                )}
              </div>
            ) : null}

            {stage === 'receipt' ? (
              <div className="receipt">
                <h3>Your bank emailed a receipt</h3>
                <p className="fine">It&rsquo;s still only in this browser. It gets encrypted here, and only the enclave can open it.</p>
                <pre className="mail" tabIndex={0}>{email.slice(email.indexOf('From:'))}</pre>
                <div className="row">
                  <button className="primary" onClick={() => hand(email)}>Hand it to the teller</button>
                  <label className="filebtn">
                    Use a .eml file instead
                    <input type="file" accept=".eml,message/rfc822" onChange={(e) => e.target.files?.[0] && readFile(e.target.files[0])} />
                  </label>
                </div>
              </div>
            ) : null}

            {stage === 'reading' || stage === 'paid' || stage === 'refused' ? (
              <ol className="steps">
                <Step state="pass" label="Encrypted in this browser" />
                {STEPS.map((s, i) => <Step key={s.id} state={stateOf(s.id, i)} label={dev && s.dev ? s.dev : s.label} />)}
                {stage === 'paid' ? <Step state="pass" label="The contract checked the signature and paid" /> : null}
              </ol>
            ) : null}

            {stage === 'refused' ? (
              <div className="verdict">
                <Stamp kind="refused">Refused</Stamp>
                <p>{result?.code ? refusal(result.code) : error}</p>
                <button onClick={reset}>Back to the window</button>
              </div>
            ) : null}

            {stage === 'paid' && settled ? (
              <div className="verdict">
                <Stamp kind="paid">Paid</Stamp>
                <p><TxLink hash={settleHash}>The contract released {tokenText(settled.token_amount)} USDC</TxLink> to {short(settled.buyer, 14)}.</p>
                <div className="columns">
                  <div>
                    <h3>On the chain</h3>
                    <ul className="plain">
                      <li>The order and the token amount</li>
                      <li>The enclave&rsquo;s signature</li>
                      <li>A nullifier: <span className="mono">{short(settled.nullifier ?? '', 8)}</span></li>
                    </ul>
                  </div>
                  <div>
                    <h3>Never on the chain</h3>
                    <ul className="plain">
                      <li>The email, even encrypted</li>
                      <li>Your bank and your name</li>
                      <li>The seller&rsquo;s payment details</li>
                    </ul>
                  </div>
                </div>
                {result?.attestationUrl ? <p className="fine"><a href={result.attestationUrl} target="_blank" rel="noreferrer">Hardware attestation for this run</a></p> : null}
                <button onClick={reset}>Back to the window</button>
              </div>
            ) : null}
          </Ticket>
        ) : null}
      </div>
    </>
  );
}

export { TELLER, getOffer };
