import type { ReactNode } from 'react';
import { EXPLORER, TOKEN_DECIMALS } from '../config';

export function Stamp({ kind, children }: { kind: 'paid' | 'refused'; children: ReactNode }) {
  return <div className={`stamp stamp-${kind}`} role="status">{children}</div>;
}

export function Ticket({ children, label }: { children: ReactNode; label?: string }) {
  return (
    <section className="ticket" aria-label={label}>
      {children}
    </section>
  );
}

export type StepState = 'wait' | 'run' | 'pass' | 'fail';

export function Step({ state, label, detail }: { state: StepState; label: string; detail?: string }) {
  const mark = state === 'pass' ? '✓' : state === 'fail' ? '✕' : state === 'run' ? '…' : '';
  return (
    <li className={`step step-${state}`}>
      <span className="step-mark" aria-hidden="true">{mark}</span>
      <span>
        {label}
        {detail ? <small>{detail}</small> : null}
      </span>
      <span className="sr">{state === 'pass' ? 'passed' : state === 'fail' ? 'failed' : state === 'run' ? 'running' : 'waiting'}</span>
    </li>
  );
}

export const tokenText = (amount: string | number) => (Number(amount) / 10 ** TOKEN_DECIMALS).toLocaleString('en-US', { maximumFractionDigits: 2 });

export const short = (s: string, n = 10) => (s.length > n * 2 ? `${s.slice(0, n)}…${s.slice(-6)}` : s);

export function TxLink({ hash, children }: { hash: string; children?: ReactNode }) {
  return (
    <a href={`${EXPLORER}/txns/${hash}`} target="_blank" rel="noreferrer">
      {children ?? short(hash, 8)}
    </a>
  );
}

export function Notice({ tone = 'plain', children }: { tone?: 'plain' | 'warn' | 'bad'; children: ReactNode }) {
  return <p className={`notice notice-${tone}`}>{children}</p>;
}
