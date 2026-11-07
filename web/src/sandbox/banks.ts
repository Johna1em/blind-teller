// Three fictional banks in three languages and formats. `.example` domains are
// reserved by RFC 2606, so no real bank can hold them. This is the sample data
// judges use, and the reason "no new code per bank" can be shown in one click.

import { dkimSign } from '../lib/dkimsign';
import sandboxKey from './sandbox-dkim-private.json';

export interface Payment {
  amountMinor: number;
  payee: string;
  note: string;
  payerEmail: string;
  balanceMinor: number;
  status?: 'ok' | 'failed';
  direction?: 'debit' | 'credit';
  /** Unix seconds. */
  at: number;
}

export interface Bank {
  id: string;
  name: string;
  rail: string;
  currency: string;
  locale: string;
  domain: string;
  format: (minor: number) => string;
  template: (p: Payment, amount: string, balance: string, ref: string) => { subject: string; body: string };
}

const group = (minor: number) => Math.floor(minor / 100).toString();
const cents = (minor: number) => String(minor % 100).padStart(2, '0');

function indian(minor: number): string {
  const w = group(minor);
  const last3 = w.slice(-3);
  const rest = w.slice(0, -3).replace(/\B(?=(\d{2})+(?!\d))/g, ',');
  return `${rest ? `${rest},` : ''}${last3}.${cents(minor)}`;
}

function dotted(minor: number): string {
  return `${group(minor).replace(/\B(?=(\d{3})+(?!\d))/g, '.')},${cents(minor)}`;
}

export const BANKS: Bank[] = [
  {
    id: 'meridian',
    name: 'Meridian Bank',
    rail: 'sandbox-upi',
    currency: 'INR',
    locale: 'English · UPI',
    domain: 'alerts.meridianbank.example',
    format: (m) => `Rs. ${indian(m)}`,
    template: (p, amount, balance, ref) => ({
      subject: 'Debit alert: your UPI payment',
      body: [
        'Hello,',
        '',
        'Your UPI payment has been processed.',
        '',
        `Amount: ${amount}`,
        'Currency: INR',
        `Status: ${p.status === 'failed' ? 'Failed' : 'Successful'}`,
        `Type: ${p.direction === 'credit' ? 'Credit' : 'Debit'}`,
        `To: ${p.payee}`,
        `Reference: ${ref}`,
        `Note: ${p.note}`,
        `Available balance: ${balance}`,
        '',
        'This is an automated message from Meridian Bank.',
      ].join('\r\n'),
    }),
  },
  {
    id: 'aurora',
    name: 'Banco Aurora',
    rail: 'sandbox-pix',
    currency: 'BRL',
    locale: 'Português · Pix',
    domain: 'avisos.bancoaurora.example',
    format: (m) => `R$ ${dotted(m)}`,
    template: (p, amount, balance, ref) => ({
      subject: 'Comprovante do seu Pix',
      body: [
        'Olá,',
        '',
        'Seu Pix foi enviado.',
        '',
        `Valor: ${amount}`,
        'Moeda: BRL',
        `Situação: ${p.status === 'failed' ? 'Falhou' : 'Concluído'}`,
        `Tipo: ${p.direction === 'credit' ? 'Crédito' : 'Débito'}`,
        `Para: ${p.payee}`,
        `Identificador: ${ref}`,
        `Mensagem: ${p.note}`,
        `Saldo disponível: ${balance}`,
        '',
        'Mensagem automática do Banco Aurora.',
      ].join('\r\n'),
    }),
  },
  {
    id: 'rhein',
    name: 'Rheinbank',
    rail: 'sandbox-sepa',
    currency: 'EUR',
    locale: 'Deutsch · SEPA',
    domain: 'service.rheinbank.example',
    format: (m) => `${dotted(m)} EUR`,
    template: (p, amount, balance, ref) => ({
      subject: 'Ihre SEPA-Echtzeitüberweisung',
      body: [
        'Guten Tag,',
        '',
        'Ihre Überweisung wurde ausgeführt.',
        '',
        `Betrag: ${amount}`,
        'Währung: EUR',
        `Status: ${p.status === 'failed' ? 'Fehlgeschlagen' : 'Ausgeführt'}`,
        `Art: ${p.direction === 'credit' ? 'Gutschrift' : 'Lastschrift'}`,
        `An: ${p.payee}`,
        `Referenz: ${ref}`,
        `Verwendungszweck: ${p.note}`,
        `Verfügbarer Saldo: ${balance}`,
        '',
        'Automatische Nachricht der Rheinbank.',
      ].join('\r\n'),
    }),
  },
];

export const bankForRail = (rail: string) => BANKS.find((b) => b.rail === rail) ?? BANKS[0];

function rfc2822(seconds: number): string {
  const d = new Date(seconds * 1000);
  const days = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const p = (n: number) => String(n).padStart(2, '0');
  return `${days[d.getUTCDay()]}, ${p(d.getUTCDate())} ${months[d.getUTCMonth()]} ${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
}

/** RFC 2047, so a subject with `ü` stays valid in a header. */
function encodeWord(s: string): string {
  if (/^[\x20-\x7e]*$/.test(s)) return s;
  const bytes = new TextEncoder().encode(s);
  return `=?UTF-8?B?${btoa(String.fromCharCode(...bytes))}?=`;
}

/** Issue a DKIM-signed receipt, the way a bank's mail server would. */
export async function issueEmail(bank: Bank, p: Payment): Promise<string> {
  const ref = String(600_000_000_000 + (p.amountMinor * 7919 + p.at) % 99_999_999_999);
  const { subject, body } = bank.template(p, bank.format(p.amountMinor), bank.format(p.balanceMinor), ref);
  const head = [
    `From: ${bank.name} <noreply@${bank.domain}>`,
    `To: <${p.payerEmail}>`,
    `Subject: ${encodeWord(subject)}`,
    `Date: ${rfc2822(p.at)}`,
    `Message-ID: <${p.at}.${ref}@${bank.domain}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
  ].join('\r\n');
  return dkimSign(`${head}\r\n\r\n${body}\r\n`, { domain: bank.domain, timestamp: p.at, pkcs8: sandboxKey.pkcs8 });
}
