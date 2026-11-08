import type { ReactNode } from 'react';
import { Icon, type IconName } from './Art';

const PIPELINE: [IconName, string][] = [
  ['bank', 'Your bank'],
  ['mail', 'Signed receipt'],
  ['lock', 'Sealed in your browser'],
  ['chip', 'Secure hardware'],
  ['shield', 'Two private AIs'],
  ['coin', 'NEAR pays'],
];

function Good({ title, children }: { title: string; children: ReactNode }) {
  return (
    <li>
      <h3>{title}</h3>
      {children}
    </li>
  );
}

export function How() {
  return (
    <article className="essay">
      <section className="hero hero-small">
        <p className="eyebrow">How it works</p>
        <h1>How a contract reads an email it never sees</h1>
        <p className="hero-lede">A smart contract can hold crypto, but it can&rsquo;t see a bank account. Blind Teller closes that gap without anyone reading your bank&rsquo;s email.</p>
      </section>

      <ul className="pipeline" aria-label="The path of a payment">
        {PIPELINE.map(([icon, label], i) => (
          <PipelineStep key={label} icon={icon} label={label} last={i === PIPELINE.length - 1} />
        ))}
      </ul>

      <ol className="flow">
        <li><strong>The seller locks USDC</strong> in a NEAR contract and lists a rate. Their bank details are sealed to an enclave.</li>
        <li><strong>You take the offer.</strong> You get an exact amount to pay, and the enclave re-seals the seller&rsquo;s details to your browser alone.</li>
        <li><strong>You pay from your normal banking app.</strong> Your bank emails a receipt, as banks do.</li>
        <li><strong>Your browser encrypts that email</strong> and sends it straight to the enclave. It never touches the chain, even as ciphertext.</li>
        <li><strong>The enclave checks DKIM,</strong> the signature every bank&rsquo;s mail server adds. It proves the bank sent this email and nobody edited it.</li>
        <li><strong>Two private models read it,</strong> end-to-end encrypted, inside NEAR AI Cloud&rsquo;s secure hardware. They only copy out facts. Fixed code decides.</li>
        <li><strong>The enclave signs a verdict,</strong> and the contract checks that signature, a one-time nullifier, and that the model keys are proven on-chain. Then it pays.</li>
      </ol>

      <h2>Why AI, and why private</h2>
      <p>
        Proving a bank email with zero-knowledge circuits has been tried, and it works. But every bank needs its own circuit, and a template change breaks
        it. ZKP2P moved away from email proofs for that reason. A private model reads any format in any language with no new code, and the secure
        hardware means the convenience doesn&rsquo;t cost you your privacy.
      </p>

      <h2>Why this helps NEAR</h2>
      <p>
        A fiat ramp brings new users to NEAR Intents from any bank that emails a receipt, including the currencies card ramps serve poorly. Parts of it are also
        public goods any NEAR project can use:
      </p>
      <ul className="cards3">
        <Good title="Model registry">NEAR AI Cloud&rsquo;s allowlist lives on Base. This contract proves model keys on NEAR, through the same verifier the MPC network uses, so any contract can ask if a key is genuine.</Good>
        <Good title="Encrypted NEAR AI calls">The Rust client for NEAR AI&rsquo;s E2EE protocol here runs on OutLayer and matches NEAR&rsquo;s published test vectors. Any OutLayer project can reuse it.</Good>
        <Good title="A path to email facts">Nothing in the pipeline is specific to banks. New rules could prove other facts from a signed email, such as a flight delay or a paid invoice, for any contract. That part isn&rsquo;t built yet.</Good>
      </ul>
    </article>
  );
}

function PipelineStep({ icon, label, last }: { icon: IconName; label: string; last: boolean }) {
  return (
    <>
      <li><Icon name={icon} size={16} />{label}</li>
      {last ? null : <li className="to" aria-hidden="true"><Icon name="arrow" size={16} /></li>}
    </>
  );
}
