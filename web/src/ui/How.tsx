export function How() {
  return (
    <article className="essay">
      <section className="hero hero-small">
        <h1>How a contract reads an email it never sees</h1>
        <p>A smart contract can hold crypto, but it can&rsquo;t see a bank account. Blind Teller closes that gap without anyone reading your bank&rsquo;s email.</p>
      </section>

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
      <ul className="plain">
        <li><strong>Model registry.</strong> NEAR AI Cloud&rsquo;s allowlist lives on Base. This contract proves model keys on NEAR, through the same verifier the MPC network uses, so any contract can ask if a key is genuine.</li>
        <li><strong>Encrypted NEAR AI calls from an enclave.</strong> The Rust client for NEAR AI&rsquo;s E2EE protocol here runs on OutLayer and matches NEAR&rsquo;s published test vectors. Any OutLayer project can reuse it.</li>
        <li><strong>A path to email facts.</strong> Nothing in the pipeline is specific to banks. New rules could prove other facts from a signed email, such as a flight delay or a paid invoice, for any contract. That part isn&rsquo;t built yet.</li>
      </ul>

      <h2>What it doesn&rsquo;t do</h2>
      <ul className="plain">
        <li>Bank rails show the payer to the seller, so you&rsquo;re private from the public and the platform, not from your counterparty.</li>
        <li>The crypto side is public unless it&rsquo;s routed privately afterwards.</li>
        <li>A debit alert shows money left your account, not that it arrived. Instant rails and order limits narrow this gap.</li>
        <li>This is a testnet prototype with fictional banks. P2P fiat is regulated in many countries, so real money needs legal review.</li>
      </ul>
    </article>
  );
}
