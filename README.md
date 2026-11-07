# Blind Teller

Buy crypto with an ordinary bank transfer. A private AI reads your bank's payment email inside secure hardware, and a NEAR contract releases the funds. Nobody else sees the email, and nothing about your bank reaches the chain.

- **Hosted demo:** https://test.fastfs.io/blindteller.testnet/blindteller.testnet/index.html
- **Track:** Privacy & Private AI (`privacy`), built at NEAR HACKATHON
- **Status:** testnet prototype with fictional banks. See [What's real](#whats-real) for what runs live today.
- **Licence:** MIT
- **Trust limits:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## The problem

A smart contract can hold crypto, but it can't see a bank account. People who trade crypto for bank money today have three options:

| Option | What goes wrong |
|---|---|
| A custodial exchange | It holds your crypto and your identity documents |
| A P2P trade with a payment screenshot | Screenshots are easy to fake |
| A zero-knowledge proof of a bank email | Every bank needs its own circuit or parser, and a template change breaks it |

Blind Teller uses the receipt email that banks already send. Banks sign those emails with DKIM. An enclave checks the signature and two private models read the text, so one pipeline can serve any bank in any language without new code per bank. The email stays inside secure hardware.

## Try it

You need a browser. You don't need a wallet, funds or a login. Each order takes under a minute.

| # | Do this | You should see |
|---|---|---|
| 1 | Open the [hosted demo](https://test.fastfs.io/blindteller.testnet/blindteller.testnet/index.html) | Three offers from fictional banks: Meridian Bank (INR), Banco Aurora (BRL) and Rheinbank (EUR) |
| 2 | Click **10** on Meridian Bank | The contract locks 10 USDC. Your browser shows the seller's payment details, which the enclave re-sealed for this browser alone, and an exact amount such as `Rs. 885.01` |
| 3 | Click **Send Rs. 885.01** (your amount may differ) | The fictional bank issues a DKIM-signed receipt email, shown on the page |
| 4 | Click **Hand it to the teller** | The page encrypts the email and sends it to the enclave. Each check ticks off, the page shows **PAID**, and the contract pays 10 USDC to the demo buyer |
| 5 | Read **On the chain** and **Never on the chain** | The chain holds the order, the amount, a signature and a nullifier. It doesn't hold the email, the bank, or anyone's name |
| 6 | Read **Send it to any chain** | Live NEAR Intents quotes for this amount to Solana, Base, Arbitrum and Ethereum. These are dry quotes, because testnet tokens can't bridge |
| 7 | Click **Check this yourself** | 12 checks run in your browser. One fails on purpose: *Read by the two private models*, because the demo uses the labelled rule-based reader. See [What's real](#whats-real) |
| 8 | Open **Try to cheat** and run each attack | Each one runs on the real enclave and comes back **REFUSED** with a reason: edited amount, forged bank, lookalike domain, prompt injection, underpayment with a note, wrong payee, failed payment, reused receipt |
| 9 | Open **Proof** and click **Run the checks** | 9 checks per model, with a fresh nonce: Intel quote, NVIDIA GPUs, boot log, and the key's proof on NEAR. Then the enclave's keys are compared with the contract's |
| 10 | On **Proof**, choose a recent `.eml` from your own inbox | The enclave checks the real signature against the sender's live DNS and answers **GENUINE** or **REFUSED**. It stores nothing and moves no money |

For step 10, Gmail users can open a message, click the three dots, then **Download message**. Older mail can fail if the sender has rotated its key. Senders with keys under 2048 bits are refused.

## What's real

| Part | Status today |
|---|---|
| Escrow contract | **Live on testnet.** Orders settle with test USDC |
| Model registry | **Live on testnet.** Both model keys are proven on NEAR through `tee-verifier` |
| Enclave (OutLayer, Intel TDX) | **Live.** Decrypts, checks DKIM, runs the rules, signs verdicts |
| Attestation checks | **Live.** They run in your browser with a fresh nonce |
| DKIM on real mail | **Live.** See [Real mail test](#real-mail-test) |
| Two private models on NEAR AI Cloud | **Built, not yet run live.** It needs an API key. The E2EE code matches NEAR's published test vectors, and the full path passes against a scripted model server |
| Reader on the hosted demo | **A rule-based stand-in,** labelled in the UI and stamped `dev-rules` in each verdict, so it can't pass as an AI read |
| Banks | **Fictional.** Their signing key is public on purpose, and their domains use `.example` |
| Any-chain payout | **Quotes only.** They come from the mainnet 1Click API, and nothing moves |
| Wallet login and a seller page | **Not built.** The demo uses a capped demo buyer, and offers are listed by script |

## How it works

1. **Offer.** A seller locks USDC in the contract and lists a rate and a rail. Their bank details are sealed to the enclave. The contract stores the sealed blob and a hash of it.
2. **Order.** A buyer takes the offer with `take_offer`. The order gets an exact fiat amount, with up to 99 minor units added as a tag, so it can be told apart from other orders.
3. **Reveal.** The enclave re-seals the seller's details to the buyer's one-time key.
4. **Payment.** The buyer pays from their normal bank app, and the bank emails a receipt.
5. **Proof.** The buyer's browser seals the `.eml` to the enclave and calls OutLayer over HTTPS. The email never goes on-chain, even encrypted.
6. **Authenticity.** The enclave checks DKIM (RFC 6376) against keys fetched from two DNS resolvers, which must agree. It requires `From` to be signed and aligned, and refuses `l=`, duplicate headers and keys under 2048 bits.
7. **Reading.** Two different models on NEAR AI Cloud read the email through E2EE to their attested keys. They only copy facts into a fixed schema.
8. **Decision.** Fixed Rust code decides, not the AI. The models must agree, the amount must match the order to the penny, the recipient must match the seller, and every amount in the email must be explained. Text the payer wrote is removed before these checks, and instruction-like text is refused.
9. **Settlement.** The enclave signs a verdict. `settle` rebuilds the order terms, verifies the signature with `env::ed25519_verify`, spends a one-time nullifier, asks the registry whether both model keys are attested, and pays the buyer.

If no proof arrives, the order expires and the USDC returns to the offer.

### Who can see what

| Party | Sees |
|---|---|
| The public and the chain | Order state, token amounts, accounts, verdict signature, nullifier |
| The seller | The payment arriving in their bank account, as with any transfer |
| OutLayer enclave | The email, while it runs, inside TDX |
| NEAR AI model TEE | The email, while it runs, through E2EE |
| Us | Nothing. The site is static and there is no backend |

## Check it yourself

These commands use public data only. They need no keys or account.

```bash
git clone <this repository>
cd blind-teller/web
npm ci
npx tsx scripts/verify.ts
```

`verify.ts` re-checks the latest settled order against the chain: its terms, the enclave's signature, the nullifier and the model keys. To also check the enclave run, pass an order id and the attestation URL from **Raw hardware attestation for this run** on the paid screen:

```bash
npx tsx scripts/verify.ts 9 <attestation url>
```

That adds the active Wasm hash on `outlayer.testnet`, the project id, Intel's signature on the worker's quote, debug mode, the worker's measurements on-chain, and OutLayer's task hash in the quote. Exit code 0 means every check passed. Sandbox orders exit 1 by design, because the *read by the two private models* check fails for them.

## Real mail test

On 7 Nov 2026 we sent 14 fresh messages from public Linux kernel mailing lists through the deployed enclave, using `web/scripts/inspect.ts`.

| Result | Count |
|---|---|
| Genuine, including `gmail.com`, `kernel.org` and `intel.com` | 9 |
| Refused with `dkim_key_weak`: the sender's key is under 2048 bits | 5 |

A separate December 2025 Gmail message came back `dkim_key_revoked`, because Google no longer publishes that selector.

## Run it locally

Needs Node 24. The page talks to the contracts already on testnet.

```bash
cd web
npm ci
npm run dev
```

Then open the URL Vite prints.

To run the tests you also need Rust 1.99.1, which `rust-toolchain.toml` selects:

```bash
cargo test -p teller -p model-registry -p teller-core
```

```bash
cargo test -p blind-teller-enclave --features dev-extractor
```

```bash
cd web && npx vitest run
```

That's 169 tests. They cover the contracts, DKIM, sealing, E2EE against NEAR's vectors, 32 pipeline and attack cases, and shared vectors across Rust and TypeScript. [The threat model](docs/THREAT_MODEL.md) names the test behind each attack.

To deploy your own copy, you need a funded testnet account in the NEAR CLI keychain and about 10 NEAR. Build the contracts with `cargo near build non-reproducible-wasm --no-abi` in each contract folder, then:

```bash
BT_CONTRACT=teller.youraccount.testnet cargo build -p blind-teller-enclave --target wasm32-wasip2 --release --features wasi,dev-extractor
```

```bash
cd web && BT_ROOT=youraccount.testnet npx tsx scripts/deploy.ts
```

To turn on the real models, set `NEAR_AI_API_KEY` in your environment and run `scripts/set-model-key.ts`. Never put the key in a file.

## Deployed on testnet

| What | Where |
|---|---|
| Escrow | [`teller.blindteller.testnet`](https://testnet.nearblocks.io/address/teller.blindteller.testnet) |
| Model registry | [`models.blindteller.testnet`](https://testnet.nearblocks.io/address/models.blindteller.testnet) |
| Enclave project | `blindteller.testnet/teller` on `outlayer.testnet` |
| Enclave build | `c6f3724e65a3ecf45d950c30de115e1ecb08e3039f84bc4ff0cf7464411a6c85` |
| Token | `usdc.fakes.testnet` |
| Quote verifier | `tee-verifier-2026-11-02.testnet` |
| Website | On NEAR through FastFS, under `blindteller.testnet` |

[deployments/testnet.json](deployments/testnet.json) has the keys and hashes.

## Reusable parts for NEAR

- **Model registry (`contracts/model-registry`).** NEAR AI Cloud's allowlist lives on Base. This contract proves model signing keys on NEAR through `tee-verifier`, the same verifier the MPC network uses. Anyone can relay a proof, and any contract can call `is_attested(key)`.
- **Rust client for NEAR AI E2EE v3 (`enclave/src/e2ee.rs`, `enclave/src/nearai.rs`).** It runs on OutLayer, matches NEAR's published vectors byte for byte, and requires a `provider_tee` signature rather than a gateway one.
- **DKIM for OutLayer (`enclave/src/dkim.rs`).** A strict verifier with no bank-specific code. New rules on top could prove other facts from signed email, such as a flight delay or a paid invoice. Those rules aren't built.

## Limits

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full list. The main ones:

- Hardware attestation means a genuine quote from a trusted operator. It isn't a mathematical proof of privacy, and physical attacks on TEEs exist.
- OutLayer's master key holder and NEAR AI's operators are trusted. NEAR AI's measured config is a launcher, so the quote doesn't pin the model weights.
- The Wasm hash proves which binary ran. We haven't shown that another machine can rebuild the same hash from this source.
- A debit alert shows money left an account, not that it arrived.
- The seller sees who paid them. The crypto leg is public unless it's routed privately afterwards.
- Anyone can call the enclave again with the same email. A one-shot limit isn't built.
- P2P fiat exchange is regulated in many countries. Real money needs legal review.

## Repository map

| Path | What it is |
|---|---|
| `contracts/teller` | Escrow: offers, orders, settlement, refunds |
| `contracts/model-registry` | On-chain proofs of model keys |
| `crates/teller-core` | Canonical strings shared by the contract and enclave |
| `enclave` | The OutLayer job: DKIM, sealing, E2EE, rules, verdicts |
| `web/src` | React site, browser crypto and attestation checks |
| `web/src/sandbox` | The fictional banks |
| `web/scripts` | Deploy, register models, host, verify, inspect |
| `fixtures` | Test vectors shared across Rust and TypeScript |
| `docs/THREAT_MODEL.md` | Trust assumptions, attacks and limits |

## Libraries and AI use

**Baseline:** nothing here predates the hackathon. The first commit is dated 7 Nov 2026, and there's no earlier code or template.

**AI code:** the code, tests and docs were written with Claude Code (Claude Opus 5.5).

**Rust:** `near-sdk`, `borsh`, `rsa`, `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, `serde`, `serde_json`, `hex`, `base64`, `getrandom`, `outlayer`, `wasi-http-client`.

**Web:** `react`, `@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@phala/dcap-qvl`, `vite`, `vitest`, `tsx`, `typescript`.

**Services:** OutLayer, NEAR AI Cloud, `tee-verifier`, FastFS, the NEAR Intents 1Click API, Google and Cloudflare DNS-over-HTTPS, Phala's PCCS mirror, and NVIDIA's attestation service.

## Licence

[MIT](LICENSE)
